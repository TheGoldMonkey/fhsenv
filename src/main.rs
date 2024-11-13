use std::{ffi::{CString, OsStr}, path::{Path, PathBuf}, process::Stdio};
use anyhow::{anyhow, bail, Context, Result};
use nix::{sched::{unshare, setns, CloneFlags}, sys::signal, unistd::{execvp, Uid, User}};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use tokio::{fs, process::Command};

async fn subprocess<I: IntoIterator<Item: AsRef<OsStr>>>(program: &str, args: I) -> Result<String> {
    let output = Command::new(program).args(args).output().await?;

    if !output.status.success() {
        bail!("Error running {program}: {}.", String::from_utf8(output.stderr.clone())?);
    }

    Ok(String::from_utf8(output.stdout)?.trim().into())
}

async fn create_ld_so_conf() -> Result<()> {
    let ld_so_conf_entries = [
        "/lib",
        "/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/lib/i386-linux-gnu",
        "/lib32",
        "/usr/lib/i386-linux-gnu",
        "/usr/lib32",
        "/run/opengl-driver/lib",
        "/run/opengl-driver-32/lib"
    ];

    fs::write(Path::new("/etc/ld.so.conf"), ld_so_conf_entries.join("\n")).await
        .context("Couldn't write to /etc/ld.so.conf.").map_err(Into::into)
}

fn prepend_entries_in_env(key: &str, additions: &[&str]) {
    let mut val = std::env::var(key).unwrap_or_default();
    if !val.is_empty() {
        val = ":".to_string() + &val;
    }
    std::env::set_var(key, additions.join(":") + &val);
}

fn prepare_env_vars() {
    prepend_entries_in_env("PATH", &[
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/run/wrappers/bin"
    ]);

    prepend_entries_in_env("XDG_DATA_DIRS", &[
        "/usr/local/share",
        "/usr/share",
        "/run/opengl-driver/share",
        "/run/opengl-driver-32/share"
    ]);

    prepend_entries_in_env("ACLOCAL_PATH", &["/usr/share/aclocal"]);
    prepend_entries_in_env("PKG_CONFIG_PATH", &["/usr/lib/pkgconfig"]);
    prepend_entries_in_env("LD_LIBRARY_PATH", &["/run/opengl-driver/lib", "/run/opengl-driver-32/lib"]);
    std::env::set_var("LOCALE_ARCHIVE", "/usr/lib/locale/locale-archive");
}

async fn get_fhs_path(fhs_definition: &str) -> Result<PathBuf> {
    let derivation_path = subprocess("nix-instantiate", &["-E", &fhs_definition]).await?;
    let output = subprocess("nix", &["derivation", "show", &derivation_path]).await?;
    let derivation = serde_json::from_str::<serde_json::Value>(&output)?;

    let pattern = regex::Regex::new(r"^(.*)-shell-env$")?;
    let fhsenv_name = &pattern.captures(derivation[&derivation_path]["name"].as_str().unwrap_or_default())
        .ok_or(anyhow!("Couldn't parse derivation for environment name."))?[1];

    let serde_json::Value::Object(input_drvs) = &derivation[&derivation_path]["inputDrvs"] else {
        bail!("Couldn't parse derivation for FHS store path.");
    };
    let pattern = regex::Regex::new(&format!(r"/nix/store/([^-]+)-{}-fhs.drv", regex::escape(fhsenv_name)))?;
    let fhs_drv = input_drvs.keys().filter_map(|input_drv| pattern.find(input_drv)).next()
        .ok_or(anyhow!("Expected FHS derivation in inputDrvs."))?.as_str();

    // like subprocess but without piping stderr
    let process = Command::new("nix-store").args(["--realise", fhs_drv]).stdout(Stdio::piped()).spawn()?;
    let output = process.wait_with_output().await?;
    let fhs = Path::new(std::str::from_utf8(&output.stdout)?.trim());
    if !output.status.success() || !fhs.exists() {
        bail!("Error building {fhs_drv}.");
    }

    Ok(fhs.into())
}

#[derive(Clone, Copy)]
enum Mapping { Uid, Gid }

// TODO: there can be multiple ranges for a single user
async fn read_subuid(mapping: Mapping, username: &str) -> Result<(u32, u32)> {
    let path = match mapping { Mapping::Uid => "/etc/subuid", Mapping::Gid => "/etc/subgid" };
    let subuid = std::fs::read_to_string(path).context("Failed to read /etc/subuid.")?;
    for line in subuid.split('\n') {
        let [_username, lower_id, range] = line.split(':').collect::<Vec<_>>()[..] else {
            continue;
        };

        if _username == username {
            return Ok((
                lower_id.parse().context("User has invalid lower_id in /etc/subuid.")?,
                range.parse().context("User has invalid range in /etc/subuid.")?
            ));
        }
    }

    bail!("{username} has no entry in {path}.");
}

async fn set_mapping(mapping: Mapping, pid: u32, uid: u32, username: &str) -> Result<String> {
    let (lower_id, range) = read_subuid(mapping, &username).await?;
    let args = [
        pid,
        0, lower_id, uid,
        uid, uid, 1,
        uid + 1, lower_id + uid, range - uid
    ];

    let mapper = match mapping { Mapping::Uid => "newuidmap", Mapping::Gid => "newgidmap" };
    subprocess(mapper, args.iter().map(u32::to_string).into_iter()).await
}

// https://man7.org/linux/man-pages/man7/user_namespaces.7.html
// https://man7.org/linux/man-pages/man1/newuidmap.1.html
async fn enter_namespace() -> Result<()> {
    // TODO: does it matter whether user is root?
    // uid and guid before entering user namespace
    let uid = Uid::current().as_raw();
    let username = User::from_uid(Uid::current())
        .unwrap_or(None).ok_or(anyhow!("Failed to get username from uid."))?.name;
    let gid = nix::unistd::Gid::current().as_raw();

    // TODO: explain why spawn separate process to create namespace
    let mut process = Command::new("unshare").args(&["-U", "sleep", "infinity"]).spawn()
        .context("Couldn't create namespace.")?;
    let pid = process.id().ok_or(anyhow!("Namespace parent exited prematurely."))?;

    set_mapping(Mapping::Uid, pid, uid, &username).await.context("Failed to map uid.")?;
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny").context("Couldn't disable setgroups")?;
    set_mapping(Mapping::Gid, pid, gid, &username).await.context("Failed to map gid.")?;

    // Enter the namespace
    let ns_path = format!("/proc/{pid}/ns/user");
    let ns_fd = std::fs::File::open(&ns_path).context(format!("Failed to open {ns_path}."))?;
    setns(ns_fd, CloneFlags::CLONE_NEWUSER).context(format!("Couldn't enter {ns_path}."))?;

    if let Err(error) = signal::kill(nix::unistd::Pid::from_raw(pid as i32), signal::Signal::SIGKILL) {
        eprintln!("Failed to kill process {pid}: {error}.");
    } else if let Err(error) = process.wait().await {
        eprintln!("Failed to wait for process {pid} to exit: {error}.");
    }

    unshare(CloneFlags::CLONE_NEWNS).context("Couldn't flag namespace as mount.")?;

    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None::<&str>)
        .context("Failed to make root a slave mount.")?;

    Ok(())
}

// TODO: is there a practical limit on number of bind mounts?
async fn bind_entries(parent: &Path, target: &Path, exclusions: &[&str]) -> Result<()> {
    // TODO: loop asynchronously
    for entry in parent.read_dir()?.collect::<Result<Vec<_>, _>>()? {
        let exclude = exclusions.into_iter().any(|exclusion| entry.file_name().to_str() == Some(exclusion));
        if exclude || target.join(entry.file_name()).exists() {
            continue;
        }

        let target = target.join(entry.file_name());
        if !target.exists() {
            if entry.path().is_dir() {
                fs::create_dir(&target).await.context("Failed to create stub directory.")?;
            } else {
                fs::write(&target, "").await.context("Failed to create stub file.")?;
            }
        }

        let flags = MsFlags::MS_BIND | MsFlags::MS_REC;
        mount(Some(&entry.path()), &target, None::<&str>, flags, None::<&str>)  // mount works with files too
            .context(format!("Failed to mount {entry:?} to {target:?}."))?;
    }

    Ok(())
}

lazy_static::lazy_static! {
    static ref ROOT: &'static Path = Path::new("/");
}

async fn create_new_root(fhs_path: &Path) -> Result<PathBuf> {
    let new_root = tempfile::TempDir::new()?.into_path();
    mount(None::<&str>, &new_root, Some("tmpfs"), MsFlags::empty(), None::<&str>)?;

    bind_entries(fhs_path, &new_root, &["etc"]).await?;
    fs::create_dir(new_root.join("etc")).await.context("Failed to create etc in new_root")?;
    bind_entries(&fhs_path.join("etc"), &new_root.join("etc"), &[]).await?;

    bind_entries(&ROOT, &new_root, &["etc", "tmp"]).await?;     // TODO: explain why not mount tmp directly
    bind_entries(&ROOT.join("etc"), &new_root.join("etc"), &[]).await?;

    Ok(new_root)
}

async fn pivot_root(new_root: &Path) -> Result<()> {
    let put_old = new_root.join(tempfile::TempDir::new()?.into_path().strip_prefix("/")?);
    fs::create_dir(new_root.join("tmp")).await.context("Failed to create tmp in new root")?;
    bind_entries(&ROOT.join("tmp"), &new_root.join("tmp"), &[]).await?;

    let cwd = std::env::current_dir()?;     // cwd before pivot_root
    nix::unistd::pivot_root(new_root, &put_old)?;
    std::env::set_current_dir(&cwd)?;       // reset cwd

    // discard old root
    umount2(&ROOT.join(put_old.strip_prefix(new_root)?), MntFlags::MNT_DETACH).map_err(Into::into)
}

async fn define_fhs(cli: &Cli) -> Result<String> {
    if let Some(packages) = &cli.packages {
        if cli.shell_nix.is_some() {
            bail!("--packages isn't available when the input is provided.");
        }

        // TODO: check how nix-shell sanitizes/validates packages input
        let packages_formatted =
            packages.into_iter().map(|package| format!("({package})")).collect::<Vec<_>>().join("\n");
        Ok(format!("
            {{ pkgs ? import <nixpkgs> {{}} }}:
            (pkgs.buildFHSUserEnv {{
                name = \"fhsenv\";
                targetPkgs = pkgs: (with pkgs; [\n{packages_formatted}\n]);
            }}).env
        "))
    } else {
        let shell_nix = cli.shell_nix.as_ref().map(PathBuf::as_path).unwrap_or(Path::new("./shell.nix"));
        if !shell_nix.exists() {
            bail!("{:?} does not exist.", shell_nix.canonicalize()?);
        }

        // tokio::fs::read_to_string is multithreaded despite `#[tokio::main(flavor = "current_thread")]`
        // > CLONE_NEWUSER requires that the calling process is not threaded
        // from https://man7.org/linux/man-pages/man2/unshare.2.html
        std::fs::read_to_string(shell_nix)
            .context(format!("Failed to read from {shell_nix:?}.")).map_err(Into::into)
    }
}

fn enter_shell(cli: Cli) -> Result<()> {
    let name = CString::new("bash")?;               // TODO: use the default shell rather than bash
    let entrypoint = cli.run.unwrap_or_else(|| {
        // make the command prompt green
        let ps1 = r"\[\e[1;32m\]\u \W> \[\e[0m\]";
        let set_ps1 = format!("export PS1=\"{ps1}\"");
        // https://serverfault.com/questions/368054/
        format!("bash --init-file <(echo \"{}\")", set_ps1.replace("\"", "\\\""))
    });
    execvp(&name, &[&name, &CString::new("-c")?, &CString::new(entrypoint)?])
        .context("execvp into bash failed.")?;

    unreachable!();
}

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    shell_nix: Option<PathBuf>,

    #[arg(short, long)]
    packages: Option<Vec<String>>,

    #[arg(long)]
    run: Option<String>
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli: Cli = clap::Parser::parse();
    let fhs_definition = define_fhs(&cli).await?;
    let fhs_path = get_fhs_path(&fhs_definition).await?;

    enter_namespace().await.context("Couldn't enter namespace.")?;
    let new_root = create_new_root(&fhs_path).await.context("Couldn't create new_root")?;
    pivot_root(&new_root).await.context(format!("Couldn't pivot root to {new_root:?}."))?;

    create_ld_so_conf().await?;
    prepare_env_vars();

    enter_shell(cli)
}