use std::{ffi::CString, path::{Path, PathBuf}};
use anyhow::{anyhow, bail, Context, Result};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use tokio::{fs, process::Command};

async fn subprocess(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output().await?;

    if !output.status.success() {
        bail!("Error running {program} {}: {}.", args.join(" "), String::from_utf8(output.stderr.clone())?);
    }

    String::from_utf8(output.stdout.trim_ascii().to_vec()).map_err(Into::into)
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
        "/run/wrappers/bin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/bin",
        "/sbin"
    ]);

    prepend_entries_in_env("XDG_DATA_DIRS", &[
        "/run/opengl-driver/share",
        "/run/opengl-driver-32/share",
        "/usr/local/share",
        "/usr/share"
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
    let _match = input_drvs.keys().filter_map(|input_drv| pattern.find(input_drv)).next()
        .ok_or(anyhow!("Expected FHS derivation in inputDrvs."))?;
    let fhs_drv = Path::new(_match.as_str());

    // like subprocess but without piping stderr
    let process = Command::new("nix-build").arg(fhs_drv).stdout(std::process::Stdio::piped()).spawn()?;
    let output = process.wait_with_output().await?;
    let fhs = Path::new(std::str::from_utf8(&output.stdout)?.trim());
    if !output.status.success() || !fhs.exists() {
        bail!("Error building {fhs_drv:?}.");
    }

    Ok(fhs.into())
}

// https://man7.org/linux/man-pages/man7/user_namespaces.7.html
async fn enter_namespace() -> Result<()> {
    // TODO: does it matter whether user is root?
    // uid and guid before entering user namespace
    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUSER).context("Couldn't create namespace.")?;

    // restore uid and gid
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).await.context("Failed to map uid.")?;
    fs::write("/proc/self/setgroups", "deny").await.context("Couldn't disable setgroups")?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).await.context("Failed to map gid")?;

    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None::<&str>)
        .context("Couldn't set recursive slave mount at root.")?;

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
        // if source.is_dir() && !target.exists() {
        if !target.exists() {
            if entry.path().is_dir() {
                fs::create_dir(&target).await.context("Failed to create stub directory.")?;
            } else {
                fs::write(&target, "").await.context("Failed to create stub file.")?;
            }
        }

        let flags = MsFlags::MS_BIND | MsFlags::MS_REC;
        mount(Some(&entry.path()), &target, None::<&str>, flags, None::<&str>)  // mount works with files too
            .context(format!("Failed to mount {entry:?} to {target:?}"))?;
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
    // exclude login.defs and pam.d so to not mess with authentication
    bind_entries(&fhs_path.join("etc"), &new_root.join("etc"), &["login.defs", "pam.d"]).await?;

    // let root = Path::new("/");
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

fn define_fhs(cli: &Cli) -> Result<String> {
    if let Some(packages) = &cli.packages {      // TODO: check how nix-shell validates packages input
        if cli.shell_nix.is_some() {
            bail!("--packages isn't available when an input file is specified.");
        }

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
        let shell_nix = cli.shell_nix.as_ref().map(PathBuf::as_path).unwrap_or(Path::new("shell.nix"));
        if !shell_nix.exists() {
            bail!("{:?} does not exist.", shell_nix.canonicalize()?);
        }

        // tokio::fs::read_file_sync is multithreaded and causes unshare to error out
        // > CLONE_NEWUSER requires that the calling process is not threaded
        // from https://man7.org/linux/man-pages/man2/unshare.2.html
        std::fs::read_to_string(shell_nix)
            .context(format!("Failed to read from {shell_nix:?}.")).map_err(Into::into)
    }
}

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    shell_nix: Option<PathBuf>,

    #[arg(short, long)]
    packages: Option<Vec<String>>,

    #[arg(long)]
    run: Option<String>,

    #[arg(long)]
    command: Option<String>
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli: Cli = clap::Parser::parse();
    let fhs_definition = define_fhs(&cli)?;
    let fhs_path = get_fhs_path(&fhs_definition).await?;

    enter_namespace().await.context("Couldn't enter namespace.")?;
    let new_root = create_new_root(&fhs_path).await.context("Couldn't create new_root")?;
    pivot_root(&new_root).await.context(format!("Couldn't pivot root to {new_root:?}."))?;

    create_ld_so_conf().await?;
    prepare_env_vars();

    if let Some(command) = cli.run {
        let status = Command::new("sh").args(&["-c", &command]).status().await?;
        std::process::exit(status.code().unwrap_or(1));
    } else if let Some(command) = cli.command {
        let name = CString::new(command.clone())?;
        nix::unistd::execvp(&name, &[&name]).context(format!("execvp into {command} failed."))?;
    } else {
        let name = CString::new("bash")?;
        let ps1 = r"\[\e[1;32m\]\u \W> \[\e[0m\]";      // make the command prompt green
        let set_ps1 = format!("export PS1=\"{ps1}\"");
        // https://serverfault.com/questions/368054/
        let entrypoint = format!("bash --init-file <(echo \"{}\")", set_ps1.replace("\"", "\\\""));
        nix::unistd::execvp(&name, &[&name, &CString::new("-c")?, &CString::new(entrypoint)?])
            .context("execvp into bash failed.")?;
    }
    unreachable!();
}