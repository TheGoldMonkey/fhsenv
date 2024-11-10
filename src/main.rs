use std::{ffi::CString, path::Path};
use anyhow::{anyhow, bail, Result};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use tokio::fs;

async fn subprocess(program: &str, args: &[&str], check: bool) -> Result<String> {
    let mut command = tokio::process::Command::new(program);
    for arg in args {
        command.arg(arg);
    }

    let output = command.output().await?;
    if check && !output.status.success() {
        bail!("Error running {program} {}: {}.", args.join(" "), String::from_utf8(output.stderr.clone())?);
    }

    String::from_utf8(output.stdout).map_err(Into::into)
}

async fn get_shell_hook(derivation_path: &str) -> Result<String> {
    let output = subprocess("nix", &["derivation", "show", &derivation_path], true).await?;
    let derivation = serde_json::from_str::<serde_json::Value>(&output)?;
    let shell_hook = &derivation[&derivation_path]["env"]["shellHook"];
    shell_hook.as_str().map(str::to_owned).ok_or(anyhow!("Unable to parse derivation for shellHook."))
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

    fs::write(Path::new("/etc/ld.so.conf"), ld_so_conf_entries.join("\n")).await.map_err(Into::into)
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

async fn get_fhs(shell_nix: &str) -> Result<std::path::PathBuf> {
    let derivation_path = subprocess("nix-instantiate", &[shell_nix], true).await?;
    let shell_hook = get_shell_hook(derivation_path.trim()).await?;

    let pattern = regex::Regex::new(r"/nix/store/([^-]+)-(.+)-shell-env.drv")?;
    let fhsenv_name = &pattern.captures(&derivation_path)
        .ok_or(anyhow!("Unable to parse derivation path for FHS environment name."))?[2];

    let pattern = regex::Regex::new(&format!(r"/nix/store/([^-]+)-{}-fhs", regex::escape(fhsenv_name)))?;
    let _match = pattern.find(&shell_hook).ok_or(anyhow!("Expected {pattern} to match shellHook."))?;

    Ok(Path::new(_match.as_str()).into())
}

// https://man7.org/linux/man-pages/man7/user_namespaces.7.html
async fn enter_namespace() -> Result<()> {
    // TODO: does it matter whether user is root?
    // uid and guid before entering user namespace
    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUSER)?;  // TODO: handle this error

    // restore uid and gid
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).await?;
    fs::write("/proc/self/setgroups", "deny").await?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).await?;

    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None::<&str>)?;

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

        let mut source = entry.path();
        if fs::symlink_metadata(entry.path()).await?.file_type().is_symlink() {
            source = parent.join(fs::read_link(entry.path()).await?);
        }

        let target = target.join(entry.file_name());
        // if source.is_dir() && !target.exists() {
        if !target.exists() {
            if source.is_dir() {
                fs::create_dir(&target).await?;
            } else {
                fs::write(&target, "").await?;
            }
        }

        let flags = MsFlags::MS_BIND | MsFlags::MS_REC;
        mount(Some(&source), &target, None::<&str>, flags, None::<&str>)?;  // mount works with files too
    }

    Ok(())
}

lazy_static::lazy_static! {
    static ref ROOT: &'static Path = Path::new("/");
}

async fn create_new_root(fhs: &Path) -> Result<std::path::PathBuf> {
    let new_root = tempfile::TempDir::new()?.into_path();
    mount(None::<&str>, &new_root, Some("tmpfs"), MsFlags::empty(), None::<&str>)?;

    bind_entries(fhs, &new_root, &["etc"]).await?;
    fs::create_dir(new_root.join("etc")).await?;
    // exclude login.defs and pam.d so to not mess with authentication
    bind_entries(&fhs.join("etc"), &new_root.join("etc"), &["login.defs", "pam.d"]).await?;

    // let root = Path::new("/");
    bind_entries(&ROOT, &new_root, &["etc", "tmp"]).await?;     // TODO: explain why not mount tmp directly
    bind_entries(&ROOT.join("etc"), &new_root.join("etc"), &[]).await?;

    Ok(new_root)
}

async fn pivot_root(new_root: &Path) -> Result<()> {
    let put_old = new_root.join(tempfile::TempDir::new()?.into_path().strip_prefix("/")?);
    fs::create_dir(new_root.join("tmp")).await?;
    bind_entries(&ROOT.join("tmp"), &new_root.join("tmp"), &[]).await?;

    let cwd = std::env::current_dir()?;     // cwd before pivot_root
    nix::unistd::pivot_root(new_root, &put_old)?;
    std::env::set_current_dir(&cwd)?;       // reset cwd

    // discard old root
    umount2(&ROOT.join(put_old.strip_prefix(new_root)?), MntFlags::MNT_DETACH).map_err(Into::into)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let shell_nix = std::env::args().nth(1).ok_or(anyhow!("shell.nix path missing."))?;

    // asynchronously build the fhs store path
    let handle = tokio::spawn(glib::clone!(#[to_owned] shell_nix,
        async move { subprocess("nix-build", &[&shell_nix], false).await }));

    let fhs = get_fhs(&shell_nix).await?;
    enter_namespace().await?;
    handle.await??;     // create_new_root needs the fhs store path built
    let new_root = create_new_root(&fhs).await?;
    pivot_root(&new_root).await?;

    create_ld_so_conf().await?;
    prepare_env_vars();

    std::env::set_var("PS1", r"\[\e[1;32m\]\u \W> \[\e[0m\]");      // make command prompt green
    nix::unistd::execvp(&CString::new("bash")?, &[CString::new("bash")?, CString::new("--norc")?])?;
    unreachable!();
}