use std::{ffi::CString, fs, path::Path};
use anyhow::{anyhow, bail, Result};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MntFlags, MsFlags};

fn subprocess(program: &str, args: &[&str], check: bool) -> Result<String> {
    let mut command = std::process::Command::new(program);
    for arg in args {
        command.arg(arg);
    }

    let output = command.output()?;
    if check && !output.status.success() {
        bail!("Error running {program} {}: {}.", args.join(" "), String::from_utf8(output.stderr.clone())?);
    }

    String::from_utf8(output.stdout).map_err(Into::into)
}

fn get_shell_hook(derivation_path: &str) -> Result<String> {
    let output = subprocess("nix", &["derivation", "show", &derivation_path], true)?;
    let derivation = serde_json::from_str::<serde_json::Value>(&output)?;
    let shell_hook = &derivation[&derivation_path]["env"]["shellHook"];
    shell_hook.as_str().map(str::to_owned).ok_or(anyhow!("Unable to parse derivation for shellHook."))
}

// https://man7.org/linux/man-pages/man7/user_namespaces.7.html
fn map_user(uid: u32, gid: u32) -> Result<()> {
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;

    // disable setgroups before writing to gid_map to protect rwx---rwx files
    fs::write("/proc/self/setgroups", "deny")?;
    
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).map_err(Into::into)
}

// TODO: is there a practical limit on number of bind mounts?
fn bind_entries(parent: &Path, sandbox: &Path, exclusions: &[&str]) -> Result<()> {
    for entry in parent.read_dir()?.collect::<Result<Vec<_>, _>>()? {
        let exclude = exclusions.into_iter().any(|exclusion| entry.file_name().to_str() == Some(exclusion));
        if exclude || sandbox.join(entry.file_name()).exists() {
            continue;
        }

        let mut source = entry.path();
        if fs::symlink_metadata(entry.path())?.file_type().is_symlink() {
            source = parent.join(fs::read_link(entry.path())?);
        }

        let target = sandbox.join(entry.file_name());
        // if source.is_dir() && !target.exists() {
        if !target.exists() {
            if source.is_dir() {
                fs::create_dir(&target)?;
            } else {
                fs::write(&target, "")?;
            }
        }

        let flags = MsFlags::MS_BIND | MsFlags::MS_REC;
        mount(Some(&source), &target, None::<&str>, flags, None::<&str>)?;  // mount works with files too
    }

    Ok(())
}

fn create_ld_so_conf() -> Result<()> {
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
        "/run/opengl-driver-32/lib",
    ];

    fs::write(Path::new("/etc/ld.so.conf"), ld_so_conf_entries.join("\n")).map_err(Into::into)
}

fn prepend_entries_in_env(key: &str, additions: &[&str]) {
    let mut val = std::env::var(key).unwrap_or_default();
    if !val.is_empty() {
        val = ":".to_string() + &val;
    }
    std::env::set_var(key, additions.join(":") + &val);
}

fn prepare_env() {
    prepend_entries_in_env("PATH", &[
        "/run/wrappers/bin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/bin",
        "/sbin",
    ]);

    prepend_entries_in_env("PKG_CONFIG_PATH", &["/usr/lib/pkgconfig"]);

    prepend_entries_in_env("LD_LIBRARY_PATH", &[
        "/run/opengl-driver/lib",
        "/run/opengl-driver-32/lib",
    ]);

    prepend_entries_in_env("XDG_DATA_DIRS", &[
        "/run/opengl-driver/share",
        "/run/opengl-driver-32/share",
        "/usr/local/share",
        "/usr/share",
    ]);

    prepend_entries_in_env("ACLOCAL_PATH", &["/usr/share/aclocal"]);

    std::env::set_var("LOCALE_ARCHIVE", "/usr/lib/locale/locale-archive");
}

fn get_fhs() -> Result<std::path::PathBuf> {
    let shell_nix = &std::env::args().nth(1).ok_or(anyhow!("shell.nix path missing."))?;
    subprocess("nix-build", &[shell_nix], false)?;      // build the fhs environment
    let derivation_path = subprocess("nix-instantiate", &[shell_nix], true)?;
    let shell_hook = get_shell_hook(derivation_path.trim())?;

    let pattern = regex::Regex::new(r"/nix/store/([^-]+)-(.+)-shell-env.drv")?;
    let fhsenv_name = &pattern.captures(&derivation_path)
        .ok_or(anyhow!("Unable to parse derivation path for FHS environment name."))?[2];

    let pattern = regex::Regex::new(&format!(r"/nix/store/([^-]+)-{}-fhs", regex::escape(fhsenv_name)))?;
    let _match = pattern.find(&shell_hook).ok_or(anyhow!("Expected {pattern} to match shellHook."))?;

    Ok(Path::new(_match.as_str()).into())
}

fn main() -> Result<()> {
    let fhs = get_fhs()?;

    // TODO: does it matter whether user is root?
    // uid and guid before entering user namespace
    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();

    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUSER)?;  // TODO: handle this error
    map_user(uid, gid)?;    // restore uid and guid
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None::<&str>)?;

    let sandbox = tempfile::TempDir::new()?.into_path();
    mount(None::<&str>, &sandbox, Some("tmpfs"), MsFlags::empty(), None::<&str>)?;

    bind_entries(&fhs, &sandbox, &["etc"])?;
    fs::create_dir(sandbox.join("etc"))?;
    // exclude login.defs and pam.d so to not mess with authentication
    bind_entries(&fhs.join("etc"), &sandbox.join("etc"), &["login.defs", "pam.d"])?;

    let root = Path::new("/");
    bind_entries(root, &sandbox, &["etc", "tmp"])?;     // TODO: explain why not mount tmp directly
    bind_entries(&root.join("etc"), &sandbox.join("etc"), &[])?;

    // indirectly join sandbox with tempdir since joining with an absolute path substitutes with it
    let put_old = sandbox.join(tempfile::TempDir::new()?.into_path().strip_prefix("/")?);
    fs::create_dir(sandbox.join("tmp"))?;
    bind_entries(&root.join("tmp"), &sandbox.join("tmp"), &[])?;

    let cwd = std::env::current_dir()?;     // cwd before pivot_root
    nix::unistd::pivot_root(&sandbox, &put_old)?;
    std::env::set_current_dir(&cwd)?;       // reset cwd

    // discard old root
    umount2(&root.join(put_old.strip_prefix(sandbox)?), MntFlags::MNT_DETACH)?;

    create_ld_so_conf()?;
    prepare_env();

    std::env::set_var("PS1", r"\[\e[1;32m\]\u \W> \[\e[0m\]");      // make command prompt green
    nix::unistd::execv(&CString::new("/bin/bash")?, &[CString::new("bash")?, CString::new("--norc")?])?;

    Ok(())
}