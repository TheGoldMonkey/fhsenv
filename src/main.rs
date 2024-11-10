use std::{ffi::{CString, OsStr}, fs, path::Path/* , os::unix::fs::symlink */, process::Command};
use anyhow::{anyhow, bail, Result};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, umount2, MntFlags, MsFlags};

fn get_derivation_path() -> Result<String> {
    let subprocess = Command::new("nix-instantiate").arg("test/shell.nix").output()?;
    if !subprocess.status.success() {
        bail!("Unable to evaluate shell.nix: {:?}.", subprocess.stderr);
    }

    Ok(String::from_utf8(subprocess.stdout)?.trim().to_string())
}

fn get_shell_hook(derivation_path: &str) -> Result<String> {
    let subprocess = Command::new("nix").args(&["derivation", "show", &derivation_path]).output()?;
    if !subprocess.status.success() {
        bail!("Unable to open derivation: {:?}.", subprocess.stderr);
    }
    let derivation = serde_json::from_str::<serde_json::Value>(&String::from_utf8(subprocess.stdout)?)?;

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

fn main() -> Result<()> {
    let derivation_path = &get_derivation_path()?;
    let shell_hook = get_shell_hook(derivation_path)?;

    let pattern = regex::Regex::new(r"/nix/store/([^-]+)-(.+)-shell-env.drv")?;
    let fhsenv_name = &pattern.captures(derivation_path)
        .ok_or(anyhow!("Unable to parse derivation path for FHS environment name."))?[2];

    let pattern = regex::Regex::new(&format!(r"/nix/store/([^-]+)-{}-fhs", regex::escape(fhsenv_name)))?;
    let _match = pattern.find(&shell_hook).ok_or(anyhow!("Expected {pattern} to match shellHook."))?;
    let fhs = Path::new(_match.as_str());
    dbg!(fhs);

    // TODO: does it matter whether user is root?
    // uid and guid before entering user namespace
    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();

    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUSER)?;  // TODO: handle this error
    map_user(uid, gid)?;    // restore uid and guid
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None::<&str>)?;

    let sandbox = tempfile::TempDir::new()?.into_path();
    dbg!(&sandbox);
    mount(None::<&str>, &sandbox, Some("tmpfs"), MsFlags::empty(), None::<&str>)?;

    bind_entries(fhs, &sandbox, &["etc"])?;
    fs::create_dir(sandbox.join("etc"))?;
    // exclude login.defs and pam.d so to not mess with authentication
    bind_entries(&fhs.join("etc"), &sandbox.join("etc"), &["login.defs", "pam.d"])?;
    // dbg!(sandbox.join("usr/include").read_dir()?.collect::<Result<Vec<_>, _>>()?);

    let root = Path::new("/");
    bind_entries(root, &sandbox, &["etc", "tmp"])?;     // TODO: explain why not mount tmp directly
    bind_entries(&root.join("etc"), &sandbox.join("etc"), &[])?;

    // indirectly join sandbox with tempdir since joining with an absolute path substitutes with it
    // let put_old =
    //     sandbox.join(tempfile::TempDir::new()?.into_path().components().skip(1).collect::<PathBuf>());
    let put_old = sandbox.join(tempfile::TempDir::new()?.into_path().strip_prefix("/")?);
    dbg!(&put_old);
    fs::create_dir(sandbox.join("tmp"))?;
    bind_entries(&root.join("tmp"), &sandbox.join("tmp"), &[])?;
    // dbg!(sandbox.join("var").read_dir()?.collect::<Result<Vec<_>, _>>()?);

    let cwd = std::env::current_dir()?;     // cwd before pivot_root
    nix::unistd::pivot_root(&sandbox, &put_old)?;
    std::env::set_current_dir(&cwd)?;       // reset cwd

    // update put_old
    let filename = put_old.file_name().map(OsStr::to_str).flatten()
        .ok_or(anyhow!("TempDir initialized with invalid name: {:?}", put_old.file_name()))?;
    let put_old = Path::new("/tmp").join(filename);

    // mount(None::<&str>, put_old, None::<&str>, MsFlags::MS_PRIVATE, None::<&str>)?;
    // dbg!(put_old.read_dir()?.collect::<Result<Vec<_>, _>>()?);
    umount2(&put_old, MntFlags::MNT_DETACH)?;
    // dbg!(put_old.read_dir()?.collect::<Result<Vec<_>, _>>()?);

    // extract glibc path via regex from shell_hook
    // let pattern = regex::Regex::new(r"/nix/store/([^\s]+?)-glibc-[^/\s]+")?;
    // let captures = pattern.find(&shell_hook).ok_or(anyhow!("Unable to find glibc path in shellHook."))?;
    // let glibc_path = Path::new(captures.as_str());

    // symlink /etc/ld.so.conf and /etc/ld.so.cache from glibc/etc
    // symlink(glibc_path.join("etc/ld.so.conf"), sandbox.join("etc/ld.so.conf"))?;
    // symlink(glibc_path.join("etc/ld.so.cache"), sandbox.join("etc/ld.so.cache"))?;

    create_ld_so_conf()?;

    nix::unistd::execv(&CString::new("/bin/bash")?, &[CString::new("bash")?]).map(drop).map_err(Into::into)
}