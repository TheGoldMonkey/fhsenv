use std::{fs, path::Path, process::Command};
use anyhow::{anyhow, bail, Result};
use nix::sched::{unshare, CloneFlags};
use nix::mount::{mount, MsFlags};

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
// TODO: try mapping to self
fn map_user_to_root(uid: u32, gid: u32) -> Result<()> {
    fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;

    // disable setgroups before writing to gid_map to protect rwx---rwx files
    fs::write("/proc/self/setgroups", "deny")?;
    
    fs::write("/proc/self/gid_map", format!("0 {gid} 1")).map_err(Into::into)
}

// TODO: make it loop over entries itself
fn bind_entries(source: &Path, sandbox: &Path) -> Result<()> {
    for entry in source.read_dir()?.collect::<Result<Vec<_>, _>>()? {
        let target = sandbox.join(entry.file_name());
        if entry.file_name() == "etc" || sandbox.join(entry.file_name()).exists() {
            continue;
        } else if entry.path().is_dir() {
            if !target.exists() {
                fs::create_dir(&target)?;
            }

            let flags = MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY;
            mount(Some(&entry.path()), &target, None::<&str>, flags, None::<&str>)?;
        } else {
            let mut source = entry.path();
            if fs::symlink_metadata(entry.path())?.file_type().is_symlink() {
                source = fs::read_link(entry.path())?;
            }

            fs::hard_link(source, target)?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let derivation_path = &get_derivation_path()?;
    let shell_hook = get_shell_hook(derivation_path)?;

    let pattern = regex::Regex::new(r"/nix/store/([^-]+)-(.+)-shell-env.drv")?;
    let fhsenv_name = &pattern.captures(derivation_path)
        .ok_or(anyhow!("Unable to parse derivation path for FHS environment name."))?[2];

    let pattern = regex::Regex::new(&format!(r"/nix/store/([^-]+)-{}-fhs", regex::escape(fhsenv_name)))?;
    let capture = pattern.captures(&shell_hook).ok_or(anyhow!("Expected {pattern} to match shellHook."))?;
    let fhs = Path::new(&capture[0]);

    // TODO: add check that user isn't root
    let uid = nix::unistd::Uid::current().as_raw();
    let gid = nix::unistd::Gid::current().as_raw();

    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUSER)?;  // TODO: handle this error
    map_user_to_root(uid, gid)?;
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None::<&str>)?;

    let sandbox = tempfile::TempDir::new()?;
    let sandbox = sandbox.path();
    dbg!(&sandbox);
    mount(None::<&str>, sandbox, Some("tmpfs"), MsFlags::empty(), None::<&str>)?;

    bind_entries(fhs, sandbox)?;
    // dbg!(sandbox.join("usr/include").read_dir()?.collect::<Result<Vec<_>, _>>()?);

    bind_entries(Path::new("/"), sandbox)?;
    // dbg!(sandbox.join("var").read_dir()?.collect::<Result<Vec<_>, _>>()?);

    todo!()
}