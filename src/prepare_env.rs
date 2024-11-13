use anyhow::{Context, Result};

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
        "/run/opengl-driver-32/lib"
    ];

    std::fs::write(std::path::Path::new("/etc/ld.so.conf"), ld_so_conf_entries.join("\n"))
        .context("Couldn't write to /etc/ld.so.conf.").map_err(Into::into)
}

fn prepend_entries_in_env(key: &str, additions: &[&str]) {
    let mut val = std::env::var(key).unwrap_or_default();
    if !val.is_empty() {
        val = ":".to_string() + &val;
    }
    std::env::set_var(key, additions.join(":") + &val);
}

pub fn prepare_env() -> Result<()> {
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

    create_ld_so_conf()
}
