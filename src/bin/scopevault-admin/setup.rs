//! `setup` and `setup --revert`: switch the current user's account from
//! gnome-keyring to scopevault, and back.
//!
//! Everything that makes scopevault the user's Secret Service and Secret
//! portal backend lives in the user's own directories, so a package can
//! install scopevault without changing anything for other accounts. The
//! files are the ones in `packaging/`, compiled in, so they always match
//! this version. What `setup` does is the "Switching over" part of
//! docs/INSTALL.md that needs no decisions: importing, moving items and
//! logging out stay with the user.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The files `setup` writes, relative to the user's data or config
/// directory, with their contents.
const SECRETS_SERVICE: &str = include_str!("../../../packaging/org.freedesktop.secrets.service");
const PORTAL_SERVICE: &str = include_str!("../../../packaging/eu.nosini.ScopeVault.Portal.service");
const KEYRING_AUTOSTART: &str = include_str!("../../../packaging/gnome-keyring-secrets.desktop");
const PORTAL_FILE: &str = include_str!("../../../packaging/scopevault.portal");
/// Used when the system has no gnome-portals.conf to start from.
const PORTALS_CONF: &str = include_str!("../../../packaging/gnome-portals.conf");

const SECRET_KEY: &str = "org.freedesktop.impl.portal.Secret";
const BACKEND: &str = "scopevault";
/// Where `setup` keeps the user's own gnome-portals.conf; xdg-desktop-portal
/// only reads files named `*portals.conf`.
const BACKUP_SUFFIX: &str = ".before-scopevault";

const OUR_UNITS: [&str; 2] = ["scopevault.service", "scopevault-unlock.service"];
const KEYRING_UNITS: [&str; 2] = ["gnome-keyring-daemon.socket", "gnome-keyring-daemon.service"];

/// The user's directories, from the XDG base directory variables.
struct Dirs {
    config: PathBuf,
    data: PathBuf,
    /// System configuration and data directories, highest precedence first.
    system: Vec<PathBuf>,
}

impl Dirs {
    fn from_env() -> Result<Self, String> {
        let home = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_absolute());
        let var = |name: &str, fallback: &str| -> Result<PathBuf, String> {
            match std::env::var_os(name).map(PathBuf::from).filter(|p| p.is_absolute()) {
                Some(p) => Ok(p),
                None => home.as_ref().map(|h| h.join(fallback)).ok_or_else(|| "HOME is not set".to_owned()),
            }
        };
        let list = |name: &str, fallback: &str| -> Vec<PathBuf> {
            let value = std::env::var_os(name).filter(|v| !v.is_empty()).unwrap_or_else(|| fallback.into());
            std::env::split_paths(&value).filter(|p| p.is_absolute()).collect()
        };
        // xdg-desktop-portal's search order (portals.conf(5)).
        let mut system = list("XDG_CONFIG_DIRS", "/etc/xdg");
        system.push("/etc".into());
        system.extend(list("XDG_DATA_DIRS", "/usr/local/share:/usr/share"));
        system.push("/usr/share".into());
        Ok(Dirs { config: var("XDG_CONFIG_HOME", ".config")?, data: var("XDG_DATA_HOME", ".local/share")?, system })
    }

    /// The plain files `setup` installs, with their contents.
    fn files(&self) -> [(PathBuf, &'static str); 4] {
        [
            (self.data.join("dbus-1/services/org.freedesktop.secrets.service"), SECRETS_SERVICE),
            (
                self.data.join(format!("dbus-1/services/{}.service", scopevault::portal_backend::BACKEND_NAME)),
                PORTAL_SERVICE,
            ),
            (self.config.join("autostart/gnome-keyring-secrets.desktop"), KEYRING_AUTOSTART),
            (self.data.join("xdg-desktop-portal/portals/scopevault.portal"), PORTAL_FILE),
        ]
    }

    fn portals_conf(&self) -> PathBuf {
        self.config.join("xdg-desktop-portal/gnome-portals.conf")
    }

    fn portals_backup(&self) -> PathBuf {
        let mut name = self.portals_conf().into_os_string();
        name.push(BACKUP_SUFFIX);
        name.into()
    }

    /// The system's gnome-portals.conf, the one xdg-desktop-portal reads when
    /// the user has none.
    fn system_portals_conf(&self) -> Option<String> {
        self.system.iter().find_map(|d| std::fs::read_to_string(d.join("xdg-desktop-portal/gnome-portals.conf")).ok())
    }
}

/// The key's value in the `[preferred]` group, if it is set there.
fn preferred(conf: &str, key: &str) -> Option<String> {
    let mut in_preferred = false;
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_preferred = line == "[preferred]";
        } else if in_preferred
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(v.trim().to_owned());
        }
    }
    None
}

/// `conf` with the key's line in `[preferred]` set to `value`, or removed
/// with `None`. A missing line is added at the top of the group, a missing
/// group at the end.
fn set_preferred(conf: &str, key: &str, value: Option<&str>) -> String {
    let mut out = Vec::new();
    let mut in_preferred = false;
    let mut seen_group = false;
    let mut done = false;
    for line in conf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_preferred = trimmed == "[preferred]";
            out.push(line.to_owned());
            if in_preferred && !seen_group {
                seen_group = true;
                if let Some(v) = value.filter(|_| preferred(conf, key).is_none()) {
                    out.push(format!("{key}={v}"));
                    done = true;
                }
            }
            continue;
        }
        if in_preferred && trimmed.split_once('=').is_some_and(|(k, _)| k.trim() == key) {
            if let Some(v) = value.filter(|_| !done) {
                out.push(format!("{key}={v}"));
                done = true;
            }
            continue;
        }
        out.push(line.to_owned());
    }
    if let Some(v) = value.filter(|_| !done) {
        if !out.last().is_none_or(|l| l.trim().is_empty()) {
            out.push(String::new());
        }
        out.push("[preferred]".to_owned());
        out.push(format!("{key}={v}"));
    }
    out.join("\n") + "\n"
}

fn write(path: &Path, contents: &str) -> Result<(), String> {
    let fail = |e: std::io::Error| format!("cannot write {}: {e}", path.display());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::write(&tmp, contents).map_err(fail)?;
    std::fs::rename(&tmp, path).map_err(fail)
}

fn remove(path: &Path) -> Result<bool, String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("`systemctl --user {}` failed", args.join(" "))) }
}

/// Asks the session bus to read its activation files again; dbus-broker
/// reads them only when asked.
async fn reload_bus() {
    let reload = async {
        let conn = zbus::Connection::session().await?;
        zbus::fdo::DBusProxy::new(&conn).await?.reload_config().await
    };
    if let Err(e) = reload.await {
        eprintln!(
            "scopevault-admin: cannot ask the session bus to reload its configuration ({e}); log out and back in"
        );
    }
}

/// Copies of a manual install that would win over a package's files.
fn manual_leftovers(dirs: &Dirs) -> Vec<PathBuf> {
    let packaged = std::env::current_exe().is_ok_and(|e| e.starts_with("/usr/"));
    if !packaged {
        return Vec::new();
    }
    let mut found: Vec<PathBuf> = OUR_UNITS.iter().map(|u| dirs.config.join("systemd/user").join(u)).collect();
    if let Some(home) = std::env::var_os("HOME") {
        let bin = PathBuf::from(home).join(".local/bin");
        found.extend(["scopevault-daemon", "scopevault-admin", "scopevault-gui"].map(|b| bin.join(b)));
    }
    found.retain(|p| p.exists());
    found
}

fn print_leftovers(dirs: &Dirs) {
    let leftovers = manual_leftovers(dirs);
    if leftovers.is_empty() {
        return;
    }
    println!();
    println!("Files of a manual installation take precedence over this package's:");
    for p in &leftovers {
        println!("  {}", p.display());
    }
    println!("Remove them, then run `systemctl --user daemon-reload`:");
    let list: Vec<String> = leftovers.iter().map(|p| format!("'{}'", p.display())).collect();
    println!("  rm {}", list.join(" "));
}

/// `socket` is the daemon's administrative socket: if a daemon answers
/// there, it already serves this account (it exits when it cannot own
/// org.freedesktop.secrets).
pub async fn setup(socket: Option<PathBuf>) -> ExitCode {
    let dirs = match Dirs::from_env() {
        Ok(d) => d,
        Err(e) => return super::fail(e),
    };
    match install(&dirs) {
        Ok(()) => {}
        Err(e) => return super::fail(e),
    }
    reload_bus().await;
    let serving = match &socket {
        Some(s) => super::request(s, &scopevault::admin::protocol::Request::Status, None).await.is_ok(),
        None => false,
    };
    if serving {
        println!("scopevault is set up for your account, and already serves it: nothing");
        println!("else to do.");
        print_leftovers(&dirs);
        return ExitCode::SUCCESS;
    }
    let vault = dirs.data.join("scopevault");
    println!("scopevault is set up for your account; it takes over at your next login.");
    println!();
    println!("Before you log out:");
    if scopevault::store::Vault::exists(&vault) {
        println!("  A vault exists already ({}). To add what gnome-keyring has", vault.display());
        println!("  that it doesn't (running the import again only adds what is new):");
    } else {
        println!("  Copy your secrets from gnome-keyring, which runs until you log out:");
    }
    println!("    scopevault-admin import --pinentry /usr/bin/pinentry-gnome3");
    println!("Then log out and back in. Flatpak apps that use the Secret Service");
    println!("directly find their items in `host` until you move them (INSTALL.md,");
    println!("\"Switching over\", step 6).");
    print_leftovers(&dirs);
    ExitCode::SUCCESS
}

fn install(dirs: &Dirs) -> Result<(), String> {
    for (path, contents) in dirs.files() {
        write(&path, contents)?;
    }
    let conf = dirs.portals_conf();
    let current = match std::fs::read_to_string(&conf) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {}: {e}", conf.display())),
    };
    // The user's own file is kept aside, once, unless it already selects
    // scopevault. xdg-desktop-portal reads only the first gnome-portals.conf
    // it finds, so a new one starts as a copy of the system's.
    let base = match &current {
        Some(c) => {
            let backup = dirs.portals_backup();
            if preferred(c, SECRET_KEY).as_deref() != Some(BACKEND) && !backup.exists() {
                write(&backup, c)?;
            }
            c.clone()
        }
        None => dirs.system_portals_conf().unwrap_or_else(|| PORTALS_CONF.to_owned()),
    };
    write(&conf, &set_preferred(&base, SECRET_KEY, Some(BACKEND)))?;

    systemctl(&["daemon-reload"])?;
    let mut enable = vec!["enable"];
    enable.extend(OUR_UNITS);
    systemctl(&enable)?;
    let mut mask = vec!["mask"];
    mask.extend(KEYRING_UNITS);
    systemctl(&mask)
}

pub async fn revert() -> ExitCode {
    let dirs = match Dirs::from_env() {
        Ok(d) => d,
        Err(e) => return super::fail(e),
    };
    if let Err(e) = uninstall(&dirs) {
        return super::fail(e);
    }
    reload_bus().await;
    // Only now: while the activation file was there, any request would have
    // started the daemon again.
    if let Err(e) = systemctl(&["stop", "scopevault.service"]) {
        eprintln!("scopevault-admin: {e}");
    }
    let vault = dirs.data.join("scopevault");
    println!("scopevault is switched off for your account; gnome-keyring takes over at");
    println!("your next login. The vault stays in {}.", vault.display());
    println!();
    println!("To keep what you stored in scopevault since the switch, export it before");
    println!("you log out (xdg-desktop-portal keeps using scopevault until then):");
    println!("  gnome-keyring-daemon --start --components=secrets");
    println!("  scopevault-admin export --pinentry /usr/bin/pinentry-gnome3");
    println!("and, if apps got new Secret portal keys from scopevault:");
    println!("  scopevault-admin export --scope portal --pinentry /usr/bin/pinentry-gnome3");
    println!("Then log out and back in.");
    ExitCode::SUCCESS
}

fn uninstall(dirs: &Dirs) -> Result<(), String> {
    let mut disable = vec!["disable"];
    disable.extend(OUR_UNITS);
    systemctl(&disable)?;
    let mut unmask = vec!["unmask"];
    unmask.extend(KEYRING_UNITS);
    systemctl(&unmask)?;
    for (path, _) in dirs.files() {
        remove(&path)?;
    }

    let conf = dirs.portals_conf();
    let backup = dirs.portals_backup();
    if backup.exists() {
        std::fs::rename(&backup, &conf).map_err(|e| format!("cannot restore {}: {e}", conf.display()))?;
    } else if let Ok(current) = std::fs::read_to_string(&conf) {
        // No file of the user's own was kept: theirs selected scopevault
        // already, or `setup` made it from the system's. The Secret line
        // goes back to what the system's file says, and a file that is then
        // the system's goes.
        let system = dirs.system_portals_conf();
        let value = system.as_deref().and_then(|s| preferred(s, SECRET_KEY));
        let reverted = set_preferred(&current, SECRET_KEY, value.as_deref());
        let same = match &system {
            Some(s) => reverted == set_preferred(s, SECRET_KEY, value.as_deref()),
            None => preferred(&reverted, "default").is_none() && reverted.lines().all(is_blank_or_group),
        };
        if same {
            remove(&conf)?;
        } else {
            write(&conf, &reverted)?;
        }
    }
    systemctl(&["daemon-reload"])
}

fn is_blank_or_group(line: &str) -> bool {
    let line = line.trim();
    line.is_empty() || line.starts_with('#') || line == "[preferred]"
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: &str = "[preferred]\ndefault=gnome;gtk;\norg.freedesktop.impl.portal.Secret=gnome-keyring;\n";

    #[test]
    fn the_secret_line_is_replaced_in_place() {
        let set = set_preferred(SYSTEM, SECRET_KEY, Some(BACKEND));
        assert_eq!(set, "[preferred]\ndefault=gnome;gtk;\norg.freedesktop.impl.portal.Secret=scopevault\n");
        assert_eq!(preferred(&set, SECRET_KEY).as_deref(), Some(BACKEND));
        assert_eq!(set_preferred(&set, SECRET_KEY, Some("gnome-keyring;")), SYSTEM);
    }

    #[test]
    fn a_missing_line_or_group_is_added() {
        let set = set_preferred("[preferred]\ndefault=gnome;gtk;\n", SECRET_KEY, Some(BACKEND));
        assert_eq!(set, "[preferred]\norg.freedesktop.impl.portal.Secret=scopevault\ndefault=gnome;gtk;\n");
        let set = set_preferred("# mine\n", SECRET_KEY, Some(BACKEND));
        assert_eq!(set, "# mine\n\n[preferred]\norg.freedesktop.impl.portal.Secret=scopevault\n");
        assert_eq!(
            set_preferred("", SECRET_KEY, Some(BACKEND)),
            "[preferred]\norg.freedesktop.impl.portal.Secret=scopevault\n"
        );
    }

    #[test]
    fn only_the_preferred_group_counts() {
        let conf =
            "[other]\norg.freedesktop.impl.portal.Secret=x\n[preferred]\n org.freedesktop.impl.portal.Secret = y \n";
        assert_eq!(preferred(conf, SECRET_KEY).as_deref(), Some("y"));
        let set = set_preferred(conf, SECRET_KEY, None);
        assert_eq!(set, "[other]\norg.freedesktop.impl.portal.Secret=x\n[preferred]\n");
    }

    #[test]
    fn the_packaged_files_are_the_expected_ones() {
        assert!(SECRETS_SERVICE.contains("Name=org.freedesktop.secrets"));
        assert!(SECRETS_SERVICE.contains("SystemdService=scopevault.service"));
        assert!(PORTAL_SERVICE.contains(&format!("Name={}", scopevault::portal_backend::BACKEND_NAME)));
        assert!(KEYRING_AUTOSTART.contains("Hidden=true"));
        assert_eq!(preferred(PORTALS_CONF, SECRET_KEY).as_deref(), Some(BACKEND));
    }
}
