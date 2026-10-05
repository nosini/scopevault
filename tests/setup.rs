//! `scopevault-admin setup` and `setup --revert`, in a temporary home, with
//! a stand-in for `systemctl` that records its calls.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::TestBus;
use common::tempdir::TempDir;

const ADMIN: &str = env!("CARGO_BIN_EXE_scopevault-admin");
const SYSTEM_CONF: &str = "[preferred]\ndefault=gnome;gtk;\norg.freedesktop.impl.portal.Secret=gnome-keyring;\n";

struct Home {
    tmp: TempDir,
    bus: TestBus,
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Home {
    fn new() -> Self {
        let tmp = TempDir::new("setup");
        for d in ["home", "bin", "share/xdg-desktop-portal", "etc", "run"] {
            std::fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        std::fs::write(tmp.path().join("share/xdg-desktop-portal/gnome-portals.conf"), SYSTEM_CONF).unwrap();
        Home { tmp, bus: TestBus::start() }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    /// The stand-in `systemctl`: logs its arguments, and fails for `fail`.
    fn systemctl(&self, fail: Option<&str>) {
        let script = format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\n{}exit 0\n",
            self.path("systemctl.log").display(),
            fail.map(|f| format!("case \"$*\" in *{f}*) exit 1 ;; esac\n")).unwrap_or_default()
        );
        let path = self.path("bin/systemctl");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }

    fn calls(&self) -> Vec<String> {
        let log = std::fs::read_to_string(self.path("systemctl.log")).unwrap_or_default();
        std::fs::remove_file(self.path("systemctl.log")).ok();
        log.lines().map(str::to_owned).collect()
    }

    fn admin(&self, args: &[&str]) -> Out {
        let path = format!("{}:/usr/bin:/bin", self.path("bin").display());
        let out = Command::new(ADMIN)
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_DIRS", self.path("etc"))
            .env("XDG_DATA_DIRS", self.path("share"))
            .env("DBUS_SESSION_BUS_ADDRESS", &self.bus.address)
            .env("XDG_RUNTIME_DIR", self.path("run"))
            .output()
            .unwrap();
        Out {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn home(&self, rel: &str) -> PathBuf {
        self.path("home").join(rel)
    }

    fn conf(&self) -> PathBuf {
        self.home(".config/xdg-desktop-portal/gnome-portals.conf")
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

const INSTALLED: [&str; 4] = [
    ".local/share/dbus-1/services/org.freedesktop.secrets.service",
    ".local/share/dbus-1/services/eu.nosini.ScopeVault.Portal.service",
    ".config/autostart/gnome-keyring-secrets.desktop",
    ".local/share/xdg-desktop-portal/portals/scopevault.portal",
];

#[test]
fn setup_switches_the_account_and_revert_switches_it_back() {
    let h = Home::new();
    h.systemctl(None);

    let out = h.admin(&["setup"]);
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("scopevault-admin import"), "{}", out.stdout);
    assert!(out.stderr.is_empty(), "{}", out.stderr);
    for rel in INSTALLED {
        let packaged = rel.rsplit('/').next().unwrap();
        let want = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging").join(packaged));
        assert_eq!(read(&h.home(rel)), want, "{rel}");
    }
    // The system's file, with the Secret line changed.
    assert_eq!(read(&h.conf()), SYSTEM_CONF.replace("=gnome-keyring;", "=scopevault"));
    assert_eq!(
        h.calls(),
        [
            "--user daemon-reload",
            "--user enable scopevault.service scopevault-unlock.service",
            "--user mask gnome-keyring-daemon.socket gnome-keyring-daemon.service",
        ]
    );

    let out = h.admin(&["setup", "--revert"]);
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("scopevault-admin export"), "{}", out.stdout);
    for rel in INSTALLED {
        assert!(!h.home(rel).exists(), "{rel} is still there");
    }
    assert!(!h.conf().exists(), "the copy of the system's file is still there");
    assert_eq!(
        h.calls(),
        [
            "--user disable scopevault.service scopevault-unlock.service",
            "--user unmask gnome-keyring-daemon.socket gnome-keyring-daemon.service",
            "--user daemon-reload",
            "--user stop scopevault.service",
        ]
    );
}

#[test]
fn the_users_own_portal_configuration_comes_back() {
    let h = Home::new();
    h.systemctl(None);
    let mine = "# mine\n[preferred]\ndefault=gtk;\norg.freedesktop.impl.portal.FileChooser=kde\n";
    std::fs::create_dir_all(h.conf().parent().unwrap()).unwrap();
    std::fs::write(h.conf(), mine).unwrap();

    assert!(h.admin(&["setup"]).ok);
    let set = read(&h.conf());
    assert!(set.contains("org.freedesktop.impl.portal.Secret=scopevault"), "{set}");
    assert!(set.contains("FileChooser=kde"), "the user's settings are kept: {set}");
    // A second run keeps the first backup, the user's file.
    assert!(h.admin(&["setup"]).ok);

    assert!(h.admin(&["setup", "--revert"]).ok);
    assert_eq!(read(&h.conf()), mine);
    let backups: Vec<_> =
        std::fs::read_dir(h.conf().parent().unwrap()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
}

#[test]
fn a_manual_switch_is_taken_over() {
    // Set up by hand as INSTALL.md used to say: a copy of the system's file
    // with scopevault selected. setup keeps no backup of it, and revert
    // gives the system's choice back.
    let h = Home::new();
    h.systemctl(None);
    std::fs::create_dir_all(h.conf().parent().unwrap()).unwrap();
    let manual = SYSTEM_CONF.replace("=gnome-keyring;", "=scopevault") + "org.freedesktop.impl.portal.Print=gtk\n";
    std::fs::write(h.conf(), &manual).unwrap();

    assert!(h.admin(&["setup"]).ok);
    assert_eq!(read(&h.conf()), manual);
    assert!(h.admin(&["setup", "--revert"]).ok);
    let reverted = read(&h.conf());
    assert!(reverted.contains("org.freedesktop.impl.portal.Secret=gnome-keyring;"), "{reverted}");
    assert!(reverted.contains("Print=gtk"), "the user's own line is kept: {reverted}");
}

#[test]
fn a_failing_systemctl_fails_setup() {
    let h = Home::new();
    h.systemctl(Some("enable"));
    let out = h.admin(&["setup"]);
    assert!(!out.ok);
    assert!(out.stderr.contains("systemctl --user enable"), "{}", out.stderr);
}

#[test]
fn an_account_scopevault_already_serves_needs_nothing_more() {
    // A running daemon answers on its administrative socket: setup takes
    // over the files and says there is nothing left to do.
    let h = Home::new();
    h.systemctl(None);
    let out = h.admin(&["setup"]);
    assert!(out.stdout.contains("scopevault-admin import"), "no daemon yet: {}", out.stdout);

    let socket = h.path("run/scopevault/admin");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let daemon = std::thread::spawn(move || {
        use std::io::{BufRead as _, Write as _};
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        std::io::BufReader::new(&stream).read_line(&mut line).unwrap();
        (&stream).write_all(b"{\"reply\":\"error\",\"message\":\"any reply will do\"}\n").unwrap();
        line
    });
    let out = h.admin(&["setup"]);
    assert!(out.ok, "{}{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("already serves it"), "{}", out.stdout);
    assert!(!out.stdout.contains("import"), "{}", out.stdout);
    assert!(daemon.join().unwrap().contains("status"), "setup asked for the status");
}
