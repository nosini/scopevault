//! Shared helpers for tests that need a real, private message bus.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A private dbus-daemon that is killed when dropped.
///
/// The daemon is taken from `$DBUS_DAEMON` or `dbus-daemon` on `PATH`; it
/// must report `ProcessFD` in `GetConnectionCredentials` (dbus ≥ 1.15.8 built
/// with `SO_PEERPIDFD`, or dbus-broker ≥ 35) for identity tests to pass.
pub struct TestBus {
    child: Child,
    pub dir: tempdir::TempDir,
    pub address: String,
}

pub mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(|| "/tmp".into());
            let mut b = [0u8; 8];
            getrandom::fill(&mut b).unwrap();
            let p = base.join(format!("{prefix}-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()));
            std::fs::create_dir(&p).unwrap();
            std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
            TempDir(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl TestBus {
    pub fn start() -> Self {
        let dir = tempdir::TempDir::new("scopevault-test");
        let socket = dir.path().join("bus");
        let config = dir.path().join("bus.conf");
        std::fs::write(
            &config,
            format!(
                "<busconfig><type>session</type><listen>unix:path={}</listen><auth>EXTERNAL</auth>\
                 <policy context=\"default\"><allow send_destination=\"*\" eavesdrop=\"true\"/>\
                 <allow eavesdrop=\"true\"/><allow own=\"*\"/></policy></busconfig>",
                socket.display()
            ),
        )
        .unwrap();
        let daemon = std::env::var_os("DBUS_DAEMON").unwrap_or_else(|| "dbus-daemon".into());
        let child = Command::new(&daemon)
            .arg(format!("--config-file={}", config.display()))
            .arg("--nofork")
            .stdout(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot run {daemon:?} (set DBUS_DAEMON): {e}"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "dbus-daemon did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::create_dir(dir.path().join("run")).unwrap();
        TestBus { child, address: format!("unix:path={}", socket.display()), dir }
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.dir.path().join("run")
    }

    pub async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str()).unwrap().build().await.unwrap()
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn support_script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support").join(name)
}
