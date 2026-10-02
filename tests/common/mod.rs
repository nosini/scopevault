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

pub mod service;

/// Password of vaults made by [`VaultFixture`].
pub const PASSWORD: &str = "correct horse";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Unlocked,
    Locked,
    Missing,
}

/// A vault in a temporary directory, with an unlocker whose dialogs are
/// answered by `tests/support/fake-pinentry.sh`. Each fixture gets its own
/// wrapper script, so tests using it can run in parallel.
pub struct VaultFixture {
    pub tmp: tempdir::TempDir,
    pub unlocker: std::sync::Arc<scopevault::prompts::unlock::Unlocker>,
}

impl VaultFixture {
    pub fn new(state: VaultState) -> Self {
        use scopevault::crypto::KdfParams;
        use scopevault::prompts::unlock::{Unlocker, VaultSlot};
        use scopevault::store::Vault;

        let tmp = tempdir::TempDir::new("vault");
        let fake = tmp.path().join("pinentry");
        std::fs::create_dir(&fake).unwrap();
        std::fs::write(fake.join("pins"), "").unwrap();
        let wrapper = tmp.path().join("pinentry.sh");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nFAKE_PINENTRY_DIR='{}' exec '{}' \"$@\"\n",
                fake.display(),
                support_script("fake-pinentry.sh").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();

        let dir = tmp.path().join("vault");
        let slot = match state {
            VaultState::Unlocked => {
                VaultSlot { vault: Some(Vault::create(&dir, PASSWORD.as_bytes(), KdfParams::MINIMUM).unwrap()), dir }
            }
            // Locked in memory rather than closed and reopened: a child
            // forked meanwhile by a parallel test could briefly hold the
            // vault's `flock` (see `store_crash.rs`).
            VaultState::Locked => {
                let mut v = Vault::create(&dir, PASSWORD.as_bytes(), KdfParams::MINIMUM).unwrap();
                v.lock();
                VaultSlot { vault: Some(v), dir }
            }
            VaultState::Missing => VaultSlot::open(dir).unwrap(),
        };
        let config =
            scopevault::prompts::pinentry::PinentryConfig { program: wrapper, timeout: Duration::from_secs(20) };
        let unlocker = Unlocker::new(std::sync::Arc::new(std::sync::Mutex::new(slot)), config, KdfParams::MINIMUM);
        VaultFixture { tmp, unlocker }
    }

    fn fake(&self) -> PathBuf {
        self.tmp.path().join("pinentry")
    }

    /// Sets the answers for the next dialogs (one per `GETPIN`).
    pub fn set_pins(&self, pins: &[&str]) {
        std::fs::write(self.fake().join("pins"), pins.join("\n") + "\n").unwrap();
        let _ = std::fs::remove_file(self.fake().join("count"));
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.fake().join("log")).unwrap_or_default()
    }

    /// Number of dialogs started so far.
    pub fn dialogs(&self) -> usize {
        self.log().matches("STARTED").count()
    }

    /// PID of the most recently started pinentry.
    pub fn pinentry_pid(&self) -> Option<i32> {
        std::fs::read_to_string(self.fake().join("pid")).ok()?.trim().parse().ok()
    }

    pub fn unlocked(&self) -> bool {
        self.unlocker.vault().lock().unwrap().is_unlocked()
    }

    /// Global lock, as the administrative interface would do it.
    pub fn lock_vault(&self) {
        if let Some(v) = self.unlocker.vault().lock().unwrap().vault.as_mut() {
            v.lock();
        }
    }
}
