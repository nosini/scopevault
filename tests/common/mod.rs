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

/// The login password [`FakeCheck::new`] accepts.
pub const LOGIN_PASSWORD: &str = "login password";

/// Stands in for `unix_chkpwd`: accepts one password, or cannot check at
/// all (`broken`). Counts its calls.
pub struct FakeCheck {
    pub accept: std::sync::Mutex<Vec<u8>>,
    pub broken: std::sync::atomic::AtomicBool,
    pub calls: std::sync::atomic::AtomicUsize,
}

impl FakeCheck {
    pub fn new(accept: &str) -> std::sync::Arc<Self> {
        std::sync::Arc::new(FakeCheck {
            accept: std::sync::Mutex::new(accept.as_bytes().to_vec()),
            broken: std::sync::atomic::AtomicBool::new(false),
            calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// The login password changes (as `passwd` would change it).
    pub fn set(&self, accept: &str) {
        *self.accept.lock().unwrap() = accept.as_bytes().to_vec();
    }

    pub fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl scopevault::login::PasswordCheck for FakeCheck {
    fn check(&self, password: &[u8]) -> Result<bool, String> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.broken.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("the checker is broken".into());
        }
        Ok(*self.accept.lock().unwrap() == password)
    }
}

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
        use scopevault::prompts::unlock::UnlockTimings;
        Self::with_timings(
            state,
            UnlockTimings {
                implicit_wait: Duration::from_secs(1),
                not_ready_delay: Duration::from_millis(100),
                not_ready_window: Duration::from_secs(1),
            },
        )
    }

    /// [`VaultFixture::new`] with other waits, for tests that need a longer
    /// implicit wait than the fixture's 1 s.
    pub fn with_timings(state: VaultState, timings: scopevault::prompts::unlock::UnlockTimings) -> Self {
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
                let v = Vault::create(&dir, PASSWORD.as_bytes(), KdfParams::MINIMUM).unwrap();
                VaultSlot::new(dir, Some(v))
            }
            // Locked in memory rather than closed and reopened: a child
            // forked meanwhile by a parallel test could briefly hold the
            // vault's `flock` (see `store_crash.rs`).
            VaultState::Locked => {
                let mut v = Vault::create(&dir, PASSWORD.as_bytes(), KdfParams::MINIMUM).unwrap();
                v.lock();
                VaultSlot::new(dir, Some(v))
            }
            VaultState::Missing => VaultSlot::open(dir).unwrap(),
        };
        let config =
            scopevault::prompts::pinentry::PinentryConfig { program: wrapper, timeout: Duration::from_secs(20) };
        let slot = std::sync::Arc::new(std::sync::Mutex::new(slot));
        let unlocker = Unlocker::with_timings(slot, config, KdfParams::MINIMUM, timings);
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
        self.unlocker.lock(&mut self.unlocker.vault().lock().unwrap());
    }
}
