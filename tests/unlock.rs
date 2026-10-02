//! The unlock helper (pinentry) and unlock coordination, using
//! `tests/support/fake-pinentry.sh` in place of a real dialog.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::tempdir::TempDir;
use scopevault::crypto::KdfParams;
use scopevault::identity::{AppId, Scope};
use scopevault::prompts::pinentry::PinentryConfig;
use scopevault::prompts::unlock::{UnlockOutcome, Unlocker, VaultSlot};
use scopevault::store::Vault;

struct Fixture {
    tmp: TempDir,
    unlocker: Arc<Unlocker>,
}

impl Fixture {
    fn new(pins: &[&str], existing_password: Option<&[u8]>) -> Self {
        let tmp = TempDir::new("unlock");
        let fake = tmp.path().join("pinentry");
        std::fs::create_dir(&fake).unwrap();
        std::fs::write(fake.join("pins"), pins.join("\n") + "\n").unwrap();
        // SAFETY: only this test binary's tests set this variable, always to
        // their own fixture directory before starting a dialog; tests that
        // read it run serially (see `serial`).
        unsafe { std::env::set_var("FAKE_PINENTRY_DIR", &fake) };
        let dir = tmp.path().join("vault");
        if let Some(pw) = existing_password {
            drop(Vault::create(&dir, pw, KdfParams::MINIMUM).unwrap());
        }
        let slot = Arc::new(Mutex::new(VaultSlot::open(dir).unwrap()));
        let config =
            PinentryConfig { program: common::support_script("fake-pinentry.sh"), timeout: Duration::from_secs(20) };
        Fixture { unlocker: Unlocker::new(slot, config, KdfParams::MINIMUM), tmp }
    }

    fn fake(&self) -> PathBuf {
        self.tmp.path().join("pinentry")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.fake().join("log")).unwrap_or_default()
    }

    fn dialogs(&self) -> usize {
        self.log().matches("STARTED").count()
    }

    fn unlocked(&self) -> bool {
        self.unlocker.vault().lock().unwrap().is_unlocked()
    }
}

/// The fake pinentry is configured through the environment, so tests in
/// this file must not overlap.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn app() -> Scope {
    Scope::Flatpak(AppId::parse("org.example.App").unwrap())
}

fn reopen(dir: &Path, pw: &[u8]) -> bool {
    let mut v = Vault::open(dir).unwrap();
    v.unlock(pw).is_ok()
}

#[tokio::test]
async fn creates_a_vault_on_first_use() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::new(&["first password"], None);
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Unlocked);
    assert!(fx.unlocked());
    let log = fx.log();
    assert!(log.contains("SETREPEAT"), "new passwords are entered twice: {log}");
    assert!(log.contains("org.example.App"), "dialog names the requesting app");
    // The dialog text never contains the password.
    assert!(!log.contains("first password"));
    drop(fx.unlocker.vault().lock().unwrap().vault.take());
    assert!(reopen(&fx.tmp.path().join("vault"), b"first password"));
}

#[tokio::test]
async fn wrong_then_right_password() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::new(&["wrong", "right%25 pw"], Some(b"right%25 pw"));
    assert_eq!(fx.unlocker.ensure_unlocked(&Scope::Host).await, UnlockOutcome::Unlocked);
    assert!(fx.log().contains("SETERROR Wrong password"));
    assert_eq!(fx.dialogs(), 2);
}

#[tokio::test]
async fn cancel_and_too_many_attempts() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::new(&["CANCEL"], Some(b"pw"));
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Cancelled);
    assert!(!fx.unlocked());

    let fx = Fixture::new(&["a", "b", "c", "pw"], Some(b"pw"));
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Cancelled);
    assert!(!fx.unlocked());
    assert_eq!(fx.dialogs(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_share_one_dialog() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::new(&["pw"], Some(b"pw"));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let u = fx.unlocker.clone();
            tokio::spawn(async move { u.ensure_unlocked(&app()).await })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), UnlockOutcome::Unlocked);
    }
    assert_eq!(fx.dialogs(), 1);
    // Once unlocked, no further dialogs.
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Unlocked);
    assert_eq!(fx.dialogs(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn abandoned_dialog_is_killed() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::new(&["HANG", "pw"], Some(b"pw"));
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let u = fx.unlocker.clone();
            tokio::spawn(async move { u.ensure_unlocked(&app()).await })
        })
        .collect();
    // Wait until the dialog is waiting for input.
    for _ in 0..100 {
        if fx.log().contains("GETPIN") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pid: i32 = std::fs::read_to_string(fx.fake().join("pid")).unwrap().trim().parse().unwrap();
    assert!(Path::new(&format!("/proc/{pid}")).exists());

    // One waiter leaving keeps the dialog; the last one leaving kills it.
    waiters[0].abort();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(Path::new(&format!("/proc/{pid}")).exists(), "dialog must survive while someone waits");
    waiters[1].abort();
    let mut gone = false;
    for _ in 0..100 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        if stat.is_empty() || stat.split_whitespace().nth(2) == Some("Z") {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(gone, "pinentry still running after all waiters left");
    assert!(!fx.unlocked());

    // A later request gets a fresh dialog.
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Unlocked);
    assert_eq!(fx.dialogs(), 2);
}

#[tokio::test]
async fn missing_pinentry_fails_cleanly() {
    let _s = SERIAL.lock().await;
    let tmp = TempDir::new("unlock");
    let slot = Arc::new(Mutex::new(VaultSlot::open(tmp.path().join("vault")).unwrap()));
    let config = PinentryConfig { program: "/nonexistent/pinentry".into(), timeout: Duration::from_secs(5) };
    let u = Unlocker::new(slot, config, KdfParams::MINIMUM);
    assert!(matches!(u.ensure_unlocked(&app()).await, UnlockOutcome::Failed(_)));
    // Automatic unlocks then pause instead of retrying a broken dialog.
    assert_eq!(u.ensure_unlocked_implicit(&app()).await, UnlockOutcome::Cancelled);
}
