//! The unlock helper (pinentry) and unlock coordination, using
//! `tests/support/fake-pinentry.sh` in place of a real dialog.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::tempdir::TempDir;
use scopevault::crypto::{KdfParams, Slot};
use scopevault::identity::{AppId, Scope};
use scopevault::prompts::pinentry::PinentryConfig;
use scopevault::prompts::unlock::{MAX_ATTEMPTS, SlotUnlock, UnlockOutcome, UnlockTimings, Unlocker, VaultSlot};
use scopevault::store::Vault;
use zeroize::Zeroizing;

struct Fixture {
    tmp: TempDir,
    unlocker: Arc<Unlocker>,
}

impl Fixture {
    fn new(pins: &[&str], existing_password: Option<&[u8]>) -> Self {
        Self::with_timings(pins, existing_password, timings(Duration::from_secs(1)))
    }

    fn with_timings(pins: &[&str], existing_password: Option<&[u8]>, t: UnlockTimings) -> Self {
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
        Fixture { unlocker: Unlocker::with_timings(slot, config, KdfParams::MINIMUM, t), tmp }
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

/// The fixture's short waits, with the implicit wait chosen per test. The
/// not-ready retry is fast (100 ms delay, 1 s window), so tests with a
/// `FAIL`ing pinentry finish quickly.
fn timings(implicit_wait: Duration) -> UnlockTimings {
    UnlockTimings {
        implicit_wait,
        not_ready_delay: Duration::from_millis(100),
        not_ready_window: Duration::from_secs(1),
    }
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

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_dialog_makes_implicit_requests_wait() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::with_timings(&["CANCEL"], Some(b"pw"), timings(Duration::from_secs(3)));
    let started = Instant::now();
    assert_eq!(fx.unlocker.ensure_unlocked_implicit(&app(), Instant::now()).await, UnlockOutcome::Cancelled);
    // It waited about implicit_wait instead of returning at once, and no
    // second dialog was opened meanwhile.
    assert!(started.elapsed() >= Duration::from_millis(2500), "{:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    assert_eq!(fx.dialogs(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wait_counts_from_when_the_request_arrived() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::with_timings(&["pw"], Some(b"pw"), timings(Duration::from_secs(1)));
    // Queued for longer than the implicit wait: it gives up at once and
    // opens no dialog.
    let arrived = Instant::now() - Duration::from_secs(2);
    let started = Instant::now();
    assert_eq!(fx.unlocker.ensure_unlocked_implicit(&app(), arrived).await, UnlockOutcome::Cancelled);
    assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
    assert_eq!(fx.dialogs(), 0);
    assert!(!fx.unlocked());
}

#[tokio::test(flavor = "multi_thread")]
async fn during_the_cooldown_an_implicit_request_waits_for_an_explicit_unlock() {
    let _s = SERIAL.lock().await;
    // implicit_wait 10 s: an Unlocked result cannot be the deadline.
    let fx = Fixture::with_timings(&["CANCEL", "pw"], Some(b"pw"), timings(Duration::from_secs(10)));
    let waiter = {
        let u = fx.unlocker.clone();
        tokio::spawn(async move { u.ensure_unlocked_implicit(&app(), Instant::now()).await })
    };
    for _ in 0..100 {
        if fx.dialogs() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The dialog answers CANCEL at once; the request keeps waiting without
    // opening another dialog.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!fx.unlocked(), "the cancel left the vault locked");

    // An explicit prompt is not subject to the cooldown; it unlocks the
    // vault, and the waiting implicit request finishes with it.
    let explicit = {
        let u = fx.unlocker.clone();
        tokio::spawn(async move { u.ensure_unlocked(&app()).await })
    };
    assert_eq!(explicit.await.unwrap(), UnlockOutcome::Unlocked);
    assert_eq!(waiter.await.unwrap(), UnlockOutcome::Unlocked);
    assert_eq!(fx.dialogs(), 2, "the cancelled dialog and the explicit one");
}

#[tokio::test(flavor = "multi_thread")]
async fn during_the_cooldown_a_portal_request_waits_for_an_explicit_unlock() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::with_timings(&["CANCEL", "pw"], Some(b"pw"), timings(Duration::from_secs(10)));
    let waiter = {
        let u = fx.unlocker.clone();
        tokio::spawn(async move { u.ensure_unlocked_portal("org.example.App").await })
    };
    for _ in 0..100 {
        if fx.dialogs() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!fx.unlocked());

    let explicit = {
        let u = fx.unlocker.clone();
        tokio::spawn(async move { u.ensure_unlocked(&app()).await })
    };
    assert_eq!(explicit.await.unwrap(), UnlockOutcome::Unlocked);
    assert_eq!(waiter.await.unwrap(), UnlockOutcome::Unlocked);
    assert_eq!(fx.dialogs(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prompter_that_is_not_ready_is_retried() {
    let _s = SERIAL.lock().await;
    // FAIL answers with a device error, as a pinentry without a window does.
    let fx = Fixture::with_timings(&["FAIL", "pw"], Some(b"pw"), timings(Duration::from_secs(1)));
    let started = Instant::now();
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Unlocked);
    assert_eq!(fx.dialogs(), 2, "the failed attempt and the retry");
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());

    // EXIT makes pinentry quit without replying; the same retry applies.
    let fx = Fixture::with_timings(&["EXIT", "pw"], Some(b"pw"), timings(Duration::from_secs(1)));
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Unlocked);
    assert_eq!(fx.dialogs(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prompter_that_never_gets_ready_fails_after_the_window() {
    let _s = SERIAL.lock().await;
    let pins: Vec<&str> = vec!["FAIL"; 40];
    let fx = Fixture::with_timings(&pins, Some(b"pw"), timings(Duration::from_secs(1)));
    let started = Instant::now();
    assert!(matches!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Failed(_)));
    // The not_ready_window passed before the failure, with a retry every
    // not_ready_delay: a few pinentry runs, more than the MAX_ATTEMPTS
    // password attempts but bounded by the window.
    assert!(started.elapsed() >= Duration::from_millis(800), "{:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    let runs = fx.dialogs();
    assert!(runs > MAX_ATTEMPTS && runs <= 40, "{runs} pinentry runs");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_pinentry_fails_cleanly() {
    let _s = SERIAL.lock().await;
    let tmp = TempDir::new("unlock");
    let slot = Arc::new(Mutex::new(VaultSlot::open(tmp.path().join("vault")).unwrap()));
    let config = PinentryConfig { program: "/nonexistent/pinentry".into(), timeout: Duration::from_secs(5) };
    // A long not-ready window, so a retried Spawn error would show.
    let t = UnlockTimings { not_ready_window: Duration::from_secs(10), ..timings(Duration::from_secs(2)) };
    let u = Unlocker::with_timings(slot, config, KdfParams::MINIMUM, t);
    let started = Instant::now();
    assert!(matches!(u.ensure_unlocked(&app()).await, UnlockOutcome::Failed(_)));
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "Spawn is not retried, well under not_ready_window: {:?}",
        started.elapsed()
    );
    // The failure starts the cooldown; an implicit request then waits
    // without a dialog and gives up only at its own deadline.
    let started = Instant::now();
    assert_eq!(u.ensure_unlocked_implicit(&app(), Instant::now()).await, UnlockOutcome::Cancelled);
    assert!(started.elapsed() >= Duration::from_millis(1500), "{:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_shows_the_error_line_again() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::with_timings(&["wrong", "FAIL", "right"], Some(b"right"), timings(Duration::from_secs(1)));
    assert_eq!(fx.unlocker.ensure_unlocked(&app()).await, UnlockOutcome::Unlocked);
    let log = fx.log();
    assert!(
        log.matches("SETERROR Wrong password").count() >= 2,
        "the retried dialog shows the error line again: {log}"
    );
    assert_eq!(fx.dialogs(), 3, "wrong password, the FAIL retry, the right one");
}

impl Fixture {
    /// Gives the (locked) vault a login slot for `login`, using the master
    /// password `master`.
    fn add_login_slot(&self, master: &[u8], login: &[u8]) {
        let mut slot = self.unlocker.vault().lock().unwrap();
        let v = slot.vault.as_mut().unwrap();
        v.unlock(master).unwrap();
        let wrap = v.vault_key().unwrap().wrap_for(Slot::Login, login, KdfParams::MINIMUM).unwrap();
        v.replace_key_slot(Slot::Login, None, Some(&wrap)).unwrap();
        v.lock();
    }

    fn pinentry_pid(&self) -> i32 {
        std::fs::read_to_string(self.fake().join("pid")).unwrap().trim().parse().unwrap()
    }

    async fn wait_for_getpin(&self) {
        for _ in 0..100 {
            if self.log().contains("GETPIN") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the dialog never asked for a password");
    }
}

fn alive(pid: i32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    !stat.is_empty() && stat.split_whitespace().nth(2) != Some("Z")
}

fn pw(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_login_slot_unlocks_and_closes_an_open_dialog() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::new(&["HANG"], Some(b"master"));
    fx.add_login_slot(b"master", b"login");
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let u = fx.unlocker.clone();
            tokio::spawn(async move { u.ensure_unlocked(&app()).await })
        })
        .collect();
    fx.wait_for_getpin().await;
    let pid = fx.pinentry_pid();

    // A wrong password leaves the vault locked and the dialog open.
    assert_eq!(fx.unlocker.unlock_with_slot(Slot::Login, pw("master")).await, SlotUnlock::WrongPassword);
    assert!(!fx.unlocked());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(alive(pid), "a failed slot unlock must not close the dialog");

    assert_eq!(fx.unlocker.unlock_with_slot(Slot::Login, pw("login")).await, SlotUnlock::Unlocked);
    assert!(fx.unlocked());
    for w in waiters {
        let outcome = tokio::time::timeout(Duration::from_secs(5), w).await.expect("waiter not released").unwrap();
        assert_eq!(outcome, UnlockOutcome::Unlocked);
    }
    let mut gone = false;
    for _ in 0..100 {
        if !alive(pid) {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(gone, "pinentry still running after the vault was unlocked");
    assert_eq!(fx.unlocker.unlock_with_slot(Slot::Login, pw("login")).await, SlotUnlock::AlreadyUnlocked);
    assert_eq!(fx.dialogs(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slot_unlock_serves_requests_waiting_out_the_cooldown() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::with_timings(&["CANCEL"], Some(b"master"), timings(Duration::from_secs(10)));
    fx.add_login_slot(b"master", b"login");
    // The cancelled dialog starts the cooldown; the request keeps waiting.
    let u = fx.unlocker.clone();
    let waiting = tokio::spawn(async move { u.ensure_unlocked_implicit(&app(), Instant::now()).await });
    for _ in 0..100 {
        if fx.log().contains("GETPIN") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiting.is_finished());
    let started = Instant::now();
    assert_eq!(fx.unlocker.unlock_with_slot(Slot::Login, pw("login")).await, SlotUnlock::Unlocked);
    assert_eq!(waiting.await.unwrap(), UnlockOutcome::Unlocked);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(fx.dialogs(), 1);
}

#[tokio::test]
async fn a_slot_unlock_needs_a_vault_with_that_slot() {
    let _s = SERIAL.lock().await;
    let fx = Fixture::new(&[], None);
    assert_eq!(fx.unlocker.unlock_with_slot(Slot::Login, pw("login")).await, SlotUnlock::NoSlot);
    let fx = Fixture::new(&[], Some(b"master"));
    assert_eq!(fx.unlocker.unlock_with_slot(Slot::Login, pw("master")).await, SlotUnlock::NoSlot);
    assert!(!fx.unlocked());
    assert_eq!(fx.dialogs(), 0);
}
