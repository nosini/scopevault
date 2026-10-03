//! Locking the vault before the system sleeps, against a stand-in for
//! logind on a private bus.

mod common;

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{TestBus, VaultFixture, VaultState};
use zbus::object_server::SignalEmitter;

#[derive(Default)]
struct Inhibitors {
    /// Our ends of the descriptors handed out, with the arguments.
    taken: Vec<(UnixStream, (String, String, String, String))>,
}

struct FakeLogind {
    inhibitors: Arc<Mutex<Inhibitors>>,
}

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl FakeLogind {
    fn inhibit(
        &self,
        what: String,
        who: String,
        why: String,
        mode: String,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        let (ours, theirs) = UnixStream::pair().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        ours.set_nonblocking(true).unwrap();
        self.inhibitors.lock().unwrap().taken.push((ours, (what, who, why, mode)));
        Ok(std::os::fd::OwnedFd::from(theirs).into())
    }

    #[zbus(signal)]
    async fn prepare_for_sleep(emitter: &SignalEmitter<'_>, start: bool) -> zbus::Result<()>;
}

/// Whether the holder of inhibitor `i` closed it.
fn released(inh: &Arc<Mutex<Inhibitors>>, i: usize) -> bool {
    let g = inh.lock().unwrap();
    let mut buf = [0u8; 1];
    matches!((&g.taken[i].0).read(&mut buf), Ok(0))
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_vault_is_locked_before_sleep_and_the_inhibitor_released() {
    let bus = TestBus::start();
    let inhibitors = Arc::new(Mutex::new(Inhibitors::default()));
    let logind = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.login1")
        .unwrap()
        .serve_at("/org/freedesktop/login1", FakeLogind { inhibitors: inhibitors.clone() })
        .unwrap()
        .build()
        .await
        .unwrap();
    let emit = |start: bool| {
        let logind = logind.clone();
        async move {
            let emitter = SignalEmitter::new(&logind, "/org/freedesktop/login1").unwrap();
            FakeLogind::prepare_for_sleep(&emitter, start).await.unwrap();
        }
    };

    let vault = VaultFixture::new(VaultState::Unlocked);
    let calls = Arc::new(Mutex::new(Vec::new()));
    // Records whether the vault was unlocked, and whether the newest
    // inhibitor was still held when locking: sleep must wait for the lock.
    let lock = {
        let unlocker = vault.unlocker.clone();
        let calls = calls.clone();
        let inhibitors = inhibitors.clone();
        move || {
            let newest = inhibitors.lock().unwrap().taken.len() - 1;
            let held = !released(&inhibitors, newest);
            let mut slot = unlocker.vault().lock().unwrap();
            let v = slot.vault.as_mut().unwrap();
            let was = v.is_unlocked();
            v.lock();
            calls.lock().unwrap().push((was, held));
            was
        }
    };
    tokio::spawn(scopevault::sleep::lock_before_sleep(bus.connect().await, lock));

    let count = || inhibitors.lock().unwrap().taken.len();
    wait_for("the inhibitor", || count() == 1).await;
    let args = inhibitors.lock().unwrap().taken[0].1.clone();
    assert_eq!((args.0.as_str(), args.1.as_str(), args.3.as_str()), ("sleep", "scopevault", "delay"));
    assert!(!released(&inhibitors, 0));
    assert!(vault.unlocked());

    emit(true).await;
    wait_for("the release", || released(&inhibitors, 0)).await;
    assert!(!vault.unlocked(), "locked before the inhibitor was released");
    assert_eq!(*calls.lock().unwrap(), vec![(true, true)]);

    // Resume: a new inhibitor for the next sleep; the vault stays locked
    // until something unlocks it.
    emit(false).await;
    wait_for("a new inhibitor", || count() == 2).await;
    assert!(!released(&inhibitors, 1));
    assert!(!vault.unlocked());

    // Another sleep with the vault already locked.
    emit(true).await;
    wait_for("the second release", || released(&inhibitors, 1)).await;
    assert_eq!(*calls.lock().unwrap(), vec![(true, true), (false, true)]);

    // A sleep signal from anyone but logind is ignored.
    emit(false).await;
    wait_for("a third inhibitor", || count() == 3).await;
    let other = bus.connect().await;
    let emitter = SignalEmitter::new(&other, "/org/freedesktop/login1").unwrap();
    FakeLogind::prepare_for_sleep(&emitter, true).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!released(&inhibitors, 2));
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_logind_the_daemon_still_starts() {
    let bus = TestBus::start();
    let task = tokio::spawn(scopevault::sleep::lock_before_sleep(bus.connect().await, || true));
    // Inhibit fails (nobody owns the name); the watcher keeps running.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished());
}
