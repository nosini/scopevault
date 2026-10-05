//! The Secret portal backend on a private bus.
//!
//! The backend serves on a second connection of the same bus as the Secret
//! Service, sharing the fixture's identity table and unlocker. A "frontend"
//! is a connection identified as `host` that owns
//! `org.freedesktop.portal.Desktop`, as xdg-desktop-portal does.

mod common;

use std::collections::HashMap;
use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::sync::MutexGuard;
use std::time::Duration;

use common::service::{Fixture, collections, flatpak, search};
use common::tempdir::TempDir;
use common::{PASSWORD, VaultFixture, VaultState};
use scopevault::identity::{Principal, Scope};
use scopevault::portal_backend::{BACKEND_NAME, BACKEND_PATH, FRONTEND_NAME, PortalBackend};
use scopevault::prompts::unlock::{UnlockOutcome, VaultSlot};
use scopevault::store::{AdminAuthority, PortableItem, Secret};
use zbus::Connection;
use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue};

const SECRET_IFACE: &str = "org.freedesktop.impl.portal.Secret";
const REQUEST_IFACE: &str = "org.freedesktop.impl.portal.Request";
const HANDLE: &str = "/org/freedesktop/portal/desktop/request/test/one";
const APP: &str = "org.example.App";
const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";

struct PortalFixture {
    fx: Fixture,
    /// Root of the applications' private data, nested one level so tests can
    /// check that nothing outside it was touched.
    app_data: TempDir,
    _portal_conn: Connection,
}

async fn fixture(state: VaultState) -> PortalFixture {
    let fx = common::service::fixture(state).await;
    let app_data = TempDir::new("portal-apps");
    let app_root = app_data.path().join("apps");
    std::fs::create_dir(&app_root).unwrap();
    let portal_conn = fx.bus.connect().await;
    let backend = PortalBackend::new(portal_conn.clone(), fx.resolver.clone(), fx.vault.unlocker.clone(), app_root);
    backend.start().await.unwrap();
    portal_conn.request_name(BACKEND_NAME).await.unwrap();
    PortalFixture { fx, app_data, _portal_conn: portal_conn }
}

impl PortalFixture {
    /// A connection identified as `who`; with `own`, it also owns the
    /// frontend's well-known name.
    async fn frontend(&self, who: Option<Principal>, own: bool) -> Connection {
        let c = self.fx.client(who).await;
        if own {
            c.request_name(FRONTEND_NAME).await.unwrap();
        }
        c
    }

    /// A connection with no identity, for Close calls from the outside.
    async fn connection(&self) -> Connection {
        self.fx.bus.connect().await
    }

    /// The fixture's vault, under the daemon's mutex.
    fn store(&self) -> MutexGuard<'_, VaultSlot> {
        self.fx.vault.unlocker.vault().lock().unwrap()
    }
}

/// The portal scope's keys as (label, app ID, bytes), sorted.
fn stored_keys(fx: &PortalFixture) -> Vec<(String, String, Vec<u8>)> {
    let mut slot = fx.store();
    let v = slot.vault.as_mut().unwrap();
    let mut out = Vec::new();
    for c in v.export(&AdminAuthority::offline(), &Scope::Portal).unwrap() {
        for i in c.items {
            out.push((i.label, i.attributes.get("app_id").cloned().unwrap_or_default(), i.secret.value.to_vec()));
        }
    }
    out.sort();
    out
}

fn key_item(app_id: &str, byte: u8) -> PortableItem {
    PortableItem {
        label: format!("Application key for {app_id}"),
        attributes: [
            ("app_id".to_owned(), app_id.to_owned()),
            ("xdg:schema".to_owned(), "org.freedesktop.portal.Secret".to_owned()),
        ]
        .into(),
        secret: Secret::new(vec![byte; 64], "application/octet-stream"),
        created: 1_600_000_000,
        modified: 1_700_000_000,
    }
}

type CallError = (String, String);

/// Calls RetrieveSecret with a pipe's write end. Returns the reply (the
/// response code, or the D-Bus error) and what an app reading the pipe saw.
/// The local write end is dropped before reading, so the read end sees EOF
/// as soon as the backend has written (or never touched) its copy.
async fn retrieve_at(c: &Connection, handle: &str, app_id: &str) -> (Result<u32, CallError>, Vec<u8>) {
    let (mut rd, wr) = std::io::pipe().unwrap();
    let response = retrieve_with_fd(c, handle, app_id, wr.as_fd()).await;
    drop(wr);
    let mut buf = Vec::new();
    let bytes = tokio::task::spawn_blocking(move || {
        rd.read_to_end(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();
    (response, bytes)
}

/// Calls RetrieveSecret with a copy of `fd`.
async fn retrieve_with_fd(c: &Connection, handle: &str, app_id: &str, fd: BorrowedFd<'_>) -> Result<u32, CallError> {
    let fd = OwnedFd::from(fd.try_clone_to_owned().unwrap());
    let options: HashMap<String, OwnedValue> = HashMap::new();
    let path = OwnedObjectPath::try_from(handle.to_owned()).unwrap();
    let reply = c
        .call_method(
            Some(BACKEND_NAME),
            BACKEND_PATH,
            Some(SECRET_IFACE),
            "RetrieveSecret",
            &(path, app_id, fd, options),
        )
        .await;
    match reply {
        Ok(m) => {
            let (response, _): (u32, HashMap<String, OwnedValue>) = m.body().deserialize().unwrap();
            Ok(response)
        }
        Err(zbus::Error::MethodError(name, msg, _)) => Err((name.to_string(), msg.unwrap_or_default())),
        Err(e) => panic!("transport error: {e}"),
    }
}

async fn retrieve(c: &Connection, app_id: &str) -> (Result<u32, CallError>, Vec<u8>) {
    retrieve_at(c, HANDLE, app_id).await
}

/// Calls Close on a request object.
async fn close(c: &Connection, handle: &str) -> Result<(), CallError> {
    match c.call_method(Some(BACKEND_NAME), handle, Some(REQUEST_IFACE), "Close", &()).await {
        Ok(_) => Ok(()),
        Err(zbus::Error::MethodError(name, msg, _)) => Err((name.to_string(), msg.unwrap_or_default())),
        Err(e) => panic!("transport error: {e}"),
    }
}

/// Asserts the call was refused as a non-frontend and nothing was written.
async fn refused(c: &Connection, app_id: &str) {
    let (r, bytes) = retrieve(c, app_id).await;
    assert_eq!(r.unwrap_err().0, ACCESS_DENIED);
    assert!(bytes.is_empty(), "nothing was written to the pipe");
}

/// Waits until the current dialog asks for a password; returns its PID.
async fn dialog_waiting(v: &VaultFixture, dialogs: usize) -> i32 {
    for _ in 0..250 {
        if v.dialogs() >= dialogs && v.log().matches("GETPIN").count() >= dialogs {
            return v.pinentry_pid().unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no dialog appeared: {}", v.log());
}

async fn process_gone(pid: i32) -> bool {
    for _ in 0..150 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        if stat.is_empty() || stat.split_whitespace().nth(2) == Some("Z") {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn an_imported_key_is_served_byte_for_byte() {
    let fx = fixture(VaultState::Unlocked).await;
    {
        let mut slot = fx.store();
        let report = slot
            .vault
            .as_mut()
            .unwrap()
            .import_portal_keys(&AdminAuthority::offline(), &[key_item(APP, 0x2b)])
            .unwrap();
        assert_eq!((report.imported, report.skipped), (1, 0));
    }
    let fe = fx.frontend(Some(Principal::Host), true).await;
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes, vec![0x2b; 64]);
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes, vec![0x2b; 64], "the same bytes again");
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_frontend_is_served() {
    let fx = fixture(VaultState::Unlocked).await;
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();

    // A host process that does not own the frontend's name.
    refused(&fx.frontend(Some(Principal::Host), false).await, APP).await;
    // A Flatpak app that owns it.
    let app = fx.frontend(Some(flatpak("org.example.Fake")), true).await;
    refused(&app, APP).await;
    // An unidentified caller that owns it.
    let stranger = fx.frontend(None, true).await;
    refused(&stranger, APP).await;
    // A host process calling while another connection owns the name.
    let owner = fx.frontend(Some(Principal::Host), true).await;
    refused(&fx.frontend(Some(Principal::Host), false).await, APP).await;
    drop(owner);

    assert!(stored_keys(&fx).is_empty(), "no key was created");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_is_created_only_in_an_initialised_portal() {
    let fx = fixture(VaultState::Unlocked).await;
    let fe = fx.frontend(Some(Principal::Host), true).await;

    // No portal scope yet: refused, and nothing created.
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 2, "refused with response 2");
    assert!(bytes.is_empty());
    assert!(stored_keys(&fx).is_empty());
    assert!(!fx.store().vault.as_ref().unwrap().portal_initialised().unwrap());

    // After init: created and served.
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes.len(), 64);
    let (r, bytes2) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes2, bytes, "the same bytes again");
    assert_eq!(stored_keys(&fx).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keyring_file_of_its_own_blocks_creation() {
    let fx = fixture(VaultState::Unlocked).await;
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();
    let keyrings = fx.app_data.path().join("apps").join(APP).join("data").join("keyrings");
    std::fs::create_dir_all(&keyrings).unwrap();
    std::fs::write(keyrings.join("default.keyring"), b"encrypted with the old key").unwrap();
    let fe = fx.frontend(Some(Principal::Host), true).await;

    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 2);
    assert!(bytes.is_empty());
    assert!(stored_keys(&fx).is_empty(), "no key was created");

    // With a key in the vault, the file does not matter: it is served.
    fx.store().vault.as_mut().unwrap().admin_create_portal_key(&AdminAuthority::offline(), APP).unwrap();
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes.len(), 64);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_app_ids_are_refused() {
    let fx = fixture(VaultState::Unlocked).await;
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();
    let fe = fx.frontend(Some(Principal::Host), true).await;

    for app_id in ["", "..", "a/b", "../x"] {
        let (r, bytes) = retrieve(&fe, app_id).await;
        assert_eq!(r.unwrap(), 2, "{app_id:?}");
        assert!(bytes.is_empty(), "{app_id:?}");
    }
    assert!(stored_keys(&fx).is_empty(), "nothing was created");
    assert!(fx.app_data.path().join("apps").read_dir().unwrap().next().is_none());
    assert!(!fx.app_data.path().join("x").exists(), "no directory outside the root was touched");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_locked_vault_is_unlocked_through_the_dialog() {
    let fx = fixture(VaultState::Unlocked).await;
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();
    fx.fx.vault.lock_vault();
    let fe = fx.frontend(Some(Principal::Host), true).await;

    // The correct password unlocks, and the key is created and served.
    fx.fx.vault.set_pins(&[PASSWORD]);
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes.len(), 64);

    // A cancelled dialog is response 1, after the portal request waited out
    // the fixture's 1 s implicit deadline instead of failing at once.
    fx.fx.vault.lock_vault();
    fx.fx.vault.set_pins(&["CANCEL"]);
    let started = std::time::Instant::now();
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 1);
    assert!(bytes.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(800), "{:?}", started.elapsed());

    // A request made during the cooldown waits without a dialog and is
    // served once the vault is unlocked through the fixture's unlocker.
    fx.fx.vault.lock_vault();
    let waiter = {
        let fe = fe.clone();
        tokio::spawn(async move { retrieve(&fe, APP).await })
    };
    fx.fx.vault.set_pins(&[PASSWORD]);
    let u = fx.fx.vault.unlocker.clone();
    assert_eq!(u.ensure_unlocked(&Scope::Host).await, UnlockOutcome::Unlocked);
    let (r, bytes) = tokio::time::timeout(Duration::from_secs(10), waiter).await.unwrap().unwrap();
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes.len(), 64, "the key created earlier is served");
    assert_eq!(fx.fx.vault.dialogs(), 3, "no dialog for the waiting request itself");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_vault_nothing_happens() {
    let fx = fixture(VaultState::Missing).await;
    let fe = fx.frontend(Some(Principal::Host), true).await;
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 2);
    assert!(bytes.is_empty());
    assert_eq!(fx.fx.vault.dialogs(), 0, "no dialog");
    assert!(fx.store().vault.is_none(), "still no vault");
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_the_request_cancels_the_call() {
    let fx = fixture(VaultState::Locked).await;
    let fe = fx.frontend(Some(Principal::Host), true).await;
    fx.fx.vault.set_pins(&["HANG"]);
    let handle = "/org/freedesktop/portal/desktop/request/test/cancel";
    let mut task = {
        let fe = fe.clone();
        tokio::spawn(async move { retrieve_at(&fe, handle, APP).await })
    };
    let pid = dialog_waiting(&fx.fx.vault, 1).await;

    // Close from another connection is refused, and the call keeps waiting.
    let other = fx.connection().await;
    let err = close(&other, handle).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "{err:?}");
    assert!(tokio::time::timeout(Duration::from_millis(300), &mut task).await.is_err(), "the call kept waiting");

    // The frontend's Close cancels it, and the dialog goes away.
    close(&fe, handle).await.unwrap();
    let (r, bytes) = task.await.unwrap();
    assert_eq!(r.unwrap(), 1);
    assert!(bytes.is_empty());
    assert!(process_gone(pid).await, "pinentry still running after Close");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_secret_service_cannot_see_the_portal_scope() {
    let fx = fixture(VaultState::Unlocked).await;
    {
        let mut slot = fx.store();
        let v = slot.vault.as_mut().unwrap();
        v.init_portal(&AdminAuthority::offline()).unwrap();
        v.admin_create_portal_key(&AdminAuthority::offline(), APP).unwrap();
    }

    // A host Secret Service client sees neither the collection nor the item.
    let host = fx.frontend(Some(Principal::Host), false).await;
    let cols = collections(&host).await;
    assert!(!cols.iter().any(|c| c.contains("portal")), "{cols:?}");
    let found = search(&host, &[("app_id", APP)]).await.unwrap();
    assert!(found.0.is_empty() && found.1.is_empty(), "{found:?}");

    // The portal itself holds the key.
    assert_eq!(stored_keys(&fx).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_calls_for_a_new_app_create_one_key() {
    let fx = fixture(VaultState::Unlocked).await;
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();
    let fe = fx.frontend(Some(Principal::Host), true).await;

    let (a, b) = tokio::join!(
        retrieve_at(&fe, "/org/freedesktop/portal/desktop/request/test/a", APP),
        retrieve_at(&fe, "/org/freedesktop/portal/desktop/request/test/b", APP),
    );
    assert_eq!(a.0.as_ref().ok(), Some(&0), "{a:?}");
    assert_eq!(b.0.as_ref().ok(), Some(&0), "{b:?}");
    assert_eq!(a.1.len(), 64);
    assert_eq!(a.1, b.1, "both calls got the same key");
    assert_eq!(stored_keys(&fx).len(), 1, "exactly one key was created");
}

/// An unlocked fixture whose vault holds a key for [`APP`], and its
/// frontend.
async fn serving_fixture() -> (PortalFixture, Connection) {
    let fx = fixture(VaultState::Unlocked).await;
    {
        let mut slot = fx.store();
        let v = slot.vault.as_mut().unwrap();
        v.init_portal(&AdminAuthority::offline()).unwrap();
        v.admin_create_portal_key(&AdminAuthority::offline(), APP).unwrap();
    }
    let fe = fx.frontend(Some(Principal::Host), true).await;
    (fx, fe)
}

/// Fills a pipe through `wr` until a write would block; returns how many
/// bytes it holds. `wr` is left blocking.
fn fill_pipe(wr: &std::io::PipeWriter) -> usize {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    let flags = fcntl_getfl(wr).unwrap();
    fcntl_setfl(wr, flags | OFlags::NONBLOCK).unwrap();
    let mut filled = 0;
    loop {
        match rustix::io::write(wr, &[0u8; 4096]) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::AGAIN) => break,
            Err(e) => panic!("{e}"),
        }
    }
    fcntl_setfl(wr, flags).unwrap();
    filled
}

/// Reads `rd` until every write end is closed, within ten seconds.
async fn read_all(mut rd: std::io::PipeReader) -> Vec<u8> {
    let read = tokio::task::spawn_blocking(move || {
        let mut buf = Vec::new();
        rd.read_to_end(&mut buf).unwrap();
        buf
    });
    tokio::time::timeout(Duration::from_secs(10), read).await.expect("a write end stayed open").unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_apps_file_description_keeps_its_flags() {
    // The fd shares its open file description with the app. Flags set on
    // it are the app's to change back, so the backend must not rely on
    // them, nor change them.
    let (fx, fe) = serving_fixture().await;
    let (rd, wr) = std::io::pipe().unwrap();
    assert_eq!(retrieve_with_fd(&fe, HANDLE, APP, wr.as_fd()).await.unwrap(), 0);
    let flags = rustix::fs::fcntl_getfl(&wr).unwrap();
    assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK), "the backend made the app's pipe non-blocking");
    drop(wr);
    assert_eq!(read_all(rd).await.len(), 64);
    drop(fx);
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_the_request_stops_a_pending_write() {
    let (_fx, fe) = serving_fixture().await;
    let (rd, wr) = std::io::pipe().unwrap();
    let filled = fill_pipe(&wr);
    let handle = "/org/freedesktop/portal/desktop/request/test/full";
    let task = {
        let fe = fe.clone();
        let fd = wr.as_fd().try_clone_to_owned().unwrap();
        tokio::spawn(async move { retrieve_with_fd(&fe, handle, APP, fd.as_fd()).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished(), "the write waits for the full pipe");

    close(&fe, handle).await.unwrap();
    assert_eq!(task.await.unwrap().unwrap(), 1, "cancelled");
    // The app drains its pipe after the Close: the key must not follow.
    drop(wr);
    let bytes = read_all(rd).await;
    assert_eq!(bytes.len(), filled, "{} key bytes were written after the Close", bytes.len() - filled);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_pipes_and_sockets_get_the_key() {
    let (fx, fe) = serving_fixture().await;

    let path = fx.app_data.path().join("plain-file");
    let file = std::fs::File::create(&path).unwrap();
    assert_eq!(retrieve_with_fd(&fe, HANDLE, APP, file.as_fd()).await.unwrap(), 2);
    drop(file);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0, "nothing was written to the regular file");

    // oo7 passes one end of a socket pair.
    let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(retrieve_with_fd(&fe, HANDLE, APP, a.as_fd()).await.unwrap(), 0);
    drop(a);
    let mut bytes = Vec::new();
    b.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len(), 64);
}

#[test]
fn full_pipes_hold_no_threads() {
    // Requests waiting for an app to read its pipe must not hold any of the
    // runtime's blocking threads: classification, the login socket and key
    // derivation need them.
    let rt = tokio::runtime::Builder::new_multi_thread().max_blocking_threads(4).enable_all().build().unwrap();
    rt.block_on(async {
        let (_fx, fe) = serving_fixture().await;
        let mut pipes = Vec::new();
        let mut pending = Vec::new();
        for i in 0..4 {
            let (rd, wr) = std::io::pipe().unwrap();
            fill_pipe(&wr);
            let fe = fe.clone();
            let fd = wr.as_fd().try_clone_to_owned().unwrap();
            let handle = format!("/org/freedesktop/portal/desktop/request/test/full{i}");
            pending.push(tokio::spawn(async move { retrieve_with_fd(&fe, &handle, APP, fd.as_fd()).await }));
            pipes.push((rd, wr));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let started = std::time::Instant::now();
        let blocking = tokio::task::spawn_blocking(|| ());
        tokio::time::timeout(Duration::from_secs(2), blocking)
            .await
            .expect("no blocking thread was free while the writes waited")
            .unwrap();
        let (r, bytes) = retrieve(&fe, APP).await;
        assert_eq!(r.unwrap(), 0);
        assert_eq!(bytes.len(), 64);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        drop(pipes);
        for p in pending {
            p.await.unwrap().unwrap();
        }
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn symlinks_in_the_apps_data_count_as_a_keyring_file() {
    // The app arranges its own directory: where a symlink leads is its
    // choice, so the check must not follow one.
    let fx = fixture(VaultState::Unlocked).await;
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();
    let fe = fx.frontend(Some(Principal::Host), true).await;
    let apps = fx.app_data.path().join("apps");
    let elsewhere = fx.app_data.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();

    // `data` dangles, for example into storage that is not mounted.
    std::fs::create_dir(apps.join("org.example.Dangling")).unwrap();
    std::os::unix::fs::symlink(fx.app_data.path().join("missing"), apps.join("org.example.Dangling/data")).unwrap();
    // `keyrings` leads to a directory without the file.
    std::fs::create_dir_all(apps.join("org.example.Moved/data")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, apps.join("org.example.Moved/data/keyrings")).unwrap();
    // The file itself is a dangling symlink.
    std::fs::create_dir_all(apps.join("org.example.Link/data/keyrings")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("gone"), apps.join("org.example.Link/data/keyrings/default.keyring"))
        .unwrap();

    for app in ["org.example.Dangling", "org.example.Moved", "org.example.Link"] {
        let (r, bytes) = retrieve(&fe, app).await;
        assert_eq!(r.unwrap(), 2, "{app}");
        assert!(bytes.is_empty(), "{app}");
    }
    assert!(stored_keys(&fx).is_empty(), "no key was created: {:?}", stored_keys(&fx));

    // A plain directory without the file still gets a key.
    std::fs::create_dir_all(apps.join(APP).join("data/keyrings")).unwrap();
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes.len(), 64);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_flatpak_apps_get_a_key_automatically() {
    // A snap keeps its keyring file under ~/snap, where the backend does
    // not look, so a fresh key could make its data unreadable.
    let fx = fixture(VaultState::Unlocked).await;
    fx.store().vault.as_mut().unwrap().init_portal(&AdminAuthority::offline()).unwrap();
    let fe = fx.frontend(Some(Principal::Host), true).await;

    for app_id in ["snap.firefox", "firefox"] {
        let (r, bytes) = retrieve(&fe, app_id).await;
        assert_eq!(r.unwrap(), 2, "{app_id}");
        assert!(bytes.is_empty(), "{app_id}");
    }
    assert!(stored_keys(&fx).is_empty(), "no key was created: {:?}", stored_keys(&fx));

    // Created explicitly, the key is served.
    fx.store().vault.as_mut().unwrap().admin_create_portal_key(&AdminAuthority::offline(), "snap.firefox").unwrap();
    let (r, bytes) = retrieve(&fe, "snap.firefox").await;
    assert_eq!(r.unwrap(), 0);
    assert_eq!(bytes.len(), 64);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_ends_when_the_frontend_loses_its_name() {
    let fx = fixture(VaultState::Locked).await;
    let fe = fx.frontend(Some(Principal::Host), true).await;
    fx.fx.vault.set_pins(&["HANG"]);
    let handle = "/org/freedesktop/portal/desktop/request/test/moved";
    let task = {
        let fe = fe.clone();
        tokio::spawn(async move { retrieve_at(&fe, handle, APP).await })
    };
    let pid = dialog_waiting(&fx.fx.vault, 1).await;

    // Another frontend takes over: the old one's request is dropped, and
    // its dialog goes away.
    fe.release_name(FRONTEND_NAME).await.unwrap();
    let _successor = fx.frontend(Some(Principal::Host), true).await;
    let (r, bytes) = tokio::time::timeout(Duration::from_secs(5), task).await.expect("the call kept waiting").unwrap();
    // 1 (cancelled) would mean it only gave up at the fixture's unlock
    // deadline, a second after the call.
    assert_eq!(r.unwrap(), 2, "the request was dropped when the name moved");
    assert!(bytes.is_empty());
    assert!(process_gone(pid).await, "pinentry still running after the frontend went away");
}
