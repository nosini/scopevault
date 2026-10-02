//! The Secret portal backend on a private bus.
//!
//! The backend serves on a second connection of the same bus as the Secret
//! Service, sharing the fixture's identity table and unlocker. A "frontend"
//! is a connection identified as `host` that owns
//! `org.freedesktop.portal.Desktop`, as xdg-desktop-portal does.

mod common;

use std::collections::HashMap;
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::sync::MutexGuard;
use std::time::Duration;

use common::service::{Fixture, collections, flatpak, search};
use common::tempdir::TempDir;
use common::{PASSWORD, VaultFixture, VaultState};
use scopevault::identity::{Principal, Scope};
use scopevault::portal_backend::{BACKEND_NAME, BACKEND_PATH, FRONTEND_NAME, PortalBackend};
use scopevault::prompts::unlock::VaultSlot;
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
    let fd = OwnedFd::from(wr.as_fd().try_clone_to_owned().unwrap());
    drop(wr);
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
    let response = match reply {
        Ok(m) => {
            let (response, _): (u32, HashMap<String, OwnedValue>) = m.body().deserialize().unwrap();
            Ok(response)
        }
        Err(zbus::Error::MethodError(name, msg, _)) => Err((name.to_string(), msg.unwrap_or_default())),
        Err(e) => panic!("transport error: {e}"),
    };
    let mut buf = Vec::new();
    let bytes = tokio::task::spawn_blocking(move || {
        rd.read_to_end(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();
    (response, bytes)
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

    // A cancelled dialog is response 1.
    fx.fx.vault.lock_vault();
    fx.fx.vault.set_pins(&["CANCEL"]);
    let (r, bytes) = retrieve(&fe, APP).await;
    assert_eq!(r.unwrap(), 1);
    assert!(bytes.is_empty());
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
