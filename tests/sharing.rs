//! Explicit item sharing on a private bus.
//!
//! Identity comes from the fixed table (see `common::service`); grants are
//! created directly with `Vault::share` on the fixture's vault, and the
//! service's grant signal method is called the way the admin server does.

mod common;

use std::collections::HashMap;
use std::sync::MutexGuard;
use std::time::Duration;

use common::service::{
    ClientSession, Fixture, ITEM_IFACE, PROPS, SERVICE, SVC_IFACE, SignalLog, call, collections, create_collection,
    create_item, fixture, get, get_secret, introspect_children, run_prompt, search, xlock,
};
use common::{PASSWORD, VaultState};
use scopevault::identity::{Principal, Scope};
use scopevault::prompts::unlock::VaultSlot;
use scopevault::service_api::dispatch::GrantChange;
use scopevault::store::{AdminAuthority, GrantListing};
use zbus::zvariant::Value;

const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
const IS_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";
const SHARED_COL: &str = "/org/freedesktop/secrets/collection/Shared";
const LOGIN_COL: &str = "/org/freedesktop/secrets/collection/login";
const B: &str = "org.example.B";
const C: &str = "org.example.C";

fn b_scope() -> Scope {
    common::service::flatpak(B).scope()
}

fn c_scope() -> Scope {
    common::service::flatpak(C).scope()
}

fn vault(fx: &Fixture) -> MutexGuard<'_, VaultSlot> {
    fx.vault.unlocker.vault().lock().unwrap()
}

/// The host's login collection with one item, as (connection, item path,
/// item ID, session).
async fn host_item(fx: &Fixture) -> (zbus::Connection, String, String, ClientSession) {
    let host = fx.client(Some(Principal::Host)).await;
    create_collection(&host, "Login", "default").await;
    let session = ClientSession::plain(&host).await;
    let item =
        create_item(&host, LOGIN_COL, &session, "Mail", &[("check", "yes")], b"host-secret", false).await.unwrap();
    let id = item.rsplit('/').next().unwrap().to_owned();
    (host, item, id, session)
}

/// Shares the host's `item` with `grantee`, straight through the vault.
fn share(fx: &Fixture, item: &str, grantee: &Scope, write: bool) -> String {
    vault(fx)
        .vault
        .as_mut()
        .unwrap()
        .share(&AdminAuthority::offline(), &Scope::Host, &format!("login/{item}"), grantee, write)
        .unwrap()
}

fn unshare(fx: &Fixture, grant: &str) {
    vault(fx).vault.as_mut().unwrap().unshare(&AdminAuthority::offline(), grant).unwrap();
}

fn grants(fx: &Fixture) -> Vec<GrantListing> {
    vault(fx).vault.as_ref().unwrap().grants(&AdminAuthority::offline(), None).unwrap()
}

async fn read_item(c: &zbus::Connection, item_path: &str) -> Result<(Vec<u8>, String), (String, String)> {
    let s = ClientSession::plain(c).await;
    get_secret(c, item_path, &s).await
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_grant_there_is_no_shared_collection() {
    let fx = fixture(VaultState::Unlocked).await;
    let _host_item = host_item(&fx).await;
    let b = fx.client(Some(common::service::flatpak(B))).await;
    let cols = collections(&b).await;
    assert!(!cols.iter().any(|c| c.ends_with("/Shared")), "{cols:?}");
    let found = search(&b, &[("check", "yes")]).await.unwrap();
    assert!(found.0.is_empty() && found.1.is_empty(), "{found:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_grant_shows_the_item_in_shared() {
    let fx = fixture(VaultState::Unlocked).await;
    let (host, item_path, item_id, _) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), false);
    let grant_path = format!("{SHARED_COL}/{grant}");

    let b = fx.client(Some(common::service::flatpak(B))).await;
    let cols = collections(&b).await;
    assert!(cols.contains(&SHARED_COL.to_owned()), "{cols:?}");

    // Search finds it, reading returns the value.
    let found = search(&b, &[("check", "yes")]).await.unwrap();
    assert_eq!(found.0, vec![grant_path.clone()], "{found:?}");
    assert!(found.1.is_empty(), "{found:?}");
    assert_eq!(read_item(&b, &grant_path).await.unwrap(), (b"host-secret".to_vec(), "text/plain".into()));

    // Label and attributes match the owner's item.
    let owner_label: String = get(&host, &item_path, ITEM_IFACE, "Label").await.unwrap().try_into().unwrap();
    let label: String = get(&b, &grant_path, ITEM_IFACE, "Label").await.unwrap().try_into().unwrap();
    assert_eq!(label, owner_label);
    let owner_attrs: HashMap<String, String> =
        get(&host, &item_path, ITEM_IFACE, "Attributes").await.unwrap().try_into().unwrap();
    let attrs: HashMap<String, String> =
        get(&b, &grant_path, ITEM_IFACE, "Attributes").await.unwrap().try_into().unwrap();
    assert_eq!(attrs, owner_attrs);

    // Introspection lists the virtual collection.
    let children = introspect_children(&b, "/org/freedesktop/secrets/collection").await.unwrap();
    assert!(children.contains(&"Shared".to_owned()), "{children:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_grant_refuses_every_write() {
    let fx = fixture(VaultState::Unlocked).await;
    let (_host, _item_path, item_id, _) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), false);
    let grant_path = format!("{SHARED_COL}/{grant}");
    let b = fx.client(Some(common::service::flatpak(B))).await;
    let s = ClientSession::plain(&b).await;
    let attrs: HashMap<&str, &str> = [("k", "v")].into_iter().collect();

    let err = call(&b, &grant_path, ITEM_IFACE, "SetSecret", &s.encode(b"new", "text/plain")).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "SetSecret: {err:?}");
    let err = call(&b, &grant_path, PROPS, "Set", &(ITEM_IFACE, "Label", Value::from("x"))).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "Label: {err:?}");
    let err = call(&b, &grant_path, PROPS, "Set", &(ITEM_IFACE, "Attributes", Value::from(attrs))).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "Attributes: {err:?}");
    let err = call(&b, &grant_path, ITEM_IFACE, "Delete", &()).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "Delete item: {err:?}");
    let err = create_item(&b, SHARED_COL, &s, "x", &[("k", "v")], b"x", false).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "CreateItem: {err:?}");
    let err = call(&b, SHARED_COL, "org.freedesktop.Secret.Collection", "Delete", &()).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "Delete collection: {err:?}");
    let err =
        call(&b, SERVICE, SVC_IFACE, "SetAlias", &("default", common::service::obj(SHARED_COL))).await.unwrap_err();
    assert_eq!(err.0, ACCESS_DENIED, "SetAlias: {err:?}");

    // Nothing changed: the value is still the original one.
    assert_eq!(read_item(&b, &grant_path).await.unwrap(), (b"host-secret".to_vec(), "text/plain".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_grant_allows_set_secret() {
    let fx = fixture(VaultState::Unlocked).await;
    let (host, item_path, item_id, hs) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), true);
    let grant_path = format!("{SHARED_COL}/{grant}");

    let b = fx.client(Some(common::service::flatpak(B))).await;
    let s = ClientSession::plain(&b).await;
    call(&b, &grant_path, ITEM_IFACE, "SetSecret", &s.encode(b"new-secret", "text/plain")).await.unwrap();
    assert_eq!(get_secret(&host, &item_path, &hs).await.unwrap(), (b"new-secret".to_vec(), "text/plain".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_shared_path_looks_exactly_like_a_missing_one() {
    let fx = fixture(VaultState::Unlocked).await;
    let (_host, _item_path, item_id, _) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), false);
    let grant_path = format!("{SHARED_COL}/{grant}");

    let c = fx.client(Some(common::service::flatpak(C))).await;
    let cs = ClientSession::plain(&c).await;
    let unknown = format!("{LOGIN_COL}/{}", "f".repeat(32));
    let err_grant = call(&c, &grant_path, ITEM_IFACE, "GetSecret", &(cs.path.clone(),)).await.unwrap_err();
    let err_unknown = call(&c, &unknown, ITEM_IFACE, "GetSecret", &(cs.path,)).await.unwrap_err();
    assert_eq!(err_grant.0, err_unknown.0, "{err_grant:?} vs {err_unknown:?}");
    let found = search(&c, &[("check", "yes")]).await.unwrap();
    assert!(found.0.is_empty() && found.1.is_empty(), "{found:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unshare_removes_the_item_from_the_grantee() {
    let fx = fixture(VaultState::Unlocked).await;
    let (_host, _item_path, item_id, _) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), false);
    let grant_path = format!("{SHARED_COL}/{grant}");
    let b = fx.client(Some(common::service::flatpak(B))).await;
    let cs = ClientSession::plain(&b).await;
    assert_eq!(read_item(&b, &grant_path).await.unwrap(), (b"host-secret".to_vec(), "text/plain".into()));

    unshare(&fx, &grant);
    let err = call(&b, &grant_path, ITEM_IFACE, "GetSecret", &(cs.path,)).await.unwrap_err();
    assert_eq!(err.0, UNKNOWN_OBJECT, "{err:?}");
    let cols = collections(&b).await;
    assert!(!cols.contains(&SHARED_COL.to_owned()), "{cols:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn grants_follow_their_item_through_delete_move_and_reset() {
    let fx = fixture(VaultState::Unlocked).await;
    let auth = AdminAuthority::offline();

    // The owner deleting the item removes the grant.
    let (host, item_path, item_id, hs) = host_item(&fx).await;
    share(&fx, &item_id, &b_scope(), false);
    call(&host, &item_path, ITEM_IFACE, "Delete", &()).await.unwrap();
    assert!(grants(&fx).is_empty(), "the grant went with the item");

    // Moving the item loses the grant.
    let item = create_item(&host, LOGIN_COL, &hs, "Moved", &[("check", "moved")], b"m", false).await.unwrap();
    let id = item.rsplit('/').next().unwrap().to_owned();
    share(&fx, &id, &b_scope(), false);
    vault(&fx).vault.as_mut().unwrap().move_items(&auth, &Scope::Host, &[format!("login/{id}")], &b_scope()).unwrap();
    assert!(grants(&fx).is_empty(), "the grant went with the moved item");

    // Resetting the owner removes the grants it gave away.
    let item = create_item(&host, LOGIN_COL, &hs, "Reset", &[("check", "reset")], b"r", false).await.unwrap();
    let id = item.rsplit('/').next().unwrap().to_owned();
    share(&fx, &id, &b_scope(), false);
    vault(&fx).vault.as_mut().unwrap().reset_scope(&auth, &Scope::Host).unwrap();
    assert!(grants(&fx).is_empty(), "the owner's reset removed the grant");

    // Resetting a grantee removes only the grants given to it.
    let item = create_item(&host, LOGIN_COL, &hs, "Again", &[("check", "again")], b"a", false).await.unwrap();
    let id = item.rsplit('/').next().unwrap().to_owned();
    let kept = share(&fx, &id, &c_scope(), false);
    share(&fx, &id, &b_scope(), false);
    vault(&fx).vault.as_mut().unwrap().reset_scope(&auth, &b_scope()).unwrap();
    let all = grants(&fx);
    assert_eq!(all.iter().map(|g| g.id.as_str()).collect::<Vec<_>>(), [kept.as_str()], "only B's grant went");
}

#[tokio::test(flavor = "multi_thread")]
async fn locking_hides_or_locks_shared_items() {
    let fx = fixture(VaultState::Unlocked).await;
    let (host, item_path, item_id, hs) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), false);
    let grant_path = format!("{SHARED_COL}/{grant}");
    let b = fx.client(Some(common::service::flatpak(B))).await;
    let bs = ClientSession::plain(&b).await;
    let from = fx.service_name().await;

    // The owner locks its collection: the item is invisible to B, and B is
    // told that it and Shared disappeared.
    let b_log = SignalLog::start(&b, &from);
    let b_collections = |log: &SignalLog| -> Vec<Vec<String>> {
        log.changed_values(SERVICE, "Collections")
            .into_iter()
            .map(|v| {
                let paths: Vec<zbus::zvariant::OwnedObjectPath> = v.try_into().unwrap();
                paths.iter().map(|p| p.to_string()).collect()
            })
            .collect()
    };
    xlock(&host, "Lock", &[LOGIN_COL]).await.unwrap();
    let err = call(&b, &grant_path, ITEM_IFACE, "GetSecret", &(bs.path.clone(),)).await.unwrap_err();
    assert_eq!(err.0, UNKNOWN_OBJECT, "{err:?}");
    let cols = collections(&b).await;
    assert!(!cols.contains(&SHARED_COL.to_owned()), "{cols:?}");
    let m = b_log.wait_for(SHARED_COL, "ItemDeleted", Duration::from_secs(5)).await.expect("B's ItemDeleted");
    let (p,): (zbus::zvariant::OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), grant_path);
    b_log.wait_for(SERVICE, "PropertiesChanged", Duration::from_secs(5)).await.expect("B's Collections change");
    assert_eq!(b_collections(&b_log), [vec![LOGIN_COL.to_owned()]]);

    // Unlocking brings both back, and B is told.
    fx.vault.set_pins(&[PASSWORD]);
    let (_, prompt) = xlock(&host, "Unlock", &[LOGIN_COL]).await.unwrap();
    run_prompt(&host, &from, &prompt).await;
    let m = b_log.wait_for(SHARED_COL, "ItemCreated", Duration::from_secs(5)).await.expect("B's ItemCreated");
    let (p,): (zbus::zvariant::OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), grant_path);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while b_collections(&b_log).len() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(b_collections(&b_log), [vec![LOGIN_COL.to_owned()], vec![SHARED_COL.to_owned(), LOGIN_COL.to_owned()]]);
    drop(b_log);

    // B locks Shared: only B's view is affected.
    xlock(&b, "Lock", &[SHARED_COL]).await.unwrap();
    let err = call(&b, &grant_path, ITEM_IFACE, "GetSecret", &(bs.path.clone(),)).await.unwrap_err();
    assert_eq!(err.0, IS_LOCKED, "{err:?}");
    assert_eq!(get_secret(&host, &item_path, &hs).await.unwrap(), (b"host-secret".to_vec(), "text/plain".into()));
    let cols = collections(&host).await;
    assert!(!cols.contains(&SHARED_COL.to_owned()), "{cols:?}");
    fx.vault.set_pins(&[PASSWORD]);
    let (_, prompt) = xlock(&b, "Unlock", &[SHARED_COL]).await.unwrap();
    run_prompt(&b, &from, &prompt).await;
    assert_eq!(get_secret(&b, &grant_path, &bs).await.unwrap(), (b"host-secret".to_vec(), "text/plain".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn signals_reach_exactly_the_scopes_involved() {
    let fx = fixture(VaultState::Unlocked).await;
    let (host, item_path, item_id, hs) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), false);
    let grant_path = format!("{SHARED_COL}/{grant}");
    let b = fx.client(Some(common::service::flatpak(B))).await;
    let c = fx.client(Some(common::service::flatpak(C))).await;
    let from = fx.service_name().await;
    // A connection's principal is recorded on its first request: B and C
    // must be identified, or the signals below would have no receiver.
    collections(&b).await;
    collections(&c).await;
    let b_log = SignalLog::start(&b, &from);
    let c_log = SignalLog::start(&c, &from);

    // The owner changes the secret: B hears ItemChanged with the grant path,
    // C hears nothing.
    call(&host, &item_path, ITEM_IFACE, "SetSecret", &hs.encode(b"changed", "text/plain")).await.unwrap();
    let m = b_log.wait_for(SHARED_COL, "ItemChanged", Duration::from_secs(5)).await.expect("B's ItemChanged");
    let (p,): (zbus::zvariant::OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), grant_path);
    assert!(
        c_log.wait_for(SHARED_COL, "ItemChanged", Duration::from_millis(300)).await.is_none(),
        "C receives none of the owner's signals"
    );

    // The owner deletes: B hears ItemDeleted with the grant path.
    call(&host, &item_path, ITEM_IFACE, "Delete", &()).await.unwrap();
    let m = b_log.wait_for(SHARED_COL, "ItemDeleted", Duration::from_secs(5)).await.expect("B's ItemDeleted");
    let (p,): (zbus::zvariant::OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), grant_path);

    // A grantee with write access changes the secret: the owner hears
    // ItemChanged with the owner's item path.
    let item = create_item(&host, LOGIN_COL, &hs, "Two", &[("check", "two")], b"two", false).await.unwrap();
    let id = item.rsplit('/').next().unwrap().to_owned();
    let grant2 = share(&fx, &id, &b_scope(), true);
    let grant2_path = format!("{SHARED_COL}/{grant2}");
    let host_log = SignalLog::start(&host, &from);
    let bs = ClientSession::plain(&b).await;
    call(&b, &grant2_path, ITEM_IFACE, "SetSecret", &bs.encode(b"written", "text/plain")).await.unwrap();
    let m = host_log.wait_for(LOGIN_COL, "ItemChanged", Duration::from_secs(5)).await.expect("the owner's ItemChanged");
    let (p,): (zbus::zvariant::OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), item);

    // Share and unshare, signalled the way the admin server does it: the
    // grantee hears ItemCreated/ItemDeleted on Shared, and Collections
    // changes when Shared itself appears or disappears.
    let grant3 = share(&fx, &id, &c_scope(), false);
    fx.service.grant_changed(GrantChange {
        grantee: c_scope(),
        grant: grant3.clone(),
        created: true,
        shared_appeared: true,
        shared_disappeared: false,
    });
    let m = c_log.wait_for(SHARED_COL, "ItemCreated", Duration::from_secs(5)).await.expect("C's ItemCreated");
    let (p,): (zbus::zvariant::OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), format!("{SHARED_COL}/{grant3}"));
    let m = c_log.wait_for(SERVICE, "PropertiesChanged", Duration::from_secs(5)).await.expect("C's Collections change");
    let (iface, _changed, _invalidated): (String, HashMap<String, zbus::zvariant::OwnedValue>, Vec<String>) =
        m.body().deserialize().unwrap();
    assert_eq!(iface, "org.freedesktop.Secret.Service");
    unshare(&fx, &grant3);
    fx.service.grant_changed(GrantChange {
        grantee: c_scope(),
        grant: grant3.clone(),
        created: false,
        shared_appeared: false,
        shared_disappeared: true,
    });
    c_log.wait_for(SHARED_COL, "ItemDeleted", Duration::from_secs(5)).await.expect("C's ItemDeleted");
    // The second Collections change (the first came with the share above).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let n = c_log.names().iter().filter(|(_, _, m)| m == "PropertiesChanged").count();
        if n >= 2 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "C's second Collections change: {:?}", c_log.names());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn grants_survive_a_global_lock_and_unlock() {
    let fx = fixture(VaultState::Unlocked).await;
    let (_host, _item_path, item_id, _) = host_item(&fx).await;
    let grant = share(&fx, &item_id, &b_scope(), true);
    let grant_path = format!("{SHARED_COL}/{grant}");
    let b = fx.client(Some(common::service::flatpak(B))).await;
    let bs = ClientSession::plain(&b).await;
    assert_eq!(get_secret(&b, &grant_path, &bs).await.unwrap(), (b"host-secret".to_vec(), "text/plain".into()));

    assert!(fx.service.global_lock());
    assert!(!fx.vault.unlocked());
    // Unlocking rebuilds the index from disk; the grants must be intact.
    fx.vault.unlocker.vault().lock().unwrap().vault.as_mut().unwrap().unlock(PASSWORD.as_bytes()).unwrap();
    let all = grants(&fx);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, grant);
    assert_eq!(get_secret(&b, &grant_path, &bs).await.unwrap(), (b"host-secret".to_vec(), "text/plain".into()));
}
