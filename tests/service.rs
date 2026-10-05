//! The full Secret Service API on the encrypted store, on a private
//! bus, with `tests/support/fake-pinentry.sh` answering dialogs.
//!
//! Identity comes from a fixed table (see `common::service`); everything
//! after identification is production code.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use common::service::*;
use common::{PASSWORD, VaultFixture, VaultState};
use scopevault::identity::Principal;
use scopevault::prompts::unlock::UnlockTimings;
use scopevault::service_api::dispatch::{MAX_PROMPTS_PER_CONNECTION, MAX_SESSIONS_PER_CONNECTION};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const IS_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";
const NO_SESSION: &str = "org.freedesktop.Secret.Error.NoSession";
const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";

fn app_a() -> Principal {
    flatpak("org.example.A")
}

fn app_b() -> Principal {
    flatpak("org.example.B")
}

fn paths_of(v: OwnedValue) -> Vec<String> {
    strings(v.try_into().unwrap())
}

async fn locked_prop(c: &zbus::Connection, path: &str, iface: &str) -> bool {
    get(c, path, iface, "Locked").await.unwrap().try_into().unwrap()
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
async fn item_lifecycle_with_plain_and_dh_sessions() {
    let fx = fixture(VaultState::Unlocked).await;
    let a = fx.client(Some(app_a())).await;
    let a2 = fx.client(Some(app_a())).await;
    collections(&a2).await;
    let from = fx.service_name().await;
    let col = create_collection(&a, "Login", "default").await;

    for (n, dh) in [(0, false), (1, true)] {
        let s = if dh { ClientSession::dh(&a).await } else { ClientSession::plain(&a).await };
        let secrets: [&[u8]; 3] = [b"", "p\u{e4}ssw\u{f6}rd \u{1f511}".as_bytes(), &[0, 255, 1, 254, 0, 0, 7]];
        for (k, secret) in secrets.iter().enumerate() {
            let tag = format!("{n}-{k}");
            let log = SignalLog::start(&a2, &from);
            let item =
                create_item(&a, &col, &s, "Entry", &[("user", "alice"), ("tag", &tag)], secret, true).await.unwrap();
            assert!(item.starts_with(&format!("{col}/")), "items are children of their collection");
            assert_eq!(get_secret(&a, &item, &s).await.unwrap(), (secret.to_vec(), "text/plain".into()));
            assert!(log.wait_for(&col, "ItemCreated", Duration::from_secs(2)).await.is_some(), "{:?}", log.names());

            // Found by attributes, through the service and the collection.
            assert_eq!(search(&a, &[("tag", &tag)]).await.unwrap(), (vec![item.clone()], vec![]));
            let attrs: HashMap<&str, &str> = [("tag", tag.as_str())].into();
            let m = call(&a, &col, COL_IFACE, "SearchItems", &(attrs,)).await.unwrap();
            let (found,): (Vec<OwnedObjectPath>,) = m.body().deserialize().unwrap();
            assert_eq!(strings(found), std::slice::from_ref(&item));

            // GetSecrets: keyed by the path the client used; unknown paths skipped.
            let alias_path = item.replace("/collection/login/", "/aliases/default/");
            let m = call(
                &a,
                SERVICE,
                SVC_IFACE,
                "GetSecrets",
                &(vec![obj(&item), obj(&alias_path), obj(&format!("{col}/ffff"))], &s.path),
            )
            .await
            .unwrap();
            let (map,): (HashMap<OwnedObjectPath, WireSecret>,) = m.body().deserialize().unwrap();
            assert_eq!(map.len(), 2);
            assert_eq!(s.decode(&map[&obj(&alias_path)]).0, secret.to_vec());

            // Replacing an item with the same attributes keeps its path.
            let same =
                create_item(&a, &col, &s, "Entry", &[("user", "alice"), ("tag", &tag)], b"new", true).await.unwrap();
            assert_eq!(same, item);
            assert_eq!(get_secret(&a, &item, &s).await.unwrap().0, b"new");
            let other =
                create_item(&a, &col, &s, "Entry", &[("user", "alice"), ("tag", &tag)], b"x", false).await.unwrap();
            assert_ne!(other, item);
            call(&a, &other, ITEM_IFACE, "Delete", &()).await.unwrap();

            // SetSecret, Label, Attributes.
            call(&a, &item, ITEM_IFACE, "SetSecret", &(s.encode(secret, "application/octet-stream"),)).await.unwrap();
            assert_eq!(get_secret(&a, &item, &s).await.unwrap(), (secret.to_vec(), "application/octet-stream".into()));
            call(&a, &item, PROPS, "Set", &(ITEM_IFACE, "Label", Value::from("Renamed"))).await.unwrap();
            let label: String = get(&a, &item, ITEM_IFACE, "Label").await.unwrap().try_into().unwrap();
            assert_eq!(label, "Renamed");
            let new_attrs: HashMap<&str, &str> = [("tag", "changed")].into();
            call(&a, &item, PROPS, "Set", &(ITEM_IFACE, "Attributes", Value::from(new_attrs))).await.unwrap();
            assert_eq!(search(&a, &[("tag", &tag)]).await.unwrap().0, Vec::<String>::new());
            assert_eq!(search(&a, &[("tag", "changed")]).await.unwrap().0, std::slice::from_ref(&item));
            let e = call(&a, &item, PROPS, "Set", &(ITEM_IFACE, "Attributes", Value::from("x"))).await.unwrap_err();
            assert_eq!(e.0, "org.freedesktop.DBus.Error.InvalidArgs");

            // Delete.
            let log = SignalLog::start(&a2, &from);
            call(&a, &item, ITEM_IFACE, "Delete", &()).await.unwrap();
            assert_eq!(get_secret(&a, &item, &s).await.unwrap_err().0, UNKNOWN_OBJECT);
            assert!(!paths_of(get(&a, &col, COL_IFACE, "Items").await.unwrap()).contains(&item));
            assert!(log.wait_for(&col, "ItemDeleted", Duration::from_secs(2)).await.is_some());
        }
    }

    // Collection deletion takes its items and aliases with it.
    call(&a, &col, COL_IFACE, "Delete", &()).await.unwrap();
    assert!(collections(&a).await.is_empty());
    let m = call(&a, SERVICE, SVC_IFACE, "ReadAlias", &("default",)).await.unwrap();
    assert_eq!(m.body().deserialize::<(OwnedObjectPath,)>().unwrap().0.as_str(), "/");
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_belong_to_their_connection() {
    let fx = fixture(VaultState::Unlocked).await;
    let a1 = fx.client(Some(app_a())).await;
    let a2 = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    let col = create_collection(&a1, "Login", "").await;
    let s1 = ClientSession::plain(&a1).await;
    let item = create_item(&a1, &col, &s1, "x", &[("k", "v")], b"secret", false).await.unwrap();

    // Another connection of the *same app* cannot use a1's session either.
    let wire = s1.encode(b"forged", "text/plain");
    for c in [&a2, &b] {
        let e = call(c, &item, ITEM_IFACE, "GetSecret", &(&s1.path,)).await.unwrap_err();
        // b cannot see the item at all; a2 sees it but not the session.
        let expected = if std::ptr::eq(c, &a2) { NO_SESSION } else { UNKNOWN_OBJECT };
        assert_eq!(e.0, expected);
        let e = call(c, SERVICE, SVC_IFACE, "GetSecrets", &(vec![obj(&item)], &s1.path)).await.unwrap_err();
        assert_eq!(e.0, NO_SESSION);
        let e = call(c, &s1.path, "org.freedesktop.Secret.Session", "Close", &()).await.unwrap_err();
        assert_eq!(e.0, UNKNOWN_OBJECT);
        assert!(introspect_children(c, "/org/freedesktop/secrets/session").await.unwrap().is_empty());
    }
    let mut props: HashMap<&str, Value> = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Value::from("forged"));
    let e = call(&a2, &col, COL_IFACE, "CreateItem", &(props, wire, false)).await.unwrap_err();
    assert_eq!(e.0, NO_SESSION);
    let e = call(&a2, &item, ITEM_IFACE, "GetSecret", &(obj("/not/a/session"),)).await.unwrap_err();
    assert_eq!(e.0, NO_SESSION);
    assert_eq!(get_secret(&a1, &item, &s1).await.unwrap().0, b"secret");

    // Closing ends the session.
    call(&a1, &s1.path, "org.freedesktop.Secret.Session", "Close", &()).await.unwrap();
    assert_eq!(get_secret(&a1, &item, &s1).await.unwrap_err().0, NO_SESSION);

    // Unsupported algorithms and malformed DH input.
    let e = call(&a1, SERVICE, SVC_IFACE, "OpenSession", &("rot13", Value::from(""))).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.NotSupported");
    let e =
        call(&a1, SERVICE, SVC_IFACE, "OpenSession", &("dh-ietf1024-sha256-aes128-cbc-pkcs7", Value::from(vec![1u8])))
            .await
            .unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.InvalidArgs");

    // Sessions per connection are limited.
    let mut open = Vec::new();
    for _ in 0..MAX_SESSIONS_PER_CONNECTION {
        open.push(ClientSession::plain(&a2).await);
    }
    let e = call(&a2, SERVICE, SVC_IFACE, "OpenSession", &("plain", Value::from(""))).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.LimitsExceeded");
    assert_eq!(introspect_children(&a2, "/org/freedesktop/secrets/session").await.unwrap().len(), open.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_objects_inside_arrays_are_ignored() {
    let fx = fixture(VaultState::Unlocked).await;
    let a = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    let col_a = create_collection(&a, "Alpha Keys", "").await;
    let col_b = create_collection(&b, "Beta Keys", "").await;
    let sa = ClientSession::plain(&a).await;
    let sb = ClientSession::plain(&b).await;
    let item_a = create_item(&a, &col_a, &sa, "a", &[("k", "v")], b"alpha", false).await.unwrap();
    let item_b = create_item(&b, &col_b, &sb, "b", &[("k", "v")], b"beta", false).await.unwrap();

    // Identical attributes: each app finds only its own item.
    assert_eq!(search(&a, &[("k", "v")]).await.unwrap().0, std::slice::from_ref(&item_a));
    assert_eq!(search(&b, &[("k", "v")]).await.unwrap().0, std::slice::from_ref(&item_b));

    let m = call(&b, SERVICE, SVC_IFACE, "GetSecrets", &(vec![obj(&item_a), obj(&item_b)], &sb.path)).await.unwrap();
    let (map,): (HashMap<OwnedObjectPath, WireSecret>,) = m.body().deserialize().unwrap();
    assert_eq!(map.keys().map(|k| k.to_string()).collect::<Vec<_>>(), std::slice::from_ref(&item_b));
    assert_eq!(sb.decode(&map[&obj(&item_b)]).0, b"beta");

    assert_eq!(xlock(&b, "Lock", &[&col_a, &item_a]).await.unwrap(), (vec![], "/".into()));
    assert!(!locked_prop(&a, &col_a, COL_IFACE).await, "B must not lock A's collection");
    assert_eq!(xlock(&b, "Unlock", &[&col_a, &item_a]).await.unwrap(), (vec![], "/".into()));
    assert_eq!(get_secret(&a, &item_a, &sa).await.unwrap().0, b"alpha");

    // Mixed arrays: B's own objects are handled, A's are not mentioned.
    assert_eq!(xlock(&b, "Lock", &[&item_a, &item_b]).await.unwrap(), (vec![item_b.clone()], "/".into()));
    assert!(locked_prop(&b, &col_b, COL_IFACE).await);
    assert!(!locked_prop(&a, &col_a, COL_IFACE).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn logical_lock_affects_one_collection_and_needs_the_password_again() {
    let fx = fixture(VaultState::Unlocked).await;
    let a = fx.client(Some(app_a())).await;
    let a2 = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    collections(&a2).await;
    let from = fx.service_name().await;
    let sa = ClientSession::plain(&a).await;
    let sb = ClientSession::plain(&b).await;
    let work = create_collection(&a, "Work", "").await;
    let home = create_collection(&a, "Home", "").await;
    let col_b = create_collection(&b, "Work", "").await;
    assert_eq!(work, col_b, "same readable path in two scopes");
    let item = create_item(&a, &work, &sa, "w", &[("k", "v")], b"work secret", false).await.unwrap();
    let home_item = create_item(&a, &home, &sa, "h", &[("k", "v")], b"home secret", false).await.unwrap();
    let item_b = create_item(&b, &col_b, &sb, "b", &[("k", "v")], b"b secret", false).await.unwrap();

    let log = SignalLog::start(&a2, &from);
    assert_eq!(xlock(&a, "Lock", &[&work]).await.unwrap(), (vec![work.clone()], "/".into()));
    assert!(log.wait_for(&work, "PropertiesChanged", Duration::from_secs(2)).await.is_some());
    // Each item's Locked changes too; libsecret caches it per item.
    assert!(log.wait_for(&item, "PropertiesChanged", Duration::from_secs(2)).await.is_some());
    let item_locked = |log: &SignalLog, item: &str| -> Vec<bool> {
        log.changed_values(item, "Locked").into_iter().map(|v| v.try_into().unwrap()).collect()
    };
    assert_eq!(item_locked(&log, &item), [true]);
    assert!(item_locked(&log, &home_item).is_empty());
    assert!(locked_prop(&a, &work, COL_IFACE).await);
    assert!(locked_prop(&a, &item, ITEM_IFACE).await);
    assert_eq!(get_secret(&a, &item, &sa).await.unwrap_err().0, IS_LOCKED);
    assert_eq!(search(&a, &[("k", "v")]).await.unwrap(), (vec![home_item.clone()], vec![item.clone()]));
    let m = call(&a, SERVICE, SVC_IFACE, "GetSecrets", &(vec![obj(&item), obj(&home_item)], &sa.path)).await.unwrap();
    assert_eq!(m.body().deserialize::<(HashMap<OwnedObjectPath, WireSecret>,)>().unwrap().0.len(), 1);
    assert_eq!(create_item(&a, &work, &sa, "n", &[], b"n", false).await.unwrap_err().0, IS_LOCKED);
    let e = call(&a, &item, ITEM_IFACE, "SetSecret", &(sa.encode(b"x", "text/plain"),)).await.unwrap_err();
    assert_eq!(e.0, IS_LOCKED);

    // The other collection of the same app and the other app are unaffected.
    assert_eq!(get_secret(&a, &home_item, &sa).await.unwrap().0, b"home secret");
    assert!(!locked_prop(&b, &col_b, COL_IFACE).await);
    assert_eq!(get_secret(&b, &item_b, &sb).await.unwrap().0, b"b secret");

    // Unlocking returns what is already open and a prompt for the rest.
    let (open, prompt) = xlock(&a, "Unlock", &[&item, &home]).await.unwrap();
    assert_eq!(open, std::slice::from_ref(&home));
    assert_ne!(prompt, "/");
    fx.vault.set_pins(&["CANCEL"]);
    let (dismissed, result) = run_prompt(&a, &from, &prompt).await;
    assert!(dismissed);
    assert!(paths_of(result).is_empty());
    assert!(locked_prop(&a, &work, COL_IFACE).await);

    let (_, prompt) = xlock(&a, "Unlock", &[&item, &home]).await.unwrap();
    fx.vault.set_pins(&["wrong", PASSWORD]);
    let (dismissed, result) = run_prompt(&a, &from, &prompt).await;
    assert!(!dismissed);
    assert_eq!(paths_of(result), [home.clone(), item.clone()]);
    for _ in 0..100 {
        if item_locked(&log, &item).len() > 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(item_locked(&log, &item), [true, false]);
    assert!(item_locked(&log, &home_item).is_empty());
    assert!(!locked_prop(&a, &work, COL_IFACE).await);
    assert_eq!(get_secret(&a, &item, &sa).await.unwrap().0, b"work secret");
    assert!(fx.vault.log().contains("locked collections"), "the confirmation dialog explains itself");
    // One pinentry run per attempt: cancel, wrong, right.
    assert_eq!(fx.vault.dialogs(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_vault_unlocks_on_demand() {
    let fx = fixture(VaultState::Locked).await;
    let a = fx.client(Some(app_a())).await;
    fx.vault.set_pins(&[PASSWORD]);
    // A request that needs the vault opens the shared dialog and waits.
    assert_eq!(search(&a, &[("k", "v")]).await.unwrap(), (vec![], vec![]));
    assert!(fx.vault.unlocked());
    assert_eq!(fx.vault.dialogs(), 1);
    assert!(fx.vault.log().contains("org.example.A"), "the dialog names the requesting app");
}

/// A request that waited for the unlock while a global lock lands right
/// after it is told the vault is locked, not that its object is missing.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_right_after_the_unlock_is_not_a_missing_object() {
    let fx = fixture(VaultState::Unlocked).await;
    let a = fx.client(Some(app_a())).await;
    let s = ClientSession::plain(&a).await;
    let item = create_item(&a, "/org/freedesktop/secrets/aliases/default", &s, "i", &[], b"x", false).await.unwrap();
    fx.vault.lock_vault();
    // Locks again as soon as a dialog has unlocked the vault, before the
    // requests that waited for it go on.
    let mut unlocked = fx.vault.unlocker.subscribe_unlocked();
    let unlocker = fx.vault.unlocker.clone();
    let relock = tokio::spawn(async move {
        while unlocked.recv().await.is_ok() {
            if let Some(v) = unlocker.vault().lock().unwrap().vault.as_mut() {
                v.lock();
            }
        }
    });
    fx.vault.set_pins(&[PASSWORD; 4]);
    let mut raced = 0;
    for _ in 0..4 {
        let mut clients = Vec::new();
        for _ in 0..4 {
            clients.push(fx.client(Some(app_a())).await);
        }
        let reads = clients.iter().map(|c| get(c, &item, ITEM_IFACE, "Label"));
        for r in futures_util::future::join_all(reads).await {
            if let Err(e) = r {
                assert_eq!(e.0, IS_LOCKED, "{e:?}");
                raced += 1;
            }
        }
    }
    relock.abort();
    assert!(raced > 0, "no request met the lock");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_vault_is_created_on_first_use() {
    let fx = fixture(VaultState::Missing).await;
    let host = fx.client(Some(Principal::Host)).await;
    fx.vault.set_pins(&["new password"]);
    assert_eq!(collections(&host).await, ["/org/freedesktop/secrets/collection/login"]);
    assert!(fx.vault.unlocked());
    assert!(fx.vault.log().contains("SETREPEAT"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_unlock_makes_requests_wait_without_new_dialogs() {
    let fx = fixture(VaultState::Locked).await;
    let a = fx.client(Some(app_a())).await;
    fx.vault.set_pins(&["CANCEL"]);
    // The request waits out the fixture's 1 s implicit deadline instead of
    // failing at once, and exactly one dialog was shown.
    let started = std::time::Instant::now();
    assert_eq!(search(&a, &[]).await.unwrap_err().0, IS_LOCKED);
    assert!(started.elapsed() >= Duration::from_millis(800), "{:?}", started.elapsed());
    assert_eq!(fx.vault.dialogs(), 1);
    // Requests made during the cooldown wait, without another dialog.
    for _ in 0..2 {
        let started = std::time::Instant::now();
        assert_eq!(get(&a, SERVICE, SVC_IFACE, "Collections").await.unwrap_err().0, IS_LOCKED);
        assert!(started.elapsed() >= Duration::from_millis(800), "{:?}", started.elapsed());
        assert_eq!(call(&a, SERVICE, SVC_IFACE, "ReadAlias", &("default",)).await.unwrap_err().0, IS_LOCKED);
    }
    assert_eq!(fx.vault.dialogs(), 1);
    // CreateItem and Lock still answer at once without a dialog.
    let s = ClientSession::plain(&a).await;
    let e = create_item(&a, "/org/freedesktop/secrets/aliases/default", &s, "x", &[], b"x", true).await.unwrap_err();
    assert_eq!(e.0, IS_LOCKED);
    let started = std::time::Instant::now();
    assert_eq!(xlock(&a, "Lock", &["/org/freedesktop/secrets/aliases/default"]).await.unwrap(), (vec![], "/".into()));
    assert!(started.elapsed() < Duration::from_millis(800), "{:?}", started.elapsed());
    assert_eq!(fx.vault.dialogs(), 1);
    assert!(!fx.vault.unlocked());

    // An explicit Unlock prompt is not subject to the cooldown.
    let (open, prompt) = xlock(&a, "Unlock", &["/org/freedesktop/secrets/aliases/default"]).await.unwrap();
    assert!(open.is_empty());
    fx.vault.set_pins(&[PASSWORD]);
    let (dismissed, result) = run_prompt(&a, &fx.service_name().await, &prompt).await;
    assert!(!dismissed);
    assert_eq!(paths_of(result), ["/org/freedesktop/secrets/collection/login"], "the scope's own login collection");
    assert!(fx.vault.unlocked());
    assert_eq!(fx.vault.dialogs(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_waiting_during_the_cooldown_is_served_by_a_later_unlock() {
    let timings = UnlockTimings { implicit_wait: Duration::from_secs(10), ..UnlockTimings::default() };
    let fx = fixture_with(VaultFixture::with_timings(VaultState::Locked, timings)).await;
    let a = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    // B's request joins the dialog, which is cancelled, and keeps waiting.
    fx.vault.set_pins(&["CANCEL", PASSWORD]);
    let started = std::time::Instant::now();
    let waiting = tokio::spawn(async move { search(&b, &[]).await });
    while fx.vault.dialogs() == 0 || !fx.vault.log().contains("GETPIN") {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished(), "B's request must outlast the cancelled dialog");

    // A's explicit Unlock (a connection of its own: calls of one connection
    // are handled in order) unlocks the vault, which serves B too.
    let (_, prompt) = xlock(&a, "Unlock", &["/org/freedesktop/secrets/aliases/default"]).await.unwrap();
    let (dismissed, _) = run_prompt(&a, &fx.service_name().await, &prompt).await;
    assert!(!dismissed);
    let found = tokio::time::timeout(Duration::from_secs(10), waiting).await.unwrap().unwrap();
    assert!(found.is_ok(), "{found:?}");
    assert!(started.elapsed() < Duration::from_secs(9), "served by the unlock, not the deadline");
    assert_eq!(fx.vault.dialogs(), 2);
}

/// The sequence libsecret's `secret_password_store` performs against a
/// locked keyring (`secret-methods.c`, `on_store_create`).
#[tokio::test(flavor = "multi_thread")]
async fn libsecret_store_sequence_on_a_locked_vault() {
    let fx = fixture(VaultState::Unlocked).await;
    let from = fx.service_name().await;
    let host = fx.client(Some(Principal::Host)).await;
    let watcher = fx.client(Some(Principal::Host)).await;
    let col = create_collection(&host, "Default keyring", "default").await;
    let s = ClientSession::dh(&host).await;
    create_item(&host, &col, &s, "old", &[("service", "mail")], b"old", true).await.unwrap();
    collections(&watcher).await;
    fx.vault.lock_vault();

    let default = "/org/freedesktop/secrets/aliases/default";
    let e = create_item(&host, default, &s, "new", &[("service", "mail")], b"new", true).await.unwrap_err();
    assert_eq!(e.0, IS_LOCKED);
    let (open, prompt) = xlock(&host, "Unlock", &[default]).await.unwrap();
    assert!(open.is_empty());
    let log = SignalLog::start(&watcher, &from);
    fx.vault.set_pins(&[PASSWORD]);
    let (dismissed, result) = run_prompt(&host, &from, &prompt).await;
    assert!(!dismissed);
    assert_eq!(paths_of(result), std::slice::from_ref(&col), "canonical path of the aliased collection");
    // Other connections of the scope learn that its collections are back.
    assert!(log.wait_for(SERVICE, "PropertiesChanged", Duration::from_secs(2)).await.is_some());

    // Transfer sessions survive a vault lock; the retry succeeds.
    let item = create_item(&host, default, &s, "new", &[("service", "mail")], b"new", true).await.unwrap();
    assert_eq!(get_secret(&host, &item, &s).await.unwrap().0, b"new");
    assert_eq!(search(&host, &[("service", "mail")]).await.unwrap().0.len(), 1, "replaced, not added");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_collection_on_a_locked_vault_uses_a_prompt() {
    let fx = fixture(VaultState::Locked).await;
    let from = fx.service_name().await;
    let a = fx.client(Some(app_a())).await;
    let (col, prompt) = try_create_collection(&a, "Work", "").await.unwrap();
    assert_eq!(col, "/");
    assert_eq!(fx.vault.dialogs(), 0, "no dialog before Prompt()");
    fx.vault.set_pins(&[PASSWORD]);
    let (dismissed, result) = run_prompt(&a, &from, &prompt).await;
    assert!(!dismissed);
    let path: OwnedObjectPath = result.try_into().unwrap();
    assert_eq!(path.as_str(), "/org/freedesktop/secrets/collection/work");
    assert_eq!(collections(&a).await, ["/org/freedesktop/secrets/collection/login".to_owned(), path.to_string()]);
    // The prompt is gone once completed.
    let e = call(&a, &prompt, PROMPT_IFACE, "Prompt", &("",)).await.unwrap_err();
    assert_eq!(e.0, UNKNOWN_OBJECT);
}

#[tokio::test(flavor = "multi_thread")]
async fn prompts_belong_to_their_connection_and_complete_only_there() {
    let fx = fixture(VaultState::Locked).await;
    let from = fx.service_name().await;
    let a1 = fx.client(Some(app_a())).await;
    let a2 = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    for c in [&a2, &b] {
        ClientSession::plain(c).await; // identified, so eligible for signals
    }
    let (_, prompt) = xlock(&a1, "Unlock", &["/org/freedesktop/secrets/aliases/default"]).await.unwrap();
    for c in [&a2, &b] {
        for m in ["Prompt", "Dismiss"] {
            let e = if m == "Prompt" {
                call(c, &prompt, PROMPT_IFACE, m, &("",)).await
            } else {
                call(c, &prompt, PROMPT_IFACE, m, &()).await
            };
            assert_eq!(e.unwrap_err().0, UNKNOWN_OBJECT);
        }
        assert!(introspect_children(c, "/org/freedesktop/secrets/prompt").await.unwrap().is_empty());
    }
    assert_eq!(introspect_children(&a1, "/org/freedesktop/secrets/prompt").await.unwrap().len(), 1);

    let logs = [SignalLog::start(&a2, &from), SignalLog::start(&b, &from)];
    fx.vault.set_pins(&[PASSWORD]);
    let (dismissed, _) = run_prompt(&a1, &from, &prompt).await;
    assert!(!dismissed);
    tokio::time::sleep(Duration::from_millis(300)).await;
    for log in &logs {
        assert!(log.find(&prompt, "Completed").is_none(), "{:?}", log.names());
    }

    // Pending prompts per connection are limited.
    fx.vault.lock_vault();
    for _ in 0..MAX_PROMPTS_PER_CONNECTION {
        xlock(&a1, "Unlock", &["/org/freedesktop/secrets/aliases/x"]).await.unwrap();
    }
    let e = xlock(&a1, "Unlock", &["/org/freedesktop/secrets/aliases/x"]).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.LimitsExceeded");
}

/// An `Unlock` prompt keeps only the distinct paths that can name an
/// object, and a scope's pending prompts hold a bounded number of them, so
/// an app cannot make the daemon keep every request it sends.
#[tokio::test(flavor = "multi_thread")]
async fn unlock_prompts_hold_a_bounded_set_of_paths() {
    use scopevault::service_api::dispatch::MAX_UNLOCK_PATHS_PER_SCOPE;
    let fx = fixture(VaultState::Locked).await;
    let a1 = fx.client(Some(app_a())).await;
    let a2 = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    let collections =
        |n: usize| (0..n).map(|n| format!("/org/freedesktop/secrets/collection/c{n}")).collect::<Vec<_>>();
    fn as_strs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    // Repeated and invalid paths are not kept: one path held.
    let mut objects = vec!["/"; 100_000];
    objects.extend(["/org/freedesktop/secrets/aliases/default"; 10_000]);
    let (_, first) = xlock(&a1, "Unlock", &objects).await.unwrap();
    assert_ne!(first, "/");
    // Nothing that can name an object: no prompt.
    let none = ["/", "/org/freedesktop/secrets/session/s1", "/org/freedesktop/secrets/collection"];
    assert_eq!(xlock(&a1, "Unlock", &none).await.unwrap(), (vec![], "/".into()));

    // The scope's other connection may add up to the limit, not past it.
    let fill = collections(MAX_UNLOCK_PATHS_PER_SCOPE - 1);
    let (_, prompt) = xlock(&a2, "Unlock", &as_strs(&fill)).await.unwrap();
    assert_ne!(prompt, "/");
    let e = xlock(&a2, "Unlock", &["/org/freedesktop/secrets/collection/more"]).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.LimitsExceeded", "{e:?}");

    // Another scope is not affected.
    let (_, prompt) = xlock(&b, "Unlock", &as_strs(&collections(MAX_UNLOCK_PATHS_PER_SCOPE))).await.unwrap();
    assert_ne!(prompt, "/");

    // Completed prompts no longer count.
    call(&a1, &first, PROMPT_IFACE, "Dismiss", &()).await.unwrap();
    let (_, prompt) = xlock(&a2, "Unlock", &["/org/freedesktop/secrets/collection/more"]).await.unwrap();
    assert_ne!(prompt, "/");
}

#[tokio::test(flavor = "multi_thread")]
async fn dismissing_a_prompt_closes_its_dialog() {
    let fx = fixture(VaultState::Locked).await;
    let from = fx.service_name().await;
    let a = fx.client(Some(app_a())).await;

    // Dismissed before Prompt(): typed empty result, no dialog.
    let (_, prompt) = try_create_collection(&a, "Work", "").await.unwrap();
    let log = SignalLog::start(&a, &from);
    call(&a, &prompt, PROMPT_IFACE, "Dismiss", &()).await.unwrap();
    let m = log.wait_for(&prompt, "Completed", Duration::from_secs(2)).await.unwrap();
    let (dismissed, result): (bool, OwnedValue) = m.body().deserialize().unwrap();
    assert!(dismissed);
    assert_eq!(OwnedObjectPath::try_from(result).unwrap().as_str(), "/");

    // Dismissed while the dialog is open: the dialog goes away.
    fx.vault.set_pins(&["HANG"]);
    let (_, prompt) = xlock(&a, "Unlock", &["/org/freedesktop/secrets/aliases/default"]).await.unwrap();
    call(&a, &prompt, PROMPT_IFACE, "Prompt", &("",)).await.unwrap();
    let pid = dialog_waiting(&fx.vault, 1).await;
    call(&a, &prompt, PROMPT_IFACE, "Dismiss", &()).await.unwrap();
    let m = log.wait_for(&prompt, "Completed", Duration::from_secs(2)).await.unwrap();
    let (dismissed, result): (bool, OwnedValue) = m.body().deserialize().unwrap();
    assert!(dismissed);
    assert!(paths_of(result).is_empty());
    assert!(process_gone(pid).await, "pinentry still running after Dismiss");
    assert!(!fx.vault.unlocked());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_owner_disconnecting_closes_its_dialog() {
    let fx = fixture(VaultState::Locked).await;
    let a = fx.client(Some(app_a())).await;
    fx.vault.set_pins(&["HANG"]);
    let (_, prompt) = xlock(&a, "Unlock", &["/org/freedesktop/secrets/aliases/default"]).await.unwrap();
    call(&a, &prompt, PROMPT_IFACE, "Prompt", &("",)).await.unwrap();
    let pid = dialog_waiting(&fx.vault, 1).await;
    assert!(Path::new(&format!("/proc/{pid}")).exists());
    a.close().await.unwrap();
    assert!(process_gone(pid).await, "pinentry still running after its requester left");
    assert!(!fx.vault.unlocked());
}

/// A client that disconnects while its request waits for the unlock dialog:
/// the wait ends (closing the dialog, since nobody else waits), and requests
/// it had queued behind it are dropped rather than run for a connection that
/// no longer exists.
#[tokio::test(flavor = "multi_thread")]
async fn a_departed_connection_leaves_no_dialog_or_state_behind() {
    let fx = fixture(VaultState::Locked).await;
    let a = fx.client(Some(app_a())).await;
    let watcher = fx.client(Some(app_a())).await;
    fx.vault.set_pins(&["HANG"]);
    let waiting = {
        let a = a.clone();
        tokio::spawn(async move { search(&a, &[("k", "v")]).await })
    };
    let pid = dialog_waiting(&fx.vault, 1).await;
    // Queued behind the waiting search; sent without waiting for replies.
    for _ in 0..3 {
        let m = zbus::message::Message::method_call(SERVICE, "OpenSession")
            .unwrap()
            .destination(DEST)
            .unwrap()
            .interface(SVC_IFACE)
            .unwrap()
            .build(&("plain", Value::from("")))
            .unwrap();
        a.send(&m).await.unwrap();
    }
    let alias = "/org/freedesktop/secrets/aliases/default";
    let m = zbus::message::Message::method_call(SERVICE, "Unlock")
        .unwrap()
        .destination(DEST)
        .unwrap()
        .interface(SVC_IFACE)
        .unwrap()
        .build(&(vec![obj(alias)],))
        .unwrap();
    a.send(&m).await.unwrap();
    a.close().await.unwrap();
    waiting.abort();

    assert!(process_gone(pid).await, "pinentry still running after its only requester left");
    for _ in 0..100 {
        if fx.service.active_connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Give a (wrongly) surviving worker time to run the queued requests.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fx.service.open_sessions(), 0);
    assert_eq!(fx.service.pending_prompts(), 0);
    assert_eq!(fx.service.active_connections(), 0);
    assert_eq!(fx.vault.dialogs(), 1);
    // The service still works for others: a later request gets a new dialog.
    fx.vault.set_pins(&[PASSWORD]);
    assert!(search(&watcher, &[("k", "v")]).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_collection_lives_in_memory_only() {
    let fx = fixture(VaultState::Unlocked).await;
    let a = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    let col = create_collection(&a, "Temporary", "session").await;
    assert_eq!(col, "/org/freedesktop/secrets/collection/session");
    let s = ClientSession::plain(&a).await;
    let item = create_item(&a, "/org/freedesktop/secrets/aliases/session", &s, "t", &[("k", "v")], b"temp", false)
        .await
        .unwrap();
    assert_eq!(get_secret(&a, &item, &s).await.unwrap().0, b"temp");
    let m = call(&b, SERVICE, SVC_IFACE, "ReadAlias", &("session",)).await.unwrap();
    assert_eq!(m.body().deserialize::<(OwnedObjectPath,)>().unwrap().0.as_str(), "/", "per scope");

    // Gone after a global lock and unlock.
    fx.vault.lock_vault();
    fx.vault.set_pins(&[PASSWORD]);
    assert_eq!(collections(&a).await, ["/org/freedesktop/secrets/collection/login"]);
    assert_eq!(get_secret(&a, &item, &s).await.unwrap_err().0, UNKNOWN_OBJECT);
}

/// Cryptomator's Secret Service library (`purejava/secret-service`, used by
/// cryptomator/integrations-linux 1.7.0) never creates a collection: it
/// expects `default`, or else `/collection/login`, to exist, as with
/// gnome-keyring.
#[tokio::test(flavor = "multi_thread")]
async fn each_scope_starts_with_a_login_collection() {
    let fx = fixture(VaultState::Unlocked).await;
    let a = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    let login = "/org/freedesktop/secrets/collection/login";
    let default = "/org/freedesktop/secrets/aliases/default";
    let m = call(&a, SERVICE, SVC_IFACE, "ReadAlias", &("default",)).await.unwrap();
    assert_eq!(m.body().deserialize::<(OwnedObjectPath,)>().unwrap().0.as_str(), login);
    let label: String = get(&a, default, COL_IFACE, "Label").await.unwrap().try_into().unwrap();
    assert_eq!(label, "Login");

    // Cryptomator's storePassphrase, then loadPassphrase after a restart.
    let attrs = HashMap::from([("Vault", "v1")]);
    let found = |c: &zbus::Connection| {
        let (c, attrs) = (c.clone(), attrs.clone());
        async move {
            let m = call(&c, default, COL_IFACE, "SearchItems", &(attrs,)).await.unwrap();
            strings(m.body().deserialize::<(Vec<OwnedObjectPath>,)>().unwrap().0)
        }
    };
    assert!(found(&a).await.is_empty());
    assert_eq!(xlock(&a, "Unlock", &[default]).await.unwrap(), (vec![login.to_owned()], "/".into()));
    let s = ClientSession::dh(&a).await;
    let item =
        create_item(&a, default, &s, "Cryptomator", &[("Vault", "v1"), ("Name", "test")], b"pw", false).await.unwrap();
    fx.vault.lock_vault();
    fx.vault.set_pins(&[PASSWORD]);
    assert_eq!(found(&a).await, std::slice::from_ref(&item));
    let s = ClientSession::dh(&a).await;
    assert_eq!(get_secret(&a, &item, &s).await.unwrap().0, b"pw");
    // B has its own, empty, login collection under the same path.
    assert!(found(&b).await.is_empty());

    // A scope that deletes its login collection does not get it back.
    call(&b, login, COL_IFACE, "Delete", &()).await.unwrap();
    assert!(collections(&b).await.is_empty());
    fx.vault.lock_vault();
    fx.vault.set_pins(&[PASSWORD]);
    assert!(collections(&b).await.is_empty());
    let m = call(&b, SERVICE, SVC_IFACE, "ReadAlias", &("default",)).await.unwrap();
    assert_eq!(m.body().deserialize::<(OwnedObjectPath,)>().unwrap().0.as_str(), "/");
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_and_excess_queued_requests_are_refused() {
    use scopevault::service_api::dispatch::{MAX_QUEUED_BYTES, MAX_REQUEST_BYTES};
    let fx = fixture(VaultState::Locked).await;
    let a = fx.client(Some(app_a())).await;
    let e = search(&a, &[("k", &"x".repeat(MAX_REQUEST_BYTES))]).await.unwrap_err();
    assert_eq!(e, ("org.freedesktop.DBus.Error.LimitsExceeded".into(), "Request too large".into()));

    // Requests queue up behind one waiting for the dialog. Big ones from
    // several connections exhaust the shared budget; then the rest are
    // refused at once instead of being held in memory.
    fx.vault.set_pins(&["HANG"]);
    let big = "x".repeat(MAX_REQUEST_BYTES - 4096);
    let per_conn = 20;
    let conns = MAX_QUEUED_BYTES / (per_conn * big.len()) + 1;
    let mut pending = Vec::new();
    for _ in 0..conns {
        let c = fx.client(Some(app_a())).await;
        for _ in 0..per_conn {
            let c = c.clone();
            let big = big.clone();
            pending.push(tokio::spawn(async move {
                let attrs: HashMap<&str, &str> = [("k", big.as_str())].into();
                match c.call_method(Some(DEST), SERVICE, Some(SVC_IFACE), "SearchItems", &(attrs,)).await {
                    Ok(_) => "ok".to_owned(),
                    Err(zbus::Error::MethodError(n, msg, _)) => format!("{n}: {}", msg.unwrap_or_default()),
                    Err(other) => format!("transport: {other}"),
                }
            }));
        }
    }
    dialog_waiting(&fx.vault, 1).await;
    // Everything beyond the budget is answered while the dialog is still up.
    let mut refused = 0;
    for _ in 0..250 {
        refused = pending.iter().filter(|t| t.is_finished()).count();
        if refused > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(refused > 0, "nothing was refused");
    let pid = fx.vault.pinentry_pid().unwrap();
    rustix::process::kill_process(rustix::process::Pid::from_raw(pid).unwrap(), rustix::process::Signal::KILL).unwrap();
    let mut outcomes: HashMap<String, usize> = HashMap::new();
    for t in pending {
        *outcomes.entry(t.await.unwrap()).or_default() += 1;
    }
    assert!(
        outcomes.get("org.freedesktop.DBus.Error.LimitsExceeded: Too many requests").copied().unwrap_or(0) >= 1,
        "{outcomes:?}"
    );
    assert!(outcomes.keys().all(|k| k.starts_with("org.freedesktop")), "{outcomes:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unidentified_connections_hold_no_slots_and_scopes_have_a_cap() {
    use scopevault::service_api::dispatch::MAX_CONNECTIONS_PER_SCOPE;
    let fx = fixture(VaultState::Unlocked).await;
    let mut strangers = Vec::new();
    for _ in 0..40 {
        let c = fx.client(None).await;
        let e = call(&c, SERVICE, "org.freedesktop.DBus.Peer", "Ping", &()).await.unwrap_err();
        assert_eq!(e.0, "org.freedesktop.DBus.Error.AccessDenied");
        strangers.push(c);
    }
    for _ in 0..100 {
        if fx.service.active_connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fx.service.active_connections(), 0, "denied connections are not tracked while idle");
    // Still denied on their next request.
    let e = call(&strangers[0], SERVICE, "org.freedesktop.DBus.Peer", "Ping", &()).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.AccessDenied");

    let mut a = Vec::new();
    for _ in 0..MAX_CONNECTIONS_PER_SCOPE {
        let c = fx.client(Some(app_a())).await;
        collections(&c).await;
        a.push(c);
    }
    let extra = fx.client(Some(app_a())).await;
    let e = call(&extra, SERVICE, PROPS, "Get", &(SVC_IFACE, "Collections")).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.LimitsExceeded");
    // Refused connections keep no slot of the global limit while idle.
    let mut refused = Vec::new();
    for _ in 0..20 {
        let c = fx.client(Some(app_a())).await;
        let e = call(&c, SERVICE, PROPS, "Get", &(SVC_IFACE, "Collections")).await.unwrap_err();
        assert_eq!(e.0, "org.freedesktop.DBus.Error.LimitsExceeded");
        refused.push(c);
    }
    for _ in 0..100 {
        if fx.service.active_connections() == MAX_CONNECTIONS_PER_SCOPE {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fx.service.active_connections(), MAX_CONNECTIONS_PER_SCOPE, "refused connections are not tracked");
    // Other scopes are unaffected.
    let b = fx.client(Some(app_b())).await;
    collections(&b).await;
    // Room again once one of A's connections leaves.
    a.pop().unwrap().close().await.unwrap();
    for _ in 0..100 {
        if call(&extra, SERVICE, PROPS, "Get", &(SVC_IFACE, "Collections")).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("a slot did not free up");
}

/// An app whose dialogs keep being cancelled cannot reopen them at once
/// through new prompts; another app still gets its dialog.
#[tokio::test(flavor = "multi_thread")]
async fn repeatedly_cancelled_prompts_stop_showing_dialogs_for_that_app() {
    use scopevault::prompts::unlock::EXPLICIT_REFUSAL_LIMIT;
    let fx = fixture(VaultState::Locked).await;
    let from = fx.service_name().await;
    let a = fx.client(Some(app_a())).await;
    let b = fx.client(Some(app_b())).await;
    let alias = "/org/freedesktop/secrets/aliases/default";
    fx.vault.set_pins(&["CANCEL"; EXPLICIT_REFUSAL_LIMIT]);
    for n in 1..=EXPLICIT_REFUSAL_LIMIT {
        let (_, prompt) = xlock(&a, "Unlock", &[alias]).await.unwrap();
        let (dismissed, _) = run_prompt(&a, &from, &prompt).await;
        assert!(dismissed);
        assert_eq!(fx.vault.dialogs(), n);
    }
    // Over the limit: dismissed without a dialog, for A only.
    let (_, prompt) = xlock(&a, "Unlock", &[alias]).await.unwrap();
    let (dismissed, result) = run_prompt(&a, &from, &prompt).await;
    assert!(dismissed);
    assert!(paths_of(result).is_empty());
    assert_eq!(fx.vault.dialogs(), EXPLICIT_REFUSAL_LIMIT);
    fx.vault.set_pins(&[PASSWORD]);
    let (_, prompt) = xlock(&b, "Unlock", &[alias]).await.unwrap();
    let (dismissed, _) = run_prompt(&b, &from, &prompt).await;
    assert!(!dismissed);
    assert_eq!(fx.vault.dialogs(), EXPLICIT_REFUSAL_LIMIT + 1);
    assert!(fx.vault.unlocked());
}

/// Prompts run at the same time on a collection the app locked itself
/// show no more dialogs than the refusal limit allows: the limit is checked
/// when each dialog's turn comes, not when its prompt starts waiting.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_prompts_keep_to_the_refusal_limit() {
    use scopevault::prompts::unlock::EXPLICIT_REFUSAL_LIMIT;
    let fx = fixture(VaultState::Unlocked).await;
    let from = fx.service_name().await;
    let a = fx.client(Some(app_a())).await;
    let alias = "/org/freedesktop/secrets/aliases/default";
    xlock(&a, "Lock", &[alias]).await.unwrap();
    fx.vault.set_pins(&["CANCEL"; MAX_PROMPTS_PER_CONNECTION]);
    let mut prompts = Vec::new();
    for _ in 0..MAX_PROMPTS_PER_CONNECTION {
        let (_, prompt) = xlock(&a, "Unlock", &[alias]).await.unwrap();
        assert_ne!(prompt, "/");
        prompts.push(prompt);
    }
    let results = futures_util::future::join_all(prompts.iter().map(|p| run_prompt(&a, &from, p))).await;
    assert!(results.iter().all(|(dismissed, _)| *dismissed));
    assert_eq!(fx.vault.dialogs(), EXPLICIT_REFUSAL_LIMIT);
}

/// Repeating paths in `GetSecrets` decrypts nothing twice, and the
/// plaintext one call can return is bounded, also when distinct paths
/// (aliases) name the same item.
#[tokio::test(flavor = "multi_thread")]
async fn get_secrets_is_deduplicated_and_bounded() {
    use scopevault::service_api::dispatch::MAX_SECRET_BYTES_PER_REPLY;
    use scopevault::store::MAX_SECRET_BYTES;
    let fx = fixture(VaultState::Unlocked).await;
    let a = fx.client(Some(app_a())).await;
    let s = ClientSession::plain(&a).await;
    let col = create_collection(&a, "Big", "").await;
    let item = create_item(&a, &col, &s, "big", &[("k", "v")], &vec![7u8; MAX_SECRET_BYTES], false).await.unwrap();
    let id = item.rsplit('/').next().unwrap().to_owned();

    // One path 10 000 times: one answer.
    let repeated = vec![obj(&item); 10_000];
    let m = call(&a, SERVICE, SVC_IFACE, "GetSecrets", &(repeated, &s.path)).await.unwrap();
    let (map,): (HashMap<OwnedObjectPath, WireSecret>,) = m.body().deserialize().unwrap();
    assert_eq!(map.len(), 1);
    assert_eq!(s.decode(&map[&obj(&item)]).0.len(), MAX_SECRET_BYTES);

    // Distinct paths to the same item are answered each, up to the bound.
    let fits = MAX_SECRET_BYTES_PER_REPLY / MAX_SECRET_BYTES;
    let mut paths = vec![obj(&item)];
    for n in 1..=fits {
        let alias = format!("big{n}");
        call(&a, SERVICE, SVC_IFACE, "SetAlias", &(alias.as_str(), obj(&col))).await.unwrap();
        paths.push(obj(&format!("/org/freedesktop/secrets/aliases/{alias}/{id}")));
    }
    let m = call(&a, SERVICE, SVC_IFACE, "GetSecrets", &(&paths[..fits], &s.path)).await.unwrap();
    let (map,): (HashMap<OwnedObjectPath, WireSecret>,) = m.body().deserialize().unwrap();
    assert_eq!(map.len(), fits);
    let e = call(&a, SERVICE, SVC_IFACE, "GetSecrets", &(&paths[..], &s.path)).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.LimitsExceeded", "{e:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn other_connections_cannot_stall_startup() {
    // Between start() and the end of the daemon's setup, every connection
    // that comes or goes on the bus sends a NameOwnerChanged into the
    // service's stream. Unread, 64 of them stopped the connection, and the
    // setup's own calls (RequestName) never got their replies.
    let vault = VaultFixture::new(VaultState::Unlocked);
    let bus = std::sync::Arc::new(common::TestBus::start());
    let conn = bus.connect().await;
    let resolver = std::sync::Arc::new(FixedResolver::default());
    let service = scopevault::service_api::SecretService::new(conn.clone(), resolver, vault.unlocker.clone());
    let _serving = service.clone().start().await.unwrap();

    let mut others = Vec::new();
    for _ in 0..80 {
        others.push(bus.connect().await);
    }
    tokio::time::timeout(Duration::from_secs(5), conn.request_name(DEST))
        .await
        .expect("the service connection stopped reading")
        .unwrap();
    drop(others);
}
