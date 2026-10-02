//! Administrative operations on the vault (all scopes, atomic).

mod common;

use std::collections::BTreeMap;

use common::tempdir::TempDir;
use scopevault::crypto::KdfParams;
use scopevault::identity::{AppId, Principal, Scope};
use scopevault::store::{
    AdminAuthority, PortableCollection, PortableItem, Secret, StoreError, Vault, split_portal_keys,
};

const PW: &[u8] = b"correct horse battery staple";
const KDF: KdfParams = KdfParams::MINIMUM;

fn app(id: &str) -> Principal {
    Principal::Flatpak { app_id: AppId::parse(id).unwrap(), instance_id: "1".into(), risks: Default::default() }
}

fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn text(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec(), "text/plain")
}

fn reopen(dir: &std::path::Path, v: Vault) -> Vault {
    drop(v);
    let mut v = Vault::open(dir).unwrap();
    v.unlock(PW).unwrap();
    v
}

/// A vault where A has two items, B one, and host one.
fn setup(dir: &std::path::Path) -> (Vault, String, String) {
    let mut v = Vault::create(dir, PW, KDF).unwrap();
    let a = app("org.example.A");
    let mut sa = v.scoped(&a).unwrap();
    let col = sa.create_collection("Login", "default").unwrap().0;
    let i1 = sa.create_item(&col, "one", attrs(&[("k", "1")]), &text("a-one"), false).unwrap().0;
    let i2 = sa.create_item(&col, "two", attrs(&[("k", "2")]), &text("a-two"), false).unwrap().0;
    let mut sb = v.scoped(&app("org.example.B")).unwrap();
    let bcol = sb.create_collection("Login", "default").unwrap().0;
    sb.create_item(&bcol, "b", attrs(&[("k", "1")]), &text("b-one"), false).unwrap();
    let mut sh = v.scoped(&Principal::Host).unwrap();
    let hcol = sh.create_collection("Login", "default").unwrap().0;
    sh.create_item(&hcol, "h", attrs(&[("k", "h")]), &text("host"), false).unwrap();
    (v, format!("{col}/{i1}"), format!("{col}/{i2}"))
}

fn a_scope() -> Scope {
    app("org.example.A").scope()
}

#[test]
fn a_failed_transaction_changes_nothing() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let (mut v, _, _) = setup(&dir);
    let auth = AdminAuthority::offline();
    let r: Result<(), StoreError> = v.transaction(|v| {
        let mut s = v.scoped_admin(&auth, Scope::Host)?;
        let col = s.create_collection("New", "")?.0;
        s.create_item(&col, "x", attrs(&[]), &text("x"), false)?;
        v.scoped_admin(&auth, a_scope())?.delete_collection("login")?;
        Err(StoreError::Invalid("stop"))
    });
    assert!(matches!(r, Err(StoreError::Invalid("stop"))));
    let check = |v: &mut Vault| {
        assert_eq!(v.scoped(&Principal::Host).unwrap().collection_names(), ["login"]);
        assert_eq!(v.scoped(&app("org.example.A")).unwrap().collection("login").unwrap().items.len(), 2);
    };
    check(&mut v);
    let mut v = reopen(&dir, v);
    check(&mut v);
}

#[test]
fn moving_items_keeps_everything_and_is_all_or_nothing() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let (mut v, i1, i2) = setup(&dir);
    let auth = AdminAuthority::offline();
    let before = v.scoped(&app("org.example.A")).unwrap().item("login", i1.split('/').nth(1).unwrap()).unwrap();

    // One missing item aborts the whole move.
    let r = v.move_items(&auth, &a_scope(), &[i1.clone(), "login/ffff".into()], &Scope::Host);
    assert!(matches!(r, Err(StoreError::NoSuchObject)), "{r:?}");
    assert_eq!(v.scoped(&app("org.example.A")).unwrap().collection("login").unwrap().items.len(), 2);

    let moved = v.move_items(&auth, &a_scope(), std::slice::from_ref(&i1), &Scope::Host).unwrap();
    let mut v = reopen(&dir, v);
    let (col, item) = moved[0].split_once('/').unwrap();
    let h = v.scoped(&Principal::Host).unwrap();
    assert_eq!(col, "login", "into the target's default collection");
    let info = h.item(col, item).unwrap();
    assert_eq!((info.label, info.attributes, info.created), (before.label, before.attributes, before.created));
    assert_eq!(h.read_secret(col, item).unwrap(), text("a-one"));
    let a = v.scoped(&app("org.example.A")).unwrap();
    assert_eq!(a.collection("login").unwrap().items, [i2.split('/').nth(1).unwrap()]);

    // A scope without a default collection gets one.
    let c = v.move_items(&auth, &a_scope(), &[i2], &app("org.example.New").scope()).unwrap();
    assert_eq!(c[0].split('/').next(), Some("login"));
    let n = v.scoped(&app("org.example.New")).unwrap();
    assert_eq!(n.alias("default").as_deref(), Some("login"));
}

#[test]
fn admin_access_ignores_logical_locks() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let (mut v, i1, _) = setup(&dir);
    v.scoped(&app("org.example.A")).unwrap().set_collection_locked("login", true).unwrap();
    let (col, item) = i1.split_once('/').unwrap();
    assert!(matches!(v.scoped(&app("org.example.A")).unwrap().read_secret(col, item), Err(StoreError::Locked)));
    let auth = AdminAuthority::offline();
    v.move_items(&auth, &a_scope(), &[i1], &Scope::Host).unwrap();
}

#[test]
fn resetting_a_scope_removes_only_its_data() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let (mut v, _, _) = setup(&dir);
    let auth = AdminAuthority::offline();
    assert_eq!(v.reset_scope(&auth, &a_scope()).unwrap(), (1, 2));
    assert_eq!(v.reset_scope(&auth, &a_scope()).unwrap(), (0, 0));
    let mut v = reopen(&dir, v);
    let scopes: Vec<String> = v.scope_summaries(&auth).unwrap().into_iter().map(|s| s.scope).collect();
    assert_eq!(scopes, ["host", "flatpak/org.example.B"]);
    assert!(v.scoped(&app("org.example.A")).unwrap().collection_names().is_empty());
    let b = v.scoped(&app("org.example.B")).unwrap();
    assert_eq!(b.collection("login").unwrap().items.len(), 1);
}

fn sample() -> Vec<PortableCollection> {
    let item = |label: &str, k: &str, secret: Secret| PortableItem {
        label: label.into(),
        attributes: attrs(&[("k", k), ("xdg:schema", "org.example.Test")]),
        secret,
        created: 1_600_000_000,
        modified: 1_700_000_000,
    };
    vec![
        PortableCollection {
            label: "Login".into(),
            aliases: vec!["default".into()],
            items: vec![
                item("binary", "1", Secret::new(vec![0, 255, 1, 0], "application/octet-stream")),
                item("Ünïcödé ✓", "2", text("pässwörd 🔑")),
                item("empty", "3", text("")),
            ],
        },
        PortableCollection { label: "Work".into(), aliases: vec![], items: vec![item("w", "4", text("work"))] },
    ]
}

#[test]
fn import_merges_by_label_is_repeatable_and_exports_back() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let auth = AdminAuthority::offline();
    // The host already has its (empty) login collection.
    v.scoped_admin(&auth, Scope::Host).unwrap().ensure_namespace().unwrap();

    let r = v.import(&auth, &Scope::Host, &sample()).unwrap();
    assert_eq!((r.collections_created, r.items_imported, r.items_skipped), (1, 4, 0));
    assert!(r.aliases_set.is_empty(), "host already had default");
    let again = v.import(&auth, &Scope::Host, &sample()).unwrap();
    assert_eq!((again.collections_created, again.items_imported, again.items_skipped), (0, 0, 4));

    let mut v = reopen(&dir, v);
    let out = v.export(&auth, &Scope::Host).unwrap();
    let mut expected = sample();
    for (c, e) in out.iter().zip(expected.iter_mut()) {
        // Order within a collection follows item IDs; compare as sets.
        assert_eq!(c.label, e.label);
        assert_eq!(c.items.len(), e.items.len());
        for item in &e.items {
            assert!(c.items.contains(item), "{} missing after export", item.label);
        }
    }
    assert_eq!(out[0].aliases, ["default"]);

    // Into a scope without data, aliases are taken over.
    let r = v.import(&auth, &app("org.example.A").scope(), &sample()).unwrap();
    assert_eq!((r.collections_created, r.items_imported), (2, 4));
    assert_eq!(r.aliases_set, ["default"]);
}

#[test]
fn the_generic_schema_counts_as_no_schema() {
    // gnome-keyring reports `xdg:schema` = Generic for schema-less items only
    // after reloading them from disk, so the same item can come both ways.
    let tmp = TempDir::new("admin");
    let mut v = Vault::create(&tmp.path().join("vault"), PW, KDF).unwrap();
    let auth = AdminAuthority::offline();
    let item = |schema: Option<&str>| {
        let mut a = attrs(&[("app", "m")]);
        if let Some(s) = schema {
            a.insert("xdg:schema".into(), s.into());
        }
        vec![PortableCollection {
            label: "Login".into(),
            aliases: vec!["default".into()],
            items: vec![PortableItem {
                label: "a".into(),
                attributes: a,
                secret: text("one"),
                created: 0,
                modified: 0,
            }],
        }]
    };
    const GENERIC: &str = "org.freedesktop.Secret.Generic";
    assert_eq!(v.import(&auth, &Scope::Host, &item(None)).unwrap().items_imported, 1);
    assert_eq!(v.import(&auth, &Scope::Host, &item(Some(GENERIC))).unwrap().items_skipped, 1);
    // Another schema is another item.
    assert_eq!(v.import(&auth, &Scope::Host, &item(Some("org.example.Other"))).unwrap().items_imported, 1);

    assert!(item(None)[0].items[0].same_as(&item(Some(GENERIC))[0].items[0]));
    assert!(!item(None)[0].items[0].same_as(&item(Some("org.example.Other"))[0].items[0]));
    let mut extra = item(Some(GENERIC));
    extra[0].items[0].attributes.insert("x".into(), "1".into());
    assert!(!item(None)[0].items[0].same_as(&extra[0].items[0]));
}

#[test]
fn a_failing_import_leaves_nothing_behind() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let auth = AdminAuthority::offline();
    let mut cols = sample();
    cols[1].items[0].label = "x".repeat(scopevault::store::MAX_LABEL_BYTES + 1);
    assert!(matches!(v.import(&auth, &Scope::Host, &cols), Err(StoreError::Limit(_))));
    let mut v = reopen(&dir, v);
    assert!(v.scope_summaries(&auth).unwrap().is_empty());
}

// ---- the Secret portal's keys ----

/// A portal key as gnome-keyring keeps it.
fn portal_item(app_id: &str, byte: u8) -> PortableItem {
    PortableItem {
        label: format!("Application key for {app_id}"),
        attributes: attrs(&[("app_id", app_id), ("xdg:schema", "org.freedesktop.portal.Secret")]),
        secret: Secret::new(vec![byte; 64], "application/octet-stream"),
        created: 1_600_000_000,
        modified: 1_700_000_000,
    }
}

#[test]
fn splitting_portal_keys_takes_only_the_default_collection() {
    let key = portal_item("org.example.A", 1);
    let ordinary = PortableItem {
        label: "Ordinary".into(),
        attributes: attrs(&[("app_id", "org.example.B")]),
        secret: text("ordinary"),
        created: 0,
        modified: 0,
    };
    let no_schema = PortableItem {
        label: "No schema".into(),
        attributes: attrs(&[("app_id", "org.example.B"), ("xdg:schema", "org.example.Other")]),
        secret: text("x"),
        created: 0,
        modified: 0,
    };
    let invalid = PortableItem {
        label: "Bad id".into(),
        attributes: attrs(&[("app_id", "a/b"), ("xdg:schema", "org.freedesktop.portal.Secret")]),
        secret: text("y"),
        created: 0,
        modified: 0,
    };
    let elsewhere = portal_item("org.example.D", 2);
    let cols = vec![
        PortableCollection {
            label: "Login".into(),
            aliases: vec!["default".into()],
            items: vec![key.clone(), ordinary, no_schema, invalid],
        },
        PortableCollection { label: "Work".into(), aliases: vec![], items: vec![elsewhere.clone()] },
    ];
    let split = split_portal_keys(cols).unwrap();
    assert_eq!(split.keys, vec![key], "the portal key, unchanged");
    assert_eq!(split.keys[0].created, 1_600_000_000, "timestamps travel with it");
    assert_eq!(split.notes.len(), 3, "{:?}", split.notes);
    assert!(split.notes.iter().any(|n| n.contains("org.example.B")), "{:?}", split.notes);
    assert!(split.notes.iter().any(|n| n.contains("Bad id")), "{:?}", split.notes);
    assert_eq!(split.collections[0].items.len(), 3, "the noted items stay where they are");
    assert_eq!(split.collections[1].items, vec![elsewhere], "only the default collection is examined");
}

#[test]
fn an_ambiguous_app_id_stops_the_import() {
    let cols = vec![PortableCollection {
        label: "Login".into(),
        aliases: vec!["default".into()],
        items: vec![
            portal_item("org.example.Dup", 1),
            portal_item("org.example.Dup", 2),
            portal_item("org.example.Fine", 3),
        ],
    }];
    let err = split_portal_keys(cols).unwrap_err();
    assert!(err.contains("org.example.Dup"), "{err}");
    assert!(!err.contains("org.example.Fine"), "{err}");
}

#[test]
fn importing_portal_keys_is_repeatable_and_detects_conflicts() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let auth = AdminAuthority::offline();
    let key = portal_item("org.example.A", 1);

    let r = v.import_portal_keys(&auth, std::slice::from_ref(&key)).unwrap();
    assert_eq!((r.imported, r.skipped), (1, 0));
    assert!(v.portal_initialised().unwrap());
    let again = v.import_portal_keys(&auth, std::slice::from_ref(&key)).unwrap();
    assert_eq!((again.imported, again.skipped), (0, 1), "the same key is skipped");

    let exported = v.export(&auth, &Scope::Portal).unwrap();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].aliases, ["default"]);
    let item = &exported[0].items[0];
    assert_eq!((item.label.as_str(), item.created, item.modified), (key.label.as_str(), key.created, key.modified));
    assert_eq!(item.secret, key.secret);

    // Different bytes for the same app ID are a conflict, and change nothing.
    let before = v.export(&auth, &Scope::Portal).unwrap();
    let r = v.import_portal_keys(&auth, &[portal_item("org.example.A", 2), portal_item("org.example.B", 3)]);
    assert!(matches!(r, Err(StoreError::PortalConflict(ref id)) if id == "org.example.A"), "{r:?}");
    assert_eq!(v.export(&auth, &Scope::Portal).unwrap(), before, "nothing changed");

    // A key without the portal schema or without a valid app ID is refused.
    let mut wrong = portal_item("org.example.C", 4);
    wrong.attributes.remove("xdg:schema");
    assert!(matches!(v.import_portal_keys(&auth, &[wrong]), Err(StoreError::Invalid(_))));
    let mut no_id = portal_item("org.example.C", 5);
    no_id.attributes.remove("app_id");
    assert!(matches!(v.import_portal_keys(&auth, &[no_id]), Err(StoreError::Invalid(_))));
}

#[test]
fn portal_keys_cannot_be_moved_or_imported_as_ordinary_items() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let (mut v, i1, _) = setup(&dir);
    let auth = AdminAuthority::offline();

    let r = v.move_items(&auth, &Scope::Host, std::slice::from_ref(&i1), &Scope::Portal);
    assert!(matches!(r, Err(StoreError::Invalid("portal keys cannot be moved"))), "{r:?}");
    let r = v.move_items(&auth, &Scope::Portal, &[i1], &Scope::Host);
    assert!(matches!(r, Err(StoreError::Invalid("portal keys cannot be moved"))), "{r:?}");
    let r = v.import(&auth, &Scope::Portal, &sample());
    assert!(matches!(r, Err(StoreError::Invalid("use the portal key import for the portal scope"))), "{r:?}");

    // The scope itself is managed normally: init, then reset uninitialises.
    assert!(v.init_portal(&auth).unwrap());
    assert!(!v.init_portal(&auth).unwrap(), "already initialised");
    {
        let s = v.scoped_admin(&auth, Scope::Portal).unwrap();
        assert_eq!(s.collection_names(), ["portal"]);
        assert_eq!(s.collection("portal").unwrap().label, "Portal");
        assert_eq!(s.alias("default").as_deref(), Some("portal"));
    }
    v.reset_scope(&auth, &Scope::Portal).unwrap();
    assert!(!v.portal_initialised().unwrap());
    assert!(v.export(&auth, &Scope::Portal).unwrap().is_empty());
}

#[test]
fn portal_keys_are_created_only_once_per_app() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let auth = AdminAuthority::offline();

    assert!(
        matches!(
            v.admin_create_portal_key(&auth, "org.example.A"),
            Err(StoreError::Invalid("the Secret portal keys were neither imported nor initialised"))
        ),
        "not initialised yet"
    );
    v.init_portal(&auth).unwrap();

    let key = v.admin_create_portal_key(&auth, "org.example.A").unwrap();
    assert_eq!(key.value.len(), scopevault::store::PORTAL_KEY_BYTES);
    assert_eq!(key.content_type, "application/octet-stream");
    assert!(matches!(
        v.admin_create_portal_key(&auth, "org.example.A"),
        Err(StoreError::Invalid("the app already has a portal key"))
    ));
    for id in ["", ".", "..", "a/b", "../x", "x".repeat(256).as_str()] {
        assert!(matches!(v.admin_create_portal_key(&auth, id), Err(StoreError::Invalid("invalid app ID"))), "{id:?}");
    }

    let exported = v.export(&auth, &Scope::Portal).unwrap();
    assert_eq!(exported.len(), 1);
    let item = &exported[0].items[0];
    assert_eq!(item.label, "Application key for org.example.A");
    assert_eq!(item.attributes.get("app_id").map(String::as_str), Some("org.example.A"));
    assert_eq!(item.attributes.get("xdg:schema").map(String::as_str), Some("org.freedesktop.portal.Secret"));
    assert_eq!(item.secret, key, "the stored key is the returned one");
}

// ---- explicit sharing ----

fn b_scope() -> Scope {
    app("org.example.B").scope()
}

#[test]
fn sharing_validates_its_arguments() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let auth = AdminAuthority::offline();
    let mut s = v.scoped(&Principal::Host).unwrap();
    s.ensure_namespace().unwrap();
    let item = s.create_item("login", "Mail", attrs(&[("k", "v")]), &text("secret"), false).unwrap().0;
    drop(s);
    let spec = format!("login/{item}");

    // The portal scope shares nothing, and is nobody's grantee.
    assert!(matches!(v.share(&auth, &Scope::Portal, &spec, &b_scope(), false), Err(StoreError::Invalid(_))));
    assert!(matches!(v.share(&auth, &Scope::Host, &spec, &Scope::Portal, false), Err(StoreError::Invalid(_))));
    // Not to itself.
    assert!(matches!(v.share(&auth, &Scope::Host, &spec, &Scope::Host, false), Err(StoreError::Invalid(_))));
    // Not the session collection, not a foreign item, not a malformed spec.
    assert!(matches!(v.share(&auth, &Scope::Host, "session/x", &b_scope(), false), Err(StoreError::Invalid(_))));
    let unknown = "f".repeat(32);
    assert!(
        matches!(
            v.share(&auth, &Scope::Host, &format!("login/{unknown}"), &b_scope(), false),
            Err(StoreError::NoSuchObject)
        ),
        "no such item"
    );
    assert!(matches!(
        v.share(&auth, &Scope::Host, &format!("nowhere/{item}"), &b_scope(), false),
        Err(StoreError::NoSuchObject)
    ));
    assert!(matches!(v.share(&auth, &Scope::Host, "login", &b_scope(), false), Err(StoreError::Invalid(_))));

    // Sharing again changes the access instead of adding a grant.
    let first = v.share(&auth, &Scope::Host, &spec, &b_scope(), false).unwrap();
    assert_eq!(v.grants(&auth, None).unwrap().len(), 1);
    let again = v.share(&auth, &Scope::Host, &spec, &b_scope(), true).unwrap();
    assert_eq!(first, again, "the same grant");
    let all = v.grants(&auth, None).unwrap();
    assert_eq!(all.len(), 1);
    assert!(all[0].write);
    assert_eq!(
        (all[0].owner.as_str(), all[0].collection.as_str(), all[0].item.as_str()),
        ("host", "login", item.as_str())
    );
    assert_eq!(all[0].label, "Mail");
    assert_eq!(all[0].grantee, "flatpak/org.example.B");

    // The listing can be filtered by either side.
    assert_eq!(v.grants(&auth, Some(&Scope::Host)).unwrap().len(), 1);
    assert_eq!(v.grants(&auth, Some(&b_scope())).unwrap().len(), 1);
    assert!(v.grants(&auth, Some(&app("org.example.C").scope())).unwrap().is_empty());
}

#[test]
fn grants_are_limited_per_owner() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let auth = AdminAuthority::offline();
    let mut s = v.scoped(&Principal::Host).unwrap();
    s.ensure_namespace().unwrap();
    let item = s.create_item("login", "Mail", attrs(&[("k", "v")]), &text("secret"), false).unwrap().0;
    drop(s);
    let spec = format!("login/{item}");

    for i in 0..scopevault::store::MAX_GRANTS_PER_SCOPE {
        let grantee = app(&format!("org.example.G{i}")).scope();
        v.share(&auth, &Scope::Host, &spec, &grantee, false).unwrap();
    }
    assert!(matches!(
        v.share(&auth, &Scope::Host, &spec, &app("org.example.Overflow").scope(), false),
        Err(StoreError::Limit(_))
    ));
    // At the limit, an existing grant can still change its access.
    v.share(&auth, &Scope::Host, &spec, &app("org.example.G0").scope(), true).unwrap();
}

#[test]
fn a_grant_to_a_missing_item_is_corruption() {
    let tmp = TempDir::new("admin");
    let dir = tmp.path().join("vault");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let auth = AdminAuthority::offline();
    let mut s = v.scoped(&Principal::Host).unwrap();
    s.ensure_namespace().unwrap();
    let item = s.create_item("login", "Mail", attrs(&[("k", "v")]), &text("secret"), false).unwrap().0;
    drop(s);
    v.share(&auth, &Scope::Host, &format!("login/{item}"), &b_scope(), false).unwrap();
    drop(v);

    // The item's records go away behind the vault's back; the grant then
    // points at an item its namespace does not hold.
    let raw = rusqlite::Connection::open(dir.join("vault.db")).unwrap();
    let id = scopevault::store::payload::unhex(&item).unwrap();
    for kind in [3, 4] {
        raw.execute("DELETE FROM records WHERE id = ?1 AND kind = ?2", rusqlite::params![&id[..], kind]).unwrap();
    }
    drop(raw);

    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(v.unlock(PW), Err(StoreError::Corrupt(_))), "{v:?}");
}
