//! Administrative operations on the vault (all scopes, atomic).

mod common;

use std::collections::BTreeMap;

use common::tempdir::TempDir;
use scopevault::crypto::KdfParams;
use scopevault::identity::{AppId, Principal, Scope};
use scopevault::store::{AdminAuthority, PortableCollection, PortableItem, Secret, StoreError, Vault};

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
