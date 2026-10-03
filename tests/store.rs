//! The encrypted vault on disk.

mod common;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::tempdir::TempDir;
use rusqlite::Connection;
use scopevault::crypto::{KdfParams, Slot, VaultKey};
use scopevault::identity::{AppId, Principal};
use scopevault::store::{Secret, StoreError, Vault};

const PW: &[u8] = b"correct horse battery staple";
const KDF: KdfParams = KdfParams::MINIMUM;

fn app(id: &str) -> Principal {
    Principal::Flatpak { app_id: AppId::parse(id).unwrap(), instance_id: "1".into(), risks: Default::default() }
}

fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn vault_dir(tmp: &TempDir) -> std::path::PathBuf {
    tmp.path().join("vault")
}

/// Opens the database behind the vault's back, for tampering.
fn raw(dir: &Path) -> Connection {
    Connection::open(dir.join("vault.db")).unwrap()
}

fn assert_corrupt(r: Result<(), StoreError>) {
    match r {
        Err(StoreError::Corrupt(_)) => {}
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn roundtrip_and_scope_isolation() {
    let tmp = TempDir::new("store");
    let dir = vault_dir(&tmp);
    let (a, b) = (app("org.example.A"), app("org.example.B"));
    let (a_col, a_item);
    {
        let mut v = Vault::create(&dir, PW, KDF).unwrap();
        let mut sa = v.scoped(&a).unwrap();
        a_col = sa.create_collection("Login", "default").unwrap().0;
        a_item = sa
            .create_item(
                &a_col,
                "Ünïcödé label ✓",
                attrs(&[("service", "mail")]),
                &Secret::new(vec![0, 1, 255], "application/octet-stream"),
                false,
            )
            .unwrap()
            .0;
        sa.create_item(&a_col, "empty", attrs(&[("k", "")]), &Secret::new(Vec::new(), "text/plain"), false).unwrap();
        let mut sb = v.scoped(&b).unwrap();
        let b_col = sb.create_collection("Login", "default").unwrap().0;
        assert_eq!(b_col, a_col, "same readable name in two scopes");
        sb.create_item(&b_col, "B's", attrs(&[("service", "mail")]), &Secret::new("b-secret", "text/plain"), false)
            .unwrap();
    }

    let mut v = Vault::open(&dir).unwrap();
    assert!(!v.is_unlocked());
    assert!(matches!(v.scoped(&a), Err(StoreError::Locked)));
    assert!(matches!(v.unlock(b"wrong"), Err(StoreError::WrongPassword)));
    v.unlock(PW).unwrap();

    let sa = v.scoped(&a).unwrap();
    assert_eq!(sa.alias("default").as_deref(), Some(a_col.as_str()));
    let s = sa.read_secret(&a_col, &a_item).unwrap();
    assert_eq!((&s.value[..], s.content_type.as_str()), (&[0u8, 1, 255][..], "application/octet-stream"));
    assert_eq!(sa.item(&a_col, &a_item).unwrap().label, "Ünïcödé label ✓");
    assert_eq!(sa.search(&attrs(&[("service", "mail")])).len(), 1);
    assert_eq!(sa.search(&BTreeMap::new()).len(), 2);
    let empty = sa.search(&attrs(&[("k", "")]));
    assert_eq!(sa.read_secret(&empty[0].0, &empty[0].1).unwrap().value.len(), 0);

    // B sees its own item only and cannot address A's by name.
    let sb = v.scoped(&b).unwrap();
    let found = sb.search(&attrs(&[("service", "mail")]));
    assert_eq!(found.len(), 1);
    assert_ne!(found[0].1, a_item);
    assert!(matches!(sb.read_secret(&a_col, &a_item), Err(StoreError::NoSuchObject)));
    assert!(sb.item(&a_col, &a_item).is_none());
    // Host has nothing.
    assert!(v.scoped(&Principal::Host).unwrap().collection_names().is_empty());
}

#[test]
fn replace_updates_matching_item() {
    let tmp = TempDir::new("store");
    let mut v = Vault::create(&vault_dir(&tmp), PW, KDF).unwrap();
    let mut s = v.scoped(&Principal::Host).unwrap();
    let c = s.create_collection("c", "").unwrap().0;
    let at = attrs(&[("user", "me")]);
    let (i1, new1) = s.create_item(&c, "one", at.clone(), &Secret::new("1", "text/plain"), true).unwrap();
    let (i2, new2) = s.create_item(&c, "two", at.clone(), &Secret::new("2", "text/plain"), true).unwrap();
    assert!(new1 && !new2);
    assert_eq!(i1, i2);
    assert_eq!(&s.read_secret(&c, &i1).unwrap().value[..], b"2");
    let (i3, new3) = s.create_item(&c, "three", at, &Secret::new("3", "text/plain"), false).unwrap();
    assert!(new3 && i3 != i1);
    assert_eq!(s.collection(&c).unwrap().items.len(), 2);
}

fn scan_for(dir: &Path, needles: &[&[u8]]) -> Vec<String> {
    let mut hits = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let data = std::fs::read(&p).unwrap();
        for n in needles {
            if data.windows(n.len()).any(|w| w == *n) {
                hits.push(format!("{} contains {}", p.display(), String::from_utf8_lossy(n)));
            }
        }
    }
    hits
}

#[test]
fn no_plaintext_on_disk() {
    let tmp = TempDir::new("store");
    let dir = vault_dir(&tmp);
    let canaries: [&[u8]; 6] =
        [b"CANARYLABEL", b"CANARYATTRNAME", b"CANARYATTRVALUE", b"CANARYSECRET", b"CanaryApp", b"CANARYCOLLECTION"];
    let p = app("org.example.CanaryApp");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    {
        let mut s = v.scoped(&p).unwrap();
        let c = s.create_collection("CANARYCOLLECTION label", "CANARYCOLLECTION").unwrap().0;
        for i in 0..50 {
            s.create_item(
                &c,
                &format!("CANARYLABEL {i}"),
                attrs(&[("CANARYATTRNAME", &format!("CANARYATTRVALUE {i}"))]),
                &Secret::new(format!("CANARYSECRET {i}"), "text/plain"),
                false,
            )
            .unwrap();
        }
        s.set_collection_label(&c, "CANARYLABEL renamed").unwrap();
    }
    // While open: the WAL holds recent writes.
    assert!(dir.join("vault.db-wal").exists());
    assert_eq!(scan_for(&dir, &canaries), Vec::<String>::new());
    // Deleting must not leave old plaintext around either (there never was any).
    {
        let mut s = v.scoped(&p).unwrap();
        let c = s.collection_names()[0].clone();
        s.delete_collection(&c).unwrap();
    }
    drop(v);
    assert_eq!(scan_for(&dir, &canaries), Vec::<String>::new());
    // Only the expected files exist.
    let mut names: Vec<String> =
        std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    assert!(
        names.iter().all(|n| ["lock", "vault.db", "vault.db-wal", "vault.db-shm"].contains(&n.as_str())),
        "{names:?}"
    );
}

/// Builds a vault with two scopes, two items each, and returns its directory.
fn populated(tmp: &TempDir) -> std::path::PathBuf {
    let dir = vault_dir(tmp);
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    for who in [app("org.example.A"), app("org.example.B")] {
        let mut s = v.scoped(&who).unwrap();
        let c = s.create_collection("c", "default").unwrap().0;
        s.create_item(&c, "one", attrs(&[("n", "1")]), &Secret::new("s1", "text/plain"), false).unwrap();
        s.create_item(&c, "two", attrs(&[("n", "2")]), &Secret::new("s2", "text/plain"), false).unwrap();
    }
    dir
}

#[test]
fn tampering_is_detected() {
    type Tamper = fn(&Connection);
    let cases: [(&str, Tamper); 7] = [
        ("flipped item ciphertext", |c| {
            c.execute("UPDATE records SET ciphertext = CAST(X'00' || substr(ciphertext, 2) AS BLOB) WHERE id = (SELECT id FROM records WHERE kind = 3 LIMIT 1) AND kind = 3", []).unwrap();
        }),
        ("ciphertext stored as text", |c| {
            c.execute("UPDATE records SET ciphertext = 'not a blob' WHERE id = (SELECT id FROM records WHERE kind = 3 LIMIT 1) AND kind = 3", []).unwrap();
        }),
        ("truncated collection ciphertext", |c| {
            c.execute("UPDATE records SET ciphertext = substr(ciphertext, 1, length(ciphertext) - 1) WHERE id = (SELECT id FROM records WHERE kind = 2 LIMIT 1) AND kind = 2", []).unwrap();
        }),
        ("collection moved to the other namespace", |c| {
            let n = c.execute("UPDATE records AS r SET namespace = (SELECT n.id FROM records AS n WHERE n.kind = 1 AND n.id != r.namespace LIMIT 1) WHERE r.kind = 2 AND r.id = (SELECT id FROM records WHERE kind = 2 LIMIT 1)", []).unwrap();
            assert_eq!(n, 1);
        }),
        ("item ciphertexts swapped", |c| {
            let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = c
                .prepare("SELECT id, nonce, ciphertext FROM records WHERE kind = 3 LIMIT 2")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            for (me, other) in [(&rows[0], &rows[1]), (&rows[1], &rows[0])] {
                c.execute(
                    "UPDATE records SET nonce = ?1, ciphertext = ?2 WHERE id = ?3 AND kind = 3",
                    rusqlite::params![other.1, other.2, me.0],
                )
                .unwrap();
            }
        }),
        ("secret record deleted", |c| {
            c.execute(
                "DELETE FROM records WHERE id = (SELECT id FROM records WHERE kind = 4 LIMIT 1) AND kind = 4",
                [],
            )
            .unwrap();
        }),
        ("unknown record kind", |c| {
            c.execute(
                "INSERT INTO records SELECT id, 9, namespace, nonce, ciphertext FROM records WHERE kind = 3 LIMIT 1",
                [],
            )
            .unwrap();
        }),
    ];
    for (what, tamper) in cases {
        let tmp = TempDir::new("store");
        let dir = populated(&tmp);
        tamper(&raw(&dir));
        let mut v = Vault::open(&dir).unwrap();
        let r = v.unlock(PW);
        assert!(matches!(r, Err(StoreError::Corrupt(_))), "{what}: {r:?}");
        assert!(!v.is_unlocked(), "{what}: must stay locked");
    }
}

#[test]
fn tampered_secret_fails_on_read_only() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    raw(&dir)
        .execute("UPDATE records SET ciphertext = CAST(X'00' || substr(ciphertext, 2) AS BLOB) WHERE kind = 4", [])
        .unwrap();
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    let s = v.scoped(&app("org.example.A")).unwrap();
    let c = s.collection_names()[0].clone();
    let i = s.collection(&c).unwrap().items[0].clone();
    assert_corrupt(s.read_secret(&c, &i).map(|_| ()));
}

#[test]
fn header_and_format_checks() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    raw(&dir).execute("UPDATE vault SET kdf_t = 2", []).unwrap();
    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(v.unlock(PW), Err(StoreError::WrongPassword)));
    drop(v);
    raw(&dir).execute("UPDATE vault SET kdf_t = 1, kdf_m = 4294967295", []).unwrap();
    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(v.unlock(PW), Err(StoreError::Crypto(_))), "huge memory cost must be refused, not attempted");
    drop(v);
    raw(&dir).execute_batch("PRAGMA user_version = 2").unwrap();
    assert!(matches!(Vault::open(&dir), Err(StoreError::UnsupportedVersion(2))));
    raw(&dir).execute_batch("PRAGMA user_version = 1; PRAGMA application_id = 7").unwrap();
    assert!(matches!(Vault::open(&dir), Err(StoreError::NotAVault)));
}

#[test]
fn file_permissions_and_symlinks() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    for f in ["vault.db", "lock"] {
        assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
    }
    {
        let mut v = Vault::open(&dir).unwrap();
        v.unlock(PW).unwrap();
        v.scoped(&Principal::Host).unwrap().create_collection("x", "").unwrap();
        assert_eq!(mode(&dir.join("vault.db-wal")), 0o600);
    }

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(Vault::open(&dir), Err(StoreError::InsecurePath(_))));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    assert!(matches!(Vault::open(&link), Err(StoreError::InsecurePath(_))));

    let other = tmp.path().join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(dir.join("vault.db"), other.join("vault.db")).unwrap();
    assert!(matches!(Vault::open(&other), Err(StoreError::InsecurePath(_))));
}

#[test]
fn second_opener_is_refused_and_create_does_not_overwrite() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let _first = Vault::open(&dir).unwrap();
    assert!(matches!(Vault::open(&dir), Err(StoreError::InUse)));
    drop(_first);
    assert!(matches!(Vault::create(&dir, PW, KDF), Err(StoreError::Exists)));
    assert!(matches!(Vault::create(&tmp.path().join("new"), b"", KDF), Err(StoreError::Invalid(_))));
}

#[test]
fn a_failed_create_removes_only_its_own_file() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    // Another opener holds the vault: refused, and the vault stays.
    let held = Vault::open(&dir).unwrap();
    std::fs::rename(dir.join("vault.db"), dir.join("moved.db")).unwrap();
    assert!(matches!(Vault::create(&dir, PW, KDF), Err(StoreError::InUse)));
    std::fs::rename(dir.join("moved.db"), dir.join("vault.db")).unwrap();
    assert!(matches!(Vault::create(&dir, PW, KDF), Err(StoreError::InUse)));
    assert!(dir.join("vault.db").exists(), "a refused create must not remove the vault");
    drop(held);
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();

    // A failure after the file was created removes that file, so a retry
    // can succeed.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir(&fresh).unwrap();
    std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink("/nonexistent", fresh.join("vault.db-wal")).unwrap();
    assert!(matches!(Vault::create(&fresh, PW, KDF), Err(StoreError::InsecurePath(_))));
    assert!(!fresh.join("vault.db").exists());
    Vault::create(&fresh, PW, KDF).unwrap();
}

#[test]
fn password_change_keeps_data() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(v.change_password(b"wrong", b"new pw", KDF), Err(StoreError::WrongPassword)));
    v.change_password(PW, b"new pw", KDF).unwrap();
    drop(v);
    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(v.unlock(PW), Err(StoreError::WrongPassword)));
    v.unlock(b"new pw").unwrap();
    let s = v.scoped(&app("org.example.A")).unwrap();
    let c = s.collection_names()[0].clone();
    let i = s.search(&attrs(&[("n", "1")]))[0].1.clone();
    assert_eq!(&s.read_secret(&c, &i).unwrap().value[..], b"s1");
}

/// Opens `v` through its login slot, as the daemon does with the password
/// PAM delivers.
fn unlock_login(v: &mut Vault, pw: &[u8]) -> Result<(), StoreError> {
    let wrap = v.key_slot(Slot::Login)?.ok_or(StoreError::NotFound)?;
    let key = VaultKey::unwrap_for(Slot::Login, &wrap, pw)?;
    v.unlock_with_key(key)
}

fn add_login_slot(v: &mut Vault, pw: &[u8]) {
    let wrap = v.vault_key().unwrap().wrap_for(Slot::Login, pw, KDF).unwrap();
    let current = v.key_slot(Slot::Login).unwrap();
    v.replace_key_slot(Slot::Login, current.as_ref(), Some(&wrap)).unwrap();
}

#[test]
fn the_login_slot_opens_the_vault_and_the_master_password_still_does() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let mut v = Vault::open(&dir).unwrap();
    assert!(v.key_slot(Slot::Login).unwrap().is_none());
    assert!(matches!(v.vault_key(), Err(StoreError::Locked)));
    v.unlock(PW).unwrap();
    add_login_slot(&mut v, b"login pw");
    drop(v);

    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(unlock_login(&mut v, PW), Err(StoreError::WrongPassword)));
    assert!(matches!(unlock_login(&mut v, b"wrong"), Err(StoreError::WrongPassword)));
    unlock_login(&mut v, b"login pw").unwrap();
    let s = v.scoped(&app("org.example.A")).unwrap();
    let c = s.collection_names()[0].clone();
    let i = s.search(&attrs(&[("n", "1")]))[0].1.clone();
    assert_eq!(&s.read_secret(&c, &i).unwrap().value[..], b"s1");
    drop(v);

    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(v.unlock(b"login pw"), Err(StoreError::WrongPassword)));
    v.unlock(PW).unwrap();

    // Changing the master password leaves the login slot alone.
    v.change_password(PW, b"new master", KDF).unwrap();
    drop(v);
    let mut v = Vault::open(&dir).unwrap();
    unlock_login(&mut v, b"login pw").unwrap();
}

#[test]
fn key_slot_changes_are_checked_against_the_stored_one() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    let key = v.vault_key().unwrap();
    let first = key.wrap_for(Slot::Login, b"one", KDF).unwrap();
    let second = key.wrap_for(Slot::Login, b"two", KDF).unwrap();
    // Adding needs "no slot yet"; replacing needs the slot that is there.
    assert!(v.replace_key_slot(Slot::Login, Some(&first), Some(&second)).is_err());
    v.replace_key_slot(Slot::Login, None, Some(&first)).unwrap();
    assert!(v.replace_key_slot(Slot::Login, None, Some(&second)).is_err());
    v.replace_key_slot(Slot::Login, Some(&first), Some(&second)).unwrap();
    assert_eq!(v.key_slot(Slot::Login).unwrap(), Some(second.clone()));
    // The master wrap is not a key slot.
    assert!(v.replace_key_slot(Slot::Master, None, Some(&second)).is_err());
    v.replace_key_slot(Slot::Login, Some(&second), None).unwrap();
    assert!(v.key_slot(Slot::Login).unwrap().is_none());
    drop(v);
    let mut v = Vault::open(&dir).unwrap();
    assert!(matches!(unlock_login(&mut v, b"two"), Err(StoreError::NotFound)));
}

/// The table is added to existing vaults without a format change, and
/// nothing else about the file changes: older builds still open the vault
/// with the master password.
#[test]
fn key_slots_leave_the_format_alone() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let master_before: Vec<u8> =
        raw(&dir).query_row("SELECT wrapped FROM vault WHERE id = 1", [], |r| r.get(0)).unwrap();
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    add_login_slot(&mut v, b"login pw");
    drop(v);
    let db = raw(&dir);
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, scopevault::store::db::SCHEMA_VERSION);
    let master_after: Vec<u8> = db.query_row("SELECT wrapped FROM vault WHERE id = 1", [], |r| r.get(0)).unwrap();
    assert_eq!(master_before, master_after);
    let slots: i64 = db.query_row("SELECT count(*) FROM key_slots", [], |r| r.get(0)).unwrap();
    assert_eq!(slots, 1);
}

#[test]
fn backups_leave_the_login_slot_out() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    add_login_slot(&mut v, b"login pw");
    let wrapped = v.key_slot(Slot::Login).unwrap().unwrap().wrapped;
    let copy_dir = tmp.path().join("copy");
    std::fs::create_dir(&copy_dir).unwrap();
    std::fs::set_permissions(&copy_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    v.backup_into(&copy_dir.join("vault.db")).unwrap();
    // Works on a vault without slots too (nothing to drop).
    let plain = TempDir::new("store");
    let plain_dir = populated(&plain);
    Vault::open(&plain_dir).unwrap().backup_into(&plain.path().join("copy.db")).unwrap();

    // The daemon's umask makes this 0600; the test's does not.
    std::fs::set_permissions(copy_dir.join("vault.db"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = std::fs::read(copy_dir.join("vault.db")).unwrap();
    assert!(!bytes.windows(wrapped.len()).any(|w| w == &wrapped[..]), "the login wrap is still in the backup");
    let mut c = Vault::open(&copy_dir).unwrap();
    assert!(c.key_slot(Slot::Login).unwrap().is_none());
    assert!(matches!(unlock_login(&mut c, b"login pw"), Err(StoreError::NotFound)));
    c.unlock(PW).unwrap();
    assert_eq!(c.verify_secrets().unwrap(), 4);
    // The live vault keeps its slot.
    drop(v);
    let mut v = Vault::open(&dir).unwrap();
    unlock_login(&mut v, b"login pw").unwrap();
}

#[test]
fn logical_and_global_lock() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    let (a, b) = (app("org.example.A"), app("org.example.B"));
    let mut sa = v.scoped(&a).unwrap();
    let c = sa.collection_names()[0].clone();
    let i = sa.collection(&c).unwrap().items[0].clone();
    sa.set_collection_locked(&c, true).unwrap();
    assert!(sa.collection(&c).unwrap().locked);
    assert!(matches!(sa.read_secret(&c, &i), Err(StoreError::Locked)));
    assert!(matches!(sa.create_item(&c, "x", BTreeMap::new(), &Secret::new("x", ""), false), Err(StoreError::Locked)));
    // B's collection, even with the same name, is unaffected.
    let sb = v.scoped(&b).unwrap();
    assert!(!sb.collection(&c).unwrap().locked);
    let ib = sb.collection(&c).unwrap().items[0].clone();
    sb.read_secret(&c, &ib).unwrap();
    // Unlocking A's collection again restores access.
    v.scoped(&a).unwrap().set_collection_locked(&c, false).unwrap();
    v.scoped(&a).unwrap().read_secret(&c, &i).unwrap();
    // Global lock hides everything until a fresh unlock.
    v.lock();
    assert!(matches!(v.scoped(&b), Err(StoreError::Locked)));
    assert!(matches!(v.scopes(), Err(StoreError::Locked)));
    v.unlock(PW).unwrap();
    assert_eq!(v.scopes().unwrap().len(), 2);
}

#[test]
fn failed_transaction_leaves_state_unchanged() {
    let tmp = TempDir::new("store");
    let dir = populated(&tmp);
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    let a = app("org.example.A");
    let before = v.scoped(&a).unwrap().collection_names();

    // Another connection holds the write lock, so our transaction fails.
    let blocker = raw(&dir);
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let r = v.scoped(&a).unwrap().create_collection("blocked", "");
    assert!(matches!(r, Err(StoreError::Db(_))), "{r:?}");
    assert_eq!(v.scoped(&a).unwrap().collection_names(), before, "index must not change");
    blocker.execute_batch("ROLLBACK").unwrap();

    // Limits are checked before anything is written.
    let big = Secret::new(vec![0u8; scopevault::store::MAX_SECRET_BYTES + 1], "");
    let c = before[0].clone();
    assert!(matches!(
        v.scoped(&a).unwrap().create_item(&c, "big", BTreeMap::new(), &big, false),
        Err(StoreError::Limit(_))
    ));
    drop(v);
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    assert_eq!(v.scoped(&a).unwrap().collection_names(), before);
    assert_eq!(v.scoped(&a).unwrap().collection(&c).unwrap().items.len(), 2);
}

#[test]
fn concurrent_writes_and_replacement() {
    let tmp = TempDir::new("store");
    let dir = vault_dir(&tmp);
    let v = Arc::new(Mutex::new(Vault::create(&dir, PW, KDF).unwrap()));
    let c = v.lock().unwrap().scoped(&Principal::Host).unwrap().create_collection("c", "").unwrap().0;
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let (v, c) = (v.clone(), c.clone());
            std::thread::spawn(move || {
                for i in 0..20 {
                    let mut g = v.lock().unwrap();
                    let mut s = g.scoped(&Principal::Host).unwrap();
                    // Everyone replaces the same shared item ...
                    s.create_item(&c, "shared", attrs(&[("id", "shared")]), &Secret::new(format!("{t}-{i}"), ""), true)
                        .unwrap();
                    // ... and adds one of their own.
                    s.create_item(&c, "own", attrs(&[("id", &format!("{t}-{i}"))]), &Secret::new("x", ""), true)
                        .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    drop(v);
    let mut v = Vault::open(&dir).unwrap();
    v.unlock(PW).unwrap();
    let s = v.scoped(&Principal::Host).unwrap();
    assert_eq!(s.collection(&c).unwrap().items.len(), 1 + 8 * 20);
    assert_eq!(s.search(&attrs(&[("id", "shared")])).len(), 1);
}

#[test]
fn session_collection_is_memory_only() {
    let tmp = TempDir::new("store");
    let dir = vault_dir(&tmp);
    let p = app("org.example.Session");
    let mut v = Vault::create(&dir, PW, KDF).unwrap();
    let (persistent, session);
    {
        let mut s = v.scoped(&p).unwrap();
        persistent = s.create_collection("session", "default").unwrap().0;
        assert_ne!(persistent, "session", "the name is reserved for the ephemeral collection");
        session = s.create_collection("Temporary", "session").unwrap().0;
        assert_eq!(session, "session");
        assert_eq!(s.alias("session").as_deref(), Some("session"));
        let (i, _) = s
            .create_item(
                &session,
                "EPHEMERALLABEL",
                attrs(&[("k", "EPHEMERALATTR")]),
                &Secret::new("EPHEMERALSECRET", ""),
                false,
            )
            .unwrap();
        assert_eq!(&s.read_secret(&session, &i).unwrap().value[..], b"EPHEMERALSECRET");
        s.set_secret(&session, &i, &Secret::new("EPHEMERALSECRET2", "")).unwrap();
        s.set_item_label(&session, &i, "EPHEMERALLABEL2").unwrap();
        assert_eq!(s.search(&attrs(&[("k", "EPHEMERALATTR")])).len(), 1);
    }
    let needles: [&[u8]; 3] = [b"EPHEMERAL", b"Temporary", b"session\""];
    assert_eq!(scan_for(&dir, &needles), Vec::<String>::new());

    // Global lock discards it; the persistent collection and alias survive.
    v.lock();
    v.unlock(PW).unwrap();
    let s = v.scoped(&p).unwrap();
    assert_eq!(s.collection_names(), vec![persistent.clone()]);
    assert!(s.alias("session").is_none());
    assert_eq!(s.alias("default"), Some(persistent));
}
