//! Migration (import), rollback (export) and restore with
//! `scopevault-admin`, which opens the vault itself while no daemon runs.
//!
//! The "old provider" is a second Secret Service on a private bus (this
//! project's service, used through the standard API only); the desktop
//! check uses a real gnome-keyring instead
//! (`scripts/host-migration-check.sh`).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use common::tempdir::TempDir;
use common::{PASSWORD, TestBus, VaultFixture, VaultState};
use scopevault::crypto::KdfParams;
use scopevault::identity::{BusIdentityResolver, Classifier, HostBaseline, IdentityPolicy, InstanceRecords, Scope};
use scopevault::service_api::SecretService;
use scopevault::store::{AdminAuthority, Secret, Vault};

const ADMIN: &str = env!("CARGO_BIN_EXE_scopevault-admin");
const CLIENT: &str = env!("CARGO_BIN_EXE_scopevault-client");
const TARGET_PW: &str = "target password";

/// The old provider: a Secret Service on a private bus with its own vault.
struct OldProvider {
    bus: Arc<TestBus>,
    vault: VaultFixture,
}

async fn old_provider(state: VaultState) -> OldProvider {
    let bus = Arc::new(TestBus::start());
    let conn = bus.connect().await;
    let baseline = HostBaseline::capture().unwrap();
    let uid = baseline.uid;
    let classifier = Classifier {
        baseline,
        instances: InstanceRecords::new(bus.runtime_dir(), uid),
        policy: IdentityPolicy::default(),
    };
    let resolver = BusIdentityResolver::new(&conn, classifier).await.unwrap();
    let vault = VaultFixture::new(state);
    let service = SecretService::new(conn.clone(), resolver, vault.unlocker.clone());
    tokio::spawn(service.start().await.unwrap());
    conn.request_name("org.freedesktop.secrets").await.unwrap();
    OldProvider { bus, vault }
}

impl OldProvider {
    async fn client(&self, steps: &[&str]) -> Vec<String> {
        let mut cmd = Command::new(CLIENT);
        cmd.args(steps).env("DBUS_SESSION_BUS_ADDRESS", &self.bus.address).stdin(Stdio::null());
        let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
        String::from_utf8_lossy(&out.stdout).lines().map(str::to_owned).collect()
    }

    /// Stores four items: three in the default collection, one in "Work".
    async fn fill(&self) {
        let r = self
            .client(&[
                "store",
                "default",
                "Mail",
                "mail-pw",
                "service=mail,user=alice",
                "store",
                "default",
                "Ünïcödé ✓",
                "pässwörd 🔑",
                "service=web",
                "store",
                "default",
                "Empty",
                "",
                "service=empty",
                "create",
                "Work",
                "",
                "store",
                "/org/freedesktop/secrets/collection/work",
                "VPN",
                "vpn-pw",
                "service=vpn",
            ])
            .await;
        assert!(r.iter().all(|l| l.split('\t').nth(1) == Some("ok")), "{r:#?}");
    }
}

/// A pinentry for the admin tool, separate from the provider's.
struct Pins {
    dir: TempDir,
}

impl Pins {
    fn new() -> Self {
        let dir = TempDir::new("pins");
        std::fs::write(dir.path().join("pins"), "").unwrap();
        let wrapper = dir.path().join("pinentry.sh");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nFAKE_PINENTRY_DIR='{}' exec '{}' \"$@\"\n",
                dir.path().display(),
                common::support_script("fake-pinentry.sh").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        Pins { dir }
    }

    fn set(&self, pins: &[&str]) {
        std::fs::write(self.dir.path().join("pins"), pins.join("\n") + "\n").unwrap();
        let _ = std::fs::remove_file(self.dir.path().join("count"));
    }

    fn program(&self) -> PathBuf {
        self.dir.path().join("pinentry.sh")
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

async fn admin(args: &[&str], data_dir: &Path, pins: &Pins, bus: Option<&str>) -> Out {
    let mut cmd = Command::new(ADMIN);
    cmd.args(args).arg("--data-dir").arg(data_dir).arg("--pinentry").arg(pins.program()).stdin(Stdio::null());
    if let Some(b) = bus {
        cmd.args(["--bus", b]);
    }
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Opens a vault this test closed a moment ago. A child that another test
/// forks meanwhile holds a copy of the vault's `flock` until it calls exec,
/// so the open can briefly fail with `InUse`.
fn open_vault(dir: &Path) -> Vault {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match Vault::open(dir) {
            Err(scopevault::store::StoreError::InUse) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            r => return r.unwrap(),
        }
    }
}
fn host_items(dir: &Path, password: &str) -> Vec<(String, String, Vec<u8>)> {
    let mut v = open_vault(dir);
    v.unlock(password.as_bytes()).unwrap();
    let cols = v.export(&AdminAuthority::offline(), &Scope::Host).unwrap();
    let mut out: Vec<_> = cols
        .into_iter()
        .flat_map(|c| {
            let label = c.label;
            c.items.into_iter().map(move |i| (label.clone(), i.label, i.secret.value.to_vec()))
        })
        .collect();
    out.sort();
    out
}

fn portal_items(dir: &Path, password: &str) -> Vec<(String, String, Vec<u8>)> {
    let mut v = open_vault(dir);
    v.unlock(password.as_bytes()).unwrap();
    let mut out = Vec::new();
    for c in v.export(&AdminAuthority::offline(), &Scope::Portal).unwrap() {
        for i in c.items {
            out.push((c.label.clone(), i.label, i.secret.value.to_vec()));
        }
    }
    out.sort();
    out
}

/// Creates the portal key item gnome-keyring would keep, in `scope`'s
/// default collection (the host scope's, for the old provider).
fn add_portal_key(v: &mut Vault, scope: &Scope, app_id: &str, byte: u8) -> Result<(), Box<dyn std::error::Error>> {
    let mut s = v.scoped_admin(&AdminAuthority::offline(), scope.clone())?;
    s.ensure_namespace()?;
    s.create_item(
        "login",
        &format!("Application key for {app_id}"),
        [
            ("app_id".to_owned(), app_id.to_owned()),
            ("xdg:schema".to_owned(), "org.freedesktop.portal.Secret".to_owned()),
        ]
        .into(),
        &Secret::new(vec![byte; 64], "application/octet-stream"),
        false,
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_then_rollback() {
    let old = old_provider(VaultState::Unlocked).await;
    old.fill().await;
    let tmp = TempDir::new("migrate");
    let dir = tmp.path().join("vault");
    drop(Vault::create(&dir, TARGET_PW.as_bytes(), KdfParams::MINIMUM).unwrap());
    let pins = Pins::new();

    pins.set(&[TARGET_PW]);
    let out = admin(&["import"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("found 4 items in 2 collections"), "{}", out.stdout);
    assert!(out.stdout.contains("verified: all 4 items"), "{}", out.stdout);
    for secret in ["mail-pw", "pässwörd", "vpn-pw"] {
        assert!(!out.stdout.contains(secret) && !out.stderr.contains(secret), "the summary shows no secrets");
    }
    let imported = host_items(&dir, TARGET_PW);
    assert_eq!(
        imported,
        [
            ("Login".into(), "Empty".into(), b"".to_vec()),
            ("Login".into(), "Mail".into(), b"mail-pw".to_vec()),
            ("Login".into(), "Ünïcödé ✓".into(), "pässwörd 🔑".as_bytes().to_vec()),
            ("Work".into(), "VPN".into(), b"vpn-pw".to_vec()),
        ]
    );
    // The provider's default alias came along; the provider is unchanged.
    let mut v = open_vault(&dir);
    v.unlock(TARGET_PW.as_bytes()).unwrap();
    assert_eq!(v.scoped(&scopevault::identity::Principal::Host).unwrap().alias("default").as_deref(), Some("login"));
    drop(v);
    let r = old.client(&["search", "-"]).await;
    assert_eq!(r[0].split('\t').nth(2).unwrap().split(" | ").next().unwrap().split(',').count(), 4, "{r:?}");

    // Again: nothing new.
    pins.set(&[TARGET_PW]);
    let out = admin(&["import"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(out.stdout.contains("imported 0 items into host (4 already there"), "{}", out.stdout);

    // Rollback: an item created after the switch goes back to the provider.
    {
        let mut v = open_vault(&dir);
        v.unlock(TARGET_PW.as_bytes()).unwrap();
        let mut s = v.scoped(&scopevault::identity::Principal::Host).unwrap();
        s.create_item(
            "login",
            "New",
            [("service".to_owned(), "new".to_owned())].into(),
            &Secret::new(*b"new-pw", "text/plain"),
            false,
        )
        .unwrap();
    }
    pins.set(&[TARGET_PW]);
    let out = admin(&["export"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("wrote 1 items (4 already there, 0 new collections)"), "{}", out.stdout);
    assert!(out.stdout.contains("verified: all 5 items are in the provider"), "{}", out.stdout);
    let r = old.client(&["lookup", "service=new", "lookup", "service=mail"]).await;
    assert_eq!(r[0].split('\t').nth(2), Some("new-pw"));
    assert_eq!(r[1].split('\t').nth(2), Some("mail-pw"), "the old store remains usable");
}

#[tokio::test(flavor = "multi_thread")]
async fn import_unlocks_the_provider_and_creates_the_vault() {
    let old = old_provider(VaultState::Unlocked).await;
    old.fill().await;
    old.vault.lock_vault();
    let tmp = TempDir::new("migrate");
    let dir = tmp.path().join("new-vault");
    let pins = Pins::new();

    // The provider's own dialog is cancelled: nothing is created.
    old.vault.set_pins(&["CANCEL"]);
    let out = admin(&["import"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(!out.ok);
    assert!(!Vault::exists(&dir));

    // A fresh provider (no cooldown after the cancel), also locked.
    let old = old_provider(VaultState::Unlocked).await;
    old.fill().await;
    old.vault.lock_vault();
    old.vault.set_pins(&[PASSWORD]);
    pins.set(&["fresh password"]);
    let out = admin(&["import"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(old.vault.dialogs(), 1, "the provider asked for its password");
    assert_eq!(host_items(&dir, "fresh password").len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_commands_refuse_a_vault_in_use() {
    let tmp = TempDir::new("migrate");
    let dir = tmp.path().join("vault");
    let _held = Vault::create(&dir, TARGET_PW.as_bytes(), KdfParams::MINIMUM).unwrap();
    let pins = Pins::new();
    for args in [&["import"][..], &["export"], &["restore", "/nonexistent"]] {
        let out = admin(args, &dir, &pins, Some("unix:path=/nonexistent")).await;
        assert!(!out.ok);
        assert!(out.stderr.contains("stop scopevault-daemon first"), "{args:?}: {}", out.stderr);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_checks_the_backup_and_keeps_the_old_vault() {
    let tmp = TempDir::new("restore");
    let dir = tmp.path().join("vault");
    let backup = tmp.path().join("backup.db");
    let item = |v: &mut Vault, label: &str| {
        let mut s = v.scoped(&scopevault::identity::Principal::Host).unwrap();
        s.ensure_namespace().unwrap();
        s.create_item(
            "login",
            label,
            [("k".to_owned(), label.to_owned())].into(),
            &Secret::new(label.as_bytes().to_vec(), "text/plain"),
            false,
        )
        .unwrap();
    };
    {
        let mut v = Vault::create(&dir, TARGET_PW.as_bytes(), KdfParams::MINIMUM).unwrap();
        item(&mut v, "before");
        v.backup_into(&backup).unwrap();
        item(&mut v, "after");
    }
    let pins = Pins::new();

    // Not a vault, and a wrong password: nothing changes.
    let junk = tmp.path().join("junk.db");
    std::fs::write(&junk, b"not a database").unwrap();
    let out = admin(&["restore", junk.to_str().unwrap()], &dir, &pins, None).await;
    assert!(!out.ok && out.stderr.contains("not a usable backup"), "{}", out.stderr);
    pins.set(&["no", "no", "no"]);
    let out = admin(&["restore", backup.to_str().unwrap()], &dir, &pins, None).await;
    assert!(!out.ok, "{}", out.stdout);
    assert_eq!(host_items(&dir, TARGET_PW).len(), 2);
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(leftovers.iter().all(|n| !n.to_string_lossy().contains("restore-")), "{leftovers:?}");

    pins.set(&[TARGET_PW]);
    let out = admin(&["restore", backup.to_str().unwrap()], &dir, &pins, None).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("restored 1 scopes, 1 items"), "{}", out.stdout);
    let restored: Vec<String> = host_items(&dir, TARGET_PW).into_iter().map(|(_, l, _)| l).collect();
    assert_eq!(restored, ["before"]);
    let kept = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("vault.before-restore-"))
        .expect("the previous vault is kept");
    assert_eq!(host_items(&kept, TARGET_PW).len(), 2);
}

// ---- the Secret portal's keys ----

#[tokio::test(flavor = "multi_thread")]
async fn portal_keys_migrate_separately() {
    const APP: &str = "org.example.PortalApp";
    let old = old_provider(VaultState::Unlocked).await;
    // The provider's default collection holds a portal key (as gnome-keyring
    // keeps one) and an ordinary item.
    {
        let mut slot = old.vault.unlocker.vault().lock().unwrap();
        let v = slot.vault.as_mut().unwrap();
        add_portal_key(v, &Scope::Host, APP, 0x5a).unwrap();
        let mut s = v.scoped_admin(&AdminAuthority::offline(), Scope::Host).unwrap();
        s.ensure_namespace().unwrap();
        s.create_item(
            "login",
            "Mail",
            [("service".to_owned(), "mail".to_owned())].into(),
            &Secret::new(b"mail-pw".to_vec(), "text/plain"),
            false,
        )
        .unwrap();
    }
    let tmp = TempDir::new("migrate");
    let dir = tmp.path().join("vault");
    drop(Vault::create(&dir, TARGET_PW.as_bytes(), KdfParams::MINIMUM).unwrap());
    let pins = Pins::new();

    pins.set(&[TARGET_PW]);
    let out = admin(&["import"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("found 2 items in 1 collections"), "{}", out.stdout);
    assert!(out.stdout.contains("portal keys for org.example.PortalApp: 1 imported, 0 skipped"), "{}", out.stdout);
    let host = host_items(&dir, TARGET_PW);
    assert_eq!(host, [("Login".into(), "Mail".into(), b"mail-pw".to_vec())], "the key did not go into host");
    let portal = portal_items(&dir, TARGET_PW);
    assert_eq!(portal, [("Portal".into(), format!("Application key for {APP}"), vec![0x5a; 64])]);

    // Again: nothing new, and the key is skipped.
    pins.set(&[TARGET_PW]);
    let out = admin(&["import"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("imported 0 items into host (1 already there"), "{}", out.stdout);
    assert!(out.stdout.contains("portal keys for org.example.PortalApp: 0 imported, 1 skipped"), "{}", out.stdout);
    assert_eq!(portal_items(&dir, TARGET_PW).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_portal_keys_stop_the_import() {
    let old = old_provider(VaultState::Unlocked).await;
    {
        let mut slot = old.vault.unlocker.vault().lock().unwrap();
        let v = slot.vault.as_mut().unwrap();
        for byte in [1u8, 2] {
            add_portal_key(v, &Scope::Host, "org.example.Dup", byte).unwrap();
        }
    }
    let tmp = TempDir::new("migrate");
    let dir = tmp.path().join("vault");
    let pins = Pins::new();

    pins.set(&[]);
    let out = admin(&["import"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(!out.ok);
    assert!(out.stderr.contains("org.example.Dup"), "{}", out.stderr);
    assert!(!Vault::exists(&dir), "the import failed before creating the vault");
}

#[tokio::test(flavor = "multi_thread")]
async fn portal_keys_rollback_into_the_default_collection() {
    const APP: &str = "org.example.PortalApp";
    let tmp = TempDir::new("migrate");
    let dir = tmp.path().join("vault");
    {
        let mut v = Vault::create(&dir, TARGET_PW.as_bytes(), KdfParams::MINIMUM).unwrap();
        let mut s = v.scoped_admin(&AdminAuthority::offline(), Scope::Portal).unwrap();
        s.create_collection("Portal", "default").unwrap();
        s.create_item(
            "portal",
            "Application key for org.example.PortalApp",
            [
                ("app_id".to_owned(), APP.to_owned()),
                ("xdg:schema".to_owned(), "org.freedesktop.portal.Secret".to_owned()),
            ]
            .into(),
            &Secret::new(vec![7u8; 64], "application/octet-stream"),
            false,
        )
        .unwrap();
    }
    let pins = Pins::new();

    // An empty old provider: the key lands in its default collection.
    let old = old_provider(VaultState::Unlocked).await;
    pins.set(&[TARGET_PW]);
    let out = admin(&["export", "--scope", "portal"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    {
        let mut slot = old.vault.unlocker.vault().lock().unwrap();
        let v = slot.vault.as_mut().unwrap();
        let s = v.scoped_admin(&AdminAuthority::offline(), Scope::Host).unwrap();
        let found = s.search(&[("app_id".to_owned(), APP.to_owned())].into());
        assert_eq!(found.len(), 1, "{found:?}");
        let secret = s.read_secret(&found[0].0, &found[0].1).unwrap();
        assert_eq!(secret.value.as_slice(), vec![7u8; 64].as_slice(), "byte for byte");
    }

    // A different key for the same app in the provider stops the export
    // before anything is written.
    let old = old_provider(VaultState::Unlocked).await;
    {
        let mut slot = old.vault.unlocker.vault().lock().unwrap();
        let v = slot.vault.as_mut().unwrap();
        add_portal_key(v, &Scope::Host, APP, 9).unwrap();
    }
    pins.set(&[TARGET_PW]);
    let out = admin(&["export", "--scope", "portal"], &dir, &pins, Some(&old.bus.address)).await;
    assert!(!out.ok);
    assert!(out.stderr.contains(APP), "{}", out.stderr);
    {
        let mut slot = old.vault.unlocker.vault().lock().unwrap();
        let v = slot.vault.as_mut().unwrap();
        let s = v.scoped_admin(&AdminAuthority::offline(), Scope::Host).unwrap();
        let found = s.search(&[("app_id".to_owned(), APP.to_owned())].into());
        assert_eq!(found.len(), 1, "only the provider's own key is there: {found:?}");
    }
}
