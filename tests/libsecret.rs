//! Compatibility with libsecret: drives the service with `secret-tool`, a
//! real libsecret client, on a private bus. Callers are identified by the
//! production resolver (they are host processes).
//!
//! Skipped (with a message) when `secret-tool` is not on `PATH`. Note that
//! `secret-tool lock` itself is not used: before libsecret 0.21.8 it takes a
//! collection name instead of a path, and before 0.21.3 it crashes.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{PASSWORD, VaultFixture, VaultState};
use scopevault::identity::{BusIdentityResolver, Classifier, HostBaseline, IdentityPolicy, InstanceRecords};
use scopevault::service_api::SecretService;
use zbus::zvariant::OwnedObjectPath;

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Runs `secret-tool` against the private bus, with a time limit.
async fn secret_tool(address: &str, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let address = address.to_owned();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let stdin = stdin.map(<[u8]>::to_vec);
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new("timeout")
            .arg("30")
            .arg("secret-tool")
            .args(&args)
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        if let Some(data) = stdin {
            input.write_all(&data).unwrap();
        }
        drop(input);
        let out = child.wait_with_output().unwrap();
        Output {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_tool_store_lookup_lock_unlock_cancel() {
    if Command::new("secret-tool").arg("--version").output().is_err() {
        eprintln!("secret-tool not found; skipping the libsecret compatibility test");
        return;
    }
    let bus = common::TestBus::start();
    let conn = bus.connect().await;
    let baseline = HostBaseline::capture().unwrap();
    let uid = baseline.uid;
    let classifier = Classifier {
        baseline,
        instances: InstanceRecords::new(bus.runtime_dir(), uid),
        policy: IdentityPolicy::default(),
    };
    let resolver = BusIdentityResolver::new(&conn, classifier).await.unwrap();
    let vault = VaultFixture::new(VaultState::Missing);
    let service = SecretService::new(conn.clone(), resolver, vault.unlocker.clone());
    tokio::spawn(service.clone().start().await.unwrap());
    conn.request_name("org.freedesktop.secrets").await.unwrap();
    let addr = bus.address.as_str();
    let attrs = |kind: &'static str| ["app", "scopevault-test", "kind", kind];
    let lookup = |kind: &'static str| async move {
        let mut args = vec!["lookup"];
        args.extend(attrs(kind));
        secret_tool(addr, &args, None).await
    };
    let store = |kind: &'static str, value: &'static [u8]| async move {
        let mut args = vec!["store", "--label=scopevault test"];
        args.extend(attrs(kind));
        secret_tool(addr, &args, Some(value)).await
    };

    // First store: the vault is created (new password), then libsecret
    // creates the default collection after `UnknownObject`.
    vault.set_pins(&[PASSWORD]);
    let r = store("one", b"secret one").await;
    assert!(r.ok, "store: {}", r.stderr);
    assert_eq!(lookup("one").await.stdout, "secret one");
    assert_eq!(vault.dialogs(), 1);

    // Replace, Unicode, search, clear.
    assert!(store("one", b"replaced").await.ok);
    assert_eq!(lookup("one").await.stdout, "replaced");
    let unicode = "p\u{e4}ssw\u{f6}rd \u{1f511}";
    assert!(store("unicode", unicode.as_bytes()).await.ok);
    assert_eq!(lookup("unicode").await.stdout, unicode);
    let mut search = vec!["search", "--all"];
    search.extend(attrs("one"));
    let r = secret_tool(addr, &search, None).await;
    assert_eq!(r.stdout.lines().filter(|l| l.starts_with("[/")).count(), 1, "{}", r.stdout);
    assert!(store("gone", b"bye").await.ok);
    assert_eq!(lookup("gone").await.stdout, "bye");
    let mut clear = vec!["clear"];
    clear.extend(attrs("gone"));
    assert!(secret_tool(addr, &clear, None).await.ok);
    let r = lookup("gone").await;
    assert_eq!(r.stdout, "");
    assert!(!r.stderr.contains("rror"), "a missing item is not an error: {}", r.stderr);

    // Logical lock: lookup unlocks the collection through a prompt that
    // asks for the password again.
    let m = conn
        .call_method(
            Some("org.freedesktop.secrets"),
            "/org/freedesktop/secrets",
            Some("org.freedesktop.Secret.Service"),
            "Lock",
            &(vec![OwnedObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap()],),
        )
        .await
        .unwrap();
    let (locked, _): (Vec<OwnedObjectPath>, OwnedObjectPath) = m.body().deserialize().unwrap();
    assert_eq!(locked.len(), 1);
    vault.set_pins(&[PASSWORD]);
    assert_eq!(lookup("one").await.stdout, "replaced");
    assert_eq!(vault.dialogs(), 2);
    assert!(vault.log().contains("locked collections"));

    // Global lock (as after a restart): wrong, then right password.
    vault.lock_vault();
    vault.set_pins(&["wrong", PASSWORD]);
    assert_eq!(lookup("one").await.stdout, "replaced");
    assert_eq!(vault.dialogs(), 4);

    // Cancel: "locked" error, and no second dialog during the cooldown.
    vault.lock_vault();
    vault.set_pins(&["CANCEL"]);
    let r = lookup("one").await;
    assert!(!r.ok && r.stdout.is_empty());
    assert!(r.stderr.contains("locked"), "{}", r.stderr);
    let r = lookup("one").await;
    assert!(r.stderr.contains("locked"), "{}", r.stderr);
    assert_eq!(vault.dialogs(), 5);
}
