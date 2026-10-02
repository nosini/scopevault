//! Adversarial isolation tests through the production identity
//! resolver.
//!
//! Clients are separate processes running `scopevault-client`, on the host
//! or inside Flatpak-like sandboxes built by `tests/support/fake-flatpak.sh`
//! (see `identity_e2e.rs`). Nothing is substituted: callers are classified
//! from bus credentials and the kernel, exactly as in the daemon.
//!
//! The simulated sandboxes talk to the bus directly. Real Flatpaks talk
//! through xdg-dbus-proxy, which also refuses eavesdropping and
//! `BecomeMonitor`; that part is checked on the desktop by
//! `scripts/host-flatpak-check.sh`.

mod common;

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use common::{PASSWORD, TestBus, VaultFixture, VaultState};
use scopevault::identity::{BusIdentityResolver, Classifier, HostBaseline, IdentityPolicy, InstanceRecords};
use scopevault::service_api::SecretService;
use zbus::zvariant::Value;

const CLIENT: &str = env!("CARGO_BIN_EXE_scopevault-client");
const DEST: &str = "org.freedesktop.secrets";
const SERVICE: &str = "/org/freedesktop/secrets";
const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject: No such object";
const DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied: Caller could not be identified";
const A: &str = "org.example.Alpha";
const B: &str = "org.example.Beta";

/// Who runs a client.
#[derive(Clone)]
enum Who {
    Host,
    /// A sandbox: `fake-flatpak.sh` mode, app ID and instance ID.
    Sandbox(&'static str, &'static str, String),
}

struct Env {
    bus: Arc<TestBus>,
    service: Arc<SecretService<BusIdentityResolver>>,
    resolver: Arc<BusIdentityResolver>,
    vault: VaultFixture,
    service_name: String,
    next_instance: AtomicU32,
}

/// One line of client output.
#[derive(Debug, Clone)]
struct Step {
    name: String,
    ok: bool,
    out: String,
}

struct Output(Vec<Step>);

impl Output {
    /// The result of step `i`, which must have succeeded.
    fn ok(&self, i: usize) -> &str {
        let s = &self.0[i];
        assert!(s.ok, "step {i} ({}) failed: {}\nall steps: {:#?}", s.name, s.out, self.0);
        &s.out
    }

    /// The error of step `i`, which must have failed.
    fn err(&self, i: usize) -> &str {
        let s = &self.0[i];
        assert!(!s.ok, "step {i} ({}) succeeded: {}\nall steps: {:#?}", s.name, s.out, self.0);
        &s.out
    }
}

async fn env(state: VaultState) -> Env {
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
    let service = SecretService::new(conn.clone(), resolver.clone(), vault.unlocker.clone());
    tokio::spawn(service.clone().start().await.unwrap());
    conn.request_name(DEST).await.unwrap();
    let service_name = conn.unique_name().unwrap().to_string();
    Env { bus, service, resolver, vault, service_name, next_instance: AtomicU32::new(100) }
}

impl Env {
    fn flatpak(&self, app: &'static str) -> Who {
        self.sandbox("ok", app)
    }

    fn sandbox(&self, mode: &'static str, app: &'static str) -> Who {
        Who::Sandbox(mode, app, self.next_instance.fetch_add(1, Ordering::Relaxed).to_string())
    }

    fn command(&self, who: &Who, steps: &[&str]) -> Command {
        let mut cmd = match who {
            Who::Host => Command::new(CLIENT),
            Who::Sandbox(mode, app, instance) => {
                let mut c = Command::new(common::support_script("fake-flatpak.sh"));
                c.args([mode, app, instance.as_str()]).arg(self.bus.runtime_dir()).arg("--").arg(CLIENT);
                c
            }
        };
        cmd.args(steps).env("DBUS_SESSION_BUS_ADDRESS", &self.bus.address).stdin(Stdio::null());
        cmd
    }

    /// Runs a client to completion.
    async fn run(&self, who: &Who, steps: &[&str]) -> Output {
        let mut cmd = self.command(who, steps);
        let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
        let parsed = parse(&String::from_utf8_lossy(&out.stdout));
        assert!(!parsed.0.is_empty(), "client printed nothing\nstderr: {}", String::from_utf8_lossy(&out.stderr));
        parsed
    }

    /// Starts a client in the background.
    fn spawn(&self, who: &Who, steps: &[&str]) -> Child {
        self.command(who, steps).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
    }

    /// Waits until the service has forgotten every client connection.
    async fn all_connections_gone(&self) {
        for _ in 0..250 {
            if self.service.active_connections() == 0 && self.resolver.cached_connections() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "connections linger: {} tracked, {} cached identities",
            self.service.active_connections(),
            self.resolver.cached_connections()
        );
    }
}

fn parse(stdout: &str) -> Output {
    Output(
        stdout
            .lines()
            .filter_map(|l| {
                let mut f = l.splitn(3, '\t');
                let (name, status, out) = (f.next()?, f.next()?, f.next().unwrap_or(""));
                Some(Step { name: name.into(), ok: status == "ok", out: out.into() })
            })
            .collect(),
    )
}

async fn finish(child: Child) -> Output {
    let out = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap()).await.unwrap();
    parse(&String::from_utf8_lossy(&out.stdout))
}

/// Reads the first line of a background client's output.
async fn first_line(child: &mut Child) -> Step {
    let stdout = child.stdout.take().unwrap();
    // Byte by byte: a buffered reader could swallow later lines.
    let (line, stdout) = tokio::task::spawn_blocking(move || {
        let mut stdout = stdout;
        let mut line = Vec::new();
        let mut b = [0u8];
        while stdout.read(&mut b).unwrap() == 1 && b[0] != b'\n' {
            line.push(b[0]);
        }
        (String::from_utf8(line).unwrap(), stdout)
    })
    .await
    .unwrap();
    child.stdout = Some(stdout);
    parse(&line).0.remove(0)
}

const ATTRS: &str = "test=scopevault,user=alice";

#[tokio::test(flavor = "multi_thread")]
async fn identical_attributes_in_two_flatpaks_and_the_host_stay_separate() {
    let e = env(VaultState::Unlocked).await;
    for (who, secret) in [(Who::Host, "host-secret"), (e.flatpak(A), "alpha-secret"), (e.flatpak(B), "beta-secret")] {
        let out = e.run(&who, &["create", "Login", "default", "store", "default", "Entry", secret, ATTRS]).await;
        assert_eq!(out.ok(0), "/org/freedesktop/secrets/collection/login");
        out.ok(1);
    }
    // Fresh connections and instances, through the production resolver.
    for (who, secret) in [(Who::Host, "host-secret"), (e.flatpak(A), "alpha-secret"), (e.flatpak(B), "beta-secret")] {
        let out = e.run(&who, &["lookup", ATTRS, "search", "test=scopevault", "list"]).await;
        assert_eq!(out.ok(0), secret);
        let (unlocked, locked) = out.ok(1).split_once(" | ").unwrap();
        assert_eq!(unlocked.split(',').count(), 1, "exactly the caller's own item: {unlocked}");
        assert_eq!(locked, "");
        assert_eq!(out.ok(2), "/org/freedesktop/secrets/collection/login");
    }
    e.all_connections_gone().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_paths_look_exactly_like_missing_ones() {
    let e = env(VaultState::Unlocked).await;
    let a = e
        .run(
            &e.flatpak(A),
            &["create", "Login", "default", "store", "default", "A", "alpha-secret", ATTRS, "create", "Only A", ""],
        )
        .await;
    let a_item = a.ok(1).replace("/aliases/default/", "/collection/login/");
    assert_eq!(a.ok(2), "/org/freedesktop/secrets/collection/only_a");
    let b = e.run(&e.flatpak(B), &["create", "Login", "default", "store", "default", "B", "beta-secret", ATTRS]).await;
    let b_item = b.ok(1).replace("/aliases/default/", "/collection/login/");
    let b_id = b_item.rsplit('/').next().unwrap().to_owned();
    let missing_item = "/org/freedesktop/secrets/collection/login/i00000000000000000000000000000000";
    let a_col = "/org/freedesktop/secrets/collection/only_a";
    let missing_col = "/org/freedesktop/secrets/collection/nothing_here";
    let secrets_arg = format!("{a_item},{b_item}");
    let lock_arg = format!("{a_item},{a_col}");

    #[rustfmt::skip]
    let steps: Vec<&str> = vec![
        "secret", &a_item,                                          // 0
        "secret", missing_item,                                     // 1
        "get", &a_item, "org.freedesktop.Secret.Item", "Label",     // 2
        "getall", a_col, "org.freedesktop.Secret.Collection",       // 3
        "getall", missing_col, "org.freedesktop.Secret.Collection", // 4
        "introspect", a_col,                                        // 5
        "introspect", "/org/freedesktop/secrets/collection",        // 6
        "introspect", "/org/freedesktop/secrets/collection/login",  // 7
        "secrets", &secrets_arg,                                    // 8
        "lock", &lock_arg,                                          // 9
        "set-alias", "mine", a_col,                                 // 10
        "set-label", &a_item, "pwned",                              // 11
        "delete", &a_item,                                          // 12
        "delete", a_col,                                            // 13
        "search", ATTRS,                                            // 14
        "unlock", &lock_arg,                                        // 15
    ];
    for who in [e.flatpak(B), Who::Host] {
        let out = e.run(&who, &steps).await;
        for i in [0, 1, 2, 3, 4, 5, 11, 12, 13] {
            assert_eq!(out.err(i), UNKNOWN_OBJECT, "step {i}");
        }
        assert_eq!(out.err(10), "org.freedesktop.Secret.Error.NoSuchObject: No such object");
        assert_eq!(out.ok(9), "", "nothing foreign is locked");
        assert_eq!(out.ok(15), "");
        if matches!(who, Who::Host) {
            // The host has only its own, empty, login collection.
            assert_eq!(out.ok(6), "login");
            assert_eq!(out.ok(7), "");
            assert_eq!(out.ok(8), "");
            assert_eq!(out.ok(14), " | ");
        } else {
            assert_eq!(out.ok(6), "login");
            assert_eq!(out.ok(7), b_id);
            assert_eq!(out.ok(8), format!("{b_item}=beta-secret"));
            assert_eq!(out.ok(14), format!("{b_item} | "));
        }
    }

    // A's objects are untouched.
    let a = e
        .run(
            &e.flatpak(A),
            &[
                "secret",
                &a_item,
                "get",
                a_col,
                "org.freedesktop.Secret.Collection",
                "Locked",
                "list",
                "get",
                &a_item,
                "org.freedesktop.Secret.Item",
                "Label",
            ],
        )
        .await;
    assert_eq!(a.ok(0), "alpha-secret");
    assert_eq!(a.ok(1), "false");
    assert_eq!(a.ok(2), format!("/org/freedesktop/secrets/collection/login,{a_col}"));
    assert_eq!(a.ok(3), "\"A\"");
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_app_ids_and_attributes_change_nothing() {
    let e = env(VaultState::Unlocked).await;
    let a = e.run(&e.flatpak(A), &["create", "Login", "default", "store", "default", "A", "alpha-secret", ATTRS]).await;
    a.ok(1);
    // B labels its item as if it were A's.
    let forged = format!("app_id={A},xdg:schema={A}.Password,flatpak-id={A}");
    let b = e.run(&e.flatpak(B), &["create", "Login", "default", "store", "default", A, "beta-secret", &forged]).await;
    b.ok(1);
    let out = e.run(&e.flatpak(A), &["search", &forged, "lookup", ATTRS]).await;
    assert_eq!(out.ok(0), " | ", "A does not see B's item, whatever its attributes claim");
    assert_eq!(out.ok(1), "alpha-secret");

    // The environment is not identity: B's sandbox with A's app ID in it.
    let mut cmd = e.command(&e.flatpak(B), &["lookup", ATTRS, "search", &forged]);
    cmd.env("FLATPAK_ID", A).env("SCOPEVAULT_APP_ID", A);
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
    let out = parse(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(out.ok(0), "", "B's lookup does not find A's secret");
    assert!(out.ok(1).ends_with(" | ") && out.ok(1).len() > 3, "B finds its own item: {}", out.ok(1));

    // Malformed or unverifiable identity is denied, never treated as host.
    let mut denied = vec![];
    for mode in ["plain", "no-record", "mismatch", "runtime", "symlink"] {
        denied.push((mode, e.sandbox(mode, A)));
    }
    // A finished instance's ID, presented by a process that is not that
    // instance (like a proxy left over after its sandbox exited).
    let finished = e.flatpak(A);
    e.run(&finished, &["list"]).await.ok(0);
    let Who::Sandbox(_, _, id) = &finished else { unreachable!() };
    denied.push(("proxy of a finished instance", Who::Sandbox("proxy", A, id.clone())));
    for (what, who) in denied {
        let out = e.run(&who, &["list", "search", ATTRS, "introspect", SERVICE]).await;
        for i in 0..3 {
            assert_eq!(out.err(i), DENIED, "{what}, step {i}");
        }
    }
    e.all_connections_gone().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn signals_reach_only_the_owning_scope_and_are_never_broadcast() {
    let e = env(VaultState::Unlocked).await;
    let a_col = e.run(&e.flatpak(A), &["create", "Login", "default"]).await.ok(0).to_owned();
    e.run(&e.flatpak(B), &["create", "Login", "default"]).await.ok(0);

    // Watchers call once (to be identified), then listen to every signal.
    let watch = ["list", "watch", "2500"];
    let a2 = e.spawn(&e.flatpak(A), &watch);
    let b = e.spawn(&e.flatpak(B), &watch);
    let host = e.spawn(&Who::Host, &watch);
    let denied = e.spawn(&e.sandbox("plain", A), &watch);
    let silent = e.spawn(&e.flatpak(B), &["watch", "2500"]);
    // The trusted harness monitors the whole bus (as any host process can).
    let monitor = e.spawn(&Who::Host, &["monitor", "3000"]);
    tokio::time::sleep(Duration::from_millis(800)).await;

    let item_ref = format!("{a_col}/");
    let a = e
        .run(
            &e.flatpak(A),
            &[
                "store",
                "default",
                "Entry",
                "alpha-secret",
                ATTRS,
                "set-label",
                &a_col,
                "Renamed",
                "lock",
                &a_col,
                "create",
                "Second",
                "",
            ],
        )
        .await;
    let item = a.ok(0).to_owned();
    assert!(item.contains("/aliases/default/") || item.starts_with(&item_ref));
    e.run(&e.flatpak(A), &["delete", "/org/freedesktop/secrets/collection/second"]).await.ok(0);

    let a2 = finish(a2).await;
    let seen = a2.ok(1);
    for member in ["ItemCreated", "CollectionChanged", "CollectionCreated", "CollectionDeleted", "PropertiesChanged"] {
        assert!(seen.contains(member), "A's other instance missed {member}: {seen}");
    }
    assert!(!seen.contains("to=broadcast"), "{seen}");
    for (who, out) in [("B", finish(b).await), ("host", finish(host).await)] {
        out.ok(0);
        assert_eq!(out.ok(1), "0 message(s)", "{who} saw signals of A");
    }
    let denied = finish(denied).await;
    assert_eq!(denied.err(0), DENIED);
    assert_eq!(denied.ok(1), "0 message(s)");
    assert_eq!(finish(silent).await.ok(0), "0 message(s)", "a connection that never called gets nothing");

    let monitor = finish(monitor).await;
    let all = monitor.ok(0);
    let from_service: Vec<&str> = all
        .split(" | ")
        .filter(|m| m.starts_with("Signal") && m.contains(&format!("from={}", e.service_name)))
        .collect();
    assert!(from_service.len() >= 5, "monitor saw the service's signals: {all}");
    for m in from_service {
        assert!(!m.contains("to=broadcast"), "broadcast signal: {m}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_die_with_their_connection_and_reconnects_start_fresh() {
    let e = env(VaultState::Unlocked).await;
    let a = e.run(&e.flatpak(A), &["create", "Login", "default", "store", "default", "A", "alpha-secret", ATTRS]).await;
    let item = a.ok(1).to_owned();

    // A long-lived connection of A holds a session.
    let mut holder = e.spawn(&e.flatpak(A), &["session", "secret", &item, "sleep", "1500"]);
    let s = first_line(&mut holder).await;
    assert!(s.ok, "{s:?}");
    let session = s.out;
    for who in [e.flatpak(A), e.flatpak(B), Who::Host] {
        let out = e.run(&who, &["use-session", &session, "secret", &item, "secrets", &item]).await;
        let expected = if matches!(who, Who::Sandbox(_, a, _) if a == A) {
            "org.freedesktop.Secret.Error.NoSession: No such session"
        } else {
            UNKNOWN_OBJECT
        };
        assert_eq!(out.err(1), expected);
        assert_eq!(out.err(2), "org.freedesktop.Secret.Error.NoSession: No such session");
    }
    let held = finish(holder).await;
    assert_eq!(held.ok(0), "alpha-secret", "the holder itself can use it");

    // After the holder left, its session is gone for everyone, and a new
    // connection of the same app is identified afresh.
    e.all_connections_gone().await;
    assert_eq!(e.service.open_sessions(), 0);
    let out = e.run(&e.flatpak(A), &["use-session", &session, "secret", &item, "session", "secret", &item]).await;
    assert_eq!(out.err(1), "org.freedesktop.Secret.Error.NoSession: No such session");
    assert_eq!(out.ok(3), "alpha-secret");
    e.all_connections_gone().await;
}

/// Many short-lived connections (in this process, so classified as host):
/// every one is served, and nothing is left behind.
#[tokio::test(flavor = "multi_thread")]
async fn connection_churn_leaves_nothing_behind() {
    let e = env(VaultState::Unlocked).await;
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let bus = e.bus.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..15 {
                let c = bus.connect().await;
                let m = c
                    .call_method(
                        Some(DEST),
                        SERVICE,
                        Some("org.freedesktop.Secret.Service"),
                        "OpenSession",
                        &("plain", Value::from("")),
                    )
                    .await
                    .unwrap();
                drop(m);
                // Leave with a request still in flight half of the time.
                if rand_bit() {
                    c.call_method(Some(DEST), SERVICE, Some("org.freedesktop.DBus.Peer"), "Ping", &()).await.unwrap();
                } else {
                    let m = zbus::message::Message::method_call(SERVICE, "SearchItems")
                        .unwrap()
                        .destination(DEST)
                        .unwrap()
                        .interface("org.freedesktop.Secret.Service")
                        .unwrap()
                        .build(&(std::collections::HashMap::<&str, &str>::new(),))
                        .unwrap();
                    c.send(&m).await.unwrap();
                }
                c.close().await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    e.all_connections_gone().await;
    assert_eq!(e.service.open_sessions(), 0);

    // One connection flooding requests: every request is answered (served
    // or refused), none hangs.
    let c = e.bus.connect().await;
    let calls = (0..200).map(|_| {
        c.call_method(
            Some(DEST),
            SERVICE,
            Some("org.freedesktop.DBus.Properties"),
            "GetAll",
            &("org.freedesktop.Secret.Service",),
        )
    });
    let results = tokio::time::timeout(Duration::from_secs(20), futures_util::future::join_all(calls)).await.unwrap();
    for r in &results {
        match r {
            Ok(_) => {}
            Err(zbus::Error::MethodError(n, _, _)) if n.as_str() == "org.freedesktop.DBus.Error.LimitsExceeded" => {}
            Err(other) => panic!("unexpected result: {other}"),
        }
    }
    assert!(results.iter().any(Result::is_ok));
}

fn rand_bit() -> bool {
    let mut b = [0u8];
    getrandom::fill(&mut b).unwrap();
    b[0] & 1 == 1
}

/// A Flatpak that locks or unlocks its collection affects no other scope,
/// and needs the master password to reopen it.
#[tokio::test(flavor = "multi_thread")]
async fn locking_is_per_collection_and_per_scope() {
    let e = env(VaultState::Unlocked).await;
    for (who, secret) in [(e.flatpak(A), "alpha-secret"), (e.flatpak(B), "beta-secret"), (Who::Host, "host-secret")] {
        e.run(&who, &["create", "Login", "default", "store", "default", "x", secret, ATTRS]).await.ok(1);
    }
    let col = "/org/freedesktop/secrets/collection/login";
    let out = e.run(&e.flatpak(A), &["lock", col]).await;
    assert_eq!(out.ok(0), col);
    for (who, secret) in [(e.flatpak(B), "beta-secret"), (Who::Host, "host-secret")] {
        let out = e.run(&who, &["get", col, "org.freedesktop.Secret.Collection", "Locked", "lookup", ATTRS]).await;
        assert_eq!(out.ok(0), "false");
        assert_eq!(out.ok(1), secret);
    }
    assert_eq!(e.vault.dialogs(), 0, "other scopes needed no dialog");
    // A's lookup reopens the collection through a prompt asking for the
    // master password.
    e.vault.set_pins(&[PASSWORD]);
    let out = e.run(&e.flatpak(A), &["get", col, "org.freedesktop.Secret.Collection", "Locked", "lookup", ATTRS]).await;
    assert_eq!(out.ok(0), "true");
    assert_eq!(out.ok(1), "alpha-secret");
    assert!(e.vault.dialogs() >= 1);
}
