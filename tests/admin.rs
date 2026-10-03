//! The administrative socket and `scopevault-admin`, through the
//! production identity classifier.
//!
//! `scopevault-admin` runs as a separate process, on the host or inside the
//! simulated sandboxes of `tests/support/fake-flatpak.sh`, which can reach
//! the socket (the sandbox binds the host's /tmp and /home). Only the host
//! process may be served.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use common::tempdir::TempDir;
use common::{PASSWORD, TestBus, VaultFixture, VaultState};
use scopevault::admin::server::{AdminServer, BoundSocket, PeerClassifier, bind};
use scopevault::identity::{BusIdentityResolver, Classifier, HostBaseline, IdentityPolicy, InstanceRecords};
use scopevault::service_api::SecretService;
use scopevault::store::Vault;

const ADMIN: &str = env!("CARGO_BIN_EXE_scopevault-admin");
const CLIENT: &str = env!("CARGO_BIN_EXE_scopevault-client");
const DEST: &str = "org.freedesktop.secrets";
const DENIED: &str = "access denied: only host processes may use the administrative interface";
const A: &str = "org.example.Alpha";

struct Env {
    bus: Arc<TestBus>,
    vault: VaultFixture,
    tmp: TempDir,
    socket: PathBuf,
    _bound: Arc<BoundSocket>,
    next_instance: AtomicU32,
}

#[derive(Clone)]
enum Who {
    Host,
    Sandbox(&'static str, &'static str),
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
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

    let tmp = TempDir::new("admin");
    let socket = tmp.path().join("run").join("admin");
    let bound = Arc::new(bind(&socket).unwrap());
    let classify: PeerClassifier = {
        let r = resolver.clone();
        Arc::new(move |creds| r.classifier().classify(creds).result)
    };
    let server = AdminServer::new(classify, vault.unlocker.clone(), service);
    let b = bound.clone();
    tokio::spawn(async move { server.serve(&b.listener).await });
    Env { bus, vault, tmp, socket, _bound: bound, next_instance: AtomicU32::new(500) }
}

impl Env {
    fn command(&self, who: &Who, program: &str, args: &[&str]) -> Command {
        let mut cmd = match who {
            Who::Host => Command::new(program),
            Who::Sandbox(mode, app) => {
                let instance = self.next_instance.fetch_add(1, Ordering::Relaxed).to_string();
                let mut c = Command::new(common::support_script("fake-flatpak.sh"));
                c.args([mode, app, instance.as_str()]).arg(self.bus.runtime_dir()).arg("--").arg(program);
                c
            }
        };
        cmd.args(args).env("DBUS_SESSION_BUS_ADDRESS", &self.bus.address).stdin(Stdio::null());
        cmd
    }

    async fn admin(&self, who: &Who, args: &[&str]) -> Out {
        let mut full = vec!["--socket", self.socket.to_str().unwrap()];
        full.extend_from_slice(args);
        let mut cmd = self.command(who, ADMIN, &full);
        let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
        Out {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Runs `scopevault-client`; returns its output lines.
    async fn client(&self, who: &Who, steps: &[&str]) -> Vec<String> {
        let mut cmd = self.command(who, CLIENT, steps);
        let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
        String::from_utf8_lossy(&out.stdout).lines().map(str::to_owned).collect()
    }
}

fn field(line: &str, n: usize) -> &str {
    line.split('\t').nth(n).unwrap_or("")
}

#[tokio::test(flavor = "multi_thread")]
async fn only_host_processes_are_served() {
    let e = env(VaultState::Unlocked).await;
    let dir_mode = std::fs::metadata(e.socket.parent().unwrap()).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);

    let out = e.admin(&Who::Host, &["status"]).await;
    assert!(out.ok, "{}", out.stderr);
    assert!(out.stdout.contains("unlocked"), "{}", out.stdout);

    // A Flatpak-like sandbox that can reach the socket, and an unknown
    // sandbox, are refused, for harmless and harmful requests alike.
    for who in [Who::Sandbox("ok", A), Who::Sandbox("plain", A), Who::Sandbox("no-record", A)] {
        for args in [&["status"][..], &["lock"], &["scopes"], &["reset-scope", "host"]] {
            let out = e.admin(&who, args).await;
            assert!(!out.ok, "{args:?} succeeded in a sandbox: {}", out.stdout);
            assert!(out.stderr.contains(DENIED), "{args:?}: {}", out.stderr);
        }
    }
    assert!(e.vault.unlocked(), "nothing a sandbox sent had an effect");
    assert_eq!(e.vault.dialogs(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_are_refused() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let e = env(VaultState::Unlocked).await;
    let requests: [&[u8]; 3] =
        [b"{\"op\":\"list\",\"scope\":\"host\",\"extra\":1}\n", b"not json\n", b"{\"op\":\"export-everything\"}\n"];
    for req in requests {
        let mut s = tokio::net::UnixStream::connect(&e.socket).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).await.unwrap();
        assert!(reply.contains("\"reply\":\"error\"") && reply.contains("bad request"), "{reply}");
    }
    // An overlong request.
    let mut s = tokio::net::UnixStream::connect(&e.socket).await.unwrap();
    let _ = s.write_all(&vec![b'x'; 70 * 1024]).await;
    let mut reply = String::new();
    let _ = s.read_to_string(&mut reply).await;
    assert!(reply.contains("line too long"), "{reply}");
}

#[tokio::test(flavor = "multi_thread")]
async fn global_lock_needs_a_new_unlock_and_tells_clients() {
    let e = env(VaultState::Unlocked).await;
    let store = e.client(&Who::Host, &["store", "default", "h", "host-secret", "k=v"]).await;
    assert_eq!(field(&store[0], 1), "ok", "{store:?}");
    // A client that is connected while the lock happens.
    let watcher = e.command(&Who::Host, CLIENT, &["list", "watch", "3000"]).stdout(Stdio::piped()).spawn().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let out = e.admin(&Who::Host, &["lock"]).await;
    assert_eq!(out.stdout.trim(), "locked", "{}", out.stderr);
    assert!(!e.vault.unlocked());
    assert_eq!(e.admin(&Who::Host, &["lock"]).await.stdout.trim(), "was not unlocked");
    let watched = tokio::task::spawn_blocking(move || watcher.wait_with_output().unwrap()).await.unwrap();
    let watched = String::from_utf8_lossy(&watched.stdout);
    // The client prints the signal's signature, not its values.
    assert!(
        watched.contains(
            "path=/org/freedesktop/secrets/collection/login member=org.freedesktop.DBus.Properties.PropertiesChanged"
        ),
        "{watched}"
    );

    // Nothing is returned until the password is entered again.
    e.vault.set_pins(&["CANCEL"]);
    let r = e.client(&Who::Host, &["lookup", "k=v"]).await;
    assert_eq!(field(&r[0], 1), "error", "{r:?}");
    assert!(!e.vault.unlocked());
    // An explicit Unlock (as libsecret sends) shows the dialog again.
    e.vault.set_pins(&[PASSWORD]);
    let r = e.client(&Who::Host, &["unlock", "/org/freedesktop/secrets/aliases/default", "lookup", "k=v"]).await;
    assert_eq!(field(&r[1], 2), "host-secret", "{r:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_opens_the_dialog_only_while_locked() {
    let e = env(VaultState::Locked).await;
    e.vault.set_pins(&["CANCEL"]);
    let out = e.admin(&Who::Host, &["unlock"]).await;
    assert!(!out.ok && out.stderr.contains("cancelled"), "{}", out.stderr);
    assert!(!e.vault.unlocked());

    e.vault.set_pins(&["wrong", PASSWORD]);
    let out = e.admin(&Who::Host, &["unlock"]).await;
    assert_eq!(out.stdout.trim(), "unlocked", "{}", out.stderr);
    assert!(e.vault.unlocked());
    let dialogs = e.vault.dialogs();
    let out = e.admin(&Who::Host, &["unlock"]).await;
    assert_eq!(out.stdout.trim(), "was already unlocked", "{}", out.stderr);
    assert_eq!(e.vault.dialogs(), dialogs, "no dialog while unlocked");

    let out = e.admin(&Who::Sandbox("ok", A), &["unlock"]).await;
    assert!(!out.ok && out.stderr.contains(DENIED), "{}", out.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn moving_items_needs_the_password() {
    let e = env(VaultState::Unlocked).await;
    let a = Who::Sandbox("ok", A);
    let r = e.client(&a, &["store", "default", "a", "alpha-secret", "k=v"]).await;
    assert_eq!(field(&r[0], 1), "ok", "{r:?}");
    let item = field(&r[0], 2).rsplit('/').next().unwrap().to_owned();

    let scope = format!("flatpak/{A}");
    let listed = e.admin(&Who::Host, &["list", &scope]).await;
    assert!(listed.stdout.contains(&format!("login/{item}")) && listed.stdout.contains("k=v"), "{}", listed.stdout);
    assert!(!listed.stdout.contains("alpha-secret"), "listings never show secrets");
    let scopes = e.admin(&Who::Host, &["scopes"]).await;
    assert!(scopes.stdout.contains(&scope), "{}", scopes.stdout);

    // Cancelled: nothing moves.
    e.vault.set_pins(&["CANCEL"]);
    let spec = format!("login/{item}");
    let out = e.admin(&Who::Host, &["move", &scope, "host", &spec]).await;
    assert!(!out.ok && out.stderr.contains("cancelled"), "{}", out.stderr);
    assert!(e.vault.log().contains("move 1 item from flatpak/org.example.Alpha to host"), "{}", e.vault.log());
    // A missing item fails before any dialog.
    let dialogs = e.vault.dialogs();
    let out = e.admin(&Who::Host, &["move", &scope, "host", "login/ffff"]).await;
    assert!(out.stderr.contains("has no item"), "{}", out.stderr);
    assert_eq!(e.vault.dialogs(), dialogs);

    e.vault.set_pins(&["wrong", PASSWORD]);
    let out = e.admin(&Who::Host, &["move", &scope, "host", &spec]).await;
    assert!(out.ok, "{}", out.stderr);
    let r = e.client(&Who::Host, &["lookup", "k=v"]).await;
    assert_eq!(field(&r[0], 2), "alpha-secret", "{r:?}");
    let r = e.client(&a, &["search", "k=v"]).await;
    assert_eq!(field(&r[0], 2), " | ", "A no longer has it: {r:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn resetting_a_scope_needs_the_password() {
    let e = env(VaultState::Unlocked).await;
    let a = Who::Sandbox("ok", A);
    e.client(&a, &["store", "default", "a", "alpha-secret", "k=v"]).await;
    let scope = format!("flatpak/{A}");
    e.vault.set_pins(&["CANCEL"]);
    assert!(!e.admin(&Who::Host, &["reset-scope", &scope]).await.ok);
    e.vault.set_pins(&[PASSWORD]);
    let out = e.admin(&Who::Host, &["reset-scope", &scope]).await;
    assert_eq!(out.stdout.trim(), "deleted 1 items in 1 collections", "{}", out.stderr);
    let r = e.client(&a, &["search", "k=v"]).await;
    assert_eq!(field(&r[0], 2), " | ");
}

#[tokio::test(flavor = "multi_thread")]
async fn password_change_and_backup() {
    let e = env(VaultState::Unlocked).await;
    e.client(&Who::Host, &["store", "default", "h", "kept", "k=v"]).await;

    // A wrong current password three times changes nothing.
    e.vault.set_pins(&["no", "no", "no"]);
    assert!(!e.admin(&Who::Host, &["change-password"]).await.ok);
    e.vault.set_pins(&[PASSWORD, "new password"]);
    let out = e.admin(&Who::Host, &["change-password"]).await;
    assert_eq!(out.stdout.trim(), "password changed", "{}", out.stderr);

    let file = e.tmp.path().join("backup.db");
    let out = e.admin(&Who::Host, &["backup", file.to_str().unwrap()]).await;
    assert!(out.ok, "{}", out.stderr);
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    // An existing file is never replaced.
    assert!(!e.admin(&Who::Host, &["backup", file.to_str().unwrap()]).await.ok);

    // The backup is a complete vault that opens with the new password.
    let dir = e.tmp.path().join("restored");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy(&file, dir.join("vault.db")).unwrap();
    let mut v = Vault::open(&dir).unwrap();
    assert!(v.unlock(PASSWORD.as_bytes()).is_err());
    v.unlock(b"new password").unwrap();
    let s = v.scoped(&scopevault::identity::Principal::Host).unwrap();
    let (col, item, _) = s.search(&[("k".to_owned(), "v".to_owned())].into()).remove(0);
    assert_eq!(s.read_secret(&col, &item).unwrap().value.as_slice(), b"kept");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_daemon_cannot_take_the_socket() {
    let e = env(VaultState::Unlocked).await;
    let r = bind(&e.socket);
    assert!(r.is_err_and(|err| err.to_string().contains("another scopevault daemon")));
    // Still served.
    assert!(e.admin(&Who::Host, &["status"]).await.ok);
}

#[tokio::test(flavor = "multi_thread")]
async fn sharing_needs_the_password_and_grants_list_it() {
    let e = env(VaultState::Unlocked).await;
    let r = e.client(&Who::Host, &["store", "default", "h", "host-secret", "k=v"]).await;
    assert_eq!(field(&r[0], 1), "ok", "{r:?}");
    let item = field(&r[0], 2).rsplit('/').next().unwrap().to_owned();
    let spec = format!("login/{item}");
    let grantee = "flatpak/org.example.Alpha";

    // Cancelled dialog: nothing is shared.
    e.vault.set_pins(&["CANCEL"]);
    let out = e.admin(&Who::Host, &["share", "host", &spec, grantee]).await;
    assert!(!out.ok && out.stderr.contains("cancelled"), "{}", out.stderr);
    assert!(e.vault.log().contains("give flatpak/org.example.Alpha read access to"), "{}", e.vault.log());
    let out = e.admin(&Who::Host, &["grants"]).await;
    assert!(out.stdout.contains("no grants"), "{}", out.stdout);

    // The right password shares; --write is visible in the listing.
    e.vault.set_pins(&[PASSWORD]);
    let out = e.admin(&Who::Host, &["share", "host", &spec, grantee, "--write"]).await;
    assert!(out.ok, "{}\n{}", out.stdout, out.stderr);
    let grant = out.stdout.trim().strip_prefix("grant ").unwrap().to_owned();
    let out = e.admin(&Who::Host, &["grants"]).await;
    assert!(
        out.stdout.contains(&grant) && out.stdout.contains(grantee) && out.stdout.contains("write"),
        "{}",
        out.stdout
    );
    let out = e.admin(&Who::Host, &["grants", "host"]).await;
    assert!(out.stdout.contains(&grant), "{}", out.stdout);
    let out = e.admin(&Who::Host, &["grants", grantee]).await;
    assert!(out.stdout.contains(&grant), "{}", out.stdout);
    let out = e.admin(&Who::Host, &["grants", "host", "--json"]).await;
    assert!(out.stdout.contains("\"grants\""), "{}", out.stdout);

    // Unshare needs no dialog and removes the grant.
    let dialogs = e.vault.dialogs();
    let out = e.admin(&Who::Host, &["unshare", &grant]).await;
    assert!(out.ok, "{}", out.stderr);
    assert_eq!(e.vault.dialogs(), dialogs, "unshare shows no dialog");
    let out = e.admin(&Who::Host, &["grants"]).await;
    assert!(out.stdout.contains("no grants"), "{}", out.stdout);
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_wait_retries_the_connection_only() {
    let e = env(VaultState::Unlocked).await;
    // A socket path where nothing listens: `--wait 1` fails after about a
    // second, not at once and not after minutes.
    let missing = e.tmp.path().join("run").join("absent");
    let mut cmd = Command::new(ADMIN);
    cmd.args(["--socket", missing.to_str().unwrap(), "unlock", "--wait", "1"]).stdin(Stdio::null());
    let started = std::time::Instant::now();
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("cannot connect"), "{}", stderr);
    assert!(started.elapsed() >= std::time::Duration::from_millis(900), "{:?}", started.elapsed());
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());

    // The bounds of --wait are usage errors.
    for args in [vec!["unlock", "--wait", "0"], vec!["unlock", "--wait", "601"], vec!["unlock", "--wait", "x"]] {
        let out = e.admin(&Who::Host, &args).await;
        assert!(!out.ok, "{args:?}");
        assert!(out.stderr.contains("usage: scopevault-admin"), "{args:?}: {}", out.stderr);
    }

    // Without --wait, a missing socket fails at once.
    let mut cmd = Command::new(ADMIN);
    cmd.args(["--socket", missing.to_str().unwrap(), "unlock"]).stdin(Stdio::null());
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("cannot connect"), "{}", stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_wait_reopens_a_dialog_dismissed_at_once() {
    // At login gnome-shell cancels prompts it cannot show yet, within a
    // second or two; with --wait such a cancel is retried.
    let e = env(VaultState::Locked).await;
    e.vault.set_pins(&["CANCEL", PASSWORD]);
    let out = e.admin(&Who::Host, &["unlock", "--wait", "30"]).await;
    assert_eq!(out.stdout.trim(), "unlocked", "{}", out.stderr);
    assert!(out.stderr.contains("trying again"), "{}", out.stderr);
    assert_eq!(e.vault.dialogs(), 2);

    // A cancel that took as long as a person's is final, even with --wait.
    e.vault.lock_vault();
    e.vault.set_pins(&["SLOWCANCEL", PASSWORD]);
    let dialogs = e.vault.dialogs();
    let out = e.admin(&Who::Host, &["unlock", "--wait", "30"]).await;
    assert!(!out.ok && out.stderr.contains("cancelled"), "{}", out.stderr);
    assert_eq!(e.vault.dialogs(), dialogs + 1);
    assert!(!e.vault.unlocked());
}

#[tokio::test(flavor = "multi_thread")]
async fn json_replies_include_errors() {
    let e = env(VaultState::Locked).await;
    let json = |out: &Out| -> serde_json::Value {
        serde_json::from_str(&out.stdout).unwrap_or_else(|err| panic!("{err}: {}{}", out.stdout, out.stderr))
    };
    let out = e.admin(&Who::Host, &["status", "--json"]).await;
    assert!(out.ok);
    let v = json(&out);
    assert_eq!((v["reply"].as_str(), v["vault"].as_str()), (Some("status"), Some("locked")), "{v}");

    // A cancelled dialog is an error reply on stdout, not a message on stderr.
    e.vault.set_pins(&["CANCEL"]);
    let out = e.admin(&Who::Host, &["unlock", "--json"]).await;
    assert!(!out.ok);
    let v = json(&out);
    assert_eq!(v["reply"], "error");
    assert_eq!(v["message"], scopevault::admin::protocol::CANCELLED);

    e.vault.set_pins(&[PASSWORD]);
    let v = json(&e.admin(&Who::Host, &["unlock", "--json"]).await);
    assert_eq!((v["reply"].as_str(), v["message"].as_str()), (Some("done"), Some("unlocked")), "{v}");
    let file = e.tmp.path().join("backup.db");
    let v = json(&e.admin(&Who::Host, &["backup", file.to_str().unwrap(), "--json"]).await);
    assert_eq!(v["reply"], "done", "{v}");
    let v = json(&e.admin(&Who::Host, &["backup", file.to_str().unwrap(), "--json"]).await);
    assert!(v["message"].as_str().unwrap().contains("cannot create"), "{v}");

    // So is a daemon that cannot be reached.
    let mut cmd = Command::new(ADMIN);
    cmd.args(["--socket", e.tmp.path().join("nothing").to_str().unwrap(), "status", "--json"]);
    let out = tokio::task::spawn_blocking(move || cmd.output().unwrap()).await.unwrap();
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["message"].as_str().unwrap().contains("cannot connect"), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn resetting_a_scope_revokes_grants_to_it_even_if_it_holds_nothing() {
    let e = env(VaultState::Unlocked).await;
    let r = e.client(&Who::Host, &["store", "default", "h", "host-secret", "k=v"]).await;
    let item = field(&r[0], 2).rsplit('/').next().unwrap().to_owned();
    let grantee = "flatpak/org.example.Alpha";
    e.vault.set_pins(&[PASSWORD]);
    assert!(e.admin(&Who::Host, &["share", "host", &format!("login/{item}"), grantee]).await.ok);
    // Alpha never stored anything: it has no collections of its own.
    let listed = e.admin(&Who::Host, &["list", grantee]).await;
    assert!(listed.stdout.contains("no data"), "{}", listed.stdout);

    e.vault.set_pins(&[PASSWORD]);
    let out = e.admin(&Who::Host, &["reset-scope", grantee]).await;
    assert!(out.ok, "{}", out.stderr);
    assert!(e.vault.log().contains("revoke its access to 1 items shared with it"), "{}", e.vault.log());
    let out = e.admin(&Who::Host, &["grants"]).await;
    assert!(out.stdout.contains("no grants"), "{}", out.stdout);
    let r = e.client(&Who::Sandbox("ok", A), &["search", "k=v"]).await;
    assert_eq!(field(&r[0], 2), " | ", "Alpha no longer sees the item: {r:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn item_labels_in_dialogs_are_quoted_and_shortened() {
    let e = env(VaultState::Unlocked).await;
    let hostile = "x\" from host.\nUnlock to continue";
    // 900 bytes of the escaped text used to be cut inside a character.
    let long = format!("{}{}", "a".repeat(9), "é".repeat(2000));
    for (label, shown) in [(hostile, "“x' from host. Unlock to continue”"), (long.as_str(), "é…”")] {
        let r = e.client(&Who::Host, &["store", "default", label, "s", &format!("label={}", label.len())]).await;
        assert_eq!(field(&r[0], 1), "ok", "{r:?}");
        let item = field(&r[0], 2).rsplit('/').next().unwrap().to_owned();
        e.vault.set_pins(&[PASSWORD]);
        let out = e.admin(&Who::Host, &["share", "host", &format!("login/{item}"), "flatpak/org.example.Alpha"]).await;
        assert!(out.ok, "{}", out.stderr);
        assert!(e.vault.log().contains(shown), "{}", e.vault.log());
    }
}
