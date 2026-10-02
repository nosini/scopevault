//! End-to-end: the production identity resolver and dispatcher, with clients
//! running on the host and inside Flatpak-like sandboxes built by
//! `tests/support/fake-flatpak.sh` (user + mount namespaces, a root with
//! `/.flatpak-info`, and a Flatpak-style instance record).
//!
//! Requires unprivileged user namespaces and a dbus-daemon that reports
//! `ProcessFD` (see `common::TestBus`).
//!
//! Sandboxed clients are this test binary, re-executed with
//! `SCOPEVAULT_TEST_CLIENT` set, running only the `client_helper` test.

mod common;

use std::collections::HashMap;
use std::process::Command;

use scopevault::identity::{BusIdentityResolver, Classifier, HostBaseline, IdentityPolicy, InstanceRecords};
use scopevault::service_api::SecretService;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const DEST: &str = "org.freedesktop.secrets";
const SERVICE: &str = "/org/freedesktop/secrets";

/// Client side, run in a child process. Performs the action in
/// `SCOPEVAULT_TEST_CLIENT` and prints one `RESULT:` line.
#[test]
fn client_helper() {
    let Ok(action) = std::env::var("SCOPEVAULT_TEST_CLIENT") else { return };
    let address = std::env::var("SCOPEVAULT_TEST_BUS").unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let out = rt.block_on(async move {
        let c = zbus::connection::Builder::address(address.as_str()).unwrap().build().await.unwrap();
        let result = match action.split_once(':') {
            Some(("create", label)) => {
                let mut props: HashMap<&str, Value> = HashMap::new();
                props.insert("org.freedesktop.Secret.Collection.Label", Value::from(label));
                c.call_method(
                    Some(DEST),
                    SERVICE,
                    Some("org.freedesktop.Secret.Service"),
                    "CreateCollection",
                    &(props, ""),
                )
                .await
                .map(|m| m.body().deserialize::<(OwnedObjectPath, OwnedObjectPath)>().unwrap().0.to_string())
            }
            _ => c
                .call_method(
                    Some(DEST),
                    SERVICE,
                    Some("org.freedesktop.DBus.Properties"),
                    "Get",
                    &("org.freedesktop.Secret.Service", "Collections"),
                )
                .await
                .map(|m| {
                    let (v,): (OwnedValue,) = m.body().deserialize().unwrap();
                    let mut p: Vec<String> =
                        Vec::<OwnedObjectPath>::try_from(v).unwrap().into_iter().map(|p| p.to_string()).collect();
                    p.sort();
                    p.join(",")
                }),
        };
        match result {
            Ok(s) => format!("ok {s}"),
            Err(zbus::Error::MethodError(name, _, _)) => format!("error {name}"),
            Err(e) => format!("transport {e}"),
        }
    });
    println!("RESULT: {out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn real_identity_scopes_host_and_flatpak_callers() {
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
    let vault = common::VaultFixture::new(common::VaultState::Unlocked);
    let service = SecretService::new(conn.clone(), resolver, vault.unlocker.clone());
    tokio::spawn(service.clone().start().await.unwrap());
    conn.request_name(DEST).await.unwrap();

    let col = |n: &str| format!("/org/freedesktop/secrets/collection/{n}");
    // Clients are separate processes; run them off the async runtime.
    let target = Target { address: bus.address.clone(), runtime: bus.runtime_dir() };
    let res = tokio::task::spawn_blocking(move || {
        vec![
            run_client(&target, None, "create:Host Only"),
            run_client(&target, Some(("ok", "org.example.Alpha", "101")), "create:Alpha Only"),
            run_client(&target, Some(("ok", "org.example.Alpha", "102")), "list"),
            run_client(&target, Some(("ok", "org.example.Beta", "103")), "list"),
            run_client(&target, None, "list"),
            run_client(&target, Some(("plain", "org.example.Alpha", "104")), "list"),
            run_client(&target, Some(("no-record", "org.example.Alpha", "105")), "list"),
            run_client(&target, Some(("mismatch", "org.example.Alpha", "106")), "list"),
        ]
    })
    .await
    .unwrap();

    assert_eq!(res[0], format!("ok {}", col("host_only")));
    assert_eq!(res[1], format!("ok {}", col("alpha_only")));
    // A second instance of the same app shares its scope.
    assert_eq!(res[2], format!("ok {}", col("alpha_only")));
    assert_eq!(res[3], "ok ");
    assert_eq!(res[4], format!("ok {}", col("host_only")));
    for denied in &res[5..] {
        assert_eq!(denied, "error org.freedesktop.DBus.Error.AccessDenied");
    }
}

struct Target {
    address: String,
    runtime: std::path::PathBuf,
}

/// Runs the client helper, optionally inside a fake Flatpak sandbox.
fn run_client(bus: &Target, sandbox: Option<(&str, &str, &str)>, action: &str) -> String {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = match sandbox {
        None => Command::new(&exe),
        Some((mode, app, instance)) => {
            let mut c = Command::new(common::support_script("fake-flatpak.sh"));
            c.args([mode, app, instance]).arg(&bus.runtime).arg("--").arg(&exe);
            c
        }
    };
    let out = cmd
        .args(["--exact", "client_helper", "--nocapture", "--test-threads=1"])
        .env("SCOPEVAULT_TEST_CLIENT", action)
        .env("SCOPEVAULT_TEST_BUS", &bus.address)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().find_map(|l| l.split_once("RESULT: ").map(|(_, r)| r)).map(str::to_owned).unwrap_or_else(|| {
        panic!("client produced no result\nstdout: {stdout}\nstderr: {}", String::from_utf8_lossy(&out.stderr))
    })
}
