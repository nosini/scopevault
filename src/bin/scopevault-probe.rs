//! Identity probe.
//!
//! Serves one method on the session bus and reports how the production
//! classifier sees every caller. Run it on a desktop, then call it
//! from the host, from Flatpaks and from other sandboxes (see docs/TESTING.md).
//! It never stores or touches secrets and does not own any Secret Service
//! name.

use std::sync::Arc;

use scopevault::DBUS_PREFIX;
use scopevault::identity::{BusIdentityResolver, Classification, Classifier, IdentityPolicy};
use serde_json::json;
use zbus::message::Header;

const USAGE: &str = "\
usage: scopevault-probe [serve | self | instances]

  serve      (default) own <prefix>.IdentityProbe on the session bus and
             classify every caller of WhoAmI
  self       classify this process through the bus and exit
  instances  list running Flatpak instances and verify their records
";

struct Probe {
    resolver: Arc<BusIdentityResolver>,
}

fn report(c: &Classification) -> serde_json::Value {
    match &c.result {
        Ok(p) => {
            json!({ "verdict": "allowed", "scope": p.scope().to_string(), "principal": p, "evidence": c.evidence })
        }
        Err(e) => json!({ "verdict": "denied", "reason": e.to_string(), "evidence": c.evidence }),
    }
}

#[zbus::interface(name = "eu.nosini.ScopeVault.IdentityProbe")]
impl Probe {
    /// Returns the classification of the calling connection as JSON.
    async fn who_am_i(&self, #[zbus(header)] header: Header<'_>) -> String {
        let Some(sender) = header.sender() else { return "no sender".into() };
        let c = self.resolver.classify_uncached(sender).await;
        let r = report(&c);
        println!("{sender}: {}", serde_json::to_string_pretty(&r).unwrap());
        serde_json::to_string_pretty(&r).unwrap()
    }

    /// Like WhoAmI, but waits `delay_ms` before looking at the caller, so
    /// the caller can exit (or be killed) first. Exercises PID churn.
    async fn who_am_i_delayed(&self, delay_ms: u32, #[zbus(header)] header: Header<'_>) -> String {
        let Some(sender) = header.sender().map(|s| s.to_owned()) else { return "no sender".into() };
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms.min(30_000).into())).await;
        let c = self.resolver.classify_uncached(&sender).await;
        let r = report(&c);
        println!("{sender} (after {delay_ms} ms): {}", serde_json::to_string_pretty(&r).unwrap());
        serde_json::to_string_pretty(&r).unwrap()
    }
}

async fn environment(conn: &zbus::Connection, classifier: &Classifier) -> serde_json::Value {
    let dbus = zbus::fdo::DBusProxy::new(conn).await.unwrap();
    let features = dbus.features().await.unwrap_or_default();
    let own = conn.unique_name().unwrap().clone();
    let own_creds = dbus.get_connection_credentials(own.as_ref().into()).await;
    let bus_creds =
        dbus.get_connection_credentials(zbus::names::BusName::try_from("org.freedesktop.DBus").unwrap()).await;
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let b = &classifier.baseline;
    json!({
        "kernel": kernel.trim(),
        "bus_features": features,
        "bus_reports_process_fd": own_creds.as_ref().map(|c| c.process_fd().is_some()).unwrap_or(false),
        "bus_reports_security_label": own_creds.as_ref().map(|c| c.linux_security_label().is_some()).unwrap_or(false),
        "bus_daemon_pid": bus_creds.as_ref().ok().and_then(|c| c.process_id()),
        "baseline": {
            "uid": b.uid,
            "mnt_ns": b.namespaces.mnt.ino, "user_ns": b.namespaces.user.ino, "pid_ns": b.namespaces.pid.ino,
            "net_ns": b.namespaces.net.ino,
            "security_label": b.security_label.as_deref().map(String::from_utf8_lossy),
        },
        "flatpak_runtime_dir": classifier.instances.runtime_dir().display().to_string(),
    })
}

fn list_instances(classifier: &Classifier) {
    let dir = classifier.instances.runtime_dir().join(".flatpak");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        println!("no Flatpak instance directory at {}", dir.display());
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with("-private") || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(bw) = std::fs::read(e.path().join("bwrapinfo.json")) else { continue };
        let Some(pid) = serde_json::from_slice::<serde_json::Value>(&bw)
            .ok()
            .and_then(|v| v.get("child-pid").and_then(|p| p.as_i64()))
        else {
            continue;
        };
        match scopevault::identity::flatpak::describe_pid(pid as i32) {
            Ok((h, Some(info))) => {
                let ns = h.namespaces().ok();
                let check = ns.map(|ns| classifier.instances.verify(&info, &ns));
                println!(
                    "instance {name}: app {} sandbox pid {pid} risks {:?} record check: {}",
                    info.app_id,
                    info.risks,
                    match check {
                        Some(Ok(c)) => format!("ok ({:?})", c.relation),
                        Some(Err(e)) => format!("FAILED: {e}"),
                        None => "namespaces unavailable".into(),
                    }
                );
            }
            Ok((_, None)) => println!("instance {name}: sandbox pid {pid} has no .flatpak-info"),
            Err(e) => println!("instance {name}: not running or not inspectable ({e})"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let mode = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    if !matches!(mode.as_str(), "serve" | "self" | "instances") {
        eprint!("{USAGE}");
        std::process::exit(2);
    }

    let classifier = Classifier::for_current_process(IdentityPolicy::default())?;
    if mode == "instances" {
        list_instances(&classifier);
        return Ok(());
    }

    let conn = zbus::Connection::session().await?;
    println!("environment: {}", serde_json::to_string_pretty(&environment(&conn, &classifier).await)?);
    let resolver = BusIdentityResolver::new(&conn, classifier).await?;

    if mode == "self" {
        let me = conn.unique_name().unwrap().clone();
        let c = resolver.classify_uncached(&me).await;
        println!("{}", serde_json::to_string_pretty(&report(&c))?);
        return Ok(());
    }

    let name = format!("{DBUS_PREFIX}.IdentityProbe");
    let path = format!("/{}/IdentityProbe", DBUS_PREFIX.replace('.', "/"));
    conn.object_server().at(path.as_str(), Probe { resolver }).await?;
    conn.request_name(name.as_str()).await?;
    println!("serving {name} at {path}; call WhoAmI from the clients to test. Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
