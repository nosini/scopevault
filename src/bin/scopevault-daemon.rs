//! The Scoped Secret Service daemon.
//!
//! Serves `org.freedesktop.secrets` on the session bus from the encrypted
//! vault. It refuses to start if another process owns the name; it never
//! replaces a running keyring. It exits when the bus connection closes,
//! because identity caches are valid for one bus connection only.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scopevault::admin::default_data_dir;
use scopevault::admin::server::{AdminServer, PeerClassifier, default_socket_path};
use scopevault::crypto::KdfParams;
use scopevault::identity::{BusIdentityResolver, Classifier, IdentityPolicy};
use scopevault::prompts::pinentry::PinentryConfig;
use scopevault::prompts::unlock::{Unlocker, VaultSlot};
use scopevault::service_api::SecretService;
use zbus::fdo::{RequestNameFlags, RequestNameReply};

const NAME: &str = "org.freedesktop.secrets";
/// Target time for one key derivation when a new vault is created.
const KDF_TARGET: Duration = Duration::from_secs(1);
/// How often to look for processes queued for the name.
const QUEUE_CHECK: Duration = Duration::from_secs(60);

const USAGE: &str = "\
usage: scopevault-daemon [--data-dir DIR] [--pinentry PROGRAM] [--admin-socket PATH]

Serves org.freedesktop.secrets on the session bus, and the administrative
interface (scopevault-admin) on a Unix socket.

  --data-dir DIR        vault directory (default: $XDG_DATA_HOME/scopevault)
  --pinentry PROGRAM    pinentry program for password dialogs (default: pinentry)
  --admin-socket PATH   administrative socket
                        (default: $XDG_RUNTIME_DIR/scopevault/admin)

Logging is controlled by RUST_LOG (for example RUST_LOG=info).
";

struct Options {
    data_dir: PathBuf,
    pinentry: PathBuf,
    admin_socket: PathBuf,
}

fn parse_args() -> Result<Options, String> {
    let mut data_dir = None;
    let mut pinentry = PathBuf::from("pinentry");
    let mut admin_socket = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--data-dir") => data_dir = Some(PathBuf::from(args.next().ok_or("--data-dir needs a value")?)),
            Some("--pinentry") => pinentry = PathBuf::from(args.next().ok_or("--pinentry needs a value")?),
            Some("--admin-socket") => {
                admin_socket = Some(PathBuf::from(args.next().ok_or("--admin-socket needs a value")?))
            }
            Some("-h" | "--help") => return Err(String::new()),
            _ => return Err(format!("unknown argument {a:?}")),
        }
    }
    let data_dir = match data_dir {
        Some(d) => d,
        None => default_data_dir().ok_or("cannot determine the data directory; use --data-dir")?,
    };
    if !data_dir.is_absolute() {
        return Err("--data-dir must be an absolute path".into());
    }
    let admin_socket = match admin_socket {
        Some(p) => p,
        None => default_socket_path().ok_or("XDG_RUNTIME_DIR is not set; use --admin-socket")?,
    };
    if !admin_socket.is_absolute() {
        return Err("--admin-socket must be an absolute path".into());
    }
    Ok(Options { data_dir, pinentry, admin_socket })
}

fn main() -> ExitCode {
    // Colours only on a terminal, not in files or the journal.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("scopevault-daemon: {e}");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // The identity baseline describes this process as it is now (namespaces,
    // root, LSM label). Capture it before hardening, which makes our own
    // procfs entries unreadable.
    let classifier = match Classifier::for_current_process(IdentityPolicy::default()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("scopevault-daemon: cannot capture the identity baseline: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = scopevault::hardening::harden_process() {
        eprintln!("scopevault-daemon: cannot harden the process: {e}");
        return ExitCode::FAILURE;
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("scopevault-daemon: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(opts, classifier)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scopevault-daemon: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Warns while other processes wait in the bus queue for the name.
///
/// gnome-keyring requests the name without `DO_NOT_QUEUE` whenever
/// something starts its secrets component (the Secret portal backend does).
/// If this daemon then exits, the bus hands the name to the queued process
/// at once, and applications switch keyrings without notice.
async fn watch_queue(dbus: &zbus::fdo::DBusProxy<'_>) {
    let name = zbus::names::WellKnownName::try_from(NAME).expect("valid name");
    let me = dbus.inner().connection().unique_name().map(|n| n.to_string());
    let mut reported: Vec<String> = Vec::new();
    loop {
        match dbus.list_queued_owners(name.clone()).await {
            Ok(owners) => {
                let mut waiting: Vec<String> =
                    owners.into_iter().map(|o| o.to_string()).filter(|o| Some(o) != me.as_ref()).collect();
                waiting.sort();
                if waiting != reported {
                    for owner in waiting.iter().filter(|o| !reported.contains(o)) {
                        let pid = dbus
                            .get_connection_unix_process_id(owner.as_str().try_into().expect("unique name"))
                            .await
                            .ok();
                        tracing::warn!(
                            owner = %owner,
                            pid = pid.map_or_else(|| "unknown".to_owned(), |p| p.to_string()),
                            "another process is queued for {NAME}; it takes over if this daemon exits"
                        );
                    }
                    if waiting.is_empty() {
                        tracing::info!("no process is queued for {NAME} any more");
                    }
                    reported = waiting;
                }
            }
            Err(e) => tracing::debug!(error = %e, "cannot list the queue for {NAME}"),
        }
        tokio::time::sleep(QUEUE_CHECK).await;
    }
}

fn name_taken() -> String {
    format!(
        "{NAME} is already owned by another process (probably gnome-keyring-daemon). \
         Stop it first; this daemon never replaces a running Secret Service."
    )
}

async fn run(opts: Options, classifier: Classifier) -> Result<(), String> {
    let conn = zbus::connection::Builder::session()
        .map_err(|e| format!("cannot find the session bus: {e}"))?
        .build()
        .await
        .map_err(|e| format!("cannot connect to the session bus: {e}"))?;
    // Early, friendly check before the slow setup; the authoritative one is
    // the DoNotQueue request below.
    let dbus = zbus::fdo::DBusProxy::new(&conn).await.map_err(|e| e.to_string())?;
    if dbus.name_has_owner(NAME.try_into().expect("valid name")).await.map_err(|e| e.to_string())? {
        return Err(name_taken());
    }

    let slot = VaultSlot::open(opts.data_dir.clone())
        .map_err(|e| format!("cannot open the vault in {}: {e}", opts.data_dir.display()))?;
    if slot.vault.is_none() {
        tracing::info!(dir = %opts.data_dir.display(), "no vault yet; one is created on first use");
    }
    // Calibrated only when it can matter; it takes a moment and 256 MiB.
    let kdf = if slot.vault.is_none() {
        tokio::task::spawn_blocking(|| KdfParams::calibrate(KDF_TARGET))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("cannot calibrate key derivation: {e}"))?
    } else {
        KdfParams::DEFAULT
    };
    let pinentry = PinentryConfig { program: opts.pinentry, ..PinentryConfig::default() };
    let unlocker = Unlocker::new(Arc::new(Mutex::new(slot)), pinentry, kdf);

    let resolver = BusIdentityResolver::new(&conn, classifier).await.map_err(|e| e.to_string())?;
    let service = SecretService::new(conn.clone(), resolver.clone(), unlocker.clone());
    let serving = service.clone().start().await.map_err(|e| e.to_string())?;

    // Only now take the name, so no early call is missed.
    match conn.request_name_with_flags(NAME, RequestNameFlags::DoNotQueue.into()).await {
        Ok(RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) => {}
        Ok(_) | Err(zbus::Error::NameTaken) => return Err(name_taken()),
        Err(e) => return Err(format!("cannot own {NAME}: {e}")),
    }
    tracing::info!("serving {NAME}");

    // After taking the name: a daemon that lost the name to another one
    // must not touch that one's socket.
    let socket = scopevault::admin::server::bind(&opts.admin_socket)
        .map_err(|e| format!("cannot create the administrative socket {}: {e}", opts.admin_socket.display()))?;
    let classify: PeerClassifier = {
        let r = resolver.clone();
        Arc::new(move |creds| r.classifier().classify(creds).result)
    };
    let admin = AdminServer::new(classify, unlocker, service);
    tracing::info!(socket = %opts.admin_socket.display(), "administrative interface ready");

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("cannot handle SIGTERM: {e}"))?;
    tokio::select! {
        () = admin.serve(&socket.listener) => Ok(()),
        () = watch_queue(&dbus) => Ok(()),
        r = serving => match r {
            Ok(()) => Err("the session bus connection closed".into()),
            Err(e) => Err(format!("the session bus connection failed: {e}")),
        },
        _ = term.recv() => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
