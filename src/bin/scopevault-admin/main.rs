//! Administration of the Scoped Secret Service.
//!
//! Most commands talk to the running daemon over its administrative socket.
//! The daemon serves it only to host processes, and asks for passwords in
//! its own dialog: no password passes through this tool. Restore, import
//! and export work on the vault files while the daemon is stopped (see
//! `offline.rs`).

mod offline;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::ExitCode;

use scopevault::admin::protocol::{MAX_REPLY_LINE, Reply, Request, VaultState, read_line, write_json};
use scopevault::admin::server::default_socket_path;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::UnixStream;

const USAGE: &str = "\
usage: scopevault-admin [--socket PATH] COMMAND [ARGS]

Commands (the daemon must be running):
  status                      vault state and connection counts
  lock                        lock the vault for everyone (global lock)
  change-password             change the master password (asked in a dialog)
  scopes                      scopes that have data, with their sizes
  list SCOPE [--json]         collections and items of SCOPE (no secrets)
  move FROM TO ITEM...        move items (COLLECTION/ITEM, as shown by list)
                              from scope FROM into TO's default collection;
                              asks for the master password
  reset-scope SCOPE           delete everything SCOPE holds; asks for the
                              master password
  portal init                 create the scope for the Secret portal keys if
                              it does not exist yet
  portal new-key APP-ID       create a portal key for APP-ID (refuses if it
                              has one); a keyring file the app already has
                              cannot be decrypted with the new key
  backup FILE                 write an encrypted copy of the vault to FILE;
                              it opens with the current master password

Commands that need the daemon stopped (they open the vault themselves and
ask for its password with pinentry):
  restore FILE                replace the vault with a backup, after checking
                              that it opens; the old vault is kept beside it
  import                      copy everything from the Secret Service provider
                              on the bus (for example gnome-keyring, before
                              switching) into scope `host`; creates the vault
                              if needed. Portal keys (items with the
                              org.freedesktop.portal.Secret schema) go into
                              the `portal` scope. The provider is not changed.
  export                      copy scope `host` into the provider on the bus
                              (rollback); items it already has are skipped

A SCOPE is `host`, `flatpak/APP-ID` or `portal`. With `export --scope
portal`, the portal keys are written back into the provider's default
collection.

  --socket PATH     the daemon's administrative socket
                    (default: $XDG_RUNTIME_DIR/scopevault/admin)
  --data-dir DIR    vault directory for restore, import and export
                    (default: $XDG_DATA_HOME/scopevault)
  --bus ADDRESS     bus of the other provider (default: the session bus)
  --scope SCOPE     scope to import into or export from (default: host)
  --pinentry PROG   pinentry program (default: pinentry)
";

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("scopevault-admin: {msg}");
    ExitCode::FAILURE
}

fn usage() -> ExitCode {
    eprint!("{USAGE}");
    ExitCode::from(2)
}

/// Sends one request; returns the reply and, for a backup, its bytes.
async fn request(socket: &PathBuf, req: &Request) -> Result<(Reply, Vec<u8>), String> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("cannot connect to {}: {e} (is scopevault-daemon running?)", socket.display()))?;
    let (rd, mut wr) = stream.into_split();
    write_json(&mut wr, req).await.map_err(|e| format!("cannot send the request: {e}"))?;
    let mut rd = BufReader::new(rd);
    let line = read_line(&mut rd, MAX_REPLY_LINE).await.map_err(|e| format!("no reply from the daemon: {e}"))?;
    let reply: Reply = serde_json::from_str(&line).map_err(|e| format!("unreadable reply: {e}"))?;
    let mut data = Vec::new();
    if let Reply::Backup { bytes } = reply {
        let n = usize::try_from(bytes).map_err(|_| "backup too large")?;
        data.resize(n, 0);
        rd.read_exact(&mut data).await.map_err(|e| format!("the backup was cut short: {e}"))?;
    }
    Ok((reply, data))
}

fn date(secs: u64) -> String {
    // Days since the epoch to a civil date (proleptic Gregorian), UTC.
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn print_reply(reply: &Reply, json: bool) -> ExitCode {
    if json {
        println!("{}", serde_json::to_string_pretty(reply).expect("serializable"));
        return if matches!(reply, Reply::Error { .. }) { ExitCode::FAILURE } else { ExitCode::SUCCESS };
    }
    match reply {
        Reply::Error { message } => return fail(message),
        Reply::Status(s) => {
            let state = match s.vault {
                VaultState::Missing => "not created yet",
                VaultState::Locked => "locked",
                VaultState::Unlocked => "unlocked",
            };
            println!("vault:            {state} ({})", s.data_dir);
            println!("connections:      {}", s.connections);
            println!("transfer sessions: {}", s.sessions);
            println!("pending prompts:  {}", s.prompts);
        }
        Reply::Done { message } => println!("{message}"),
        Reply::Scopes { scopes } => {
            if scopes.is_empty() {
                println!("no scope has data");
            }
            for s in scopes {
                println!("{:<50} {:>4} collections {:>6} items", s.scope, s.collections, s.items);
            }
        }
        Reply::Listing { collections } => {
            if collections.is_empty() {
                println!("no data in this scope");
            }
            for c in collections {
                let aliases = if c.aliases.is_empty() { String::new() } else { format!(" [{}]", c.aliases.join(", ")) };
                let locked = if c.locked { " (locked by its app)" } else { "" };
                println!("{}  {:?}{aliases}{locked}", c.name, c.label);
                for i in &c.items {
                    let attrs: Vec<String> = i.attributes.iter().map(|(k, v)| format!("{k}={v}")).collect();
                    println!("  {}/{}  {:?}  modified {}", c.name, i.name, i.label, date(i.modified));
                    if !attrs.is_empty() {
                        println!("      {}", attrs.join(" "));
                    }
                }
            }
        }
        Reply::Moved { items } => {
            for i in items {
                println!("moved to {i}");
            }
        }
        Reply::Reset { collections, items } => println!("deleted {items} items in {collections} collections"),
        Reply::Backup { .. } => {}
    }
    ExitCode::SUCCESS
}

async fn run() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = None;
    if args.first().map(String::as_str) == Some("--socket") {
        if args.len() < 2 {
            return usage();
        }
        socket = Some(PathBuf::from(args.remove(1)));
        args.remove(0);
    }
    let Some((cmd, rest)) = args.split_first() else { return usage() };
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    if matches!(cmd.as_str(), "restore" | "import" | "export") {
        let (opts, positional) = match offline::parse(&rest) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("scopevault-admin: {e}");
                return usage();
            }
        };
        return match (cmd.as_str(), positional.as_slice()) {
            ("restore", [file]) => offline::restore(std::path::Path::new(file), opts).await,
            ("import", []) => offline::import(opts).await,
            ("export", []) => offline::export(opts).await,
            _ => usage(),
        };
    }
    let Some(socket) = socket.or_else(default_socket_path) else {
        return fail("XDG_RUNTIME_DIR is not set; use --socket");
    };
    let (req, json) = match (cmd.as_str(), rest.as_slice()) {
        ("status", []) => (Request::Status, false),
        ("lock", []) => (Request::Lock, false),
        ("change-password", []) => (Request::ChangePassword, false),
        ("scopes", []) => (Request::Scopes, false),
        ("scopes", ["--json"]) => (Request::Scopes, true),
        ("list", [scope]) => (Request::List { scope: scope.to_string() }, false),
        ("list", [scope, "--json"]) => (Request::List { scope: scope.to_string() }, true),
        ("move", [from, to, items @ ..]) if !items.is_empty() => {
            let items = items.iter().map(|s| s.to_string()).collect();
            (Request::Move { from: from.to_string(), to: to.to_string(), items }, false)
        }
        ("reset-scope", [scope]) => (Request::ResetScope { scope: scope.to_string() }, false),
        ("portal", ["init"]) => (Request::PortalInit, false),
        ("portal", ["new-key", app_id]) => (Request::PortalNewKey { app_id: app_id.to_string() }, false),
        ("backup", [file]) => {
            // Create the file first: nothing is asked of the daemon if it
            // cannot be written, and an existing file is never replaced.
            let path = PathBuf::from(file);
            let mut out = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
                Ok(f) => f,
                Err(e) => return fail(format!("cannot create {}: {e}", path.display())),
            };
            let (reply, data) = match request(&socket, &Request::Backup).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    return fail(e);
                }
            };
            if let Reply::Error { message } = reply {
                let _ = std::fs::remove_file(&path);
                return fail(message);
            }
            if let Err(e) = out.write_all(&data).and_then(|()| out.sync_all()) {
                let _ = std::fs::remove_file(&path);
                return fail(format!("cannot write {}: {e}", path.display()));
            }
            println!("wrote {} ({} bytes); it opens with the current master password", path.display(), data.len());
            return ExitCode::SUCCESS;
        }
        ("-h" | "--help", []) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => return usage(),
    };
    match request(&socket, &req).await {
        Ok((reply, _)) => print_reply(&reply, json),
        Err(e) => fail(e),
    }
}

fn main() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return fail(format!("cannot start the runtime: {e}")),
    };
    rt.block_on(run())
}
