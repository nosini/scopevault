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
use std::time::{Duration, Instant};

use scopevault::admin::protocol::{CANCELLED, MAX_REPLY_LINE, Reply, Request, VaultState, read_line, write_json};
use scopevault::admin::server::default_socket_path;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::UnixStream;

const USAGE: &str = "\
usage: scopevault-admin [--socket PATH] COMMAND [ARGS]

Commands (the daemon must be running):
  status                      vault state and connection counts
  lock                        lock the vault for everyone (global lock)
  unlock [--wait SECONDS]     unlock the vault (password dialog) if it is
                              locked; with --wait (for login), for up to
                              SECONDS (1 to 600) wait for the daemon's socket
                              and reopen a dialog the desktop dismissed
                              before it could be answered (within 5 s)
  change-password             change the master password (asked in a dialog)
  scopes                      scopes that have data, with their sizes
  list SCOPE                  collections and items of SCOPE (no secrets)
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
  share FROM ITEM TO [--write]
                              give TO read (or, with --write, read and write)
                              access to an item (COLLECTION/ITEM, as shown by
                              list) of scope FROM; TO sees the item in its
                              `Shared` collection. Asks for the master password
  unshare GRANT               revoke a grant (its ID as shown by grants)
  grants [SCOPE]              list grants, or those where SCOPE is the owner
                              or the grantee
  backup FILE                 write an encrypted copy of the vault to FILE;
                              it opens with the current master password
                              (not with the login password)
  login-unlock enable         let the login password unlock the vault (with
                              the PAM module installed); asks for the master
                              password and the login password
  login-unlock disable        stop that; asks for the master password
  login-unlock status         whether the login password unlocks the vault

With --json as their last argument, these commands print the daemon's
reply as one JSON object on standard output, errors included
(an error is a reply of type `error` too).

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
                              (rollback); items it already has are skipped,
                              an older version (same attributes, another
                              secret or label) is replaced, and if several
                              items there could be that older version,
                              nothing is written

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

  --version         the version and the git commit it was built from
";

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("scopevault-admin: {}", shown(&msg.to_string()));
    ExitCode::FAILURE
}

/// Text for the terminal: control characters, line and paragraph
/// separators and invisible formatting (bidirectional overrides and the
/// like) are written as `\u{..}` escapes. Attributes, labels and messages
/// can hold text an app chose, which must not move the cursor, recolour
/// or reorder what is shown, or fake further lines.
fn shown(s: &str) -> std::borrow::Cow<'_, str> {
    let hidden = |c: char| {
        c.is_control()
            || matches!(c,
                '\u{ad}' | '\u{61c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}')
    };
    if !s.chars().any(hidden) {
        return s.into();
    }
    s.chars().map(|c| if hidden(c) { c.escape_unicode().to_string() } else { c.to_string() }).collect::<String>().into()
}

/// [`fail`], or with `--json` an error reply on standard output.
fn fail_as(json: bool, msg: impl std::fmt::Display) -> ExitCode {
    if json {
        return print_reply(&Reply::error(msg.to_string()), true);
    }
    fail(msg)
}

fn usage() -> ExitCode {
    eprint!("{USAGE}");
    ExitCode::from(2)
}

/// A cancel this quick did not come from the user: gnome-shell dismisses
/// prompts it cannot show yet (shortly after login it cannot open modal
/// dialogs), and pinentry reports that as a cancel.
const QUICK_CANCEL: Duration = Duration::from_secs(5);
const UNLOCK_RETRY_DELAY: Duration = Duration::from_secs(2);

/// `unlock`. With `wait` (the login unit), a dialog cancelled within
/// [`QUICK_CANCEL`] is opened again until the wait has passed; without it,
/// a cancel is final.
async fn unlock(socket: &PathBuf, wait: Option<Duration>, json: bool) -> ExitCode {
    let deadline = wait.map(|w| Instant::now() + w);
    loop {
        let asked = Instant::now();
        let remaining = deadline.map(|d| d.saturating_duration_since(asked));
        let reply = match request(socket, &Request::Unlock, remaining).await {
            Ok((reply, _)) => reply,
            Err(e) => return fail_as(json, e),
        };
        let quick_cancel =
            matches!(&reply, Reply::Error { message } if message == CANCELLED) && asked.elapsed() < QUICK_CANCEL;
        if quick_cancel && deadline.is_some_and(|d| Instant::now() + UNLOCK_RETRY_DELAY < d) {
            eprintln!(
                "scopevault-admin: the dialog was dismissed after {} ms, before anyone could answer it; \
                 trying again",
                asked.elapsed().as_millis()
            );
            tokio::time::sleep(UNLOCK_RETRY_DELAY).await;
            continue;
        }
        return print_reply(&reply, json);
    }
}

/// Sends one request; returns the reply and, for a backup, its bytes. With
/// `wait`, a connection that fails because the socket does not exist yet or
/// refuses is retried every 500 ms until the wait has passed: only the
/// connection is retried, never the request.
async fn request(socket: &PathBuf, req: &Request, wait: Option<Duration>) -> Result<(Reply, Vec<u8>), String> {
    let cannot_connect =
        |e: std::io::Error| format!("cannot connect to {}: {e} (is scopevault-daemon running?)", socket.display());
    let deadline = wait.map(|w| Instant::now() + w);
    let stream = loop {
        match UnixStream::connect(socket).await {
            Ok(s) => break s,
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused)
                    && deadline.is_some_and(|d| Instant::now() < d) =>
            {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(cannot_connect(e)),
        }
    };
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

fn date_time(secs: u64) -> String {
    let s = secs % 86_400;
    format!("{} {:02}:{:02}:{:02} UTC", date(secs), s / 3600, s / 60 % 60, s % 60)
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
        Reply::Done { message } => println!("{}", shown(message)),
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
                    let attrs: Vec<String> =
                        i.attributes.iter().map(|(k, v)| format!("{}={}", shown(k), shown(v))).collect();
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
        Reply::Grants { grants } => {
            if grants.is_empty() {
                println!("no grants");
            }
            for g in grants {
                let access = if g.write { "write" } else { "read" };
                println!("{}  {} {}/{}  {:?}  {} {}", g.id, g.owner, g.collection, g.item, g.label, g.grantee, access);
            }
        }
        Reply::Shared { grant } => println!("grant {grant}"),
        Reply::LoginUnlock(s) => {
            println!("login unlock:  {}", if s.enabled { "enabled" } else { "not enabled" });
            let when = |t: Option<u64>| t.map_or_else(|| "not since the daemon started".to_owned(), date_time);
            println!("last unlock:   {}", when(s.last_unlock));
            println!("last rewrap:   {}", when(s.last_rewrap));
        }
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
    if cmd == "--version" && rest.is_empty() {
        println!("scopevault-admin {}", scopevault::VERSION);
        return ExitCode::SUCCESS;
    }
    let mut rest: Vec<&str> = rest.iter().map(String::as_str).collect();
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
    let json = rest.last() == Some(&"--json");
    if json {
        rest.pop();
    }
    let Some(socket) = socket.or_else(default_socket_path) else {
        return fail_as(json, "XDG_RUNTIME_DIR is not set; use --socket");
    };
    // `unlock --wait` exists for the login unit: the daemon's socket may not
    // be there yet.
    if cmd.as_str() == "unlock" {
        let wait = match rest.as_slice() {
            [] => None,
            ["--wait", secs] => match secs.parse::<u64>() {
                Ok(s) if (1..=600).contains(&s) => Some(Duration::from_secs(s)),
                _ => return usage(),
            },
            _ => return usage(),
        };
        return unlock(&socket, wait, json).await;
    }
    let req = match (cmd.as_str(), rest.as_slice()) {
        ("status", []) => Request::Status,
        ("lock", []) => Request::Lock,
        ("change-password", []) => Request::ChangePassword,
        ("scopes", []) => Request::Scopes,
        ("list", [scope]) => Request::List { scope: scope.to_string() },
        ("move", [from, to, items @ ..]) if !items.is_empty() => {
            let items = items.iter().map(|s| s.to_string()).collect();
            Request::Move { from: from.to_string(), to: to.to_string(), items }
        }
        ("reset-scope", [scope]) => Request::ResetScope { scope: scope.to_string() },
        ("portal", ["init"]) => Request::PortalInit,
        ("portal", ["new-key", app_id]) => Request::PortalNewKey { app_id: app_id.to_string() },
        ("share", [from, item, to]) => {
            Request::Share { from: from.to_string(), item: item.to_string(), to: to.to_string(), write: false }
        }
        ("share", [from, item, to, "--write"]) => {
            Request::Share { from: from.to_string(), item: item.to_string(), to: to.to_string(), write: true }
        }
        ("unshare", [grant]) => Request::Unshare { grant: grant.to_string() },
        ("login-unlock", ["enable"]) => Request::LoginUnlockEnable,
        ("login-unlock", ["disable"]) => Request::LoginUnlockDisable,
        ("login-unlock", ["status"]) => Request::LoginUnlockStatus,
        ("grants", []) => Request::Grants { scope: None },
        ("grants", [scope]) => Request::Grants { scope: Some(scope.to_string()) },
        ("backup", [file]) => {
            // Create the file first: nothing is asked of the daemon if it
            // cannot be written, and an existing file is never replaced.
            let path = PathBuf::from(file);
            let mut out = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
                Ok(f) => f,
                Err(e) => return fail_as(json, format!("cannot create {}: {e}", path.display())),
            };
            let (reply, data) = match request(&socket, &Request::Backup, None).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    return fail_as(json, e);
                }
            };
            if let Reply::Error { message } = reply {
                let _ = std::fs::remove_file(&path);
                return fail_as(json, message);
            }
            if let Err(e) = out.write_all(&data).and_then(|()| out.sync_all()) {
                let _ = std::fs::remove_file(&path);
                return fail_as(json, format!("cannot write {}: {e}", path.display()));
            }
            let message =
                format!("wrote {} ({} bytes); it opens with the current master password", path.display(), data.len());
            return print_reply(&Reply::Done { message }, json);
        }
        ("-h" | "--help", []) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => return usage(),
    };
    match request(&socket, &req, None).await {
        Ok((reply, _)) => print_reply(&reply, json),
        Err(e) => fail_as(json, e),
    }
}

fn main() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return fail(format!("cannot start the runtime: {e}")),
    };
    rt.block_on(run())
}
