//! The Secret portal backend.
//!
//! xdg-desktop-portal (the frontend) asks the `org.freedesktop.impl.portal.Secret`
//! interface for an application's master secret: one key per app ID, with
//! which the app encrypts its own private files. The frontend is the only
//! caller that is served: it must own `org.freedesktop.portal.Desktop` right
//! now and be positively identified as a host process. Anything else is
//! refused before any work, so a caller can never obtain another app's key
//! by naming it.
//!
//! The backend serves on its own bus connection, owning
//! [`BACKEND_NAME`], and never touches `org.freedesktop.secrets`: the portal
//! is a separate entry point, not an administrative path on the Secret
//! Service. It does not own any name of the `impl.portal` API either; the
//! desktop's portal configuration decides which backend serves it. The keys
//! live in the reserved `portal` scope of the store
//! (`crate::store::portal`, a private module).

use std::collections::HashMap;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use zbus::message::Header;
use zbus::names::OwnedUniqueName;
use zbus::zvariant::{ObjectPath, OwnedFd, OwnedValue};

use crate::identity::{Principal, Resolved};
use crate::prompts::unlock::{UnlockOutcome, Unlocker};
use crate::store::{Secret, is_valid_portal_app_id};

/// The backend's own well-known name. It never owns
/// `org.freedesktop.impl.portal.Secret` (see the module documentation).
pub const BACKEND_NAME: &str = "eu.nosini.ScopeVault.Portal";

/// Where the Secret interface is exported.
pub const BACKEND_PATH: &str = "/org/freedesktop/portal/desktop";

/// The installed `scopevault.portal` files that declare a bus name other
/// than [`BACKEND_NAME`], with that name. xdg-desktop-portal sends the
/// Secret portal's requests to the declared name, so a file left over from
/// an older version breaks the portal while the daemon itself runs fine.
pub fn stale_portal_files() -> Vec<(PathBuf, String)> {
    let home = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share"));
    let user = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p| p.is_absolute()).or(home);
    let system = std::env::var_os("XDG_DATA_DIRS")
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    user.into_iter()
        .chain(std::env::split_paths(&system).filter(|p| p.is_absolute()))
        .map(|dir| dir.join("xdg-desktop-portal/portals/scopevault.portal"))
        .filter_map(|path| {
            let contents = std::fs::read_to_string(&path).ok()?;
            let name = portal_file_bus_name(&contents).unwrap_or_default().to_owned();
            (name != BACKEND_NAME).then_some((path, name))
        })
        .collect()
}

/// The `DBusName=` of a portal file.
fn portal_file_bus_name(contents: &str) -> Option<&str> {
    contents.lines().find_map(|l| l.trim().strip_prefix("DBusName=")).map(str::trim)
}

/// The well-known name of xdg-desktop-portal, the only allowed caller.
pub const FRONTEND_NAME: &str = "org.freedesktop.portal.Desktop";

/// Request objects are exported under this prefix, as the portal API has it.
pub const REQUEST_PREFIX: &str = "/org/freedesktop/portal/desktop/request/";

/// How long the app gets to read its key from the fd. The fd comes from the
/// app, so it may be a pipe nobody ever reads: the daemon must not wait on
/// it indefinitely.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the diagnostics lookup behind a refusal may take.
const CALLER_LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);

/// RetrieveSecret's response codes: success, cancelled by the user, refused
/// for any other reason.
const RESPONSE_SUCCESS: u32 = 0;
const RESPONSE_CANCELLED: u32 = 1;
const RESPONSE_OTHER: u32 = 2;

/// The `results` reply, which the portal API defines as empty.
type Results = HashMap<String, OwnedValue>;

fn empty_results() -> Results {
    HashMap::new()
}

/// Permission to reach the portal keys ([`crate::store::Vault::portal_key`]
/// and friends).
///
/// The backend creates one only after the caller was verified to be the
/// portal frontend. There is deliberately no offline constructor: the keys
/// are served from the running daemon or through the administrative
/// interface, never by a process holding the vault file. The keys live in
/// the store's reserved `portal` scope (`crate::store::portal`).
pub struct PortalAuthority {
    _private: (),
}

impl PortalAuthority {
    /// After [`PortalBackend`] verified the caller is the portal frontend.
    fn verified_frontend() -> Self {
        PortalAuthority { _private: () }
    }
}

/// Resolves one sender to a principal, through whichever resolver the
/// backend was built with. The `#[interface]` macro cannot be generic, hence
/// the closure.
type Resolver = Arc<dyn Fn(OwnedUniqueName) -> BoxFuture<'static, Resolved> + Send + Sync>;

#[derive(Clone)]
pub struct PortalBackend {
    conn: zbus::Connection,
    resolve: Resolver,
    unlocker: Arc<Unlocker>,
    /// Where applications' private data lives (`$HOME/.var/app`), so a key
    /// is only created for an app that has no keyring file of its own yet.
    app_data_root: PathBuf,
}

impl PortalBackend {
    pub fn new<R: crate::identity::CallerResolver>(
        conn: zbus::Connection,
        resolver: Arc<R>,
        unlocker: Arc<Unlocker>,
        app_data_root: PathBuf,
    ) -> Arc<Self> {
        let resolve: Resolver = Arc::new(move |sender: OwnedUniqueName| {
            let resolver = resolver.clone();
            Box::pin(async move { resolver.resolve(&sender).await }) as BoxFuture<'static, Resolved>
        });
        Arc::new(PortalBackend { conn, resolve, unlocker, app_data_root })
    }

    /// Exports the Secret interface at [`BACKEND_PATH`]. Request
    /// [`BACKEND_NAME`] only after this returns, so no early call is missed.
    pub async fn start(self: &Arc<Self>) -> zbus::Result<()> {
        self.conn.object_server().at(BACKEND_PATH, PortalBackend::clone(self)).await.map(|_| ())
    }

    /// The caller must be, right now, the owner of the frontend's well-known
    /// name and positively identified as a host process. Everything else is
    /// refused before any other work, without touching the fd or the vault.
    async fn authorise(&self, sender: &OwnedUniqueName) -> zbus::fdo::Result<PortalAuthority> {
        let denied = |why: String| {
            tracing::warn!(sender = %sender, reason = %why, "portal: refused a caller that is not the frontend");
            zbus::fdo::Error::AccessDenied("only the portal frontend may call this backend".into())
        };
        let dbus = match zbus::fdo::DBusProxy::new(&self.conn).await {
            Ok(d) => d,
            Err(e) => return Err(denied(e.to_string())),
        };
        let owner = match dbus.get_name_owner(FRONTEND_NAME.try_into().expect("valid name")).await {
            Ok(owner) => owner,
            // Nobody owns the name, so nobody is the frontend.
            Err(_) => return Err(denied(format!("nothing owns {FRONTEND_NAME}"))),
        };
        if owner.as_str() != sender.as_str() {
            return Err(denied(format!("{FRONTEND_NAME} is owned by another connection")));
        }
        match (self.resolve)(sender.clone()).await.as_ref() {
            Ok(Principal::Host) => Ok(PortalAuthority::verified_frontend()),
            Ok(other) => Err(denied(format!("classified as {}, not a host process", other.scope()))),
            Err(e) => Err(denied(e.to_string())),
        }
    }

    /// Whether `<app_data_root>/<app-id>/data/keyrings/default.keyring`
    /// exists. Any directory entry counts, a dangling symlink included. A
    /// stat error other than "not found" refuses: the key must not be
    /// replaced blindly, and a fresh one would not decrypt the file anyway.
    fn app_keyring_exists(&self, app_id: &str) -> Result<bool, std::io::Error> {
        let path = self.app_data_root.join(app_id).join("data").join("keyrings").join("default.keyring");
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Names the caller behind the frontend for a refused request:
    /// xdg-desktop-portal encodes the calling application's bus name into
    /// the handle, so the process that asked for another app's key can be
    /// named in the log. Diagnostics only: best-effort, bounded, and it
    /// never changes the response.
    async fn log_refused_caller(&self, handle: &str) {
        let lookup = async {
            let caller = caller_from_handle(handle)?;
            let dbus = zbus::fdo::DBusProxy::new(&self.conn).await.ok()?;
            let name = zbus::names::BusName::try_from(caller.as_str()).ok()?;
            let creds = dbus.get_connection_credentials(name).await.ok()?;
            let pid = creds.process_id()?;
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned());
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok().map(|c| {
                let spaces: Vec<u8> = c.into_iter().map(|b| if b == 0 { b' ' } else { b }).collect();
                String::from_utf8_lossy(&spaces).chars().take(300).collect::<String>()
            });
            Some((pid, exe, cmdline))
        };
        let (pid, exe, cmdline) = match tokio::time::timeout(CALLER_LOOKUP_TIMEOUT, lookup).await {
            Ok(Some((pid, exe, cmdline))) => (Some(pid), exe, cmdline),
            _ => (None, None, None),
        };
        tracing::warn!(
            handle = %handle,
            pid = pid.map(|p| p.to_string()).unwrap_or_else(|| "unknown".into()),
            exe = exe.unwrap_or_else(|| "unknown".into()),
            cmdline = cmdline.unwrap_or_else(|| "unknown".into()),
            "portal: the caller behind the refused request"
        );
    }

    /// The work of one call, after the caller was authenticated: unlock,
    /// find or create the key, write it to the fd. Each step can take a
    /// while (a dialog, key derivation), so it runs raced against the
    /// request's `Close`.
    async fn serve_request(&self, app_id: &str, fd: OwnedFd) -> (u32, Results) {
        let results = empty_results();
        if self.unlocker.vault().lock().unwrap().vault.is_none() {
            tracing::info!(app_id = %app_id, "portal: no vault exists; refusing without a dialog");
            return (RESPONSE_OTHER, results);
        }
        match self.unlocker.ensure_unlocked_portal(app_id).await {
            UnlockOutcome::Unlocked => {}
            UnlockOutcome::Cancelled => return (RESPONSE_CANCELLED, results),
            UnlockOutcome::Failed(e) => {
                tracing::warn!(app_id = %app_id, error = %e, "portal: unlocking failed");
                return (RESPONSE_OTHER, results);
            }
        }
        // Lookup and creation under one hold of the vault mutex, so two
        // concurrent calls for a new app cannot create two keys.
        let secret: Secret = {
            let mut slot = self.unlocker.vault().lock().unwrap();
            let Some(v) = slot.vault.as_mut() else {
                return (RESPONSE_OTHER, results);
            };
            let auth = PortalAuthority::verified_frontend();
            match v.portal_initialised() {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        app_id = %app_id,
                        "the Secret portal keys were neither imported nor initialised; run \
                         `scopevault-admin import` or `scopevault-admin portal init`"
                    );
                    return (RESPONSE_OTHER, results);
                }
                Err(e) => {
                    tracing::warn!(app_id = %app_id, error = %e, "portal: cannot inspect the portal keys");
                    return (RESPONSE_OTHER, results);
                }
            }
            match v.portal_key(&auth, app_id) {
                Ok(Some(key)) => key,
                Ok(None) => match self.app_keyring_exists(app_id) {
                    Ok(true) => {
                        tracing::warn!(
                            app_id = %app_id,
                            "the application has a keyring file of its own; import its key or \
                             run `scopevault-admin portal new-key {app_id}`"
                        );
                        return (RESPONSE_OTHER, results);
                    }
                    Ok(false) => match v.create_portal_key(&auth, app_id) {
                        Ok(key) => key,
                        Err(e) => {
                            tracing::warn!(app_id = %app_id, error = %e, "portal: cannot create a portal key");
                            return (RESPONSE_OTHER, results);
                        }
                    },
                    Err(e) => {
                        tracing::warn!(app_id = %app_id, error = %e, "portal: cannot look at the app's data");
                        return (RESPONSE_OTHER, results);
                    }
                },
                Err(e) => {
                    tracing::warn!(app_id = %app_id, error = %e, "portal: cannot read the portal key");
                    return (RESPONSE_OTHER, results);
                }
            }
        };
        // The key's bytes go to the app through the fd the frontend passed
        // on; they are never logged.
        match write_secret(fd, &secret.value, WRITE_TIMEOUT).await {
            Ok(()) => (RESPONSE_SUCCESS, results),
            Err(e) => {
                tracing::warn!(app_id = %app_id, error = %e, "portal: writing the key to the app's fd failed");
                (RESPONSE_OTHER, results)
            }
        }
    }
}

/// The caller of a portal request, as xdg-desktop-portal encodes it into
/// the request handle: the calling application's unique bus name with the
/// leading `:` removed and every `.` replaced by `_`. Empty handles, empty
/// components and anything with other characters give `None`.
fn caller_from_handle(handle: &str) -> Option<String> {
    let rest = handle.strip_prefix(REQUEST_PREFIX)?;
    let first = rest.split('/').next()?;
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some(format!(":{first}").replace('_', "."))
}

/// Where the key goes: the app's fd, made safe to wait on.
enum WriteTarget {
    /// A pipe or FIFO, reopened as a private, non-blocking open file
    /// description.
    Pipe(AsyncFd<std::os::fd::OwnedFd>),
    /// A socket, written with per-call non-blocking sends.
    Socket(AsyncFd<std::os::fd::OwnedFd>),
}

impl WriteTarget {
    /// Accepts writable pipes, FIFOs and sockets, the fds libsecret and
    /// oo7 pass; anything else (a regular file, a device) is refused.
    ///
    /// The fd shares its open file description with the app, which can
    /// change its flags at any time: an O_NONBLOCK set on it could be
    /// cleared again between the check and the write, which would then
    /// block. So the description's flags are never relied on, nor changed:
    /// a pipe is reopened through `/proc/self/fd` (a new description of the
    /// same pipe), and a socket is written with `MSG_DONTWAIT`.
    fn new(fd: OwnedFd) -> std::io::Result<Self> {
        use rustix::fs::{FileType, Mode, OFlags};
        let fd = std::os::fd::OwnedFd::from(fd);
        let unsupported = |what: &str| std::io::Error::new(std::io::ErrorKind::Unsupported, what.to_owned());
        let access = rustix::fs::fcntl_getfl(&fd)? & OFlags::RWMODE;
        if access != OFlags::WRONLY && access != OFlags::RDWR {
            return Err(unsupported("the fd is not open for writing"));
        }
        match FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) {
            FileType::Fifo => {
                let private = rustix::fs::open(
                    format!("/proc/self/fd/{}", fd.as_raw_fd()),
                    OFlags::WRONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                Ok(WriteTarget::Pipe(AsyncFd::with_interest(private, Interest::WRITABLE)?))
            }
            FileType::Socket => Ok(WriteTarget::Socket(AsyncFd::with_interest(fd, Interest::WRITABLE)?)),
            _ => Err(unsupported("the fd is neither a pipe nor a socket")),
        }
    }

    fn fd(&self) -> &AsyncFd<std::os::fd::OwnedFd> {
        match self {
            WriteTarget::Pipe(fd) | WriteTarget::Socket(fd) => fd,
        }
    }

    /// One write that never blocks.
    fn write_once(&self, data: &[u8]) -> std::io::Result<usize> {
        let n = match self {
            WriteTarget::Pipe(fd) => rustix::io::write(fd.get_ref(), data)?,
            WriteTarget::Socket(fd) => {
                use rustix::net::{SendFlags, send};
                send(fd.get_ref(), data, SendFlags::DONTWAIT | SendFlags::NOSIGNAL)?
            }
        };
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        Ok(n)
    }
}

/// Writes all of `data` to the app's `fd`, waiting for it to drain, but
/// never longer than `timeout`. Nothing blocks a thread: the fd belongs to
/// the app and may be a full pipe that is never read. Dropping the future
/// (the request was closed) stops the write and closes the daemon's copy
/// of the fd.
async fn write_secret(fd: OwnedFd, data: &[u8], timeout: Duration) -> std::io::Result<()> {
    let target = WriteTarget::new(fd)?;
    let write_all = async {
        let mut done = 0;
        while done < data.len() {
            let mut ready = target.fd().writable().await?;
            match ready.try_io(|_| target.write_once(&data[done..])) {
                Ok(Ok(n)) => done += n,
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Ok(Err(e)) => return Err(e),
                // Not writable after all; readiness was cleared, wait again.
                Err(_would_block) => {}
            }
        }
        Ok(())
    };
    match tokio::time::timeout(timeout, write_all).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the application did not read its secret")),
    }
}

/// Resolves once the frontend closed the request, or its sender went away.
/// A `Close` that arrived before this is called is still seen: the watched
/// value is already set.
async fn cancelled(mut rx: tokio::sync::watch::Receiver<bool>) -> bool {
    loop {
        if *rx.borrow_and_update() {
            return true;
        }
        if rx.changed().await.is_err() {
            // The request object is gone; nobody can close the call any more.
            return false;
        }
    }
}

/// The `org.freedesktop.impl.portal.Request` object for one call: the
/// frontend closes it when the application closes its request, which
/// cancels the pending work.
struct Request {
    owner: OwnedUniqueName,
    cancel: tokio::sync::watch::Sender<bool>,
}

#[zbus::interface(name = "org.freedesktop.impl.portal.Request")]
impl Request {
    /// Cancels the pending call. Only the connection that made the call may
    /// do this.
    async fn close(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<()> {
        let denied = || zbus::fdo::Error::AccessDenied("only the caller of the request may close it".into());
        let Some(sender) = header.sender() else {
            return Err(denied());
        };
        if sender.as_str() != self.owner.as_str() {
            tracing::warn!(owner = %self.owner, sender = %sender, "portal: refused Close from another connection");
            return Err(denied());
        }
        let _ = self.cancel.send(true);
        Ok(())
    }
}

#[zbus::interface(name = "org.freedesktop.impl.portal.Secret")]
impl PortalBackend {
    /// Serves one RetrieveSecret call: `(response, results)`.
    async fn retrieve_secret(
        &self,
        #[zbus(header)] header: Header<'_>,
        handle: ObjectPath<'_>,
        app_id: &str,
        fd: OwnedFd,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<(u32, Results)> {
        // The only option the frontend forwards is `token`, which libsecret
        // never sends and gnome-keyring ignores.
        let _ = options;
        let Some(sender) = header.sender().map(|s| OwnedUniqueName::from(s.to_owned())) else {
            return Err(zbus::fdo::Error::AccessDenied("no sender".into()));
        };
        self.authorise(&sender).await?;
        if !handle.as_str().strip_prefix(REQUEST_PREFIX).is_some_and(|rest| !rest.is_empty()) {
            return Err(zbus::fdo::Error::InvalidArgs(format!("the handle must start with {REQUEST_PREFIX}")));
        }
        if !is_valid_portal_app_id(app_id) {
            tracing::warn!(sender = %sender, app_id = %app_id, "portal: refused an invalid app ID");
            self.log_refused_caller(handle.as_str()).await;
            return Ok((RESPONSE_OTHER, empty_results()));
        }

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let request = Request { owner: sender.clone(), cancel: cancel_tx };
        let added = self
            .conn
            .object_server()
            .at(handle.as_str(), request)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        if !added {
            return Err(zbus::fdo::Error::Failed(format!("a request object already exists at {handle}")));
        }

        let work = self.serve_request(app_id, fd);
        let response = tokio::select! {
            true = cancelled(cancel_rx) => {
                tracing::info!(sender = %sender, app_id = %app_id, "portal: the request was closed");
                (RESPONSE_CANCELLED, empty_results())
            }
            r = work => r,
        };
        // Removed whatever the outcome. (If the call's task is dropped
        // instead, the object stays until the daemon exits; its Close then
        // only reaches a finished call.)
        if let Err(e) = self.conn.object_server().remove::<Request, _>(handle.as_str()).await {
            tracing::warn!(path = %handle, error = %e, "portal: cannot remove the request object");
        }
        // Some apps ask every second (Bitwarden), so successes are debug.
        if response.0 == RESPONSE_SUCCESS {
            tracing::debug!(app_id = %app_id, "portal: RetrieveSecret finished");
        } else {
            tracing::info!(app_id = %app_id, response = response.0, "portal: RetrieveSecret finished");
        }
        Ok(response)
    }

    /// The backend API version, the only one the frontend understands.
    #[zbus(property, name = "version")]
    async fn version(&self) -> u32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DBUS_PREFIX;

    #[test]
    fn the_backend_name_is_the_prefix_plus_portal() {
        assert_eq!(BACKEND_NAME, format!("{DBUS_PREFIX}.Portal"));
    }

    #[test]
    fn portal_file_bus_name_reads_the_dbusname_line() {
        let packaged = include_str!("../../packaging/scopevault.portal");
        assert_eq!(portal_file_bus_name(packaged), Some(BACKEND_NAME), "the packaged file names the backend");
        assert_eq!(portal_file_bus_name("[portal]\nDBusName=old.Name.Portal \n"), Some("old.Name.Portal"));
        assert_eq!(portal_file_bus_name("[portal]\nInterfaces=x\n"), None);
    }

    #[test]
    fn caller_from_handle_decodes_the_encoded_unique_name() {
        assert_eq!(caller_from_handle(&format!("{REQUEST_PREFIX}1_234/token")), Some(":1.234".to_owned()));
        assert_eq!(
            caller_from_handle(&format!("{REQUEST_PREFIX}1_234/token/extra")),
            Some(":1.234".to_owned()),
            "a third path component is ignored"
        );
        assert_eq!(caller_from_handle(&format!("wrong{REQUEST_PREFIX}1_234/token")), None);
        assert_eq!(caller_from_handle(REQUEST_PREFIX), None, "empty component");
        assert_eq!(caller_from_handle(&format!("{REQUEST_PREFIX}/token")), None);
        assert_eq!(caller_from_handle(&format!("{REQUEST_PREFIX}1-234/token")), None, "other characters");
    }
}
