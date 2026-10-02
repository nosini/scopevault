//! The administrative socket, served by the daemon.
//!
//! The socket lives in a private directory (mode 0700) under
//! `$XDG_RUNTIME_DIR`. File permissions alone cannot tell a host process
//! from a Flatpak app of the same user that was given access to that
//! directory, so every connecting process is classified from the kernel's
//! record of it (`SO_PEERPIDFD`, `SO_PEERCRED`, `SO_PEERSEC`) by the same
//! classifier as bus callers, and only a positively identified host process
//! is served. Anything else gets an error and nothing more.
//!
//! Operations that hand secrets to another scope or destroy data (moving
//! items, resetting a scope) also need the master password, typed into the
//! daemon's own dialog.

use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use super::AdminAuthority;
use super::peer::peer_credentials;
use super::protocol::{MAX_LINE, Reply, Request, Status, VaultState, read_line, write_json};
use crate::identity::{BusCredentials, IdentityError, Principal, Scope};
use crate::prompts::unlock::{UnlockOutcome, Unlocker};
use crate::service_api::dispatch::GrantChange;
use crate::store::{SHARED_COLLECTION, StoreError, is_valid_portal_app_id};

/// Administrative connections served at once; more are closed at once.
const MAX_CLIENTS: usize = 4;
/// How long a client may take to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What the administrative interface needs from the Secret Service.
pub trait ServiceControl: Send + Sync + 'static {
    /// See `SecretService::global_lock`. Returns false if already locked.
    fn global_lock(self: Arc<Self>) -> bool;
    /// Connections, transfer sessions and pending prompts.
    fn counters(&self) -> (usize, usize, usize);
    /// See `SecretService::grant_changed`: signals a grant change to the
    /// grantee's scope.
    fn grant_changed(self: Arc<Self>, change: GrantChange);
}

impl<R: crate::identity::CallerResolver> ServiceControl for crate::service_api::SecretService<R> {
    fn global_lock(self: Arc<Self>) -> bool {
        crate::service_api::SecretService::global_lock(&self)
    }
    fn counters(&self) -> (usize, usize, usize) {
        (self.active_connections(), self.open_sessions(), self.pending_prompts())
    }
    fn grant_changed(self: Arc<Self>, change: GrantChange) {
        crate::service_api::SecretService::grant_changed(&self, change);
    }
}

/// Classifies a peer from its kernel credentials (blocking).
pub type PeerClassifier = Arc<dyn Fn(BusCredentials) -> Result<Principal, IdentityError> + Send + Sync>;

pub struct AdminServer {
    classify: PeerClassifier,
    unlocker: Arc<Unlocker>,
    control: Arc<dyn ServiceControl>,
    slots: Arc<Semaphore>,
}

/// The bound socket; removed again when dropped.
pub struct BoundSocket {
    pub listener: UnixListener,
    path: PathBuf,
    ino: u64,
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        // Only if it is still ours.
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.ino) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The default socket path: `$XDG_RUNTIME_DIR/scopevault/admin`.
pub fn default_socket_path() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    dir.is_absolute().then(|| dir.join("scopevault").join("admin"))
}

/// Binds the socket at `path`, creating its directory with mode 0700. The
/// directory must be ours and private. A socket there that still accepts
/// connections belongs to another daemon, and binding fails; a stale one is
/// replaced.
pub fn bind(path: &Path) -> std::io::Result<BoundSocket> {
    let err = |msg: String| std::io::Error::other(msg);
    let dir = path.parent().ok_or_else(|| err(format!("{} has no parent directory", path.display())))?;
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        }
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    let m = std::fs::symlink_metadata(dir)?;
    let uid = rustix::process::getuid().as_raw();
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(err(format!("{} must be a directory owned by you with mode 0700", dir.display())));
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(m) if m.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(err(format!("another scopevault daemon is serving {}", path.display())));
            }
            std::fs::remove_file(path)?;
        }
        Ok(_) => return Err(err(format!("{} exists and is not a socket", path.display()))),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let ino = std::fs::symlink_metadata(path)?.ino();
    Ok(BoundSocket { listener, path: path.to_owned(), ino })
}

/// The confirmation dialog's outcome as a refusal, if it was not allowed.
fn refused(outcome: UnlockOutcome) -> Option<Reply> {
    match outcome {
        UnlockOutcome::Unlocked => None,
        UnlockOutcome::Cancelled => Some(Reply::error("cancelled in the password dialog")),
        UnlockOutcome::Failed(e) => Some(Reply::error(format!("the password dialog failed: {e}"))),
    }
}

fn store_error(e: StoreError) -> Reply {
    Reply::error(e.to_string())
}

fn parse_scope(s: &str) -> Result<Scope, Reply> {
    s.parse().map_err(|_| Reply::error(format!("not a scope: {s:?} (host, flatpak/APP-ID or portal)")))
}

impl AdminServer {
    pub fn new(classify: PeerClassifier, unlocker: Arc<Unlocker>, control: Arc<dyn ServiceControl>) -> Arc<Self> {
        Arc::new(AdminServer { classify, unlocker, control, slots: Arc::new(Semaphore::new(MAX_CLIENTS)) })
    }

    /// Serves connections until the process ends.
    pub async fn serve(self: Arc<Self>, listener: &UnixListener) {
        loop {
            let stream = match listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "admin socket: accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                tracing::warn!("admin socket: too many clients; connection closed");
                continue;
            };
            let this = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                this.handle(stream).await;
            });
        }
    }

    /// Classifies the peer; only a host process gets an authority.
    async fn verify(&self, stream: &UnixStream) -> Result<AdminAuthority, Reply> {
        let denied = || Reply::error("access denied: only host processes may use the administrative interface");
        let creds = peer_credentials(stream.as_fd()).map_err(|e| {
            tracing::warn!(error = %e, "admin socket: cannot read peer credentials");
            denied()
        })?;
        let classify = self.classify.clone();
        match tokio::task::spawn_blocking(move || classify(creds)).await {
            Ok(Ok(Principal::Host)) => Ok(AdminAuthority::verified_host()),
            Ok(Ok(other)) => {
                tracing::warn!(scope = %other.scope(), "admin socket: refused a sandboxed caller");
                Err(denied())
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "admin socket: refused an unidentified caller");
                Err(denied())
            }
            Err(e) => {
                tracing::warn!(error = %e, "admin socket: classification failed");
                Err(denied())
            }
        }
    }

    async fn handle(&self, stream: UnixStream) {
        let verdict = self.verify(&stream).await;
        let (rd, mut wr) = stream.into_split();
        let authority = match verdict {
            Ok(a) => a,
            Err(reply) => {
                let _ = write_json(&mut wr, &reply).await;
                return;
            }
        };
        let mut rd = BufReader::new(rd);
        let line = match tokio::time::timeout(REQUEST_TIMEOUT, read_line(&mut rd, MAX_LINE)).await {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => {
                let _ = write_json(&mut wr, &Reply::error(format!("bad request: {e}"))).await;
                return;
            }
            Err(_) => return,
        };
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let _ = write_json(&mut wr, &Reply::error(format!("bad request: {e}"))).await;
                return;
            }
        };
        tracing::info!(request = ?request, "admin request");
        if request == Request::Backup {
            match self.backup().await {
                Ok(bytes) => {
                    let header = Reply::Backup { bytes: bytes.len() as u64 };
                    if write_json(&mut wr, &header).await.is_ok() {
                        let _ = wr.write_all(&bytes).await;
                        let _ = wr.shutdown().await;
                    }
                }
                Err(reply) => {
                    let _ = write_json(&mut wr, &reply).await;
                }
            }
            return;
        }
        let reply = self.run(&authority, request).await.unwrap_or_else(|r| r);
        if let Reply::Error { message } = &reply {
            tracing::info!(error = %message, "admin request failed");
        }
        let _ = write_json(&mut wr, &reply).await;
    }

    /// Unlocks the vault for an administrative request (dialog if needed).
    async fn unlocked(&self) -> Result<(), Reply> {
        if self.unlocker.vault().lock().unwrap().vault.is_none() {
            return Err(Reply::error("there is no vault yet"));
        }
        match refused(self.unlocker.ensure_unlocked_admin().await) {
            None => Ok(()),
            Some(r) => Err(r),
        }
    }

    async fn run(&self, authority: &AdminAuthority, request: Request) -> Result<Reply, Reply> {
        let vault = self.unlocker.vault().clone();
        match request {
            Request::Status => {
                let slot = vault.lock().unwrap();
                let state = match &slot.vault {
                    None => VaultState::Missing,
                    Some(v) if v.is_unlocked() => VaultState::Unlocked,
                    Some(_) => VaultState::Locked,
                };
                let (connections, sessions, prompts) = self.control.counters();
                Ok(Reply::Status(Status {
                    vault: state,
                    data_dir: slot.dir.display().to_string(),
                    connections,
                    sessions,
                    prompts,
                }))
            }
            Request::Lock => {
                let message = if self.control.clone().global_lock() { "locked" } else { "was not unlocked" };
                Ok(Reply::Done { message: message.into() })
            }
            Request::ChangePassword => {
                if vault.lock().unwrap().vault.is_none() {
                    return Err(Reply::error("there is no vault yet"));
                }
                if let Some(r) = refused(self.unlocker.change_password().await) {
                    return Err(r);
                }
                Ok(Reply::Done { message: "password changed".into() })
            }
            Request::Scopes => {
                self.unlocked().await?;
                let mut slot = vault.lock().unwrap();
                let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                Ok(Reply::Scopes { scopes: v.scope_summaries(authority).map_err(store_error)? })
            }
            Request::List { scope } => {
                let scope = parse_scope(&scope)?;
                self.unlocked().await?;
                let mut slot = vault.lock().unwrap();
                let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                let collections = v.scoped_admin(authority, scope).map_err(store_error)?.listing();
                Ok(Reply::Listing { collections })
            }
            Request::Move { from, to, items } => {
                let (from, to) = (parse_scope(&from)?, parse_scope(&to)?);
                if items.is_empty() {
                    return Err(Reply::error("no items given"));
                }
                self.unlocked().await?;
                // Check first, so the dialog is not shown for a request that
                // would fail anyway.
                {
                    let mut slot = vault.lock().unwrap();
                    let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                    let s = v.scoped_admin(authority, from.clone()).map_err(store_error)?;
                    for spec in &items {
                        let found = spec.split_once('/').and_then(|(c, i)| s.item(c, i));
                        if found.is_none() {
                            return Err(Reply::error(format!("{from} has no item {spec}")));
                        }
                    }
                }
                let n = items.len();
                let what = if n == 1 { "1 item".to_owned() } else { format!("{n} items") };
                let action = format!("move {what} from {from} to {to}, which can then read them");
                if let Some(r) = refused(self.unlocker.confirm_admin(&action).await) {
                    return Err(r);
                }
                let mut slot = vault.lock().unwrap();
                let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                let moved = v.move_items(authority, &from, &items, &to).map_err(store_error)?;
                tracing::info!(%from, %to, items = moved.len(), "admin: items moved");
                Ok(Reply::Moved { items: moved })
            }
            Request::ResetScope { scope } => {
                let scope = parse_scope(&scope)?;
                self.unlocked().await?;
                let (collections, items) = {
                    let mut slot = vault.lock().unwrap();
                    let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                    let listing = v.scoped_admin(authority, scope.clone()).map_err(store_error)?.listing();
                    (listing.len(), listing.iter().map(|c| c.items.len()).sum::<usize>())
                };
                if collections == 0 {
                    return Ok(Reply::Reset { collections: 0, items: 0 });
                }
                let action =
                    format!("delete everything stored for {scope}: {items} items in {collections} collections");
                if let Some(r) = refused(self.unlocker.confirm_admin(&action).await) {
                    return Err(r);
                }
                let mut slot = vault.lock().unwrap();
                let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                let (collections, items) = v.reset_scope(authority, &scope).map_err(store_error)?;
                tracing::info!(%scope, collections, items, "admin: scope reset");
                Ok(Reply::Reset { collections, items })
            }
            Request::Share { from, item, to, write } => {
                let (from, to) = (parse_scope(&from)?, parse_scope(&to)?);
                if from == Scope::Portal || to == Scope::Portal {
                    return Err(Reply::error("the portal scope never shares"));
                }
                if from == to {
                    return Err(Reply::error("a scope cannot share with itself"));
                }
                // Check first, so the dialog is not shown for a request that
                // would fail anyway.
                self.unlocked().await?;
                let label = {
                    let mut slot = vault.lock().unwrap();
                    let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                    let Some((col, it)) = item.split_once('/') else {
                        return Err(Reply::error("the item must be COLLECTION/ITEM (as `list` shows it)"));
                    };
                    let s = v.scoped_admin(authority, from.clone()).map_err(store_error)?;
                    let info = s.item(col, it).ok_or_else(|| Reply::error(format!("{from} has no item {item}")))?;
                    info.label
                };
                let access = if write { "read and write" } else { "read" };
                let action = format!("give {to} {access} access to \"{label}\" from {from}");
                if let Some(r) = refused(self.unlocker.confirm_admin(&action).await) {
                    return Err(r);
                }
                let (grant, had_shared) = {
                    let mut slot = vault.lock().unwrap();
                    let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                    let had_shared = v
                        .scoped_admin(authority, to.clone())
                        .map_err(store_error)?
                        .collection_names()
                        .iter()
                        .any(|c| c == SHARED_COLLECTION);
                    let grant = v.share(authority, &from, &item, &to, write).map_err(store_error)?;
                    (grant, had_shared)
                };
                self.control.clone().grant_changed(GrantChange {
                    grantee: to.clone(),
                    grant: grant.clone(),
                    created: true,
                    shared_appeared: !had_shared,
                    shared_disappeared: false,
                });
                tracing::info!(%from, %to, item = %item, write, "admin: item shared");
                Ok(Reply::Shared { grant })
            }
            Request::Unshare { grant } => {
                self.unlocked().await?;
                let (listing, grantee, disappeared) = {
                    let mut slot = vault.lock().unwrap();
                    let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                    let listing = v.unshare(authority, &grant).map_err(store_error)?;
                    let grantee: Scope =
                        listing.grantee.parse().map_err(|e| Reply::error(format!("not a scope: {e}")))?;
                    let still = v
                        .scoped_admin(authority, grantee.clone())
                        .map_err(store_error)?
                        .collection_names()
                        .iter()
                        .any(|c| c == SHARED_COLLECTION);
                    (listing, grantee, !still)
                };
                self.control.clone().grant_changed(GrantChange {
                    grantee: grantee.clone(),
                    grant: grant.clone(),
                    created: false,
                    shared_appeared: false,
                    shared_disappeared: disappeared,
                });
                tracing::info!(grant = %grant, owner = %listing.owner, grantee = %grantee, "admin: grant removed");
                Ok(Reply::Done {
                    message: format!("removed the grant on \"{}\" from {}", listing.label, listing.grantee),
                })
            }
            Request::Grants { scope } => {
                let scope = match scope {
                    Some(s) => Some(parse_scope(&s)?),
                    None => None,
                };
                self.unlocked().await?;
                let mut slot = vault.lock().unwrap();
                let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                Ok(Reply::Grants { grants: v.grants(authority, scope.as_ref()).map_err(store_error)? })
            }
            Request::Backup => unreachable!("handled before"),
            Request::PortalInit => {
                self.unlocked().await?;
                let mut slot = vault.lock().unwrap();
                let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                let created = v.init_portal(authority).map_err(store_error)?;
                Ok(Reply::Done {
                    message: if created {
                        "initialised the Secret portal keys".into()
                    } else {
                        "the Secret portal keys were already initialised".into()
                    },
                })
            }
            Request::PortalNewKey { app_id } => {
                if !is_valid_portal_app_id(&app_id) {
                    return Err(Reply::error(format!("not a valid application ID: {app_id:?}")));
                }
                self.unlocked().await?;
                {
                    let mut slot = vault.lock().unwrap();
                    let v = slot.vault.as_mut().ok_or_else(|| Reply::error("there is no vault yet"))?;
                    v.admin_create_portal_key(authority, &app_id).map_err(store_error)?;
                }
                tracing::info!(app_id = %app_id, "admin: created a portal key");
                Ok(Reply::Done {
                    message: format!(
                        "created a portal key for {app_id}. If the application already has its own keyring file \
                         (~/.var/app/{app_id}/data/keyrings/default.keyring), that file cannot be decrypted with \
                         the new key; move it away before the application stores anything new."
                    ),
                })
            }
        }
    }

    /// A copy of the encrypted database, made in the vault's private
    /// directory and removed again after reading.
    async fn backup(&self) -> Result<Vec<u8>, Reply> {
        let vault = self.unlocker.vault().clone();
        let r = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            let slot = vault.lock().unwrap();
            let v = slot.vault.as_ref().ok_or("there is no vault yet")?;
            let name = format!(
                "backup-{}.tmp",
                crate::store::payload::hex(&crate::crypto::random_array::<16>().map_err(|e| e.to_string())?)
            );
            let tmp = slot.dir.join(name);
            let result = v
                .backup_into(&tmp)
                .map_err(|e| e.to_string())
                .and_then(|()| std::fs::read(&tmp).map_err(|e| e.to_string()));
            let _ = std::fs::remove_file(&tmp);
            result
        })
        .await;
        match r {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(e)) => Err(Reply::error(format!("backup failed: {e}"))),
            Err(e) => Err(Reply::error(format!("backup failed: {e}"))),
        }
    }
}
