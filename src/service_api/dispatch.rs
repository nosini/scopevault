//! Caller-aware message dispatch.
//!
//! zbus's `ObjectServer` keeps one global object tree: an object exists for
//! every caller, `Introspect` lists every child, and properties have one
//! value. That cannot express per-caller views, so this module reads raw
//! method calls from the connection and routes them itself:
//!
//! 1. the sender's unique name is resolved to a principal (or denied);
//! 2. if the request needs the vault's contents and the vault is locked,
//!    it is handled as described under "Locked vault" below;
//! 3. the object path is resolved *within the caller's scope* (and, for
//!    transfer sessions and prompts, within the calling connection);
//! 4. the member is validated against the interface table and handled
//!    (see `methods.rs`).
//!
//! Objects outside the caller's view produce exactly the same
//! `UnknownObject` error as paths that do not exist at all.
//!
//! # Locked vault
//!
//! While the vault is locked its metadata is encrypted, so nothing about a
//! scope's collections is known. Then:
//! - `Unlock` and `CreateCollection` return a Prompt object; the dialog
//!   appears when the client calls `Prompt()`.
//! - `CreateItem` fails with `IsLocked`; libsecret then calls `Unlock` on the
//!   collection and retries.
//! - `Lock` returns nothing locked (everything already is).
//! - Every other request that needs vault contents waits for the shared
//!   unlock dialog. If the user cancels, it fails with `IsLocked` (never with
//!   an empty answer, which a client could mistake for "no such secret").
//!
//! Signals are never broadcast. Each one is sent with a destination to every
//! identified connection of the owning scope (or, for prompt completion, to
//! the prompt's owner).
//!
//! Requests from one connection are handled in order by a per-connection
//! worker. Resource limits: request size, queued requests per connection and
//! queued bytes overall, connections overall and per scope. Connections
//! whose caller cannot be identified hold no worker while idle. When a
//! connection closes, its queued requests are dropped and a request of it
//! waiting for the unlock dialog stops waiting.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use futures_util::StreamExt;
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;
use zbus::message::{Flags, Header, Message, Type as MessageType};
use zbus::names::{OwnedUniqueName, UniqueName};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MessageStream};

use crate::identity::{CallerResolver, Principal, Scope};
use crate::prompts::unlock::{UnlockOutcome, Unlocker};
use crate::store::{SHARED_COLLECTION, ScopedVault, StoreError};

use super::interfaces::{self, Interface};
use super::paths::{self, Parsed};
use super::transfer::Algorithm;

/// Requests queued per connection before further ones are refused.
pub const MAX_QUEUED_PER_CONNECTION: usize = 32;
/// Largest request accepted. The largest legitimate one, `CreateItem` with a
/// secret, label and attributes at their limits, is well under 1 MiB.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Bytes of requests queued, all connections together.
pub const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;
/// Plaintext one `GetSecrets` call may return: 32 secrets of the largest
/// size. Paths are deduplicated first, so this bounds what one request can
/// make the daemon decrypt and hold.
pub const MAX_SECRET_BYTES_PER_REPLY: usize = 16 * 1024 * 1024;
/// Simultaneously served client connections. Connections whose caller could
/// not be identified hold a slot only while they have requests queued.
pub const MAX_CONNECTIONS: usize = 1024;
/// Identified connections per scope, so one app cannot take every slot.
/// Host applications share one scope.
pub const MAX_CONNECTIONS_PER_SCOPE: usize = 128;
/// Open transfer sessions per connection.
pub const MAX_SESSIONS_PER_CONNECTION: usize = 16;
/// Pending prompts per connection.
pub const MAX_PROMPTS_PER_CONNECTION: usize = 8;
/// Paths held by a scope's pending `Unlock` prompts, all its connections
/// together. A prompt keeps its paths until it completes, so without this
/// one app could make the daemon hold every request it ever sent.
pub const MAX_UNLOCK_PATHS_PER_SCOPE: usize = 4096;

const BUS_NAME: &str = "org.freedesktop.DBus";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub name: &'static str,
    pub message: String,
}

impl Fault {
    pub(crate) fn new(name: &'static str, message: impl Into<String>) -> Self {
        Fault { name, message: message.into() }
    }
    /// The single response for any path outside the caller's view.
    pub fn unknown_object() -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownObject", "No such object")
    }
    pub fn access_denied(why: impl Into<String>) -> Self {
        Fault::new("org.freedesktop.DBus.Error.AccessDenied", why)
    }
    pub(crate) fn unknown_method(member: &str) -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownMethod", format!("Unknown method {member}"))
    }
    pub(crate) fn unknown_interface() -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownInterface", "Unknown interface")
    }
    pub(crate) fn unknown_property() -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownProperty", "Unknown property")
    }
    pub(crate) fn read_only() -> Self {
        Fault::new("org.freedesktop.DBus.Error.PropertyReadOnly", "Property is read-only")
    }
    pub fn invalid_args(why: impl Into<String>) -> Self {
        Fault::new("org.freedesktop.DBus.Error.InvalidArgs", why)
    }
    pub(crate) fn limits(why: impl Into<String>) -> Self {
        Fault::new("org.freedesktop.DBus.Error.LimitsExceeded", why)
    }
    /// Secret Service error for object paths given as arguments.
    pub fn no_such_object() -> Self {
        Fault::new("org.freedesktop.Secret.Error.NoSuchObject", "No such object")
    }
    pub fn is_locked() -> Self {
        Fault::new("org.freedesktop.Secret.Error.IsLocked", "The keyring is locked")
    }
    pub fn no_session() -> Self {
        Fault::new("org.freedesktop.Secret.Error.NoSession", "No such session")
    }
    pub(crate) fn failed(why: impl Into<String>) -> Self {
        Fault::new("org.freedesktop.DBus.Error.Failed", why)
    }
}

impl From<StoreError> for Fault {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Locked => Fault::is_locked(),
            StoreError::NoSuchObject => Fault::no_such_object(),
            StoreError::Limit(why) => Fault::limits(why),
            StoreError::Invalid(why) => Fault::invalid_args(why),
            StoreError::NotPermitted(why) => Fault::access_denied(why),
            other => internal(other),
        }
    }
}

pub(crate) fn internal(e: impl std::fmt::Display) -> Fault {
    tracing::warn!(error = %e, "internal error while handling request");
    Fault::failed("Internal error")
}

/// An object as seen by one particular caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Intermediate(&'static str),
    Service,
    CollectionDir,
    AliasDir,
    SessionDir,
    PromptDir,
    Collection(String),
    Item(String, String),
    Session(String),
    Prompt(String),
}

impl Node {
    pub(crate) fn interfaces(&self) -> &'static [&'static Interface] {
        match self {
            Node::Service => &[&interfaces::SERVICE],
            Node::Collection(_) => &[&interfaces::COLLECTION],
            Node::Item(..) => &[&interfaces::ITEM],
            Node::Session(_) => &[&interfaces::SESSION],
            Node::Prompt(_) => &[&interfaces::PROMPT],
            _ => &[],
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SignalBody {
    Path(OwnedObjectPath),
    PropertiesChanged(&'static str, BTreeMap<&'static str, OwnedValue>),
    Completed(bool, OwnedValue),
}

#[derive(Debug, Clone)]
pub(crate) enum Target {
    /// Every identified connection of this scope.
    Scope(Scope),
    /// One connection.
    Connection(OwnedUniqueName),
}

#[derive(Debug, Clone)]
pub(crate) struct Event {
    pub target: Target,
    pub path: OwnedObjectPath,
    pub interface: &'static str,
    pub member: &'static str,
    pub body: SignalBody,
}

/// Bookkeeping for one client connection. The principal is filled in once
/// the connection has been identified; only identified connections get
/// signals. `gone` turns true when the bus reports the connection closed.
struct Peer {
    principal: OnceLock<Principal>,
    gone: watch::Sender<bool>,
    /// A request with a session this daemon never opened was logged.
    unknown_session_logged: std::sync::atomic::AtomicBool,
}

impl Peer {
    fn new() -> Self {
        Peer {
            principal: OnceLock::new(),
            gone: watch::Sender::new(false),
            unknown_session_logged: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn is_gone(&self) -> bool {
        *self.gone.borrow()
    }

    async fn wait_gone(&self) {
        let _ = self.gone.subscribe().wait_for(|g| *g).await;
    }
}

pub(crate) struct TransferSession {
    pub owner: OwnedUniqueName,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone)]
pub(crate) enum PromptAction {
    /// The distinct paths asked for that can name a collection or item.
    Unlock(BTreeSet<String>),
    CreateCollection {
        label: String,
        alias: String,
    },
}

pub(crate) struct PromptEntry {
    pub owner: OwnedUniqueName,
    pub principal: Principal,
    pub action: PromptAction,
    pub task: Option<AbortHandle>,
}

/// One method call being handled.
pub(crate) struct Call<'a> {
    pub hdr: Header<'a>,
    pub msg: &'a Message,
    pub sender: OwnedUniqueName,
    pub principal: Principal,
    pub events: Vec<Event>,
}

impl Call<'_> {
    pub fn scope(&self) -> Scope {
        self.principal.scope()
    }

    pub fn reply<B>(&self, body: &B) -> CallResult
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        Message::method_return(&self.hdr).and_then(|b| b.build(body)).map_err(internal)
    }

    pub fn signal_scope(
        &mut self,
        path: OwnedObjectPath,
        interface: &'static str,
        member: &'static str,
        body: SignalBody,
    ) {
        self.events.push(Event { target: Target::Scope(self.scope()), path, interface, member, body });
    }

    /// Queues a signal for another scope's connections — a shared item's
    /// grantees, or the owner of an item a grantee changed.
    pub fn signal_for(
        &mut self,
        scope: &Scope,
        path: OwnedObjectPath,
        interface: &'static str,
        member: &'static str,
        body: SignalBody,
    ) {
        self.events.push(Event { target: Target::Scope(scope.clone()), path, interface, member, body });
    }
}

pub type CallResult = Result<Message, Fault>;

/// A request waiting for its connection's worker, with its size charged to
/// the shared queue budget until it is dropped.
struct Queued {
    msg: Message,
    /// When the request arrived: a wait for the vault counts from here, so
    /// requests queued behind a waiting one do not each wait in full.
    received: std::time::Instant,
    _charge: Charge,
}

struct Charge {
    budget: Arc<AtomicUsize>,
    bytes: usize,
}

impl Charge {
    fn take(budget: &Arc<AtomicUsize>, bytes: usize) -> Option<Charge> {
        budget
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|n| *n <= MAX_QUEUED_BYTES)
            })
            .ok()
            .map(|_| Charge { budget: budget.clone(), bytes })
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub(crate) fn value<'a>(v: impl Into<Value<'a>>) -> Result<OwnedValue, Fault> {
    OwnedValue::try_from(v.into()).map_err(internal)
}

pub(crate) fn service_path() -> OwnedObjectPath {
    OwnedObjectPath::from(ObjectPath::from_static_str_unchecked(paths::SERVICE))
}

pub struct SecretService<R: CallerResolver> {
    pub(crate) conn: Connection,
    resolver: Arc<R>,
    pub(crate) unlocker: Arc<Unlocker>,
    peers: Mutex<HashMap<OwnedUniqueName, Arc<Peer>>>,
    machine_id: Option<String>,
    pub(crate) sessions: Mutex<HashMap<String, TransferSession>>,
    pub(crate) prompts: Mutex<HashMap<String, PromptEntry>>,
    queued_bytes: Arc<AtomicUsize>,
}

impl<R: CallerResolver> SecretService<R> {
    pub fn new(conn: Connection, resolver: Arc<R>, unlocker: Arc<Unlocker>) -> Arc<Self> {
        let machine_id = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()));
        Arc::new(SecretService {
            conn,
            resolver,
            unlocker,
            peers: Mutex::default(),
            machine_id,
            sessions: Mutex::default(),
            prompts: Mutex::default(),
            queued_bytes: Arc::default(),
        })
    }

    /// Starts listening and returns the future that serves requests until
    /// the bus connection closes. Request bus names only after this
    /// returns, so no early call is missed. When the future ends the
    /// process must exit: identity caches are valid for one connection only.
    pub async fn start(self: Arc<Self>) -> zbus::Result<impl std::future::Future<Output = zbus::Result<()>>> {
        // Disconnect notifications must arrive in the same ordered stream as
        // method calls, so a connection's departure is always processed
        // after every request it sent.
        let stream = MessageStream::from(&self.conn);
        let dbus = zbus::fdo::DBusProxy::new(&self.conn).await?;
        dbus.add_match_rule(
            zbus::MatchRule::builder()
                .msg_type(MessageType::Signal)
                .sender(BUS_NAME)?
                .interface(BUS_NAME)?
                .member("NameOwnerChanged")?
                .build(),
        )
        .await?;

        let mut unlocked = self.unlocker.subscribe_unlocked();
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            while unlocked.recv().await.is_ok() {
                let Some(this) = weak.upgrade() else { break };
                this.announce_unlock().await;
            }
        });
        Ok(self.serve(stream))
    }

    async fn serve(self: Arc<Self>, mut stream: MessageStream) -> zbus::Result<()> {
        let mut workers: HashMap<OwnedUniqueName, mpsc::Sender<Queued>> = HashMap::new();
        while let Some(msg) = stream.next().await {
            let msg = msg?;
            let hdr = msg.header();
            match msg.message_type() {
                MessageType::Signal => {
                    if let Some(gone) = disconnected_peer(&msg) {
                        workers.remove(&gone);
                        self.forget_connection(&gone);
                    }
                }
                MessageType::MethodCall => {
                    let Some(sender) = hdr.sender().map(|s| OwnedUniqueName::from(s.to_owned())) else { continue };
                    if msg.data().len() > MAX_REQUEST_BYTES {
                        self.spawn_fault(&msg, Fault::limits("Request too large"));
                        continue;
                    }
                    let Some(charge) = Charge::take(&self.queued_bytes, msg.data().len()) else {
                        self.spawn_fault(&msg, Fault::limits("Too many requests"));
                        continue;
                    };
                    // Workers of unidentified callers stop when idle.
                    if workers.get(&sender).is_some_and(mpsc::Sender::is_closed) {
                        workers.remove(&sender);
                    }
                    if !workers.contains_key(&sender) && workers.len() >= MAX_CONNECTIONS {
                        workers.retain(|_, tx| !tx.is_closed());
                        if workers.len() >= MAX_CONNECTIONS {
                            self.spawn_fault(&msg, Fault::limits("Too many connections"));
                            continue;
                        }
                    }
                    let tx = workers.entry(sender.clone()).or_insert_with(|| self.spawn_worker(&sender));
                    match tx.try_send(Queued { msg, received: std::time::Instant::now(), _charge: charge }) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(q)) => {
                            self.spawn_fault(&q.msg, Fault::limits("Too many requests"))
                        }
                        // The worker stopped since the check above.
                        Err(mpsc::error::TrySendError::Closed(q)) => {
                            let tx = self.spawn_worker(&sender);
                            let _ = tx.try_send(q);
                            workers.insert(sender, tx);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Drops everything bound to a connection that went away. Its worker
    /// stops waiting for the vault and skips requests still queued; aborting
    /// its prompt tasks closes their dialogs unless another request waits
    /// too.
    /// A request named a transfer session that does not exist (not one of
    /// another connection: that is refused silently). libsecret opens one
    /// session per process and never opens another, so a program that
    /// started before this daemon (a restart, or a logout that stopped it)
    /// keeps failing with `NoSession` until it is restarted. Logged once per
    /// connection, with the program, so the journal says what to restart.
    pub(crate) fn note_unknown_session(&self, sender: &OwnedUniqueName) {
        let first = self
            .peers
            .lock()
            .unwrap()
            .get(sender)
            .is_some_and(|p| !p.unknown_session_logged.swap(true, std::sync::atomic::Ordering::Relaxed));
        if !first {
            return;
        }
        let conn = self.conn.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            let lookup = async {
                let dbus = zbus::fdo::DBusProxy::new(&conn).await.ok()?;
                let pid = dbus.get_connection_unix_process_id(sender.as_ref().into()).await.ok()?;
                let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
                Some((pid, exe.map(|p| p.to_string_lossy().into_owned())))
            };
            let (pid, exe) = match tokio::time::timeout(std::time::Duration::from_secs(2), lookup).await {
                Ok(Some((pid, exe))) => (pid.to_string(), exe.unwrap_or_else(|| "unknown".into())),
                _ => ("unknown".into(), "unknown".into()),
            };
            tracing::info!(
                sender = %sender,
                pid,
                exe,
                "a client used a transfer session this daemon never opened, probably one from before a daemon \
                 restart; libsecret does not open a new one, so restart that program"
            );
        });
    }

    fn forget_connection(&self, gone: &OwnedUniqueName) {
        if let Some(peer) = self.peers.lock().unwrap().remove(gone) {
            // Before the cleanup below, so a request that creates a session
            // or prompt concurrently sees the flag afterwards (see `handle`).
            peer.gone.send_replace(true);
        }
        self.drop_connection_state(gone);
    }

    fn drop_connection_state(&self, gone: &OwnedUniqueName) {
        self.sessions.lock().unwrap().retain(|_, s| &s.owner != gone);
        self.prompts.lock().unwrap().retain(|_, p| {
            let keep = &p.owner != gone;
            if !keep && let Some(t) = &p.task {
                t.abort();
            }
            keep
        });
    }

    fn spawn_worker(self: &Arc<Self>, sender: &OwnedUniqueName) -> mpsc::Sender<Queued> {
        let (tx, mut rx) = mpsc::channel::<Queued>(MAX_QUEUED_PER_CONNECTION);
        let peer = Arc::new(Peer::new());
        self.peers.lock().unwrap().insert(sender.clone(), peer.clone());
        let this = self.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            while let Some(q) = rx.recv().await {
                let identified = this.handle(&q.msg, q.received, &peer).await;
                drop(q);
                // An unidentified or unadmitted caller keeps no worker or
                // connection slot while idle; its next request starts a new worker. Closing
                // first means nothing sent meanwhile is lost: it is either
                // drained here or refused to the sender, which respawns.
                if !identified && rx.is_empty() {
                    rx.close();
                    while let Some(q) = rx.recv().await {
                        this.handle(&q.msg, q.received, &peer).await;
                    }
                    let mut peers = this.peers.lock().unwrap();
                    if peers.get(&sender).is_some_and(|p| Arc::ptr_eq(p, &peer)) {
                        peers.remove(&sender);
                    }
                    break;
                }
            }
        });
        tx
    }

    fn spawn_fault(self: &Arc<Self>, msg: &Message, fault: Fault) {
        let this = self.clone();
        let msg = msg.clone();
        tokio::spawn(async move { this.send_reply(&msg, Err(fault)).await });
    }

    async fn send_reply(&self, msg: &Message, result: CallResult) {
        let hdr = msg.header();
        if hdr.primary().flags().contains(Flags::NoReplyExpected) {
            return;
        }
        let reply = match result {
            Ok(r) => r,
            Err(f) => match Message::error(&hdr, f.name).and_then(|b| b.build(&(f.message.as_str(),))) {
                Ok(m) => m,
                Err(e) => return tracing::warn!(error = %e, "cannot build error reply"),
            },
        };
        if let Err(e) = self.conn.send(&reply).await {
            tracing::debug!(error = %e, "cannot send reply");
        }
    }

    /// Handles one request. Returns whether the connection holds a slot:
    /// false for a caller that could not be identified or was not admitted
    /// (its scope is at [`MAX_CONNECTIONS_PER_SCOPE`]), whose worker then
    /// stops once idle, so it keeps no slot of [`MAX_CONNECTIONS`] either.
    async fn handle(self: &Arc<Self>, msg: &Message, received: std::time::Instant, peer: &Peer) -> bool {
        let hdr = msg.header();
        let Some(sender) = hdr.sender().map(|s| OwnedUniqueName::from(s.to_owned())) else { return false };
        // Queued before the connection closed: nobody is left to answer.
        if peer.is_gone() {
            return true;
        }
        let principal = match &*self.resolver.resolve(&sender).await {
            Ok(p) => p.clone(),
            Err(_) => {
                self.send_reply(msg, Err(Fault::access_denied("Caller could not be identified"))).await;
                return false;
            }
        };
        if peer.principal.get().is_none() && !self.admit(peer, &principal) {
            self.send_reply(msg, Err(Fault::limits("Too many connections for this application"))).await;
            return false;
        }
        let mut call = Call { hdr, msg, sender, principal, events: Vec::new() };
        let result = self.dispatch(&mut call, received, peer).await;
        // The connection may have closed while this request ran, after its
        // state was dropped; drop whatever the request added since.
        if peer.is_gone() {
            self.drop_connection_state(&call.sender);
        }
        // Names only: arguments may contain secrets and are never logged.
        tracing::debug!(
            sender = %call.sender,
            scope = %call.scope(),
            path = ?call.hdr.path().map(|p| p.as_str()),
            interface = ?call.hdr.interface().map(|i| i.as_str()),
            member = ?call.hdr.member().map(|m| m.as_str()),
            outcome = match &result {
                Ok(_) => "ok",
                Err(f) => f.name,
            },
            "request"
        );
        // Reply first: a client that reacts to a signal by calling us again
        // should already have its answer.
        self.send_reply(msg, result).await;
        for e in std::mem::take(&mut call.events) {
            self.emit(e).await;
        }
        true
    }

    /// Records a newly identified connection's principal, unless its scope
    /// already has [`MAX_CONNECTIONS_PER_SCOPE`] connections.
    fn admit(&self, peer: &Peer, principal: &Principal) -> bool {
        let peers = self.peers.lock().unwrap();
        let scope = principal.scope();
        let same = peers.values().filter(|p| p.principal.get().map(Principal::scope).as_ref() == Some(&scope)).count();
        if same >= MAX_CONNECTIONS_PER_SCOPE {
            return false;
        }
        let _ = peer.principal.set(principal.clone());
        true
    }

    pub(crate) fn vault_unlocked(&self) -> bool {
        self.unlocker.vault().lock().unwrap().is_unlocked()
    }

    /// Runs `f` on the caller's scope of the unlocked vault. A scope's first
    /// use creates its `login` collection.
    pub(crate) fn with_vault<T>(
        &self,
        principal: &Principal,
        f: impl FnOnce(&mut ScopedVault<'_>) -> Result<T, Fault>,
    ) -> Result<T, Fault> {
        let mut slot = self.unlocker.vault().lock().unwrap();
        let vault = slot.vault.as_mut().ok_or_else(Fault::is_locked)?;
        let mut scoped = vault.scoped(principal)?;
        scoped.ensure_namespace()?;
        f(&mut scoped)
    }

    async fn dispatch(self: &Arc<Self>, call: &mut Call<'_>, received: std::time::Instant, peer: &Peer) -> CallResult {
        let path = call.hdr.path().ok_or_else(Fault::unknown_object)?.to_owned();
        let member = call.hdr.member().ok_or_else(|| Fault::unknown_method(""))?.to_string();
        let interface = call.hdr.interface().map(|i| i.to_string());

        // Peer works on any path and reveals nothing about objects.
        if interface.as_deref() == Some(interfaces::PEER.name)
            || (interface.is_none() && matches!(member.as_str(), "Ping" | "GetMachineId"))
        {
            return self.peer_method(call, &member);
        }

        let parsed = paths::parse(path.as_str());
        if needs_vault(&parsed, interface.as_deref(), &member) && !self.vault_unlocked() {
            let on_collection = matches!(parsed, Parsed::Collection(_) | Parsed::AliasedCollection(_));
            if on_collection && member == "CreateItem" {
                return Err(Fault::is_locked());
            }
            if matches!(parsed, Parsed::Service) && member == "Lock" {
                return call.reply(&(Vec::<OwnedObjectPath>::new(), paths::none()));
            }
            tracing::debug!(sender = %call.sender, member = %member, "waiting for the vault to be unlocked");
            // A client that leaves stops waiting, so the dialog closes
            // unless someone else waits for it too.
            let scope = call.scope();
            let outcome = tokio::select! {
                o = self.unlocker.ensure_unlocked_implicit(&scope, received) => o,
                () = peer.wait_gone() => return Err(Fault::is_locked()),
            };
            match outcome {
                UnlockOutcome::Unlocked => {}
                UnlockOutcome::Cancelled => return Err(Fault::is_locked()),
                UnlockOutcome::Failed(why) => {
                    tracing::warn!(reason = %why, "unlocking failed");
                    return Err(Fault::is_locked());
                }
            }
        }

        let node = self.resolve_node(&call.principal, &call.sender, &parsed)?.ok_or_else(Fault::unknown_object)?;
        let iface = match interface.as_deref() {
            Some(name) => interfaces::STANDARD
                .iter()
                .chain(node.interfaces())
                .find(|i| i.name == name)
                .copied()
                .ok_or_else(Fault::unknown_interface)?,
            None => interfaces::STANDARD
                .iter()
                .chain(node.interfaces())
                .find(|i| i.method(&member).is_some())
                .copied()
                .ok_or_else(|| Fault::unknown_method(&member))?,
        };
        let method = iface.method(&member).ok_or_else(|| Fault::unknown_method(&member))?;
        // Compared as parsed signatures: zvariant represents a body holding
        // one struct (`SetSecret`'s `(oayays)`) exactly like a body of that
        // struct's fields, so no string form distinguishes them.
        let expected: zbus::zvariant::Signature = method.in_signature().parse().map_err(internal)?;
        if *call.msg.body().signature() != expected {
            return Err(Fault::invalid_args(format!("expected signature '{}'", method.in_signature())));
        }

        match (iface.name, &node) {
            ("org.freedesktop.DBus.Introspectable", _) => {
                let xml = interfaces::introspect(node.interfaces(), &self.children(call, &node)?);
                call.reply(&(xml,))
            }
            ("org.freedesktop.DBus.Properties", _) => self.properties(call, &member, &node),
            ("org.freedesktop.Secret.Service", _) => self.service_method(call, &member),
            ("org.freedesktop.Secret.Collection", Node::Collection(c)) => self.collection_method(call, &member, c),
            ("org.freedesktop.Secret.Item", Node::Item(c, i)) => self.item_method(call, &member, c, i),
            ("org.freedesktop.Secret.Session", Node::Session(id)) => {
                self.sessions.lock().unwrap().remove(id);
                call.reply(&())
            }
            ("org.freedesktop.Secret.Prompt", Node::Prompt(id)) => self.prompt_method(call, &member, id),
            _ => Err(Fault::unknown_method(&member)),
        }
    }

    fn peer_method(&self, call: &Call<'_>, member: &str) -> CallResult {
        if !call.msg.body().signature().to_string_no_parens().is_empty() {
            return Err(Fault::invalid_args("expected no arguments"));
        }
        match member {
            "Ping" => call.reply(&()),
            "GetMachineId" => match &self.machine_id {
                Some(id) => call.reply(&(id.as_str(),)),
                None => Err(Fault::failed("Machine ID unavailable")),
            },
            other => Err(Fault::unknown_method(other)),
        }
    }

    /// Resolves a path for this caller, or `None` if it is outside the
    /// caller's view (whether or not it exists elsewhere). Fails if the
    /// vault was locked since the request waited for it: the object may
    /// well exist.
    fn resolve_node(
        &self,
        principal: &Principal,
        sender: &UniqueName<'_>,
        parsed: &Parsed<'_>,
    ) -> Result<Option<Node>, Fault> {
        let in_vault = |f: &dyn Fn(&ScopedVault<'_>) -> Option<Node>| self.with_vault(principal, |v| Ok(f(v)));
        Ok(match *parsed {
            Parsed::Root => Some(Node::Intermediate("org")),
            Parsed::Org => Some(Node::Intermediate("freedesktop")),
            Parsed::Freedesktop => Some(Node::Intermediate("secrets")),
            Parsed::Service => Some(Node::Service),
            Parsed::CollectionDir => Some(Node::CollectionDir),
            Parsed::AliasDir => Some(Node::AliasDir),
            Parsed::SessionDir => Some(Node::SessionDir),
            Parsed::PromptDir => Some(Node::PromptDir),
            Parsed::Collection(c) => in_vault(&|v| v.collection(c).map(|_| Node::Collection(c.to_owned())))?,
            Parsed::AliasedCollection(a) => in_vault(&|v| v.alias(a).map(Node::Collection))?,
            Parsed::Item(c, i) => in_vault(&|v| v.item(c, i).map(|_| Node::Item(c.to_owned(), i.to_owned())))?,
            Parsed::AliasedItem(a, i) => {
                in_vault(&|v| v.alias(a).filter(|c| v.item(c, i).is_some()).map(|c| Node::Item(c, i.to_owned())))?
            }
            Parsed::Session(id) => {
                let s = self.sessions.lock().unwrap();
                s.get(id).filter(|s| s.owner.as_str() == sender.as_str()).map(|_| Node::Session(id.to_owned()))
            }
            Parsed::Prompt(id) => {
                let p = self.prompts.lock().unwrap();
                p.get(id).filter(|p| p.owner.as_str() == sender.as_str()).map(|_| Node::Prompt(id.to_owned()))
            }
            Parsed::Unknown => None,
        })
    }

    fn children(&self, call: &Call<'_>, node: &Node) -> Result<Vec<String>, Fault> {
        let owned_by_caller = |owner: &OwnedUniqueName| owner == &call.sender;
        Ok(match node {
            Node::Intermediate(child) => vec![(*child).to_owned()],
            Node::Service => ["collection", "aliases", "session", "prompt"].map(String::from).to_vec(),
            Node::CollectionDir => self.with_vault(&call.principal, |v| Ok(v.collection_names()))?,
            Node::AliasDir => self.with_vault(&call.principal, |v| {
                Ok(v.aliases().into_iter().filter(|a| v.alias(a).is_some()).collect())
            })?,
            Node::Collection(c) => {
                self.with_vault(&call.principal, |v| Ok(v.collection(c).map(|c| c.items).unwrap_or_default()))?
            }
            Node::SessionDir => self
                .sessions
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, s)| owned_by_caller(&s.owner))
                .map(|(k, _)| k.clone())
                .collect(),
            Node::PromptDir => self
                .prompts
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, p)| owned_by_caller(&p.owner))
                .map(|(k, _)| k.clone())
                .collect(),
            Node::Item(..) | Node::Session(_) | Node::Prompt(_) => Vec::new(),
        })
    }

    /// Delivers an event to its target connections.
    pub(crate) async fn emit(&self, e: Event) {
        let targets: Vec<OwnedUniqueName> = match &e.target {
            Target::Connection(c) => vec![c.clone()],
            Target::Scope(scope) => self
                .peers
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, p)| p.principal.get().map(Principal::scope).as_ref() == Some(scope))
                .map(|(n, _)| n.clone())
                .collect(),
        };
        for dest in targets {
            let built = Message::signal(e.path.as_ref(), e.interface, e.member)
                .and_then(|b| b.destination(dest.as_ref()))
                .and_then(|b| match &e.body {
                    SignalBody::Path(p) => b.build(&(p,)),
                    SignalBody::PropertiesChanged(iface, changed) => b.build(&(*iface, changed, Vec::<String>::new())),
                    SignalBody::Completed(dismissed, result) => b.build(&(*dismissed, result)),
                });
            match built {
                Ok(m) => {
                    if let Err(err) = self.conn.send(&m).await {
                        tracing::debug!(error = %err, "cannot send signal");
                    }
                }
                Err(err) => tracing::warn!(error = %err, "cannot build signal"),
            }
        }
    }

    /// After the vault is unlocked, tells every identified connection that
    /// its scope's collections are now visible.
    async fn announce_unlock(&self) {
        for p in self.active_principals() {
            let Ok(cols) = self.with_vault(&p, |v| Ok(v.collection_names())) else { continue };
            let paths: Vec<OwnedObjectPath> = cols.iter().map(|c| paths::collection(c)).collect();
            let Ok(v) = value(paths) else { continue };
            let mut changed = BTreeMap::new();
            changed.insert("Collections", v);
            self.emit(Event {
                target: Target::Scope(p.scope()),
                path: service_path(),
                interface: interfaces::PROPERTIES.name,
                member: "PropertiesChanged",
                body: SignalBody::PropertiesChanged(interfaces::SERVICE.name, changed),
            })
            .await;
        }
    }

    /// One identified principal per scope with a connection.
    fn active_principals(&self) -> Vec<Principal> {
        let peers = self.peers.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        peers.values().filter_map(|p| p.principal.get()).filter(|p| seen.insert(p.scope())).cloned().collect()
    }

    /// Global lock, for the administrative interface: drops the vault key
    /// and all decrypted metadata, so nothing is returned until the next
    /// unlock dialog succeeds. Connections are told that their collections
    /// are locked. Returns false if the vault was not unlocked.
    ///
    /// Transfer sessions stay open. They protect secrets in transit to
    /// their own connection only, and libsecret opens one session per
    /// process and never reopens it, so dropping them would break every
    /// running application until it restarts.
    pub fn global_lock(self: &Arc<Self>) -> bool {
        let principals = self.active_principals();
        let mut locked: Vec<(Scope, Vec<String>)> = Vec::new();
        {
            let mut slot = self.unlocker.vault().lock().unwrap();
            let Some(v) = slot.vault.as_mut().filter(|v| v.is_unlocked()) else { return false };
            for p in &principals {
                if let Ok(s) = v.scoped(p) {
                    locked.push((p.scope(), s.collection_names()));
                }
            }
            v.lock();
        }
        let this = self.clone();
        tokio::spawn(async move {
            for (scope, collections) in locked {
                for c in collections {
                    let Ok(v) = value(true) else { continue };
                    this.emit(Event {
                        target: Target::Scope(scope.clone()),
                        path: paths::collection(&c),
                        interface: interfaces::PROPERTIES.name,
                        member: "PropertiesChanged",
                        body: SignalBody::PropertiesChanged(
                            interfaces::COLLECTION.name,
                            BTreeMap::from([("Locked", v)]),
                        ),
                    })
                    .await;
                }
            }
        });
        true
    }

    /// Client connections currently tracked (for diagnostics and tests).
    pub fn active_connections(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    /// Open transfer sessions, all connections together.
    pub fn open_sessions(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Prompts not yet completed or dismissed, all connections together.
    pub fn pending_prompts(&self) -> usize {
        self.prompts.lock().unwrap().len()
    }

    /// After a `share` or `unshare` through the administrative interface:
    /// tells every identified connection of the grantee scope that an item
    /// appeared in or disappeared from its `Shared` collection, and that the
    /// service's `Collections` changed when `Shared` itself appeared or
    /// disappeared. No other scope is told.
    pub fn grant_changed(self: &Arc<Self>, change: GrantChange) {
        let this = self.clone();
        tokio::spawn(async move {
            for e in this.grant_events(&change) {
                this.emit(e).await;
            }
        });
    }

    /// The signals for a [`GrantChange`], to the grantee scope only.
    pub(crate) fn grant_events(&self, change: &GrantChange) -> Vec<Event> {
        let member = if change.created { "ItemCreated" } else { "ItemDeleted" };
        let mut events = vec![Event {
            target: Target::Scope(change.grantee.clone()),
            path: paths::collection(SHARED_COLLECTION),
            interface: interfaces::COLLECTION.name,
            member,
            body: SignalBody::Path(paths::item(SHARED_COLLECTION, &change.grant)),
        }];
        if !change.shared_appeared && !change.shared_disappeared {
            return events;
        }
        // The property value is the grantee's own view, so only a connected
        // principal of that scope can compute it; without one, nobody
        // receives anything anyway.
        let Some(principal) = self.active_principals().into_iter().find(|p| p.scope() == change.grantee) else {
            return events;
        };
        let Ok(cols) = self.with_vault(&principal, |v| Ok(v.collection_names())) else { return events };
        let Ok(v) = value(cols.iter().map(|c| paths::collection(c)).collect::<Vec<_>>()) else { return events };
        events.push(Event {
            target: Target::Scope(change.grantee.clone()),
            path: service_path(),
            interface: interfaces::PROPERTIES.name,
            member: "PropertiesChanged",
            body: SignalBody::PropertiesChanged(interfaces::SERVICE.name, BTreeMap::from([("Collections", v)])),
        });
        events
    }
}

/// What the administrative interface reports after share/unshare, for the
/// signals to the grantee scope.
#[derive(Debug, Clone)]
pub struct GrantChange {
    pub grantee: Scope,
    /// The grant's ID (the item's path name in the grantee's view).
    pub grant: String,
    /// True for share (the item appears), false for unshare (it disappears).
    pub created: bool,
    /// Whether `Shared` appeared for the grantee with this grant.
    pub shared_appeared: bool,
    /// Whether `Shared` disappeared for the grantee with this unshare.
    pub shared_disappeared: bool,
}

/// Whether a request needs the vault's (encrypted) contents.
fn needs_vault(parsed: &Parsed<'_>, interface: Option<&str>, member: &str) -> bool {
    match parsed {
        Parsed::Collection(_)
        | Parsed::AliasedCollection(_)
        | Parsed::Item(..)
        | Parsed::AliasedItem(..)
        | Parsed::CollectionDir
        | Parsed::AliasDir => true,
        Parsed::Service => match interface {
            Some("org.freedesktop.DBus.Properties") => matches!(member, "Get" | "GetAll"),
            Some("org.freedesktop.Secret.Service") | None => {
                matches!(member, "SearchItems" | "GetSecrets" | "ReadAlias" | "SetAlias" | "Lock")
            }
            _ => false,
        },
        _ => false,
    }
}

/// If `msg` is the bus announcing that a unique name disconnected, returns it.
/// The bus daemon sets the sender field itself, so clients cannot forge this.
fn disconnected_peer(msg: &Message) -> Option<OwnedUniqueName> {
    let hdr = msg.header();
    if hdr.sender().map(|s| s.as_str()) != Some(BUS_NAME)
        || hdr.interface().map(|i| i.as_str()) != Some(BUS_NAME)
        || hdr.member().map(|m| m.as_str()) != Some("NameOwnerChanged")
    {
        return None;
    }
    let (name, _old, new): (String, String, String) = msg.body().deserialize().ok()?;
    if !new.is_empty() || !name.starts_with(':') {
        return None;
    }
    UniqueName::try_from(name).ok().map(OwnedUniqueName::from)
}
