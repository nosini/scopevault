//! Caller-aware message dispatch.
//!
//! zbus's `ObjectServer` keeps one global object tree: an object exists for
//! every caller, `Introspect` lists every child, and properties have one
//! value. That cannot express per-caller views, so this module reads raw
//! method calls from the connection and routes them itself:
//!
//! 1. the sender's unique name is resolved to a principal (or denied);
//! 2. the object path is resolved *within the caller's scope* (and, for
//!    sessions and prompts, within the calling connection);
//! 3. the member is validated against the interface table and handled.
//!
//! Objects outside the caller's view produce exactly the same
//! `UnknownObject` error as paths that do not exist at all.
//!
//! Signals are never broadcast. Each one is sent with a destination to every
//! active connection whose scope may see it.
//!
//! Requests from one connection are handled in order by a per-connection
//! worker; a bounded queue per connection limits resource use.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use futures_util::StreamExt;
use tokio::sync::mpsc;
use zbus::message::{Flags, Header, Message, Type as MessageType};
use zbus::names::{OwnedUniqueName, UniqueName};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MessageStream};

use crate::identity::{CallerResolver, Scope};

use super::interfaces::{self, Interface};
use super::model::{Model, ModelError};
use super::paths::{self, Parsed};

/// Requests queued per connection before further ones are refused.
pub const MAX_QUEUED_PER_CONNECTION: usize = 32;
/// Simultaneously served client connections.
pub const MAX_CONNECTIONS: usize = 1024;

const BUS_NAME: &str = "org.freedesktop.DBus";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub name: &'static str,
    pub message: String,
}

impl Fault {
    fn new(name: &'static str, message: impl Into<String>) -> Self {
        Fault { name, message: message.into() }
    }
    /// The single response for anything outside the caller's view.
    pub fn unknown_object() -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownObject", "No such object")
    }
    pub fn access_denied() -> Self {
        Fault::new("org.freedesktop.DBus.Error.AccessDenied", "Caller could not be identified")
    }
    fn unknown_method(member: &str) -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownMethod", format!("Unknown method {member}"))
    }
    fn unknown_interface() -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownInterface", "Unknown interface")
    }
    fn unknown_property() -> Self {
        Fault::new("org.freedesktop.DBus.Error.UnknownProperty", "Unknown property")
    }
    fn read_only() -> Self {
        Fault::new("org.freedesktop.DBus.Error.PropertyReadOnly", "Property is read-only")
    }
    pub fn invalid_args(why: impl Into<String>) -> Self {
        Fault::new("org.freedesktop.DBus.Error.InvalidArgs", why)
    }
    fn limits() -> Self {
        Fault::new("org.freedesktop.DBus.Error.LimitsExceeded", "Too many requests")
    }
    fn not_supported() -> Self {
        Fault::new("org.freedesktop.DBus.Error.NotSupported", "Not implemented yet")
    }
    /// Secret Service error for object paths given as arguments.
    pub fn no_such_object() -> Self {
        Fault::new("org.freedesktop.Secret.Error.NoSuchObject", "No such object")
    }
    fn failed(why: impl Into<String>) -> Self {
        Fault::new("org.freedesktop.DBus.Error.Failed", why)
    }
}

impl From<ModelError> for Fault {
    fn from(e: ModelError) -> Self {
        match e {
            ModelError::NoSuchObject => Fault::no_such_object(),
            ModelError::Limit(_) => Fault::new("org.freedesktop.DBus.Error.LimitsExceeded", e.to_string()),
            ModelError::Invalid(_) => Fault::invalid_args(e.to_string()),
        }
    }
}

fn internal(e: impl std::fmt::Display) -> Fault {
    tracing::warn!(error = %e, "internal error while handling request");
    Fault::failed("Internal error")
}

/// An object as seen by one particular caller.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Intermediate(&'static str),
    Service,
    CollectionDir,
    AliasDir,
    SessionDir,
    PromptDir,
    Collection(String),
    Item(String, String),
}

impl Node {
    fn interfaces(&self) -> &'static [&'static Interface] {
        match self {
            Node::Service => &[&interfaces::SERVICE],
            Node::Collection(_) => &[&interfaces::COLLECTION],
            Node::Item(..) => &[&interfaces::ITEM],
            _ => &[],
        }
    }
}

/// A signal waiting to be delivered to the connections of one scope.
#[derive(Debug, Clone)]
enum SignalBody {
    Path(OwnedObjectPath),
    PropertiesChanged(&'static str, BTreeMap<&'static str, OwnedValue>),
}

#[derive(Debug, Clone)]
struct Event {
    scope: Scope,
    path: OwnedObjectPath,
    interface: &'static str,
    member: &'static str,
    body: SignalBody,
}

/// Bookkeeping for one client connection. The scope is filled in once the
/// connection has been identified; only identified connections get signals.
#[derive(Default)]
struct Peer {
    scope: OnceLock<Scope>,
}

pub struct SecretService<R: CallerResolver> {
    conn: Connection,
    resolver: Arc<R>,
    model: Mutex<Model>,
    peers: Mutex<HashMap<OwnedUniqueName, Arc<Peer>>>,
    machine_id: Option<String>,
}

type CallResult = Result<Message, Fault>;

fn reply<B>(hdr: &Header<'_>, body: &B) -> CallResult
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    Message::method_return(hdr).and_then(|b| b.build(body)).map_err(internal)
}

fn value<'a>(v: impl Into<Value<'a>>) -> Result<OwnedValue, Fault> {
    OwnedValue::try_from(v.into()).map_err(internal)
}

impl<R: CallerResolver> SecretService<R> {
    pub fn new(conn: Connection, resolver: Arc<R>) -> Arc<Self> {
        let machine_id = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()));
        Arc::new(SecretService {
            conn,
            resolver,
            model: Mutex::new(Model::default()),
            peers: Mutex::default(),
            machine_id,
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
        Ok(self.serve(stream))
    }

    async fn serve(self: Arc<Self>, mut stream: MessageStream) -> zbus::Result<()> {
        let mut workers: HashMap<OwnedUniqueName, mpsc::Sender<Message>> = HashMap::new();
        while let Some(msg) = stream.next().await {
            let msg = msg?;
            let hdr = msg.header();
            match msg.message_type() {
                MessageType::Signal => {
                    if let Some(gone) = disconnected_peer(&msg) {
                        workers.remove(&gone);
                        self.peers.lock().unwrap().remove(&gone);
                    }
                }
                MessageType::MethodCall => {
                    let Some(sender) = hdr.sender().map(|s| OwnedUniqueName::from(s.to_owned())) else { continue };
                    if !workers.contains_key(&sender) && workers.len() >= MAX_CONNECTIONS {
                        self.spawn_fault(&msg, Fault::limits());
                        continue;
                    }
                    let tx = workers.entry(sender.clone()).or_insert_with(|| self.spawn_worker(&sender));
                    if let Err(mpsc::error::TrySendError::Full(m)) = tx.try_send(msg) {
                        self.spawn_fault(&m, Fault::limits());
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn spawn_worker(self: &Arc<Self>, sender: &OwnedUniqueName) -> mpsc::Sender<Message> {
        let (tx, mut rx) = mpsc::channel::<Message>(MAX_QUEUED_PER_CONNECTION);
        let peer = Arc::new(Peer::default());
        self.peers.lock().unwrap().insert(sender.clone(), peer.clone());
        let this = self.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                this.handle(&msg, &peer).await;
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

    async fn handle(&self, msg: &Message, peer: &Peer) {
        let mut events = Vec::new();
        let result = self.dispatch(msg, peer, &mut events).await;
        // Reply first: a client that reacts to a signal by calling us again
        // should already have its answer.
        self.send_reply(msg, result).await;
        for e in events {
            self.emit(e).await;
        }
    }

    async fn dispatch(&self, msg: &Message, peer: &Peer, events: &mut Vec<Event>) -> CallResult {
        let hdr = msg.header();
        let sender = hdr.sender().ok_or_else(Fault::access_denied)?;
        let resolved = self.resolver.resolve(sender).await;
        let scope = match &*resolved {
            Ok(p) => p.scope(),
            Err(_) => return Err(Fault::access_denied()),
        };
        let _ = peer.scope.set(scope.clone());

        let path = hdr.path().ok_or_else(Fault::unknown_object)?;
        let member = hdr.member().ok_or_else(|| Fault::unknown_method(""))?.as_str();
        let interface = hdr.interface().map(|i| i.as_str());

        // Peer works on any path and reveals nothing about objects.
        if interface == Some(interfaces::PEER.name)
            || (interface.is_none() && matches!(member, "Ping" | "GetMachineId"))
        {
            return self.peer_method(&hdr, member, msg);
        }

        let node = self.resolve_node(&scope, sender, path.as_str()).ok_or_else(Fault::unknown_object)?;

        let iface = match interface {
            Some(name) => interfaces::STANDARD
                .iter()
                .chain(node.interfaces())
                .find(|i| i.name == name)
                .copied()
                .ok_or_else(Fault::unknown_interface)?,
            None => interfaces::STANDARD
                .iter()
                .chain(node.interfaces())
                .find(|i| i.method(member).is_some())
                .copied()
                .ok_or_else(|| Fault::unknown_method(member))?,
        };
        let method = iface.method(member).ok_or_else(|| Fault::unknown_method(member))?;
        let signature = msg.body().signature().to_string_no_parens();
        if signature != method.in_signature() {
            return Err(Fault::invalid_args(format!("expected signature '{}'", method.in_signature())));
        }

        match iface.name {
            "org.freedesktop.DBus.Introspectable" => {
                let xml = interfaces::introspect(node.interfaces(), &self.children(&scope, &node));
                reply(&hdr, &(xml,))
            }
            "org.freedesktop.DBus.Properties" => self.properties(&hdr, msg, member, &scope, &node, events),
            "org.freedesktop.Secret.Service" => self.service(&hdr, msg, member, &scope, events),
            "org.freedesktop.Secret.Collection" => {
                let Node::Collection(name) = &node else { unreachable!("interface table") };
                self.collection(&hdr, msg, member, &scope, name, events)
            }
            _ => Err(Fault::not_supported()),
        }
    }

    fn peer_method(&self, hdr: &Header<'_>, member: &str, msg: &Message) -> CallResult {
        if !msg.body().signature().to_string_no_parens().is_empty() {
            return Err(Fault::invalid_args("expected no arguments"));
        }
        match member {
            "Ping" => reply(hdr, &()),
            "GetMachineId" => match &self.machine_id {
                Some(id) => reply(hdr, &(id.as_str(),)),
                None => Err(Fault::failed("Machine ID unavailable")),
            },
            other => Err(Fault::unknown_method(other)),
        }
    }

    /// Resolves a path for this caller, or `None` if it is outside the
    /// caller's view (whether or not it exists elsewhere).
    fn resolve_node(&self, scope: &Scope, _sender: &UniqueName<'_>, path: &str) -> Option<Node> {
        let model = self.model.lock().unwrap();
        let collection = |name: &str| model.collection(scope, name).map(|_| name.to_owned());
        let aliased = |alias: &str| model.alias(scope, alias).map(str::to_owned);
        match paths::parse(path) {
            Parsed::Root => Some(Node::Intermediate("org")),
            Parsed::Org => Some(Node::Intermediate("freedesktop")),
            Parsed::Freedesktop => Some(Node::Intermediate("secrets")),
            Parsed::Service => Some(Node::Service),
            Parsed::CollectionDir => Some(Node::CollectionDir),
            Parsed::AliasDir => Some(Node::AliasDir),
            Parsed::SessionDir => Some(Node::SessionDir),
            Parsed::PromptDir => Some(Node::PromptDir),
            Parsed::Collection(c) => collection(c).map(Node::Collection),
            Parsed::AliasedCollection(a) => aliased(a).map(Node::Collection),
            Parsed::Item(c, i) => {
                model.item(scope, c, i)?;
                Some(Node::Item(c.to_owned(), i.to_owned()))
            }
            Parsed::AliasedItem(a, i) => {
                let c = aliased(a)?;
                model.item(scope, &c, i)?;
                Some(Node::Item(c, i.to_owned()))
            }
            // Sessions and prompts do not exist yet.
            Parsed::Session(_) | Parsed::Prompt(_) | Parsed::Unknown => None,
        }
    }

    fn children(&self, scope: &Scope, node: &Node) -> Vec<String> {
        let model = self.model.lock().unwrap();
        match node {
            Node::Intermediate(child) => vec![(*child).to_owned()],
            Node::Service => ["collection", "aliases", "session", "prompt"].map(String::from).to_vec(),
            Node::CollectionDir => model.collection_names(scope),
            Node::AliasDir => model
                .scope(scope)
                .map(|s| s.aliases.keys().filter(|a| model.alias(scope, a).is_some()).cloned().collect())
                .unwrap_or_default(),
            Node::Collection(c) => {
                model.collection(scope, c).map(|c| c.items.keys().cloned().collect()).unwrap_or_default()
            }
            Node::SessionDir | Node::PromptDir | Node::Item(..) => Vec::new(),
        }
    }

    /// Looks up a collection given as a method argument, within `scope`.
    fn collection_arg(&self, scope: &Scope, path: &ObjectPath<'_>) -> Option<String> {
        let model = self.model.lock().unwrap();
        match paths::parse(path.as_str()) {
            Parsed::Collection(c) => model.collection(scope, c).map(|_| c.to_owned()),
            Parsed::AliasedCollection(a) => model.alias(scope, a).map(str::to_owned),
            _ => None,
        }
    }

    fn property_value(&self, scope: &Scope, node: &Node, iface: &str, prop: &str) -> Result<OwnedValue, Fault> {
        let model = self.model.lock().unwrap();
        match (node, iface, prop) {
            (Node::Service, "org.freedesktop.Secret.Service", "Collections") => {
                let paths: Vec<OwnedObjectPath> =
                    model.collection_names(scope).iter().map(|c| paths::collection(c)).collect();
                value(paths)
            }
            (Node::Collection(c), "org.freedesktop.Secret.Collection", _) => {
                let col = model.collection(scope, c).ok_or_else(Fault::unknown_object)?;
                match prop {
                    "Items" => value(col.items.keys().map(|i| paths::item(c, i)).collect::<Vec<_>>()),
                    "Label" => value(col.label.as_str()),
                    "Locked" => value(col.locked),
                    "Created" => value(col.created),
                    "Modified" => value(col.modified),
                    _ => Err(Fault::unknown_property()),
                }
            }
            (Node::Item(c, i), "org.freedesktop.Secret.Item", _) => {
                let col = model.collection(scope, c).ok_or_else(Fault::unknown_object)?;
                let item = col.items.get(i).ok_or_else(Fault::unknown_object)?;
                match prop {
                    "Locked" => value(col.locked),
                    "Attributes" => value(item.attributes.clone().into_iter().collect::<HashMap<_, _>>()),
                    "Label" => value(item.label.as_str()),
                    "Created" => value(item.created),
                    "Modified" => value(item.modified),
                    _ => Err(Fault::unknown_property()),
                }
            }
            _ => Err(Fault::unknown_property()),
        }
    }

    fn properties(
        &self,
        hdr: &Header<'_>,
        msg: &Message,
        member: &str,
        scope: &Scope,
        node: &Node,
        events: &mut Vec<Event>,
    ) -> CallResult {
        let find_iface = |name: &str| -> Result<&'static Interface, Fault> {
            node.interfaces().iter().find(|i| i.name == name).copied().ok_or_else(Fault::unknown_interface)
        };
        match member {
            "Get" => {
                let (iface, prop): (String, String) =
                    msg.body().deserialize().map_err(|e| Fault::invalid_args(e.to_string()))?;
                let i = find_iface(&iface)?;
                i.property(&prop).ok_or_else(Fault::unknown_property)?;
                let v = self.property_value(scope, node, i.name, &prop)?;
                reply(hdr, &(Value::from(v),))
            }
            "GetAll" => {
                let (iface,): (String,) = msg.body().deserialize().map_err(|e| Fault::invalid_args(e.to_string()))?;
                let mut all: HashMap<&str, OwnedValue> = HashMap::new();
                // Standard interfaces have no properties; an unknown interface
                // on an existing object yields an empty set, as GDBus does.
                if let Some(i) = node.interfaces().iter().find(|i| i.name == iface) {
                    for p in i.properties {
                        all.insert(p.name, self.property_value(scope, node, i.name, p.name)?);
                    }
                } else if !interfaces::STANDARD.iter().any(|i| i.name == iface) {
                    return Err(Fault::unknown_interface());
                }
                reply(hdr, &(all,))
            }
            "Set" => {
                let (iface, prop, v): (String, String, OwnedValue) =
                    msg.body().deserialize().map_err(|e| Fault::invalid_args(e.to_string()))?;
                let i = find_iface(&iface)?;
                let p = i.property(&prop).ok_or_else(Fault::unknown_property)?;
                if !p.writable {
                    return Err(Fault::read_only());
                }
                if v.value_signature().to_string() != p.signature {
                    return Err(Fault::invalid_args(format!("expected type '{}'", p.signature)));
                }
                self.set_property(scope, node, i, p.name, v, events)?;
                reply(hdr, &())
            }
            other => Err(Fault::unknown_method(other)),
        }
    }

    fn set_property(
        &self,
        scope: &Scope,
        node: &Node,
        iface: &'static Interface,
        prop: &'static str,
        v: OwnedValue,
        events: &mut Vec<Event>,
    ) -> Result<(), Fault> {
        match (node, prop) {
            (Node::Collection(c), "Label") => {
                let label: String = v.try_into().map_err(|_| Fault::invalid_args("expected string"))?;
                self.model.lock().unwrap().set_collection_label(scope, c, &label)?;
                let path = paths::collection(c);
                let mut changed = BTreeMap::new();
                changed.insert("Label", value(label.as_str())?);
                events.push(Event {
                    scope: scope.clone(),
                    path: path.clone(),
                    interface: interfaces::PROPERTIES.name,
                    member: "PropertiesChanged",
                    body: SignalBody::PropertiesChanged(iface.name, changed),
                });
                events.push(self.service_event(scope, "CollectionChanged", path));
                Ok(())
            }
            // Items, and so their properties, do not exist yet.
            _ => Err(Fault::not_supported()),
        }
    }

    fn service_event(&self, scope: &Scope, member: &'static str, path: OwnedObjectPath) -> Event {
        Event {
            scope: scope.clone(),
            path: OwnedObjectPath::from(ObjectPath::from_static_str_unchecked(paths::SERVICE)),
            interface: interfaces::SERVICE.name,
            member,
            body: SignalBody::Path(path),
        }
    }

    fn collections_changed(&self, scope: &Scope) -> Result<Event, Fault> {
        let mut changed = BTreeMap::new();
        changed.insert(
            "Collections",
            self.property_value(scope, &Node::Service, interfaces::SERVICE.name, "Collections")?,
        );
        Ok(Event {
            scope: scope.clone(),
            path: OwnedObjectPath::from(ObjectPath::from_static_str_unchecked(paths::SERVICE)),
            interface: interfaces::PROPERTIES.name,
            member: "PropertiesChanged",
            body: SignalBody::PropertiesChanged(interfaces::SERVICE.name, changed),
        })
    }

    fn service(
        &self,
        hdr: &Header<'_>,
        msg: &Message,
        member: &str,
        scope: &Scope,
        events: &mut Vec<Event>,
    ) -> CallResult {
        let body = msg.body();
        let bad = |e: zbus::Error| Fault::invalid_args(e.to_string());
        match member {
            "ReadAlias" => {
                let (alias,): (String,) = body.deserialize().map_err(bad)?;
                let path = match self.model.lock().unwrap().alias(scope, &alias) {
                    Some(c) => paths::collection(c),
                    None => paths::none(),
                };
                reply(hdr, &(path,))
            }
            "SetAlias" => {
                let (alias, target): (String, OwnedObjectPath) = body.deserialize().map_err(bad)?;
                let target = if target.as_str() == paths::NONE {
                    None
                } else {
                    Some(self.collection_arg(scope, &target).ok_or_else(Fault::no_such_object)?)
                };
                self.model.lock().unwrap().set_alias(scope, &alias, target.as_deref())?;
                reply(hdr, &())
            }
            "CreateCollection" => {
                let (props, alias): (HashMap<String, OwnedValue>, String) = body.deserialize().map_err(bad)?;
                let label = match props.get("org.freedesktop.Secret.Collection.Label") {
                    None => String::new(),
                    Some(v) => v
                        .try_clone()
                        .ok()
                        .and_then(|v| String::try_from(v).ok())
                        .ok_or_else(|| Fault::invalid_args("Label must be a string"))?,
                };
                let (name, created) = {
                    let mut model = self.model.lock().unwrap();
                    let before = model.collection_names(scope).len();
                    let name = model.create_collection(scope, &label, &alias)?;
                    let created = model.collection_names(scope).len() != before;
                    (name, created)
                };
                let path = paths::collection(&name);
                if created {
                    events.push(self.service_event(scope, "CollectionCreated", path.clone()));
                    events.push(self.collections_changed(scope)?);
                }
                reply(hdr, &(path, paths::none()))
            }
            "SearchItems" => {
                let (attrs,): (HashMap<String, String>,) = body.deserialize().map_err(bad)?;
                let model = self.model.lock().unwrap();
                let (mut unlocked, mut locked) = (Vec::new(), Vec::new());
                if let Some(s) = model.scope(scope) {
                    for (cname, c) in &s.collections {
                        for (iid, item) in &c.items {
                            if attrs.iter().all(|(k, v)| item.attributes.get(k) == Some(v)) {
                                let p = paths::item(cname, iid);
                                if c.locked { locked.push(p) } else { unlocked.push(p) }
                            }
                        }
                    }
                }
                drop(model);
                reply(hdr, &(unlocked, locked))
            }
            _ => Err(Fault::not_supported()),
        }
    }

    fn collection(
        &self,
        hdr: &Header<'_>,
        msg: &Message,
        member: &str,
        scope: &Scope,
        name: &str,
        events: &mut Vec<Event>,
    ) -> CallResult {
        match member {
            "Delete" => {
                self.model.lock().unwrap().delete_collection(scope, name)?;
                events.push(self.service_event(scope, "CollectionDeleted", paths::collection(name)));
                events.push(self.collections_changed(scope)?);
                reply(hdr, &(paths::none(),))
            }
            "SearchItems" => {
                let (attrs,): (HashMap<String, String>,) =
                    msg.body().deserialize().map_err(|e| Fault::invalid_args(e.to_string()))?;
                let model = self.model.lock().unwrap();
                let c = model.collection(scope, name).ok_or_else(Fault::unknown_object)?;
                let found: Vec<OwnedObjectPath> = c
                    .items
                    .iter()
                    .filter(|(_, item)| attrs.iter().all(|(k, v)| item.attributes.get(k) == Some(v)))
                    .map(|(iid, _)| paths::item(name, iid))
                    .collect();
                drop(model);
                reply(hdr, &(found,))
            }
            _ => Err(Fault::not_supported()),
        }
    }

    /// Delivers an event to every identified connection in its scope.
    async fn emit(&self, e: Event) {
        let targets: Vec<OwnedUniqueName> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, p)| p.scope.get() == Some(&e.scope))
            .map(|(n, _)| n.clone())
            .collect();
        for dest in targets {
            let built = Message::signal(e.path.as_ref(), e.interface, e.member)
                .and_then(|b| b.destination(dest.as_ref()))
                .and_then(|b| match &e.body {
                    SignalBody::Path(p) => b.build(&(p,)),
                    SignalBody::PropertiesChanged(iface, changed) => b.build(&(*iface, changed, Vec::<String>::new())),
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

    /// Client connections currently tracked (for diagnostics and tests).
    pub fn active_connections(&self) -> usize {
        self.peers.lock().unwrap().len()
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
