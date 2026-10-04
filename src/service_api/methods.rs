//! Secret Service method handlers, called by `dispatch.rs` once the caller
//! is identified, the object path is resolved within the caller's view and
//! the arguments' signature has been checked.
//!
//! Object paths given as *arguments* (`Unlock`, `Lock`, `GetSecrets`,
//! `SetAlias`, session paths) are resolved here the same way: only within
//! the caller's scope, or, for sessions, the calling connection. Anything
//! else is treated exactly like a path that does not exist.
//!
//! Secrets received from clients are moved into zeroizing buffers at once.
//! The D-Bus message buffers themselves belong to zbus and are not wiped.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use crate::identity::{CallerResolver, Principal};
use crate::prompts::unlock::UnlockOutcome;
use crate::store::{SHARED_COLLECTION, ScopedVault, Secret};

use super::dispatch::{
    Call, CallResult, Event, Fault, MAX_PROMPTS_PER_CONNECTION, MAX_SECRET_BYTES_PER_REPLY,
    MAX_SESSIONS_PER_CONNECTION, MAX_UNLOCK_PATHS_PER_SCOPE, Node, PromptAction, PromptEntry, SecretService,
    SignalBody, Target, TransferSession, service_path, value,
};
use super::interfaces::{self, Interface};
use super::paths::{self, Parsed};
use super::transfer;

const COLLECTION_LABEL: &str = "org.freedesktop.Secret.Collection.Label";
const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

/// A secret as it travels on the bus: `(session, parameters, value, content_type)`.
type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// A collection or item named by a method argument, resolved in the
/// caller's scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Obj {
    Collection(String),
    Item(String, String),
}

impl Obj {
    fn collection(&self) -> &str {
        match self {
            Obj::Collection(c) | Obj::Item(c, _) => c,
        }
    }

    /// The canonical path, whatever path the client used.
    fn path(&self) -> OwnedObjectPath {
        match self {
            Obj::Collection(c) => paths::collection(c),
            Obj::Item(c, i) => paths::item(c, i),
        }
    }
}

/// Resolves a collection or item path (direct or through an alias).
fn resolve_obj(v: &ScopedVault<'_>, path: &str) -> Option<Obj> {
    match paths::parse(path) {
        Parsed::Collection(c) => v.collection(c).map(|_| Obj::Collection(c.to_owned())),
        Parsed::AliasedCollection(a) => v.alias(a).map(Obj::Collection),
        Parsed::Item(c, i) => v.item(c, i).map(|_| Obj::Item(c.to_owned(), i.to_owned())),
        Parsed::AliasedItem(a, i) => {
            let c = v.alias(a)?;
            v.item(&c, i).map(|_| Obj::Item(c, i.to_owned()))
        }
        _ => None,
    }
}

fn is_locked(v: &ScopedVault<'_>, o: &Obj) -> bool {
    v.collection(o.collection()).is_none_or(|c| c.locked)
}

fn args<T>(call: &Call<'_>) -> Result<T, Fault>
where
    T: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
{
    call.msg.body().deserialize().map_err(|e: zbus::Error| Fault::invalid_args(e.to_string()))
}

fn string_prop(props: &HashMap<String, OwnedValue>, key: &str) -> Result<Option<String>, Fault> {
    props
        .get(key)
        .map(|v| match &**v {
            Value::Str(s) => Ok(s.to_string()),
            _ => Err(Fault::invalid_args(format!("{key} must be a string"))),
        })
        .transpose()
}

fn attributes_value(v: &Value<'_>) -> Result<BTreeMap<String, String>, Fault> {
    let bad = || Fault::invalid_args("attributes must be a{ss}");
    if v.value_signature().to_string() != "a{ss}" {
        return Err(bad());
    }
    let map: HashMap<String, String> = v.try_clone().ok().and_then(|v| v.try_into().ok()).ok_or_else(bad)?;
    Ok(map.into_iter().collect())
}

/// A `PropertiesChanged` signal body.
fn changed(iface: &'static str, props: Vec<(&'static str, OwnedValue)>) -> SignalBody {
    SignalBody::PropertiesChanged(iface, props.into_iter().collect())
}

const PROPERTIES_CHANGED: &str = "PropertiesChanged";

impl<R: CallerResolver> SecretService<R> {
    // ---- helpers ----

    fn service_signal(call: &mut Call<'_>, member: &'static str, path: OwnedObjectPath) {
        call.signal_scope(service_path(), interfaces::SERVICE.name, member, SignalBody::Path(path));
    }

    fn collection_signal(call: &mut Call<'_>, collection: &str, member: &'static str, item: OwnedObjectPath) {
        call.signal_scope(paths::collection(collection), interfaces::COLLECTION.name, member, SignalBody::Path(item));
    }

    fn collections_value(&self, principal: &Principal) -> Result<OwnedValue, Fault> {
        let cols = self.with_vault(principal, |v| Ok(v.collection_names()))?;
        value(cols.iter().map(|c| paths::collection(c)).collect::<Vec<_>>())
    }

    fn collections_changed(&self, call: &mut Call<'_>) -> Result<(), Fault> {
        let v = self.collections_value(&call.principal)?;
        call.signal_scope(
            service_path(),
            interfaces::PROPERTIES.name,
            PROPERTIES_CHANGED,
            changed(interfaces::SERVICE.name, vec![("Collections", v)]),
        );
        Ok(())
    }

    /// Signals the item's change to every scope it is shared with, with the
    /// item's path in each grantee's view.
    fn shared_changed(&self, call: &mut Call<'_>, c: &str, i: &str) -> Result<(), Fault> {
        for (grantee, grant) in self.with_vault(&call.principal, |v| Ok(v.grantees_of(c, i)))? {
            call.signal_for(
                &grantee,
                paths::collection(SHARED_COLLECTION),
                interfaces::COLLECTION.name,
                "ItemChanged",
                SignalBody::Path(paths::item(SHARED_COLLECTION, &grant)),
            );
        }
        Ok(())
    }

    fn items_changed(&self, call: &mut Call<'_>, collection: &str) -> Result<(), Fault> {
        let items =
            self.with_vault(&call.principal, |v| Ok(v.collection(collection).map(|c| c.items).unwrap_or_default()))?;
        let v = value(items.iter().map(|i| paths::item(collection, i)).collect::<Vec<_>>())?;
        call.signal_scope(
            paths::collection(collection),
            interfaces::PROPERTIES.name,
            PROPERTIES_CHANGED,
            changed(interfaces::COLLECTION.name, vec![("Items", v)]),
        );
        Ok(())
    }

    /// Runs `f` with the transfer session at `path`, which must belong to
    /// the calling connection.
    fn with_session<T>(
        &self,
        call: &Call<'_>,
        path: &ObjectPath<'_>,
        f: impl FnOnce(&transfer::Algorithm) -> Result<T, Fault>,
    ) -> Result<T, Fault> {
        let Parsed::Session(id) = paths::parse(path.as_str()) else { return Err(Fault::no_session()) };
        let sessions = self.sessions.lock().unwrap();
        let Some(s) = sessions.get(id) else {
            drop(sessions);
            self.note_unknown_session(&call.sender);
            return Err(Fault::no_session());
        };
        if s.owner != call.sender {
            return Err(Fault::no_session());
        }
        f(&s.algorithm)
    }

    /// Decodes a secret sent by the caller with one of its sessions.
    fn receive_secret(&self, call: &Call<'_>, wire: WireSecret) -> Result<Secret, Fault> {
        let (session, parameters, value, content_type) = wire;
        let value = Zeroizing::new(value);
        let plain = self.with_session(call, &session, |a| a.decrypt(&parameters, &value))?;
        Ok(Secret { value: plain, content_type })
    }

    /// Encodes a secret for the caller with one of its sessions.
    fn send_secret(&self, call: &Call<'_>, session: &OwnedObjectPath, secret: &Secret) -> Result<WireSecret, Fault> {
        let (params, value) = self.with_session(call, session, |a| a.encrypt(&secret.value))?;
        Ok((session.clone(), params, value, secret.content_type.clone()))
    }

    fn new_prompt(&self, call: &Call<'_>, action: PromptAction) -> Result<OwnedObjectPath, Fault> {
        let mut prompts = self.prompts.lock().unwrap();
        if prompts.values().filter(|p| p.owner == call.sender).count() >= MAX_PROMPTS_PER_CONNECTION {
            return Err(Fault::limits("Too many pending prompts"));
        }
        if let PromptAction::Unlock(objects) = &action {
            let scope = call.scope();
            let held: usize = prompts
                .values()
                .filter(|p| p.principal.scope() == scope)
                .map(|p| match &p.action {
                    PromptAction::Unlock(o) => o.len(),
                    PromptAction::CreateCollection { .. } => 0,
                })
                .sum();
            if held + objects.len() > MAX_UNLOCK_PATHS_PER_SCOPE {
                return Err(Fault::limits("Too many objects waiting to be unlocked"));
            }
        }
        let id = paths::random_id('p');
        prompts.insert(
            id.clone(),
            PromptEntry { owner: call.sender.clone(), principal: call.principal.clone(), action, task: None },
        );
        Ok(paths::prompt(&id))
    }

    // ---- org.freedesktop.DBus.Properties ----

    fn property_value(&self, principal: &Principal, node: &Node, iface: &str, prop: &str) -> Result<OwnedValue, Fault> {
        match (node, iface) {
            (Node::Service, "org.freedesktop.Secret.Service") if prop == "Collections" => {
                self.collections_value(principal)
            }
            (Node::Collection(c), "org.freedesktop.Secret.Collection") => {
                let col = self.with_vault(principal, |v| v.collection(c).ok_or_else(Fault::unknown_object))?;
                match prop {
                    "Items" => value(col.items.iter().map(|i| paths::item(c, i)).collect::<Vec<_>>()),
                    "Label" => value(col.label.as_str()),
                    "Locked" => value(col.locked),
                    "Created" => value(col.created),
                    "Modified" => value(col.modified),
                    _ => Err(Fault::unknown_property()),
                }
            }
            (Node::Item(c, i), "org.freedesktop.Secret.Item") => {
                let item = self.with_vault(principal, |v| v.item(c, i).ok_or_else(Fault::unknown_object))?;
                match prop {
                    "Locked" => value(item.locked),
                    "Attributes" => value(item.attributes.into_iter().collect::<HashMap<_, _>>()),
                    "Label" => value(item.label.as_str()),
                    "Created" => value(item.created),
                    "Modified" => value(item.modified),
                    _ => Err(Fault::unknown_property()),
                }
            }
            _ => Err(Fault::unknown_property()),
        }
    }

    pub(crate) fn properties(&self, call: &mut Call<'_>, member: &str, node: &Node) -> CallResult {
        let find_iface = |name: &str| -> Result<&'static Interface, Fault> {
            node.interfaces().iter().find(|i| i.name == name).copied().ok_or_else(Fault::unknown_interface)
        };
        match member {
            "Get" => {
                let (iface, prop): (String, String) = args(call)?;
                let i = find_iface(&iface)?;
                i.property(&prop).ok_or_else(Fault::unknown_property)?;
                let v = self.property_value(&call.principal, node, i.name, &prop)?;
                call.reply(&(Value::from(v),))
            }
            "GetAll" => {
                let (iface,): (String,) = args(call)?;
                let mut all: HashMap<&str, OwnedValue> = HashMap::new();
                // Standard interfaces have no properties; an unknown interface
                // on an existing object yields an empty set, as GDBus does.
                if let Some(i) = node.interfaces().iter().find(|i| i.name == iface) {
                    for p in i.properties {
                        all.insert(p.name, self.property_value(&call.principal, node, i.name, p.name)?);
                    }
                } else if !interfaces::STANDARD.iter().any(|i| i.name == iface) {
                    return Err(Fault::unknown_interface());
                }
                call.reply(&(all,))
            }
            "Set" => {
                let (iface, prop, v): (String, String, OwnedValue) = args(call)?;
                let i = find_iface(&iface)?;
                let p = i.property(&prop).ok_or_else(Fault::unknown_property)?;
                if !p.writable {
                    return Err(Fault::read_only());
                }
                if v.value_signature().to_string() != p.signature {
                    return Err(Fault::invalid_args(format!("expected type '{}'", p.signature)));
                }
                self.set_property(call, node, i, p.name, &v)?;
                call.reply(&())
            }
            other => Err(Fault::unknown_method(other)),
        }
    }

    fn set_property(
        &self,
        call: &mut Call<'_>,
        node: &Node,
        iface: &'static Interface,
        prop: &'static str,
        v: &Value<'_>,
    ) -> Result<(), Fault> {
        let string = || match v {
            Value::Str(s) => Ok(s.to_string()),
            _ => Err(Fault::invalid_args("expected a string")),
        };
        match (node, prop) {
            (Node::Collection(c), "Label") => {
                let label = string()?;
                self.with_vault(&call.principal, |v| Ok(v.set_collection_label(c, &label)?))?;
                let path = paths::collection(c);
                let body = changed(iface.name, vec![("Label", value(label)?)]);
                call.signal_scope(path.clone(), interfaces::PROPERTIES.name, PROPERTIES_CHANGED, body);
                Self::service_signal(call, "CollectionChanged", path);
            }
            (Node::Item(c, i), "Label" | "Attributes") => {
                let new_value = if prop == "Label" {
                    let label = string()?;
                    self.with_vault(&call.principal, |v| Ok(v.set_item_label(c, i, &label)?))?;
                    value(label)?
                } else {
                    let attrs = attributes_value(v)?;
                    let out = value(attrs.clone().into_iter().collect::<HashMap<_, _>>())?;
                    self.with_vault(&call.principal, |v| Ok(v.set_item_attributes(c, i, attrs)?))?;
                    out
                };
                let path = paths::item(c, i);
                let body = changed(iface.name, vec![(prop, new_value)]);
                call.signal_scope(path.clone(), interfaces::PROPERTIES.name, PROPERTIES_CHANGED, body);
                Self::collection_signal(call, c, "ItemChanged", path);
                self.shared_changed(call, c, i)?;
            }
            _ => return Err(Fault::read_only()),
        }
        Ok(())
    }

    // ---- org.freedesktop.Secret.Service ----

    pub(crate) fn service_method(&self, call: &mut Call<'_>, member: &str) -> CallResult {
        match member {
            "OpenSession" => {
                let (algorithm, input): (String, OwnedValue) = args(call)?;
                let (algorithm, output) = transfer::negotiate(&algorithm, &input)?;
                let output = match algorithm {
                    transfer::Algorithm::Plain => Value::from(""),
                    transfer::Algorithm::DhAes(_) => Value::from(output),
                };
                let mut sessions = self.sessions.lock().unwrap();
                if sessions.values().filter(|s| s.owner == call.sender).count() >= MAX_SESSIONS_PER_CONNECTION {
                    return Err(Fault::limits("Too many sessions"));
                }
                let id = paths::random_id('s');
                sessions.insert(id.clone(), TransferSession { owner: call.sender.clone(), algorithm });
                drop(sessions);
                call.reply(&(output, paths::session(&id)))
            }
            "CreateCollection" => {
                let (props, alias): (HashMap<String, OwnedValue>, String) = args(call)?;
                let label = string_prop(&props, COLLECTION_LABEL)?.unwrap_or_default();
                if !alias.is_empty() && !paths::is_valid_element(&alias) {
                    return Err(Fault::invalid_args("invalid alias"));
                }
                if label.len() > crate::store::MAX_LABEL_BYTES {
                    return Err(Fault::limits("label too long"));
                }
                if !self.vault_unlocked() {
                    let prompt = self.new_prompt(call, PromptAction::CreateCollection { label, alias })?;
                    return call.reply(&(paths::none(), prompt));
                }
                let (name, created) = self.with_vault(&call.principal, |v| Ok(v.create_collection(&label, &alias)?))?;
                let path = paths::collection(&name);
                if created {
                    Self::service_signal(call, "CollectionCreated", path.clone());
                    self.collections_changed(call)?;
                }
                call.reply(&(path, paths::none()))
            }
            "SearchItems" => {
                let (attrs,): (HashMap<String, String>,) = args(call)?;
                let attrs: BTreeMap<String, String> = attrs.into_iter().collect();
                let found = self.with_vault(&call.principal, |v| Ok(v.search(&attrs)))?;
                let (mut unlocked, mut locked) = (Vec::new(), Vec::new());
                for (c, i, is_locked) in found {
                    if is_locked { locked.push(paths::item(&c, &i)) } else { unlocked.push(paths::item(&c, &i)) }
                }
                call.reply(&(unlocked, locked))
            }
            "Unlock" => {
                let (objects,): (Vec<OwnedObjectPath>,) = args(call)?;
                // A prompt keeps the paths until it completes: only those
                // that can name an object are kept, once each.
                let objects: BTreeSet<String> = objects
                    .iter()
                    .filter(|p| {
                        matches!(
                            paths::parse(p.as_str()),
                            Parsed::Collection(_)
                                | Parsed::AliasedCollection(_)
                                | Parsed::Item(..)
                                | Parsed::AliasedItem(..)
                        )
                    })
                    .map(|p| p.as_str().to_owned())
                    .collect();
                if objects.is_empty() {
                    return call.reply(&(Vec::<OwnedObjectPath>::new(), paths::none()));
                }
                if !self.vault_unlocked() {
                    let prompt = self.new_prompt(call, PromptAction::Unlock(objects))?;
                    return call.reply(&(Vec::<OwnedObjectPath>::new(), prompt));
                }
                let (open, any_locked) = self.with_vault(&call.principal, |v| {
                    let resolved: BTreeSet<Obj> = objects.iter().filter_map(|p| resolve_obj(v, p)).collect();
                    let open: Vec<OwnedObjectPath> =
                        resolved.iter().filter(|o| !is_locked(v, o)).map(Obj::path).collect();
                    Ok((open, resolved.iter().any(|o| is_locked(v, o))))
                })?;
                let prompt =
                    if any_locked { self.new_prompt(call, PromptAction::Unlock(objects))? } else { paths::none() };
                call.reply(&(open, prompt))
            }
            "Lock" => {
                let (objects,): (Vec<OwnedObjectPath>,) = args(call)?;
                let (locked, newly) = self.with_vault(&call.principal, |v| {
                    let resolved: BTreeSet<Obj> = objects.iter().filter_map(|p| resolve_obj(v, p.as_str())).collect();
                    let mut newly = BTreeSet::new();
                    for o in &resolved {
                        if !is_locked(v, o) {
                            v.set_collection_locked(o.collection(), true)?;
                            newly.insert(o.collection().to_owned());
                        }
                    }
                    Ok((resolved.iter().map(Obj::path).collect::<Vec<_>>(), newly))
                })?;
                for c in newly {
                    self.lock_state_changed(call, &c, true)?;
                }
                call.reply(&(locked, paths::none()))
            }
            "GetSecrets" => {
                let (items, session): (Vec<OwnedObjectPath>, OwnedObjectPath) = args(call)?;
                // Check the session first, so a foreign session fails even
                // when no item resolves.
                self.with_session(call, &session, |_| Ok(()))?;
                // Each path is answered once and each item decrypted once,
                // however often the request repeats them; the total is
                // bounded (see MAX_SECRET_BYTES_PER_REPLY).
                let (answers, secrets) = self.with_vault(&call.principal, |v| {
                    let mut seen = BTreeSet::new();
                    let mut decrypted: HashMap<(String, String), usize> = HashMap::new();
                    let mut secrets: Vec<Secret> = Vec::new();
                    let mut answers = Vec::new();
                    let mut total = 0usize;
                    for p in &items {
                        if !seen.insert(p.as_str()) {
                            continue;
                        }
                        let Some(Obj::Item(c, i)) = resolve_obj(v, p.as_str()) else { continue };
                        let n = match decrypted.get(&(c.clone(), i.clone())) {
                            Some(&n) => n,
                            None => match v.read_secret(&c, &i) {
                                Ok(s) => {
                                    secrets.push(s);
                                    decrypted.insert((c, i), secrets.len() - 1);
                                    secrets.len() - 1
                                }
                                Err(crate::store::StoreError::Locked) => continue,
                                Err(e) => return Err(e.into()),
                            },
                        };
                        total += secrets[n].value.len();
                        if total > MAX_SECRET_BYTES_PER_REPLY {
                            return Err(Fault::limits("Too many secrets in one request; ask for fewer at a time"));
                        }
                        answers.push((p.clone(), n));
                    }
                    Ok((answers, secrets))
                })?;
                // Keyed by the path the client used, which is how libsecret
                // looks the results up.
                let mut reply: HashMap<OwnedObjectPath, WireSecret> = HashMap::new();
                for (p, n) in answers {
                    reply.insert(p, self.send_secret(call, &session, &secrets[n])?);
                }
                call.reply(&(reply,))
            }
            "ReadAlias" => {
                let (alias,): (String,) = args(call)?;
                let target = self.with_vault(&call.principal, |v| Ok(v.alias(&alias)))?;
                call.reply(&(target.map_or_else(paths::none, |c| paths::collection(&c)),))
            }
            "SetAlias" => {
                let (alias, target): (String, OwnedObjectPath) = args(call)?;
                if !paths::is_valid_element(&alias) {
                    return Err(Fault::invalid_args("invalid alias"));
                }
                self.with_vault(&call.principal, |v| {
                    let target = if target.as_str() == paths::NONE {
                        None
                    } else {
                        match resolve_obj(v, target.as_str()) {
                            Some(Obj::Collection(c)) => Some(c),
                            _ => return Err(Fault::no_such_object()),
                        }
                    };
                    Ok(v.set_alias(&alias, target.as_deref())?)
                })?;
                call.reply(&())
            }
            other => Err(Fault::unknown_method(other)),
        }
    }

    /// Signals a change of a collection's logical lock state.
    fn lock_state_changed(&self, call: &mut Call<'_>, collection: &str, locked: bool) -> Result<(), Fault> {
        let path = paths::collection(collection);
        let body = changed(interfaces::COLLECTION.name, vec![("Locked", value(locked)?)]);
        call.signal_scope(path.clone(), interfaces::PROPERTIES.name, PROPERTIES_CHANGED, body);
        Self::service_signal(call, "CollectionChanged", path);
        Ok(())
    }

    // ---- org.freedesktop.Secret.Collection ----

    pub(crate) fn collection_method(&self, call: &mut Call<'_>, member: &str, name: &str) -> CallResult {
        match member {
            "Delete" => {
                self.with_vault(&call.principal, |v| Ok(v.delete_collection(name)?))?;
                Self::service_signal(call, "CollectionDeleted", paths::collection(name));
                self.collections_changed(call)?;
                call.reply(&(paths::none(),))
            }
            "SearchItems" => {
                let (attrs,): (HashMap<String, String>,) = args(call)?;
                let attrs: BTreeMap<String, String> = attrs.into_iter().collect();
                let found = self.with_vault(&call.principal, |v| Ok(v.search(&attrs)))?;
                let paths: Vec<OwnedObjectPath> =
                    found.iter().filter(|(c, _, _)| c == name).map(|(c, i, _)| paths::item(c, i)).collect();
                call.reply(&(paths,))
            }
            "CreateItem" => {
                let (props, wire, replace): (HashMap<String, OwnedValue>, WireSecret, bool) = args(call)?;
                let label = string_prop(&props, ITEM_LABEL)?.unwrap_or_default();
                let attrs = props.get(ITEM_ATTRIBUTES).map(|v| attributes_value(v)).transpose()?.unwrap_or_default();
                let secret = self.receive_secret(call, wire)?;
                let (item, created) =
                    self.with_vault(&call.principal, |v| Ok(v.create_item(name, &label, attrs, &secret, replace)?))?;
                let path = paths::item(name, &item);
                if created {
                    Self::collection_signal(call, name, "ItemCreated", path.clone());
                    self.items_changed(call, name)?;
                } else {
                    Self::collection_signal(call, name, "ItemChanged", path.clone());
                }
                call.reply(&(path, paths::none()))
            }
            other => Err(Fault::unknown_method(other)),
        }
    }

    // ---- org.freedesktop.Secret.Item ----

    pub(crate) fn item_method(&self, call: &mut Call<'_>, member: &str, c: &str, i: &str) -> CallResult {
        match member {
            "Delete" => {
                // The grantees must be looked up before the item is gone.
                let grantees = self.with_vault(&call.principal, |v| {
                    let grantees = v.grantees_of(c, i);
                    v.delete_item(c, i)?;
                    Ok(grantees)
                })?;
                Self::collection_signal(call, c, "ItemDeleted", paths::item(c, i));
                self.items_changed(call, c)?;
                for (grantee, grant) in grantees {
                    call.signal_for(
                        &grantee,
                        paths::collection(SHARED_COLLECTION),
                        interfaces::COLLECTION.name,
                        "ItemDeleted",
                        SignalBody::Path(paths::item(SHARED_COLLECTION, &grant)),
                    );
                }
                call.reply(&(paths::none(),))
            }
            "GetSecret" => {
                let (session,): (OwnedObjectPath,) = args(call)?;
                self.with_session(call, &session, |_| Ok(()))?;
                let secret = self.with_vault(&call.principal, |v| Ok(v.read_secret(c, i)?))?;
                let wire = self.send_secret(call, &session, &secret)?;
                call.reply(&(wire,))
            }
            "SetSecret" => {
                let (wire,): (WireSecret,) = args(call)?;
                let secret = self.receive_secret(call, wire)?;
                if c == SHARED_COLLECTION {
                    // A grantee wrote a shared item: the owner hears about it
                    // with the owner's path, the co-grantees with theirs.
                    let (origin, peers) = self.with_vault(&call.principal, |v| {
                        v.set_secret(c, i, &secret)?;
                        let origin = v.shared_origin(i).ok_or_else(Fault::unknown_object)?;
                        let peers = v.shared_peers(i);
                        Ok((origin, peers))
                    })?;
                    Self::collection_signal(call, c, "ItemChanged", paths::item(c, i));
                    let (owner, collection, item) = origin;
                    call.signal_for(
                        &owner,
                        paths::collection(&collection),
                        interfaces::COLLECTION.name,
                        "ItemChanged",
                        SignalBody::Path(paths::item(&collection, &item)),
                    );
                    for (grantee, grant) in peers {
                        call.signal_for(
                            &grantee,
                            paths::collection(SHARED_COLLECTION),
                            interfaces::COLLECTION.name,
                            "ItemChanged",
                            SignalBody::Path(paths::item(SHARED_COLLECTION, &grant)),
                        );
                    }
                } else {
                    self.with_vault(&call.principal, |v| Ok(v.set_secret(c, i, &secret)?))?;
                    Self::collection_signal(call, c, "ItemChanged", paths::item(c, i));
                    self.shared_changed(call, c, i)?;
                }
                call.reply(&())
            }
            other => Err(Fault::unknown_method(other)),
        }
    }

    // ---- org.freedesktop.Secret.Prompt ----

    pub(crate) fn prompt_method(self: &Arc<Self>, call: &mut Call<'_>, member: &str, id: &str) -> CallResult {
        match member {
            "Prompt" => {
                // The window ID is untrusted presentation input; it is ignored.
                let _: (String,) = args(call)?;
                let mut prompts = self.prompts.lock().unwrap();
                let entry = prompts.get_mut(id).ok_or_else(Fault::unknown_object)?;
                if entry.task.is_none() {
                    let this = self.clone();
                    let id = id.to_owned();
                    entry.task = Some(tokio::spawn(async move { this.run_prompt(id).await }).abort_handle());
                }
                drop(prompts);
                call.reply(&())
            }
            "Dismiss" => {
                let entry = self.prompts.lock().unwrap().remove(id);
                if let Some(entry) = entry {
                    if let Some(t) = &entry.task {
                        t.abort();
                    }
                    call.events.push(completed(id, entry.owner, true, dismissed_result(&entry.action)?));
                }
                call.reply(&())
            }
            other => Err(Fault::unknown_method(other)),
        }
    }

    /// Shows the dialogs for a prompt, performs its action and reports the
    /// result to the prompt's owner.
    async fn run_prompt(self: Arc<Self>, id: String) {
        let Some((owner, principal, action)) =
            self.prompts.lock().unwrap().get(&id).map(|p| (p.owner.clone(), p.principal.clone(), p.action.clone()))
        else {
            return;
        };
        let mut events = Vec::new();
        let result = self.perform(&principal, &action, &mut events).await;
        // Dismiss or a disconnect may have removed the prompt meanwhile; then
        // `Completed` is not sent, but changes that did happen are signalled.
        if self.prompts.lock().unwrap().remove(&id).is_some() {
            let outcome = match result {
                Ok(v) => Ok((false, v)),
                Err(why) => {
                    if let Some(why) = why {
                        tracing::warn!(reason = %why, "prompt failed");
                    }
                    dismissed_result(&action).map(|v| (true, v))
                }
            };
            if let Ok((dismissed, v)) = outcome {
                events.push(completed(&id, owner, dismissed, v));
            }
        }
        for e in events {
            self.emit(e).await;
        }
    }

    /// The work behind a prompt. `Err(None)` means the user cancelled;
    /// `Err(Some(reason))` that something failed.
    async fn perform(
        &self,
        principal: &Principal,
        action: &PromptAction,
        events: &mut Vec<Event>,
    ) -> Result<OwnedValue, Option<String>> {
        let scope = principal.scope();
        let outcome = |o: UnlockOutcome| match o {
            UnlockOutcome::Unlocked => Ok(()),
            UnlockOutcome::Cancelled => Err(None),
            UnlockOutcome::Failed(why) => Err(Some(why)),
        };
        let fail = |f: Fault| Some(f.message);
        // Each dialog is subject to the scope's refusal limit; a prompt over
        // the limit is dismissed without one.
        let dialog = |o: UnlockOutcome| {
            if o != UnlockOutcome::Unlocked {
                self.unlocker.record_explicit_refusal(&scope);
            }
            outcome(o)
        };
        let over_limit = || {
            tracing::info!(scope = %scope, "prompt dismissed: too many cancelled dialogs recently");
            Err(None)
        };
        if !self.vault_unlocked() {
            if !self.unlocker.explicit_dialog_allowed(&scope) {
                return over_limit();
            }
            dialog(self.unlocker.ensure_unlocked(&scope).await)?;
        }
        let event = |path: OwnedObjectPath, interface: &'static str, member: &'static str, body: SignalBody| Event {
            target: Target::Scope(scope.clone()),
            path,
            interface,
            member,
            body,
        };
        match action {
            PromptAction::Unlock(objects) => {
                let locked_collections: BTreeSet<String> = self
                    .with_vault(principal, |v| {
                        Ok(objects
                            .iter()
                            .filter_map(|p| resolve_obj(v, p))
                            .filter(|o| is_locked(v, o))
                            .map(|o| o.collection().to_owned())
                            .collect())
                    })
                    .map_err(fail)?;
                if !locked_collections.is_empty() {
                    // Checks the limit and records a refusal itself.
                    match self.unlocker.confirm_password(&scope).await {
                        Some(o) => outcome(o)?,
                        None => return over_limit(),
                    }
                    for c in &locked_collections {
                        // The collection may have been deleted meanwhile.
                        if self.with_vault(principal, |v| Ok(v.set_collection_locked(c, false)?)).is_ok() {
                            let path = paths::collection(c);
                            let body =
                                changed(interfaces::COLLECTION.name, vec![("Locked", value(false).map_err(fail)?)]);
                            events.push(event(path.clone(), interfaces::PROPERTIES.name, PROPERTIES_CHANGED, body));
                            let body = SignalBody::Path(path);
                            events.push(event(service_path(), interfaces::SERVICE.name, "CollectionChanged", body));
                        }
                    }
                }
                let open: Vec<OwnedObjectPath> = self
                    .with_vault(principal, |v| {
                        let resolved: BTreeSet<Obj> = objects.iter().filter_map(|p| resolve_obj(v, p)).collect();
                        Ok(resolved.iter().filter(|o| !is_locked(v, o)).map(Obj::path).collect())
                    })
                    .map_err(fail)?;
                value(open).map_err(fail)
            }
            PromptAction::CreateCollection { label, alias } => {
                let (name, created) =
                    self.with_vault(principal, |v| Ok(v.create_collection(label, alias)?)).map_err(fail)?;
                let path = paths::collection(&name);
                if created {
                    let body = SignalBody::Path(path.clone());
                    events.push(event(service_path(), interfaces::SERVICE.name, "CollectionCreated", body));
                    let body = changed(
                        interfaces::SERVICE.name,
                        vec![("Collections", self.collections_value(principal).map_err(fail)?)],
                    );
                    events.push(event(service_path(), interfaces::PROPERTIES.name, PROPERTIES_CHANGED, body));
                }
                value(path).map_err(fail)
            }
        }
    }
}

/// The `Completed` signal for a prompt, sent only to its owner.
fn completed(id: &str, owner: zbus::names::OwnedUniqueName, dismissed: bool, result: OwnedValue) -> Event {
    Event {
        target: Target::Connection(owner),
        path: paths::prompt(id),
        interface: interfaces::PROMPT.name,
        member: "Completed",
        body: SignalBody::Completed(dismissed, result),
    }
}

/// The result sent with a dismissed prompt. It has the same type as a
/// successful result: libsecret checks the type even when dismissed, and
/// mishandles a mismatch.
fn dismissed_result(action: &PromptAction) -> Result<OwnedValue, Fault> {
    match action {
        PromptAction::Unlock(_) => value(Vec::<OwnedObjectPath>::new()),
        PromptAction::CreateCollection { .. } => value(paths::none()),
    }
}
