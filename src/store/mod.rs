//! The encrypted vault.
//!
//! [`Vault`] owns the database and, once unlocked, the record key and a
//! decrypted in-memory index of metadata (scopes, collections, items; never
//! secret values, which are decrypted on demand).
//!
//! Request handlers never get an unrestricted handle: they obtain a
//! [`ScopedVault`] from an authenticated [`Principal`], and every operation
//! on it is confined to that principal's scope.
//!
//! Every change is one SQLite transaction; the index is updated only after
//! the transaction commits, so a failed write leaves both unchanged.
//!
//! Lock state has two layers: the vault is physically locked (no key, no
//! index) or unlocked, and each collection is additionally logically locked
//! or not. Locking a collection affects only that collection.

pub mod db;
pub mod payload;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::crypto::{CryptoError, KdfParams, RecordAad, RecordCipher, VaultKey, random_array};
use crate::identity::{Principal, Scope};
use crate::service_api::paths;
use db::{Db, RawRecord, RecordId};
use payload::{
    CollectionPayload, ItemPayload, KIND_COLLECTION, KIND_ITEM, KIND_NAMESPACE, KIND_SECRET, NamespacePayload, hex,
    unhex,
};

pub use payload::Secret;

pub const MAX_COLLECTIONS_PER_SCOPE: usize = 256;
pub const MAX_ITEMS_PER_COLLECTION: usize = 10_000;
pub const MAX_ALIASES_PER_SCOPE: usize = 64;
pub const MAX_LABEL_BYTES: usize = 4096;
pub const MAX_ATTRIBUTES: usize = 64;
pub const MAX_ATTRIBUTE_NAME_BYTES: usize = 256;
pub const MAX_ATTRIBUTE_VALUE_BYTES: usize = 4096;
pub const MAX_SECRET_BYTES: usize = 512 * 1024;
pub const MAX_CONTENT_TYPE_BYTES: usize = 128;
/// Alias (and collection name) of the per-scope in-memory collection.
pub const SESSION_ALIAS: &str = "session";
/// The collection a new scope starts with, which the `default` alias points
/// to, as gnome-keyring's login keyring. Some clients assume it exists.
pub const LOGIN_COLLECTION: &str = "login";
pub const DEFAULT_ALIAS: &str = "default";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the vault is locked")]
    Locked,
    #[error("wrong password")]
    WrongPassword,
    #[error("the vault is in use by another process")]
    InUse,
    #[error("no vault exists here")]
    NotFound,
    #[error("a vault already exists here")]
    Exists,
    #[error("not a scopevault database")]
    NotAVault,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(i64),
    #[error("refusing insecure location: {0}")]
    InsecurePath(String),
    /// A record is damaged or was tampered with. The message never
    /// contains decrypted data.
    #[error("vault data is damaged or was tampered with: {0}")]
    Corrupt(String),
    #[error("no such object")]
    NoSuchObject,
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid argument: {0}")]
    Invalid(&'static str),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cryptographic failure: {0}")]
    Crypto(CryptoError),
}

impl From<CryptoError> for StoreError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Unwrap => StoreError::WrongPassword,
            CryptoError::Record => StoreError::Corrupt("record failed authentication".into()),
            other => StoreError::Crypto(other),
        }
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionInfo {
    pub name: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    pub locked: bool,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemInfo {
    pub name: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub created: u64,
    pub modified: u64,
    pub locked: bool,
}

#[derive(Debug, Clone)]
struct ItemEntry {
    label: String,
    attributes: BTreeMap<String, String>,
    created: u64,
    modified: u64,
}

#[derive(Debug, Clone)]
struct CollectionEntry {
    id: RecordId,
    label: String,
    created: u64,
    modified: u64,
    items: BTreeMap<RecordId, ItemEntry>,
    /// The scope's `session` collection: kept in memory only, never
    /// written to disk, gone after a global lock or restart.
    ephemeral: bool,
    /// Secrets of an ephemeral collection (persistent ones are on disk).
    secrets: HashMap<RecordId, Secret>,
}

#[derive(Debug, Clone)]
struct NamespaceEntry {
    id: RecordId,
    aliases: BTreeMap<String, RecordId>,
    /// Keyed by path name.
    collections: BTreeMap<String, CollectionEntry>,
}

impl NamespaceEntry {
    fn collection_by_id(&self, id: &RecordId) -> Option<(&String, &CollectionEntry)> {
        self.collections.iter().find(|(_, c)| &c.id == id)
    }
}

struct Unlocked {
    cipher: RecordCipher,
    namespaces: HashMap<Scope, NamespaceEntry>,
    /// Logically locked collections (by record ID).
    locked: HashSet<RecordId>,
}

pub struct Vault {
    db: Db,
    unlocked: Option<Unlocked>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("dir", &self.db.dir()).field("unlocked", &self.unlocked.is_some()).finish()
    }
}

fn new_id() -> Result<RecordId, StoreError> {
    Ok(random_array::<16>()?)
}

fn seal(
    cipher: &RecordCipher,
    kind: u8,
    namespace: RecordId,
    id: RecordId,
    plaintext: &[u8],
) -> Result<RawRecord, StoreError> {
    let sealed = cipher.seal(&RecordAad { kind, namespace, id }, plaintext)?;
    Ok(RawRecord { id, kind, namespace, nonce: sealed.nonce.to_vec(), ciphertext: sealed.ciphertext })
}

fn open_record(cipher: &RecordCipher, r: &RawRecord) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    cipher
        .open(&RecordAad { kind: r.kind, namespace: r.namespace, id: r.id }, &r.nonce, &r.ciphertext)
        .map_err(|_| StoreError::Corrupt(format!("record {} failed authentication", hex(&r.id))))
}

/// Builds the decrypted index from all records, refusing anything
/// inconsistent.
fn build_index(cipher: &RecordCipher, records: &[RawRecord]) -> Result<HashMap<Scope, NamespaceEntry>, StoreError> {
    let corrupt = |what: String| StoreError::Corrupt(what);
    let mut by_ns_id: HashMap<RecordId, (Scope, NamespaceEntry, BTreeMap<String, String>)> = HashMap::new();
    let mut seen_scopes = HashSet::new();
    let mut secrets = HashSet::new();

    for r in records.iter().filter(|r| r.kind == KIND_NAMESPACE) {
        if r.namespace != r.id {
            return Err(corrupt(format!("namespace record {} is misfiled", hex(&r.id))));
        }
        let p: NamespacePayload = payload::decode(&open_record(cipher, r)?, "namespace")?;
        let scope: Scope = p.scope.parse().map_err(|_| corrupt("namespace with invalid scope".into()))?;
        if !seen_scopes.insert(scope.clone()) {
            return Err(corrupt("two namespace records for one scope".into()));
        }
        let entry = NamespaceEntry { id: r.id, aliases: BTreeMap::new(), collections: BTreeMap::new() };
        by_ns_id.insert(r.id, (scope, entry, p.aliases));
    }

    let mut collection_ns: HashMap<RecordId, RecordId> = HashMap::new();
    for r in records.iter().filter(|r| r.kind == KIND_COLLECTION) {
        let (_, ns, _) = by_ns_id
            .get_mut(&r.namespace)
            .ok_or_else(|| corrupt(format!("collection {} has no namespace", hex(&r.id))))?;
        let p: CollectionPayload = payload::decode(&open_record(cipher, r)?, "collection")?;
        if !paths::is_valid_element(&p.name) || ns.collections.contains_key(&p.name) {
            return Err(corrupt(format!("collection {} has an invalid or duplicate name", hex(&r.id))));
        }
        if p.name == SESSION_ALIAS {
            return Err(corrupt(format!("collection {} uses a reserved name", hex(&r.id))));
        }
        let entry = CollectionEntry {
            id: r.id,
            label: p.label,
            created: p.created,
            modified: p.modified,
            items: BTreeMap::new(),
            ephemeral: false,
            secrets: HashMap::new(),
        };
        ns.collections.insert(p.name, entry);
        collection_ns.insert(r.id, r.namespace);
    }

    for r in records.iter().filter(|r| r.kind == KIND_ITEM) {
        let p: ItemPayload = payload::decode(&open_record(cipher, r)?, "item")?;
        let cid =
            unhex(&p.collection).ok_or_else(|| corrupt(format!("item {} has a malformed collection", hex(&r.id))))?;
        if collection_ns.get(&cid) != Some(&r.namespace) {
            return Err(corrupt(format!("item {} refers to a collection outside its namespace", hex(&r.id))));
        }
        let (_, ns, _) = by_ns_id.get_mut(&r.namespace).expect("checked above");
        let col = ns.collections.values_mut().find(|c| c.id == cid).expect("checked above");
        let entry = ItemEntry { label: p.label, attributes: p.attributes, created: p.created, modified: p.modified };
        if col.items.insert(r.id, entry).is_some() {
            return Err(corrupt(format!("duplicate item {}", hex(&r.id))));
        }
    }

    for r in records.iter().filter(|r| r.kind == KIND_SECRET) {
        secrets.insert((r.id, r.namespace));
    }
    for (ns_id, (_, ns, _)) in &by_ns_id {
        for c in ns.collections.values() {
            for item_id in c.items.keys() {
                if !secrets.remove(&(*item_id, *ns_id)) {
                    return Err(corrupt(format!("item {} has no secret record", hex(item_id))));
                }
            }
        }
    }
    if !secrets.is_empty() {
        return Err(corrupt("secret record without an item".into()));
    }
    if let Some(r) = records.iter().find(|r| !(KIND_NAMESPACE..=KIND_SECRET).contains(&r.kind)) {
        return Err(corrupt(format!("record {} has unknown kind {}", hex(&r.id), r.kind)));
    }

    let mut out = HashMap::new();
    for (_, (scope, mut ns, aliases)) in by_ns_id {
        for (alias, target) in aliases {
            let cid = unhex(&target).ok_or_else(|| corrupt("malformed alias target".into()))?;
            if !paths::is_valid_element(&alias) || ns.collection_by_id(&cid).is_none() {
                return Err(corrupt("alias to a missing collection".into()));
            }
            ns.aliases.insert(alias, cid);
        }
        out.insert(scope, ns);
    }
    Ok(out)
}

impl Vault {
    pub fn exists(dir: &Path) -> bool {
        Db::exists(dir)
    }

    /// Creates a new vault protected by `password` and returns it unlocked.
    pub fn create(dir: &Path, password: &[u8], kdf: KdfParams) -> Result<Vault, StoreError> {
        if password.is_empty() {
            return Err(StoreError::Invalid("empty password"));
        }
        let key = VaultKey::generate()?;
        let wrap = key.wrap(password, kdf)?;
        let db = match Db::create(dir, &wrap) {
            Ok(db) => db,
            Err(StoreError::Exists) => return Err(StoreError::Exists),
            Err(e) => {
                // Do not leave a half-initialised file that would block retries.
                let _ = std::fs::remove_file(dir.join(db::DB_FILE));
                return Err(e);
            }
        };
        let cipher = key.record_cipher();
        Ok(Vault { db, unlocked: Some(Unlocked { cipher, namespaces: HashMap::new(), locked: HashSet::new() }) })
    }

    /// Opens an existing vault, locked.
    pub fn open(dir: &Path) -> Result<Vault, StoreError> {
        Ok(Vault { db: Db::open(dir)?, unlocked: None })
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// The stored key wrap, so the slow key derivation can run without
    /// holding a lock on the vault (see [`Vault::unlock_with_key`]).
    pub fn key_wrap(&self) -> Result<crate::crypto::KeyWrap, StoreError> {
        self.db.key_wrap()
    }

    pub fn unlock(&mut self, password: &[u8]) -> Result<(), StoreError> {
        let key = VaultKey::unwrap(&self.db.key_wrap()?, password)?;
        self.unlock_with_key(key)
    }

    /// Finishes unlocking with an already unwrapped key: decrypts and
    /// checks every metadata record. On any inconsistency the vault stays
    /// locked.
    pub fn unlock_with_key(&mut self, key: VaultKey) -> Result<(), StoreError> {
        if self.unlocked.is_some() {
            return Ok(());
        }
        let cipher = key.record_cipher();
        let namespaces = build_index(&cipher, &self.db.load_all()?)?;
        self.unlocked = Some(Unlocked { cipher, namespaces, locked: HashSet::new() });
        Ok(())
    }

    /// Global lock: drops the key and all decrypted metadata.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    /// Rewraps the vault key under a new password. Requires the current
    /// password even when unlocked.
    pub fn change_password(&mut self, old: &[u8], new: &[u8], kdf: KdfParams) -> Result<(), StoreError> {
        if new.is_empty() {
            return Err(StoreError::Invalid("empty password"));
        }
        let key = VaultKey::unwrap(&self.db.key_wrap()?, old)?;
        let wrap = key.wrap(new, kdf)?;
        self.db.set_key_wrap(&wrap)
    }

    /// The scope-confined view for an authenticated principal.
    pub fn scoped(&mut self, principal: &Principal) -> Result<ScopedVault<'_>, StoreError> {
        if self.unlocked.is_none() {
            return Err(StoreError::Locked);
        }
        Ok(ScopedVault { vault: self, scope: principal.scope() })
    }

    /// Scopes that have data. For the administrative interface.
    pub fn scopes(&self) -> Result<Vec<Scope>, StoreError> {
        let u = self.unlocked.as_ref().ok_or(StoreError::Locked)?;
        let mut s: Vec<Scope> = u.namespaces.keys().cloned().collect();
        s.sort();
        Ok(s)
    }
}

/// Operations confined to one scope. Nothing reachable from here belongs
/// to another scope.
pub struct ScopedVault<'a> {
    vault: &'a mut Vault,
    scope: Scope,
}

fn validate_label(label: &str) -> Result<(), StoreError> {
    if label.len() > MAX_LABEL_BYTES { Err(StoreError::Limit("label too long")) } else { Ok(()) }
}

fn validate_attributes(attrs: &BTreeMap<String, String>) -> Result<(), StoreError> {
    if attrs.len() > MAX_ATTRIBUTES {
        return Err(StoreError::Limit("too many attributes"));
    }
    if attrs.iter().any(|(k, v)| k.len() > MAX_ATTRIBUTE_NAME_BYTES || v.len() > MAX_ATTRIBUTE_VALUE_BYTES) {
        return Err(StoreError::Limit("attribute too long"));
    }
    Ok(())
}

fn validate_secret(s: &Secret) -> Result<(), StoreError> {
    if s.value.len() > MAX_SECRET_BYTES {
        return Err(StoreError::Limit("secret too large"));
    }
    if s.content_type.len() > MAX_CONTENT_TYPE_BYTES || s.content_type.chars().any(char::is_control) {
        return Err(StoreError::Invalid("content type"));
    }
    Ok(())
}

/// Turns a label into a readable path element, unique within the scope.
fn collection_name_for(label: &str, existing: &BTreeMap<String, CollectionEntry>) -> String {
    let mut base: String =
        label.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).take(32).collect();
    if base.bytes().all(|b| b == b'_') || base == SESSION_ALIAS {
        base = "collection".into();
    }
    if !existing.contains_key(&base) {
        return base;
    }
    (2..).map(|n| format!("{base}_{n}")).find(|n| !existing.contains_key(n)).expect("unbounded")
}

fn item_name(id: &RecordId) -> String {
    hex(id)
}

impl ScopedVault<'_> {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    fn state(&self) -> &Unlocked {
        self.vault.unlocked.as_ref().expect("ScopedVault exists only while unlocked")
    }

    fn ns(&self) -> Option<&NamespaceEntry> {
        self.state().namespaces.get(&self.scope)
    }

    fn collection_entry(&self, name: &str) -> Result<&CollectionEntry, StoreError> {
        self.ns().and_then(|n| n.collections.get(name)).ok_or(StoreError::NoSuchObject)
    }

    fn item_id(&self, collection: &str, item: &str) -> Result<RecordId, StoreError> {
        let id = unhex(item).ok_or(StoreError::NoSuchObject)?;
        if self.collection_entry(collection)?.items.contains_key(&id) { Ok(id) } else { Err(StoreError::NoSuchObject) }
    }

    fn namespace_record(&self, ns: &NamespaceEntry) -> Result<RawRecord, StoreError> {
        let p = NamespacePayload {
            scope: self.scope.to_string(),
            aliases: ns
                .aliases
                .iter()
                .filter(|(_, id)| ns.collection_by_id(id).is_some_and(|(_, c)| !c.ephemeral))
                .map(|(a, id)| (a.clone(), hex(id)))
                .collect(),
        };
        seal(&self.state().cipher, KIND_NAMESPACE, ns.id, ns.id, &payload::encode(&p))
    }

    fn collection_record(&self, ns_id: RecordId, name: &str, c: &CollectionEntry) -> Result<RawRecord, StoreError> {
        let p = CollectionPayload {
            name: name.to_owned(),
            label: c.label.clone(),
            created: c.created,
            modified: c.modified,
        };
        seal(&self.state().cipher, KIND_COLLECTION, ns_id, c.id, &payload::encode(&p))
    }

    fn item_record(
        &self,
        ns_id: RecordId,
        cid: &RecordId,
        id: RecordId,
        i: &ItemEntry,
    ) -> Result<RawRecord, StoreError> {
        let p = ItemPayload {
            collection: hex(cid),
            label: i.label.clone(),
            attributes: i.attributes.clone(),
            created: i.created,
            modified: i.modified,
        };
        seal(&self.state().cipher, KIND_ITEM, ns_id, id, &payload::encode(&p))
    }

    fn secret_record(&self, ns_id: RecordId, id: RecordId, s: &Secret) -> Result<RawRecord, StoreError> {
        seal(&self.state().cipher, KIND_SECRET, ns_id, id, &payload::encode_secret(s))
    }

    /// Writes to the database, then installs `ns` as the scope's index entry.
    fn commit(
        &mut self,
        ns: NamespaceEntry,
        writes: &[RawRecord],
        deletes: &[(RecordId, u8)],
    ) -> Result<(), StoreError> {
        self.vault.db.apply(writes, deletes)?;
        let scope = self.scope.clone();
        self.vault.unlocked.as_mut().expect("unlocked").namespaces.insert(scope, ns);
        Ok(())
    }

    fn ns_or_new(&self) -> Result<(NamespaceEntry, bool), StoreError> {
        match self.ns() {
            Some(ns) => Ok((ns.clone(), false)),
            None => {
                Ok((NamespaceEntry { id: new_id()?, aliases: BTreeMap::new(), collections: BTreeMap::new() }, true))
            }
        }
    }

    // ---- reading ----

    pub fn collection_names(&self) -> Vec<String> {
        self.ns().map(|n| n.collections.keys().cloned().collect()).unwrap_or_default()
    }

    pub fn collection(&self, name: &str) -> Option<CollectionInfo> {
        let c = self.ns()?.collections.get(name)?;
        Some(CollectionInfo {
            name: name.to_owned(),
            label: c.label.clone(),
            created: c.created,
            modified: c.modified,
            locked: self.state().locked.contains(&c.id),
            items: c.items.keys().map(item_name).collect(),
        })
    }

    pub fn alias(&self, alias: &str) -> Option<String> {
        let ns = self.ns()?;
        let id = ns.aliases.get(alias)?;
        ns.collection_by_id(id).map(|(name, _)| name.clone())
    }

    pub fn aliases(&self) -> Vec<String> {
        self.ns().map(|n| n.aliases.keys().cloned().collect()).unwrap_or_default()
    }

    pub fn item(&self, collection: &str, item: &str) -> Option<ItemInfo> {
        let c = self.ns()?.collections.get(collection)?;
        let id = unhex(item)?;
        let i = c.items.get(&id)?;
        Some(ItemInfo {
            name: item.to_owned(),
            label: i.label.clone(),
            attributes: i.attributes.clone(),
            created: i.created,
            modified: i.modified,
            locked: self.state().locked.contains(&c.id),
        })
    }

    /// Items whose attributes include all of `attrs`, as (collection, item, locked).
    pub fn search(&self, attrs: &BTreeMap<String, String>) -> Vec<(String, String, bool)> {
        let Some(ns) = self.ns() else { return Vec::new() };
        let mut out = Vec::new();
        for (cname, c) in &ns.collections {
            let locked = self.state().locked.contains(&c.id);
            for (id, i) in &c.items {
                if attrs.iter().all(|(k, v)| i.attributes.get(k) == Some(v)) {
                    out.push((cname.clone(), item_name(id), locked));
                }
            }
        }
        out
    }

    /// Decrypts an item's secret. Fails on a logically locked collection.
    pub fn read_secret(&self, collection: &str, item: &str) -> Result<Secret, StoreError> {
        let id = self.item_id(collection, item)?;
        let c = self.collection_entry(collection)?;
        if self.state().locked.contains(&c.id) {
            return Err(StoreError::Locked);
        }
        if c.ephemeral {
            return c.secrets.get(&id).cloned().ok_or(StoreError::NoSuchObject);
        }
        let ns_id = self.ns().expect("collection exists").id;
        let raw = self
            .vault
            .db
            .load_one(&id, KIND_SECRET)?
            .ok_or_else(|| StoreError::Corrupt("missing secret record".into()))?;
        if raw.namespace != ns_id {
            return Err(StoreError::Corrupt("secret record is misfiled".into()));
        }
        payload::decode_secret(&open_record(&self.state().cipher, &raw)?)
    }

    // ---- logical lock state ----

    pub fn set_collection_locked(&mut self, collection: &str, locked: bool) -> Result<(), StoreError> {
        let id = self.collection_entry(collection)?.id;
        let set = &mut self.vault.unlocked.as_mut().expect("unlocked").locked;
        if locked {
            set.insert(id);
        } else {
            set.remove(&id);
        }
        Ok(())
    }

    fn ensure_writable(&self, collection: &str) -> Result<(), StoreError> {
        let id = self.collection_entry(collection)?.id;
        if self.state().locked.contains(&id) { Err(StoreError::Locked) } else { Ok(()) }
    }

    // ---- writing ----

    /// Creates a collection, or returns the one already holding `alias`.
    /// Returns the collection's path name and whether it was created.
    pub fn create_collection(&mut self, label: &str, alias: &str) -> Result<(String, bool), StoreError> {
        validate_label(label)?;
        if !alias.is_empty() && !paths::is_valid_element(alias) {
            return Err(StoreError::Invalid("alias"));
        }
        if !alias.is_empty()
            && let Some(existing) = self.alias(alias)
        {
            return Ok((existing, false));
        }
        let (mut ns, _) = self.ns_or_new()?;
        if ns.collections.len() >= MAX_COLLECTIONS_PER_SCOPE {
            return Err(StoreError::Limit("too many collections"));
        }
        if !alias.is_empty() && ns.aliases.len() >= MAX_ALIASES_PER_SCOPE && !ns.aliases.contains_key(alias) {
            return Err(StoreError::Limit("too many aliases"));
        }
        let ephemeral = alias == SESSION_ALIAS;
        let name = if ephemeral { SESSION_ALIAS.to_owned() } else { collection_name_for(label, &ns.collections) };
        let t = now();
        let entry = CollectionEntry {
            id: new_id()?,
            label: label.to_owned(),
            created: t,
            modified: t,
            items: BTreeMap::new(),
            ephemeral,
            secrets: HashMap::new(),
        };
        let mut writes = Vec::new();
        if !ephemeral {
            writes.push(self.collection_record(ns.id, &name, &entry)?);
        }
        if !alias.is_empty() {
            ns.aliases.insert(alias.to_owned(), entry.id);
        }
        ns.collections.insert(name.clone(), entry);
        if !ephemeral {
            // The namespace record may be new, and its aliases may change.
            writes.push(self.namespace_record(&ns)?);
        }
        self.commit(ns, &writes, &[])?;
        Ok((name, true))
    }

    /// Gives a scope without data its `login` collection, aliased `default`.
    /// A scope that has data keeps what it has, also after deleting all its
    /// collections.
    pub fn ensure_namespace(&mut self) -> Result<(), StoreError> {
        if self.ns().is_some() {
            return Ok(());
        }
        let (name, _) = self.create_collection("Login", DEFAULT_ALIAS)?;
        debug_assert_eq!(name, LOGIN_COLLECTION);
        Ok(())
    }

    pub fn delete_collection(&mut self, name: &str) -> Result<(), StoreError> {
        let mut ns = self.ns().cloned().ok_or(StoreError::NoSuchObject)?;
        let c = ns.collections.remove(name).ok_or(StoreError::NoSuchObject)?;
        let mut deletes = Vec::new();
        if !c.ephemeral {
            deletes.push((c.id, KIND_COLLECTION));
            for id in c.items.keys() {
                deletes.push((*id, KIND_ITEM));
                deletes.push((*id, KIND_SECRET));
            }
        }
        ns.aliases.retain(|_, target| *target != c.id);
        let writes = if c.ephemeral { Vec::new() } else { vec![self.namespace_record(&ns)?] };
        self.commit(ns, &writes, &deletes)?;
        self.vault.unlocked.as_mut().expect("unlocked").locked.remove(&c.id);
        Ok(())
    }

    /// Sets (`Some`) or removes (`None`) an alias within this scope.
    pub fn set_alias(&mut self, alias: &str, target: Option<&str>) -> Result<(), StoreError> {
        if !paths::is_valid_element(alias) {
            return Err(StoreError::Invalid("alias"));
        }
        let (mut ns, new) = self.ns_or_new()?;
        match target {
            None => {
                if new || ns.aliases.remove(alias).is_none() {
                    return Ok(());
                }
            }
            Some(name) => {
                let id = ns.collections.get(name).ok_or(StoreError::NoSuchObject)?.id;
                if ns.aliases.len() >= MAX_ALIASES_PER_SCOPE && !ns.aliases.contains_key(alias) {
                    return Err(StoreError::Limit("too many aliases"));
                }
                ns.aliases.insert(alias.to_owned(), id);
            }
        }
        let writes = vec![self.namespace_record(&ns)?];
        self.commit(ns, &writes, &[])
    }

    pub fn set_collection_label(&mut self, name: &str, label: &str) -> Result<(), StoreError> {
        validate_label(label)?;
        let mut ns = self.ns().cloned().ok_or(StoreError::NoSuchObject)?;
        let c = ns.collections.get_mut(name).ok_or(StoreError::NoSuchObject)?;
        c.label = label.to_owned();
        c.modified = now();
        let writes =
            if c.ephemeral { Vec::new() } else { vec![self.collection_record(ns.id, name, &ns.collections[name])?] };
        self.commit(ns, &writes, &[])
    }

    /// Creates an item, or with `replace` updates the item in the same
    /// collection that has exactly these attributes. Returns the item's
    /// path name and whether it was newly created.
    pub fn create_item(
        &mut self,
        collection: &str,
        label: &str,
        attributes: BTreeMap<String, String>,
        secret: &Secret,
        replace: bool,
    ) -> Result<(String, bool), StoreError> {
        validate_label(label)?;
        validate_attributes(&attributes)?;
        validate_secret(secret)?;
        self.ensure_writable(collection)?;
        let mut ns = self.ns().cloned().ok_or(StoreError::NoSuchObject)?;
        let ns_id = ns.id;
        let c = ns.collections.get_mut(collection).ok_or(StoreError::NoSuchObject)?;
        let cid = c.id;
        let t = now();
        let existing =
            if replace { c.items.iter().find(|(_, i)| i.attributes == attributes).map(|(id, _)| *id) } else { None };
        let (id, created) = match existing {
            Some(id) => {
                let i = c.items.get_mut(&id).expect("found above");
                i.label = label.to_owned();
                i.modified = t;
                (id, false)
            }
            None => {
                if c.items.len() >= MAX_ITEMS_PER_COLLECTION {
                    return Err(StoreError::Limit("too many items"));
                }
                let id = new_id()?;
                c.items.insert(id, ItemEntry { label: label.to_owned(), attributes, created: t, modified: t });
                (id, true)
            }
        };
        c.modified = t;
        let writes = if c.ephemeral {
            c.secrets.insert(id, secret.clone());
            Vec::new()
        } else {
            let item = c.items[&id].clone();
            vec![
                self.item_record(ns_id, &cid, id, &item)?,
                self.secret_record(ns_id, id, secret)?,
                self.collection_record(ns_id, collection, &ns.collections[collection])?,
            ]
        };
        self.commit(ns, &writes, &[])?;
        Ok((item_name(&id), created))
    }

    fn update_item(&mut self, collection: &str, item: &str, f: impl FnOnce(&mut ItemEntry)) -> Result<(), StoreError> {
        let id = self.item_id(collection, item)?;
        self.ensure_writable(collection)?;
        let mut ns = self.ns().cloned().expect("item exists");
        let ns_id = ns.id;
        let c = ns.collections.get_mut(collection).expect("item exists");
        let cid = c.id;
        let entry = c.items.get_mut(&id).expect("item exists");
        f(entry);
        entry.modified = now();
        let entry = entry.clone();
        let writes = if c.ephemeral { Vec::new() } else { vec![self.item_record(ns_id, &cid, id, &entry)?] };
        self.commit(ns, &writes, &[])
    }

    pub fn set_item_label(&mut self, collection: &str, item: &str, label: &str) -> Result<(), StoreError> {
        validate_label(label)?;
        self.update_item(collection, item, |i| i.label = label.to_owned())
    }

    pub fn set_item_attributes(
        &mut self,
        collection: &str,
        item: &str,
        attrs: BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        validate_attributes(&attrs)?;
        self.update_item(collection, item, |i| i.attributes = attrs)
    }

    pub fn set_secret(&mut self, collection: &str, item: &str, secret: &Secret) -> Result<(), StoreError> {
        validate_secret(secret)?;
        let id = self.item_id(collection, item)?;
        self.ensure_writable(collection)?;
        let mut ns = self.ns().cloned().expect("item exists");
        let ns_id = ns.id;
        let c = ns.collections.get_mut(collection).expect("item exists");
        let cid = c.id;
        let entry = c.items.get_mut(&id).expect("item exists");
        entry.modified = now();
        let entry = entry.clone();
        let writes = if c.ephemeral {
            c.secrets.insert(id, secret.clone());
            Vec::new()
        } else {
            vec![self.item_record(ns_id, &cid, id, &entry)?, self.secret_record(ns_id, id, secret)?]
        };
        self.commit(ns, &writes, &[])
    }

    pub fn delete_item(&mut self, collection: &str, item: &str) -> Result<(), StoreError> {
        let id = self.item_id(collection, item)?;
        self.ensure_writable(collection)?;
        let mut ns = self.ns().cloned().expect("item exists");
        let c = ns.collections.get_mut(collection).expect("item exists");
        c.items.remove(&id);
        c.modified = now();
        if c.ephemeral {
            c.secrets.remove(&id);
            return self.commit(ns, &[], &[]);
        }
        let writes = vec![self.collection_record(ns.id, collection, &ns.collections[collection])?];
        self.commit(ns, &writes, &[(id, KIND_ITEM), (id, KIND_SECRET)])
    }
}
