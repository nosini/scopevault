//! The encrypted vault.
//!
//! [`Vault`] owns the database and, once unlocked, the record key and a
//! decrypted in-memory index of metadata (scopes, collections, items; never
//! secret values, which are decrypted on demand).
//!
//! Request handlers never get an unrestricted handle: they obtain a
//! [`ScopedVault`] from an authenticated [`Principal`], and every operation
//! on it is confined to that principal's scope. Other scopes are reachable
//! only with an [`AdminAuthority`], which the administrative interface
//! creates after verifying its caller.
//!
//! Every change is one SQLite transaction; the index is updated only after
//! the transaction commits, so a failed write leaves both unchanged.
//! [`Vault::transaction`] groups several changes, possibly in several
//! scopes, into one.
//!
//! Lock state has two layers: the vault is physically locked (no key, no
//! index) or unlocked, and each collection is additionally logically locked
//! or not. Locking a collection affects only that collection.

mod admin;
pub mod db;
pub mod payload;
mod portal;
mod sharing;

pub use admin::{
    CollectionListing, ImportReport, ItemListing, PortableCollection, PortableItem, ScopeSummary, same_attributes,
};
pub use portal::{
    PORTAL_KEY_BYTES, PORTAL_SCHEMA, PortalImportReport, PortalSplit, is_valid_portal_app_id, split_portal_keys,
};
pub use sharing::{GrantListing, MAX_GRANTS_PER_SCOPE};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

pub use crate::admin::AdminAuthority;
use crate::crypto::{CryptoError, KdfParams, KeyWrap, RecordAad, RecordCipher, Slot, VaultKey, random_array};
use crate::identity::{Principal, Scope};
use crate::service_api::paths;
use db::{Db, RawRecord, RecordId};
use payload::{
    CollectionPayload, GrantPayload, ItemPayload, KIND_COLLECTION, KIND_GRANT, KIND_ITEM, KIND_NAMESPACE, KIND_SECRET,
    NamespacePayload, hex, unhex,
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
/// The virtual collection holding the items shared with a scope (see
/// `sharing`). The store never generates this name (`collection_name_for`
/// lowercases), so it cannot collide with a real collection.
pub const SHARED_COLLECTION: &str = "Shared";

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
    /// An operation the caller is not permitted, although the object exists
    /// (a write to a read-only shared item, a change to `Shared` itself).
    #[error("not permitted: {0}")]
    NotPermitted(&'static str),
    /// An imported portal key differs from the one already stored (see
    /// `crate::store::portal`). Carries the app ID.
    #[error("a different portal key exists for {0}")]
    PortalConflict(String),
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
    /// The explicit sharing grants this namespace's items are given away
    /// with, keyed by grant record ID (see `sharing`).
    grants: BTreeMap<RecordId, GrantEntry>,
}

#[derive(Debug, Clone)]
struct GrantEntry {
    item: RecordId,
    grantee: Scope,
    write: bool,
    created: u64,
}

impl NamespaceEntry {
    fn collection_by_id(&self, id: &RecordId) -> Option<(&String, &CollectionEntry)> {
        self.collections.iter().find(|(_, c)| &c.id == id)
    }
}

struct Unlocked {
    /// Kept to wrap the key for another slot (the login password's)
    /// without asking for the master password again. Anyone holding
    /// `cipher` can read everything anyway.
    key: VaultKey,
    cipher: RecordCipher,
    namespaces: HashMap<Scope, NamespaceEntry>,
    /// Logically locked collections (by record ID).
    locked: HashSet<RecordId>,
    /// Scopes that locked their `Shared` collection (a per-scope, in-memory
    /// flag: the collection is virtual, so it cannot share the real locks).
    shared_locked: HashSet<Scope>,
    /// Changes made inside [`Vault::transaction`], not yet applied.
    staged: Option<Staged>,
}

impl Unlocked {
    fn new(key: VaultKey, namespaces: HashMap<Scope, NamespaceEntry>) -> Self {
        let cipher = key.record_cipher();
        Unlocked { key, cipher, namespaces, locked: HashSet::new(), shared_locked: HashSet::new(), staged: None }
    }
}

/// Namespaces changed (`None`: removed) and record changes in order.
#[derive(Default)]
struct Staged {
    namespaces: HashMap<Scope, Option<NamespaceEntry>>,
    changes: Vec<Change>,
}

enum Change {
    Put(RawRecord),
    Delete(RecordId, u8),
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
        let entry = NamespaceEntry {
            id: r.id,
            aliases: BTreeMap::new(),
            collections: BTreeMap::new(),
            grants: BTreeMap::new(),
        };
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
    for r in records.iter().filter(|r| r.kind == KIND_GRANT) {
        let bad = |what: String| corrupt(format!("grant {} refers to {}", hex(&r.id), what));
        let (owner, ns, _) =
            by_ns_id.get_mut(&r.namespace).ok_or_else(|| corrupt(format!("grant {} has no namespace", hex(&r.id))))?;
        let p: GrantPayload = payload::decode(&open_record(cipher, r)?, "grant")?;
        let grantee: Scope = p.grantee.parse().map_err(|_| bad("an invalid grantee".into()))?;
        if grantee == Scope::Portal {
            return Err(bad("the portal scope".into()));
        }
        if *owner == grantee {
            return Err(bad("its own scope".into()));
        }
        if *owner == Scope::Portal {
            return Err(bad("an item of the portal scope".into()));
        }
        let item = unhex(&p.item).ok_or_else(|| bad("a malformed item".into()))?;
        if !ns.collections.values().any(|c| c.items.contains_key(&item)) {
            return Err(bad("an item this namespace does not hold".into()));
        }
        if ns.grants.values().any(|g| g.item == item && g.grantee == grantee) {
            return Err(bad("an item and grantee granted twice".into()));
        }
        ns.grants.insert(r.id, GrantEntry { item, grantee, write: p.write, created: p.created });
    }
    if let Some(r) = records.iter().find(|r| !(KIND_NAMESPACE..=KIND_GRANT).contains(&r.kind)) {
        return Err(corrupt(format!("record {} has unknown kind {}", hex(&r.id), r.kind)));
    }

    let mut out = HashMap::new();
    for (_, (scope, mut ns, aliases)) in by_ns_id {
        for (alias, target) in aliases {
            let cid = unhex(&target).ok_or_else(|| corrupt("malformed alias target".into()))?;
            if !paths::is_valid_element(&alias) || ns.collection_by_id(&cid).is_none() {
                return Err(corrupt("alias to a missing collection".into()));
            }
            // Versions before 0.12.2 let `session` point at a persistent
            // collection; that alias is dropped, so `session` is in memory
            // again.
            if alias == SESSION_ALIAS {
                continue;
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
        // A half-initialised file is removed by `Db::create` itself; an
        // error here (another opener, an existing vault) leaves the files
        // alone.
        let db = Db::create(dir, &wrap)?;
        Ok(Vault { db, unlocked: Some(Unlocked::new(key, HashMap::new())) })
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
    /// Decrypts and decodes every secret record, which unlocking does not
    /// do (secrets are read on demand): for checking a backup before it
    /// replaces a vault. Returns their number.
    pub fn verify_secrets(&self) -> Result<usize, StoreError> {
        let u = self.unlocked.as_ref().ok_or(StoreError::Locked)?;
        let mut n = 0;
        for r in self.db.load_all()?.iter().filter(|r| r.kind == KIND_SECRET) {
            payload::decode_secret(&open_record(&u.cipher, r)?)?;
            n += 1;
        }
        Ok(n)
    }

    pub fn unlock_with_key(&mut self, key: VaultKey) -> Result<(), StoreError> {
        if self.unlocked.is_some() {
            return Ok(());
        }
        let namespaces = build_index(&key.record_cipher(), &self.db.load_all()?)?;
        self.unlocked = Some(Unlocked::new(key, namespaces));
        Ok(())
    }

    /// Global lock: drops the key and all decrypted metadata.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    /// Writes a copy of the encrypted database to `dest` (which must not
    /// exist). It opens with the password current now. Works while locked.
    pub fn backup_into(&self, dest: &Path) -> Result<(), StoreError> {
        self.db.backup_into(dest)
    }

    /// Stores `new` in place of the key wrap `current`, if that is still the
    /// stored one. For callers that derive keys without holding the vault.
    pub fn replace_key_wrap(
        &mut self,
        current: &crate::crypto::KeyWrap,
        new: &crate::crypto::KeyWrap,
    ) -> Result<(), StoreError> {
        if &self.db.key_wrap()? != current {
            return Err(StoreError::Invalid("the password was changed meanwhile"));
        }
        self.db.set_key_wrap(new)
    }

    /// The wrap stored for `slot`, if any. Works while locked.
    pub fn key_slot(&self, slot: Slot) -> Result<Option<KeyWrap>, StoreError> {
        match slot.kind() {
            None => self.db.key_wrap().map(Some),
            Some(kind) => self.db.key_slot(kind),
        }
    }

    /// Replaces the wrap of a key slot other than the master one with
    /// `new` (`None` removes it), if `current` is still what is stored: the
    /// slow key derivation for `new` runs without holding the vault, and a
    /// change made meanwhile must not be overwritten.
    pub fn replace_key_slot(
        &mut self,
        slot: Slot,
        current: Option<&KeyWrap>,
        new: Option<&KeyWrap>,
    ) -> Result<(), StoreError> {
        let kind = slot.kind().ok_or(StoreError::Invalid("the master password has its own wrap"))?;
        if self.db.key_slot(kind)?.as_ref() != current {
            return Err(StoreError::Invalid("the key slot was changed meanwhile"));
        }
        match new {
            Some(w) => self.db.set_key_slot(kind, w),
            None => self.db.delete_key_slot(kind).map(drop),
        }
    }

    /// A copy of the vault key, to wrap it for another slot without
    /// holding the vault. Only while unlocked.
    pub fn vault_key(&self) -> Result<VaultKey, StoreError> {
        Ok(self.unlocked.as_ref().ok_or(StoreError::Locked)?.key.duplicate())
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
        Ok(ScopedVault { vault: self, scope: principal.scope(), admin: false })
    }

    /// Any scope's view, for the administrative interface. Logical
    /// collection locks do not apply to it.
    pub fn scoped_admin(&mut self, _authority: &AdminAuthority, scope: Scope) -> Result<ScopedVault<'_>, StoreError> {
        if self.unlocked.is_none() {
            return Err(StoreError::Locked);
        }
        Ok(ScopedVault { vault: self, scope, admin: true })
    }

    /// Runs `f`, then applies all its changes in one database transaction;
    /// if `f` or the transaction fails, nothing changes.
    pub fn transaction<T>(&mut self, f: impl FnOnce(&mut Vault) -> Result<T, StoreError>) -> Result<T, StoreError> {
        let u = self.unlocked.as_mut().ok_or(StoreError::Locked)?;
        if u.staged.is_some() {
            return Err(StoreError::Invalid("nested transaction"));
        }
        u.staged = Some(Staged::default());
        let result = f(self);
        let staged = self.unlocked.as_mut().and_then(|u| u.staged.take());
        let value = result?;
        let staged = staged.ok_or(StoreError::Locked)?;
        let ops: Vec<db::Op<'_>> = staged
            .changes
            .iter()
            .map(|c| match c {
                Change::Put(r) => db::Op::Put(r),
                Change::Delete(id, kind) => db::Op::Delete(*id, *kind),
            })
            .collect();
        self.db.apply_ops(&ops)?;
        let u = self.unlocked.as_mut().expect("checked above");
        for (scope, ns) in staged.namespaces {
            match ns {
                Some(ns) => u.namespaces.insert(scope, ns),
                None => u.namespaces.remove(&scope),
            };
        }
        Ok(value)
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
    /// Opened with [`AdminAuthority`]: logical collection locks are ignored.
    admin: bool,
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

/// One shared item as the grantee's view sees it: the grant, and where the
/// item really lives.
#[derive(Debug, Clone)]
struct SharedItem {
    grant: RecordId,
    write: bool,
    grant_created: u64,
    owner_scope: Scope,
    /// The owner's collection, by path name and record ID.
    owner_collection: String,
    owner_collection_id: RecordId,
    owner_ns: RecordId,
    owner_item: RecordId,
    label: String,
    attributes: BTreeMap<String, String>,
    created: u64,
    modified: u64,
}

impl ScopedVault<'_> {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    fn state(&self) -> &Unlocked {
        self.vault.unlocked.as_ref().expect("ScopedVault exists only while unlocked")
    }

    fn ns(&self) -> Option<&NamespaceEntry> {
        let st = self.state();
        match st.staged.as_ref().and_then(|s| s.namespaces.get(&self.scope)) {
            Some(staged) => staged.as_ref(),
            None => st.namespaces.get(&self.scope),
        }
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

    fn grant_record(&self, ns_id: RecordId, id: RecordId, p: &GrantPayload) -> Result<RawRecord, StoreError> {
        seal(&self.state().cipher, KIND_GRANT, ns_id, id, &payload::encode(p))
    }

    /// Writes to the database, then installs `ns` as the scope's index entry.
    /// Inside [`Vault::transaction`] both are staged instead.
    fn commit(
        &mut self,
        ns: NamespaceEntry,
        writes: &[RawRecord],
        deletes: &[(RecordId, u8)],
    ) -> Result<(), StoreError> {
        self.commit_ns(Some(ns), writes, deletes)
    }

    /// Like [`ScopedVault::commit`]; `None` removes the scope's entry.
    fn commit_ns(
        &mut self,
        ns: Option<NamespaceEntry>,
        writes: &[RawRecord],
        deletes: &[(RecordId, u8)],
    ) -> Result<(), StoreError> {
        let scope = self.scope.clone();
        if let Some(st) = self.vault.unlocked.as_mut().expect("unlocked").staged.as_mut() {
            st.changes.extend(writes.iter().cloned().map(Change::Put));
            st.changes.extend(deletes.iter().map(|(id, kind)| Change::Delete(*id, *kind)));
            st.namespaces.insert(scope, ns);
            return Ok(());
        }
        self.vault.db.apply(writes, deletes)?;
        let namespaces = &mut self.vault.unlocked.as_mut().expect("unlocked").namespaces;
        match ns {
            Some(ns) => namespaces.insert(scope, ns),
            None => namespaces.remove(&scope),
        };
        Ok(())
    }

    /// Like [`ScopedVault::commit`], but for a namespace other than the
    /// view's: a grantee's write changes the owner's namespace.
    fn commit_other(
        &mut self,
        scope: Scope,
        ns: NamespaceEntry,
        writes: &[RawRecord],
        deletes: &[(RecordId, u8)],
    ) -> Result<(), StoreError> {
        if let Some(st) = self.vault.unlocked.as_mut().expect("unlocked").staged.as_mut() {
            st.changes.extend(writes.iter().cloned().map(Change::Put));
            st.changes.extend(deletes.iter().map(|(id, kind)| Change::Delete(*id, *kind)));
            st.namespaces.insert(scope, Some(ns));
            return Ok(());
        }
        self.vault.db.apply(writes, deletes)?;
        self.vault.unlocked.as_mut().expect("unlocked").namespaces.insert(scope, ns);
        Ok(())
    }

    /// Another scope's namespace, considering staged changes (as [`Self::ns`]
    /// does for this scope's).
    fn namespace_of(&self, scope: &Scope) -> Option<NamespaceEntry> {
        let st = self.state();
        match st.staged.as_ref().and_then(|s| s.namespaces.get(scope)) {
            Some(staged) => staged.clone(),
            None => st.namespaces.get(scope).cloned(),
        }
    }

    fn ns_or_new(&self) -> Result<(NamespaceEntry, bool), StoreError> {
        match self.ns() {
            Some(ns) => Ok((ns.clone(), false)),
            None => Ok((
                NamespaceEntry {
                    id: new_id()?,
                    aliases: BTreeMap::new(),
                    collections: BTreeMap::new(),
                    grants: BTreeMap::new(),
                },
                true,
            )),
        }
    }

    // ---- shared items (see `sharing`) ----

    /// Collects `owner`'s grants to `scope` whose item is currently visible:
    /// the item still exists and its collection is not logically locked.
    fn collect_shared(st: &Unlocked, scope: &Scope, owner: &Scope, ns: &NamespaceEntry, out: &mut Vec<SharedItem>) {
        // Portal keys are never shared (`share` refuses, unlocking rejects
        // such a grant); this view does not rely on either.
        if owner == scope || *owner == Scope::Portal {
            return;
        }
        for (gid, g) in &ns.grants {
            if &g.grantee != scope {
                continue;
            }
            let Some((cname, col, item)) =
                ns.collections.iter().find_map(|(name, c)| c.items.get(&g.item).map(|i| (name, c, i)))
            else {
                continue;
            };
            if st.locked.contains(&col.id) {
                continue;
            }
            out.push(SharedItem {
                grant: *gid,
                write: g.write,
                grant_created: g.created,
                owner_scope: owner.clone(),
                owner_collection: cname.clone(),
                owner_collection_id: col.id,
                owner_ns: ns.id,
                owner_item: g.item,
                label: item.label.clone(),
                attributes: item.attributes.clone(),
                created: item.created,
                modified: item.modified,
            });
        }
    }

    /// This scope's visible shared items, sorted by grant ID. Grants are few
    /// (at most [`MAX_GRANTS_PER_SCOPE`] per owner), so they are scanned.
    fn shared_items(&self) -> Vec<SharedItem> {
        let st = self.state();
        // Staged changes replace whole namespaces (see `ns`); inside a
        // transaction the walk follows them.
        let staged = st.staged.as_ref().map(|s| &s.namespaces);
        let mut out = Vec::new();
        for (owner, ns) in &st.namespaces {
            match staged.and_then(|s| s.get(owner)) {
                Some(Some(replacement)) => Self::collect_shared(st, &self.scope, owner, replacement, &mut out),
                Some(None) => {}
                None => Self::collect_shared(st, &self.scope, owner, ns, &mut out),
            }
        }
        if let Some(s) = staged {
            for (owner, ns) in s.iter().filter(|(o, _)| !st.namespaces.contains_key(*o)) {
                if let Some(ns) = ns {
                    Self::collect_shared(st, &self.scope, owner, ns, &mut out);
                }
            }
        }
        out.sort_by_key(|s| s.grant);
        out
    }

    fn shared_by_grant(&self, item: &str) -> Option<SharedItem> {
        let id = unhex(item)?;
        self.shared_items().into_iter().find(|s| s.grant == id)
    }

    /// The `Shared` collection exists in the view only while at least one
    /// grant is visible to this scope.
    fn shared_collection(&self) -> Option<CollectionInfo> {
        let items = self.shared_items();
        if items.is_empty() {
            return None;
        }
        let created = items.iter().map(|s| s.grant_created).min().unwrap_or(0);
        let modified = items.iter().map(|s| s.modified).max().unwrap_or(0);
        Some(CollectionInfo {
            name: SHARED_COLLECTION.to_owned(),
            label: "Shared with this application".to_owned(),
            created,
            modified,
            locked: self.state().shared_locked.contains(&self.scope),
            items: items.iter().map(|s| hex(&s.grant)).collect(),
        })
    }

    /// Decrypts an item's secret out of `ns_id`'s namespace — the view's own,
    /// or the owner's through a grant.
    fn read_secret_in(&self, ns_id: RecordId, id: RecordId) -> Result<Secret, StoreError> {
        // Inside a transaction the record may have been written just now.
        let staged = self.state().staged.as_ref().and_then(|st| {
            st.changes.iter().rev().find_map(|c| match c {
                Change::Put(r) if r.id == id && r.kind == KIND_SECRET => Some(r.clone()),
                _ => None,
            })
        });
        let raw = match staged {
            Some(r) => r,
            None => self
                .vault
                .db
                .load_one(&id, KIND_SECRET)?
                .ok_or_else(|| StoreError::Corrupt("missing secret record".into()))?,
        };
        if raw.namespace != ns_id {
            return Err(StoreError::Corrupt("secret record is misfiled".into()));
        }
        payload::decode_secret(&open_record(&self.state().cipher, &raw)?)
    }

    /// The grants of one of this (owner's) view's items, as (grantee, grant
    /// ID hex). For telling grantees about changes to their shared items.
    pub fn grantees_of(&self, collection: &str, item: &str) -> Vec<(Scope, String)> {
        let Ok(id) = self.item_id(collection, item) else { return Vec::new() };
        let Some(ns) = self.ns() else { return Vec::new() };
        ns.grants.iter().filter(|(_, g)| g.item == id).map(|(gid, g)| (g.grantee.clone(), hex(gid))).collect()
    }

    /// Where one of this view's grants points: the owner's scope, collection
    /// and item (hex). For telling the owner about a grantee's write.
    pub fn shared_origin(&self, grant: &str) -> Option<(Scope, String, String)> {
        let s = self.shared_by_grant(grant)?;
        Some((s.owner_scope, s.owner_collection, hex(&s.owner_item)))
    }

    /// The other grants of the item one of this view's grants points at, as
    /// (grantee, grant ID hex). For telling co-grantees about a write.
    pub fn shared_peers(&self, grant: &str) -> Vec<(Scope, String)> {
        let Some(id) = unhex(grant) else { return Vec::new() };
        let st = self.state();
        // The grant's owner namespace and item, through this scope's grants.
        let mut item = None;
        for ns in st.namespaces.values() {
            if let Some(g) = ns.grants.get(&id).filter(|g| g.grantee == self.scope) {
                item = Some((ns.id, g.item));
            }
        }
        let Some((ns_id, item)) = item else { return Vec::new() };
        let Some(ns) = st.namespaces.values().find(|ns| ns.id == ns_id) else { return Vec::new() };
        ns.grants
            .iter()
            .filter(|(gid, g)| **gid != id && g.item == item)
            .map(|(gid, g)| (g.grantee.clone(), hex(gid)))
            .collect()
    }

    // ---- reading ----

    pub fn collection_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.ns().map(|n| n.collections.keys().cloned().collect()).unwrap_or_default();
        if !self.shared_items().is_empty() {
            names.push(SHARED_COLLECTION.to_owned());
            names.sort();
        }
        names
    }

    pub fn collection(&self, name: &str) -> Option<CollectionInfo> {
        if name == SHARED_COLLECTION {
            return self.shared_collection();
        }
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
        if collection == SHARED_COLLECTION {
            let s = self.shared_by_grant(item)?;
            return Some(ItemInfo {
                name: item.to_owned(),
                label: s.label,
                attributes: s.attributes,
                created: s.created,
                modified: s.modified,
                locked: self.state().shared_locked.contains(&self.scope),
            });
        }
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
        let mut out = Vec::new();
        if let Some(ns) = self.ns() {
            for (cname, c) in &ns.collections {
                let locked = self.state().locked.contains(&c.id);
                for (id, i) in &c.items {
                    if attrs.iter().all(|(k, v)| i.attributes.get(k) == Some(v)) {
                        out.push((cname.clone(), item_name(id), locked));
                    }
                }
            }
        }
        let locked = self.state().shared_locked.contains(&self.scope);
        for s in self.shared_items() {
            if attrs.iter().all(|(k, v)| s.attributes.get(k) == Some(v)) {
                out.push((SHARED_COLLECTION.to_owned(), hex(&s.grant), locked));
            }
        }
        out
    }

    /// Decrypts an item's secret. Fails on a logically locked collection.
    pub fn read_secret(&self, collection: &str, item: &str) -> Result<Secret, StoreError> {
        if collection == SHARED_COLLECTION {
            // The grantee's own lock of `Shared`; the owner's collection lock
            // makes the item invisible instead (see `shared_items`).
            if !self.admin && self.state().shared_locked.contains(&self.scope) {
                return Err(StoreError::Locked);
            }
            let s = self.shared_by_grant(item).ok_or(StoreError::NoSuchObject)?;
            return self.read_secret_in(s.owner_ns, s.owner_item);
        }
        let id = self.item_id(collection, item)?;
        let c = self.collection_entry(collection)?;
        if !self.admin && self.state().locked.contains(&c.id) {
            return Err(StoreError::Locked);
        }
        if c.ephemeral {
            return c.secrets.get(&id).cloned().ok_or(StoreError::NoSuchObject);
        }
        let ns_id = self.ns().expect("collection exists").id;
        self.read_secret_in(ns_id, id)
    }

    // ---- logical lock state ----

    pub fn set_collection_locked(&mut self, collection: &str, locked: bool) -> Result<(), StoreError> {
        if collection == SHARED_COLLECTION {
            // Only this scope's view is affected.
            let set = &mut self.vault.unlocked.as_mut().expect("unlocked").shared_locked;
            if locked {
                set.insert(self.scope.clone());
            } else {
                set.remove(&self.scope);
            }
            return Ok(());
        }
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
        if !self.admin && self.state().locked.contains(&id) { Err(StoreError::Locked) } else { Ok(()) }
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
        if name == SHARED_COLLECTION {
            return Err(StoreError::NotPermitted("the Shared collection cannot be deleted"));
        }
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
        // Grants for the collection's items go with them.
        let grants: Vec<RecordId> =
            ns.grants.iter().filter(|(_, g)| c.items.contains_key(&g.item)).map(|(gid, _)| *gid).collect();
        for gid in &grants {
            ns.grants.remove(gid);
        }
        deletes.extend(grants.iter().map(|gid| (*gid, KIND_GRANT)));
        ns.aliases.retain(|_, target| *target != c.id);
        let writes = if c.ephemeral { Vec::new() } else { vec![self.namespace_record(&ns)?] };
        self.commit(ns, &writes, &deletes)?;
        // A stale ID left by a transaction is harmless: IDs are never reused.
        let u = self.vault.unlocked.as_mut().expect("unlocked");
        if u.staged.is_none() {
            u.locked.remove(&c.id);
        }
        Ok(())
    }

    /// Sets (`Some`) or removes (`None`) an alias within this scope.
    pub fn set_alias(&mut self, alias: &str, target: Option<&str>) -> Result<(), StoreError> {
        if !paths::is_valid_element(alias) {
            return Err(StoreError::Invalid("alias"));
        }
        if target == Some(SHARED_COLLECTION) {
            // `Shared` is a view, not an object an alias could point at.
            return Err(StoreError::NotPermitted("an alias cannot point at Shared"));
        }
        let (mut ns, new) = self.ns_or_new()?;
        match target {
            None => {
                if alias == SESSION_ALIAS && ns.aliases.contains_key(alias) {
                    return Err(StoreError::NotPermitted("the session alias is reserved"));
                }
                if new || ns.aliases.remove(alias).is_none() {
                    return Ok(());
                }
            }
            Some(name) => {
                let c = ns.collections.get(name).ok_or(StoreError::NoSuchObject)?;
                // Only `session` names the in-memory collection, and it names
                // nothing else: whatever follows another alias must reach
                // the disk, and whatever is stored under `session` must not.
                if (alias == SESSION_ALIAS) != c.ephemeral {
                    return Err(StoreError::NotPermitted("the session alias is reserved"));
                }
                let id = c.id;
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
        if name == SHARED_COLLECTION {
            return Err(StoreError::NotPermitted("the Shared collection cannot be relabelled"));
        }
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
        if collection == SHARED_COLLECTION {
            return Err(StoreError::NotPermitted("items cannot be created in Shared"));
        }
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
        if collection == SHARED_COLLECTION {
            return Err(StoreError::NotPermitted("shared items cannot be relabelled"));
        }
        validate_label(label)?;
        self.update_item(collection, item, |i| i.label = label.to_owned())
    }

    pub fn set_item_attributes(
        &mut self,
        collection: &str,
        item: &str,
        attrs: BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        if collection == SHARED_COLLECTION {
            return Err(StoreError::NotPermitted("shared items' attributes cannot be changed"));
        }
        validate_attributes(&attrs)?;
        self.update_item(collection, item, |i| i.attributes = attrs)
    }

    pub fn set_secret(&mut self, collection: &str, item: &str, secret: &Secret) -> Result<(), StoreError> {
        validate_secret(secret)?;
        if collection == SHARED_COLLECTION {
            if !self.admin && self.state().shared_locked.contains(&self.scope) {
                return Err(StoreError::Locked);
            }
            let s = self.shared_by_grant(item).ok_or(StoreError::NoSuchObject)?;
            if !s.write {
                return Err(StoreError::NotPermitted("the item is shared read-only"));
            }
            // The owner's item keeps its own records; only its `modified`
            // time changes with the secret.
            let mut ns = self.namespace_of(&s.owner_scope).ok_or(StoreError::NoSuchObject)?;
            let cid = s.owner_collection_id;
            let entry = ns
                .collections
                .values_mut()
                .find(|c| c.id == cid)
                .and_then(|c| c.items.get_mut(&s.owner_item))
                .ok_or(StoreError::NoSuchObject)?;
            entry.modified = now();
            let entry = entry.clone();
            let writes = vec![
                self.item_record(s.owner_ns, &cid, s.owner_item, &entry)?,
                self.secret_record(s.owner_ns, s.owner_item, secret)?,
            ];
            return self.commit_other(s.owner_scope.clone(), ns, &writes, &[]);
        }
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
        if collection == SHARED_COLLECTION {
            return Err(StoreError::NotPermitted("shared items cannot be deleted"));
        }
        let id = self.item_id(collection, item)?;
        self.ensure_writable(collection)?;
        let mut ns = self.ns().cloned().expect("item exists");
        let c = ns.collections.get_mut(collection).expect("item exists");
        c.items.remove(&id);
        c.modified = now();
        // Grants travel with the item they point at.
        let grants: Vec<RecordId> = ns.grants.iter().filter(|(_, g)| g.item == id).map(|(gid, _)| *gid).collect();
        for gid in &grants {
            ns.grants.remove(gid);
        }
        let mut deletes = vec![(id, KIND_ITEM), (id, KIND_SECRET)];
        deletes.extend(grants.iter().map(|gid| (*gid, KIND_GRANT)));
        if c.ephemeral {
            c.secrets.remove(&id);
            return self.commit(ns, &[], &[]);
        }
        let writes = vec![self.collection_record(ns.id, collection, &ns.collections[collection])?];
        self.commit(ns, &writes, &deletes)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::DirBuilderExt;

    use super::*;

    /// A private directory, removed when dropped.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let base = std::env::var_os("TMPDIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
            let p = base.join(format!("scopevault-store-{}", hex(&random_array::<16>().unwrap())));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_stored_session_alias_to_a_persistent_collection_is_dropped() {
        let tmp = TempDir::new();
        let dir = tmp.0.join("vault");
        let mut v = Vault::create(&dir, b"pw", KdfParams::MINIMUM).unwrap();
        {
            let mut s = v.scoped(&Principal::Host).unwrap();
            let (name, _) = s.create_collection("Login", DEFAULT_ALIAS).unwrap();
            // What versions before 0.12.2 stored after SetAlias("session", login).
            let mut ns = s.ns().cloned().unwrap();
            ns.aliases.insert(SESSION_ALIAS.into(), ns.collections[&name].id);
            let writes = vec![s.namespace_record(&ns).unwrap()];
            s.commit(ns, &writes, &[]).unwrap();
        }
        drop(v);
        let mut v = Vault::open(&dir).unwrap();
        v.unlock(b"pw").unwrap();
        let mut s = v.scoped(&Principal::Host).unwrap();
        assert_eq!(s.alias(SESSION_ALIAS), None);
        assert_eq!(s.alias(DEFAULT_ALIAS).as_deref(), Some(LOGIN_COLLECTION));
        let (session, created) = s.create_collection("Temporary", SESSION_ALIAS).unwrap();
        assert!(created && s.collection_entry(&session).unwrap().ephemeral, "a new in-memory collection");
    }
}
