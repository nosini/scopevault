//! Administrative operations on the vault: listing scopes, moving items
//! between scopes, deleting a scope's data, and copying whole scopes in and
//! out (migration, rollback).
//!
//! Everything here needs an [`AdminAuthority`]. Operations that change more
//! than one record run in one [`Vault::transaction`]: they happen
//! completely or not at all.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::db::RecordId;
use super::{
    AdminAuthority, DEFAULT_ALIAS, ItemEntry, KIND_COLLECTION, KIND_GRANT, KIND_ITEM, KIND_NAMESPACE, KIND_SECRET,
    SESSION_ALIAS, ScopedVault, Secret, StoreError, Vault, item_name,
};
use crate::identity::Scope;

/// A scope and how much it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSummary {
    pub scope: String,
    pub collections: usize,
    pub items: usize,
}

/// A collection's metadata. Never includes secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionListing {
    pub name: String,
    pub label: String,
    pub aliases: Vec<String>,
    pub created: u64,
    pub modified: u64,
    /// Locked by its app (logical lock).
    pub locked: bool,
    pub items: Vec<ItemListing>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemListing {
    pub name: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub created: u64,
    pub modified: u64,
}

/// A collection with its items and secrets, as copied between providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableCollection {
    pub label: String,
    /// Aliases pointing to it (usually `default` or none).
    pub aliases: Vec<String>,
    pub items: Vec<PortableItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableItem {
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: Secret,
    pub created: u64,
    pub modified: u64,
}

/// gnome-keyring stores an item type rather than a schema name, and reports
/// items without a schema as `xdg:schema` = this once it has reloaded them
/// from disk (`gkm-secret-compat.c`). Freshly created items lack it.
const GENERIC_SCHEMA: &str = "org.freedesktop.Secret.Generic";

/// Whether two attribute sets name the same item, treating a missing
/// `xdg:schema` as the generic schema (see [`GENERIC_SCHEMA`]).
pub fn same_attributes(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> bool {
    let schema = |m: &BTreeMap<String, String>| m.get("xdg:schema").cloned().unwrap_or_else(|| GENERIC_SCHEMA.into());
    let rest = |m: &BTreeMap<String, String>| m.iter().filter(|(k, _)| *k != "xdg:schema").count();
    schema(a) == schema(b)
        && rest(a) == rest(b)
        && a.iter().filter(|(k, _)| *k != "xdg:schema").all(|(k, v)| b.get(k) == Some(v))
}

impl PortableItem {
    /// Equal in everything but timestamps (see [`same_attributes`]).
    pub fn same_as(&self, other: &PortableItem) -> bool {
        self.label == other.label && same_attributes(&self.attributes, &other.attributes) && self.secret == other.secret
    }
}

/// What an import did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub collections_created: usize,
    pub items_imported: usize,
    /// Items identical (label, attributes, secret and content type) to one
    /// already in the target collection, for example from an earlier run.
    pub items_skipped: usize,
    pub aliases_set: Vec<String>,
}

impl Vault {
    /// Scopes that have data, with their sizes.
    pub fn scope_summaries(&mut self, authority: &AdminAuthority) -> Result<Vec<ScopeSummary>, StoreError> {
        let mut out = Vec::new();
        for scope in self.scopes()? {
            let listing = self.scoped_admin(authority, scope.clone())?.listing();
            out.push(ScopeSummary {
                scope: scope.to_string(),
                collections: listing.len(),
                items: listing.iter().map(|c| c.items.len()).sum(),
            });
        }
        Ok(out)
    }

    /// Moves items, given as `COLLECTION/ITEM`, from one scope into the
    /// other's default collection (created if needed). Labels, attributes,
    /// secrets and timestamps are kept. Returns the new `COLLECTION/ITEM`
    /// names, in order.
    pub fn move_items(
        &mut self,
        authority: &AdminAuthority,
        from: &Scope,
        items: &[String],
        to: &Scope,
    ) -> Result<Vec<String>, StoreError> {
        if from == to {
            return Err(StoreError::Invalid("source and target scope are the same"));
        }
        // The portal keys belong to their app and their scope; a move would
        // hand one to whoever owns the target scope.
        if from == &Scope::Portal || to == &Scope::Portal {
            return Err(StoreError::Invalid("portal keys cannot be moved"));
        }
        self.transaction(|v| {
            let mut moved = Vec::new();
            for spec in items {
                let (col, item) = spec.split_once('/').ok_or(StoreError::Invalid("items are COLLECTION/ITEM"))?;
                if col == SESSION_ALIAS {
                    return Err(StoreError::Invalid("items of the session collection cannot be moved"));
                }
                let (info, secret) = {
                    let src = v.scoped_admin(authority, from.clone())?;
                    let info = src.item(col, item).ok_or(StoreError::NoSuchObject)?;
                    let secret = src.read_secret(col, item)?;
                    (info, secret)
                };
                let mut dst = v.scoped_admin(authority, to.clone())?;
                let target = dst.default_collection_or_create()?;
                let (name, _) = dst.create_item(&target, &info.label, info.attributes, &secret, false)?;
                dst.set_item_times(&target, &name, info.created, info.modified)?;
                v.scoped_admin(authority, from.clone())?.delete_item(col, item)?;
                moved.push(format!("{target}/{name}"));
            }
            Ok(moved)
        })
    }

    /// Deletes everything a scope holds. Returns (collections, items).
    /// Grants the scope gave away go with their items; grants other scopes
    /// gave to it go too, in the same transaction.
    pub fn reset_scope(&mut self, authority: &AdminAuthority, scope: &Scope) -> Result<(usize, usize), StoreError> {
        self.transaction(|v| {
            let result = v.scoped_admin(authority, scope.clone())?.delete_everything()?;
            let mut affected: Vec<(Scope, Vec<RecordId>)> = Vec::new();
            {
                let u = v.unlocked.as_ref().ok_or(StoreError::Locked)?;
                for (owner, ns) in &u.namespaces {
                    if owner == scope {
                        continue;
                    }
                    let gids: Vec<RecordId> =
                        ns.grants.iter().filter(|(_, g)| &g.grantee == scope).map(|(gid, _)| *gid).collect();
                    if !gids.is_empty() {
                        affected.push((owner.clone(), gids));
                    }
                }
            }
            for (owner, gids) in affected {
                let mut s = v.scoped_admin(authority, owner.clone())?;
                let mut ns = s.ns().cloned().ok_or(StoreError::NoSuchObject)?;
                for gid in &gids {
                    ns.grants.remove(gid);
                }
                let deletes: Vec<(RecordId, u8)> = gids.iter().map(|gid| (*gid, KIND_GRANT)).collect();
                s.commit(ns, &[], &deletes)?;
            }
            Ok(result)
        })
    }

    /// Copies collections into a scope. A collection is merged into the
    /// scope's collection with the same label, if there is one; items
    /// identical to one already there are skipped, so running an import
    /// twice adds nothing. An alias is set only where the scope does not
    /// have it yet.
    pub fn import(
        &mut self,
        authority: &AdminAuthority,
        scope: &Scope,
        collections: &[PortableCollection],
    ) -> Result<ImportReport, StoreError> {
        self.transaction(|v| v.import_body(authority, scope, collections))
    }

    /// The body of [`Vault::import`], without its transaction, so
    /// [`Vault::import_with_portal_keys`] can run it inside one bigger
    /// one. Refuses the portal scope: its keys go through
    /// [`Vault::import_portal_keys`].
    pub(super) fn import_body(
        &mut self,
        authority: &AdminAuthority,
        scope: &Scope,
        collections: &[PortableCollection],
    ) -> Result<ImportReport, StoreError> {
        if scope == &Scope::Portal {
            return Err(StoreError::Invalid("use the portal key import for the portal scope"));
        }
        let mut s = self.scoped_admin(authority, scope.clone())?;
        let mut report = ImportReport::default();
        for pc in collections {
            let existing = s.listing().into_iter().find(|c| c.label == pc.label && c.name != SESSION_ALIAS);
            let name = match existing {
                Some(c) => c.name,
                None => {
                    report.collections_created += 1;
                    s.create_collection(&pc.label, "")?.0
                }
            };
            for item in &pc.items {
                if s.has_identical(&name, item)? {
                    report.items_skipped += 1;
                    continue;
                }
                let (id, _) = s.create_item(&name, &item.label, item.attributes.clone(), &item.secret, false)?;
                s.set_item_times(&name, &id, item.created, item.modified)?;
                report.items_imported += 1;
            }
            for alias in &pc.aliases {
                if alias != SESSION_ALIAS && s.alias(alias).is_none() {
                    s.set_alias(alias, Some(&name))?;
                    report.aliases_set.push(alias.clone());
                }
            }
        }
        Ok(report)
    }

    /// A scope's persistent collections with their items and secrets, for
    /// copying them elsewhere. The `session` collection is not included.
    pub fn export(&mut self, authority: &AdminAuthority, scope: &Scope) -> Result<Vec<PortableCollection>, StoreError> {
        let s = self.scoped_admin(authority, scope.clone())?;
        let mut out = Vec::new();
        for c in s.listing().into_iter().filter(|c| c.name != SESSION_ALIAS) {
            let mut items = Vec::new();
            for i in &c.items {
                items.push(PortableItem {
                    label: i.label.clone(),
                    attributes: i.attributes.clone(),
                    secret: s.read_secret(&c.name, &i.name)?,
                    created: i.created,
                    modified: i.modified,
                });
            }
            out.push(PortableCollection { label: c.label, aliases: c.aliases, items });
        }
        Ok(out)
    }
}

impl ScopedVault<'_> {
    /// The scope's collections and items, metadata only.
    pub fn listing(&self) -> Vec<CollectionListing> {
        let Some(ns) = self.ns() else { return Vec::new() };
        ns.collections
            .iter()
            .map(|(name, c)| CollectionListing {
                name: name.clone(),
                label: c.label.clone(),
                aliases: ns.aliases.iter().filter(|(_, id)| **id == c.id).map(|(a, _)| a.clone()).collect(),
                created: c.created,
                modified: c.modified,
                locked: self.state().locked.contains(&c.id),
                items: c
                    .items
                    .iter()
                    .map(|(id, i)| ItemListing {
                        name: item_name(id),
                        label: i.label.clone(),
                        attributes: i.attributes.clone(),
                        created: i.created,
                        modified: i.modified,
                    })
                    .collect(),
            })
            .collect()
    }

    /// The collection the `default` alias points to; if there is none, a
    /// new "Login" collection that the alias then points to. Never the
    /// in-memory `session` collection, which a move would empty at the next
    /// lock.
    fn default_collection_or_create(&mut self) -> Result<String, StoreError> {
        if let Some(name) = self.alias(DEFAULT_ALIAS) {
            if self.collection_entry(&name)?.ephemeral {
                return Err(StoreError::Invalid("the default collection is the session collection"));
            }
            return Ok(name);
        }
        let (name, _) = self.create_collection("Login", "")?;
        self.set_alias(DEFAULT_ALIAS, Some(&name))?;
        Ok(name)
    }

    /// Restores an imported item's timestamps. Visible to `store::portal`,
    /// which imports keys the same way.
    pub(super) fn set_item_times(
        &mut self,
        collection: &str,
        item: &str,
        created: u64,
        modified: u64,
    ) -> Result<(), StoreError> {
        let id = self.item_id(collection, item)?;
        let mut ns = self.ns().cloned().expect("item exists");
        let ns_id = ns.id;
        let c = ns.collection_mut(collection).expect("item exists");
        let cid = c.id;
        let entry: &mut ItemEntry = c.item_mut(&id).expect("item exists");
        entry.created = created;
        entry.modified = modified;
        let entry = entry.clone();
        let writes = if c.ephemeral { Vec::new() } else { vec![self.item_record(ns_id, &cid, id, &entry)?] };
        self.commit(ns, &writes, &[])
    }

    /// Whether `collection` has an item equal to `item` in everything but
    /// its timestamps (see [`same_attributes`]).
    fn has_identical(&self, collection: &str, item: &PortableItem) -> Result<bool, StoreError> {
        let Some(c) = self.ns().and_then(|n| n.collections.get(collection)) else { return Ok(false) };
        let candidates: Vec<String> = c
            .items
            .iter()
            .filter(|(_, i)| i.label == item.label && same_attributes(&i.attributes, &item.attributes))
            .map(|(id, _)| item_name(id))
            .collect();
        for name in candidates {
            if self.read_secret(collection, &name)? == item.secret {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Deletes the scope's namespace with all its collections, items,
    /// secrets and grants. Returns (collections, items).
    fn delete_everything(&mut self) -> Result<(usize, usize), StoreError> {
        let Some(ns) = self.ns().cloned() else { return Ok((0, 0)) };
        let mut deletes = vec![(ns.id, KIND_NAMESPACE)];
        let mut items = 0;
        for c in ns.collections.values() {
            items += c.items.len();
            if c.ephemeral {
                continue;
            }
            deletes.push((c.id, KIND_COLLECTION));
            for id in c.items.keys() {
                deletes.push((*id, KIND_ITEM));
                deletes.push((*id, KIND_SECRET));
            }
        }
        for gid in ns.grants.keys() {
            deletes.push((*gid, KIND_GRANT));
        }
        let collections = ns.collections.len();
        self.commit_ns(None, &[], &deletes)?;
        Ok((collections, items))
    }
}
