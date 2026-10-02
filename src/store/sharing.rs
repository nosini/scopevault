//! Explicit sharing: the administrative interface grants one scope read or
//! write access to one item of another scope.
//!
//! No sharing by default: grants exist only where they
//! were created explicitly, carry no wildcards and never cross the reserved
//! `portal` scope. A grant is an encrypted record in the owner's namespace
//! (so backups carry it), which the grantee's view surfaces as an item of
//! the virtual `Shared` collection ([`SHARED_COLLECTION`]; see the shared
//! methods of [`ScopedVault`]). Deleting the item, its collection or its
//! namespace, or moving the item, deletes its grants with it.

use serde::{Deserialize, Serialize};

use super::payload::GrantPayload;
use super::{AdminAuthority, GrantEntry, KIND_GRANT, SESSION_ALIAS, StoreError, Vault, hex, new_id, now, unhex};
use crate::identity::Scope;

/// Grants one owner may hold at once.
pub const MAX_GRANTS_PER_SCOPE: usize = 256;

/// One grant, as listed by [`Vault::grants`]. Never includes secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantListing {
    /// The grant's ID: the item's path name in the grantee's `Shared`
    /// collection.
    pub id: String,
    pub owner: String,
    /// The owner's collection, by path name.
    pub collection: String,
    /// The owner's item, by path name.
    pub item: String,
    pub label: String,
    pub grantee: String,
    pub write: bool,
    pub created: u64,
}

impl Vault {
    /// Gives `grantee` access to one item of `owner`'s scope, `item` being
    /// `COLLECTION/ITEM` in the owner's view. Sharing an (item, grantee)
    /// pair again changes the existing grant's access instead of adding a
    /// second one. Returns the grant's ID.
    pub fn share(
        &mut self,
        auth: &AdminAuthority,
        owner: &Scope,
        item: &str,
        grantee: &Scope,
        write: bool,
    ) -> Result<String, StoreError> {
        if *owner == Scope::Portal {
            return Err(StoreError::Invalid("the portal scope cannot share items"));
        }
        if *grantee == Scope::Portal {
            return Err(StoreError::Invalid("items cannot be shared with the portal scope"));
        }
        if owner == grantee {
            return Err(StoreError::Invalid("a scope cannot share with itself"));
        }
        self.transaction(|v| {
            let (col, it) = item.split_once('/').ok_or(StoreError::Invalid("items are COLLECTION/ITEM"))?;
            if col == SESSION_ALIAS {
                return Err(StoreError::Invalid("session items cannot be shared"));
            }
            let mut s = v.scoped_admin(auth, owner.clone())?;
            let item_id = s.item_id(col, it)?;
            let mut ns = s.ns().cloned().ok_or(StoreError::NoSuchObject)?;
            let ns_id = ns.id;
            let gid =
                match ns.grants.iter().find(|(_, g)| g.item == item_id && &g.grantee == grantee).map(|(gid, _)| *gid) {
                    Some(gid) => {
                        // Sharing again changes the grant's access.
                        let entry = ns.grants.get_mut(&gid).expect("found above");
                        entry.write = write;
                        gid
                    }
                    None => {
                        if ns.grants.len() >= MAX_GRANTS_PER_SCOPE {
                            return Err(StoreError::Limit("too many grants"));
                        }
                        let gid = new_id()?;
                        ns.grants
                            .insert(gid, GrantEntry { item: item_id, grantee: grantee.clone(), write, created: now() });
                        gid
                    }
                };
            let entry = ns.grants.get(&gid).expect("just inserted");
            let payload = GrantPayload {
                item: hex(&item_id),
                grantee: grantee.to_string(),
                write: entry.write,
                created: entry.created,
            };
            let raw = s.grant_record(ns_id, gid, &payload)?;
            s.commit(ns, &[raw], &[])?;
            Ok(hex(&gid))
        })
    }

    /// Revokes one grant. Returns its listing, so the caller can tell the
    /// grantee's scope.
    pub fn unshare(&mut self, auth: &AdminAuthority, grant: &str) -> Result<GrantListing, StoreError> {
        let Some(gid) = unhex(grant) else { return Err(StoreError::NoSuchObject) };
        self.transaction(|v| {
            // A grant record lives in its owner's namespace, and grant IDs
            // are random, so at most one namespace holds it.
            let u = v.unlocked.as_ref().ok_or(StoreError::Locked)?;
            let Some(owner) =
                u.namespaces.iter().filter(|(_, ns)| ns.grants.contains_key(&gid)).map(|(s, _)| s.clone()).next()
            else {
                return Err(StoreError::NoSuchObject);
            };
            let mut s = v.scoped_admin(auth, owner.clone())?;
            let mut ns = s.ns().cloned().ok_or(StoreError::NoSuchObject)?;
            let entry = ns.grants.get(&gid).ok_or(StoreError::NoSuchObject)?;
            let listing = {
                let (cname, label) = ns
                    .collections
                    .iter()
                    .find_map(|(name, c)| c.items.get(&entry.item).map(|i| (name, &i.label)))
                    .ok_or_else(|| StoreError::Corrupt("grant without an item".into()))?;
                GrantListing {
                    id: grant.to_owned(),
                    owner: owner.to_string(),
                    collection: cname.clone(),
                    item: hex(&entry.item),
                    label: label.clone(),
                    grantee: entry.grantee.to_string(),
                    write: entry.write,
                    created: entry.created,
                }
            };
            ns.grants.remove(&gid);
            s.commit(ns, &[], &[(gid, KIND_GRANT)])?;
            Ok(listing)
        })
    }

    /// All grants, or those where `scope` is the owner or the grantee.
    pub fn grants(&self, _: &AdminAuthority, scope: Option<&Scope>) -> Result<Vec<GrantListing>, StoreError> {
        let u = self.unlocked.as_ref().ok_or(StoreError::Locked)?;
        let mut out = Vec::new();
        for (owner, ns) in &u.namespaces {
            if let Some(s) = scope
                && s != owner
                && !ns.grants.values().any(|g| &g.grantee == s)
            {
                continue;
            }
            for (gid, g) in &ns.grants {
                if let Some(s) = scope
                    && s != owner
                    && &g.grantee != s
                {
                    continue;
                }
                let Some((cname, item)) =
                    ns.collections.iter().find_map(|(name, c)| c.items.get(&g.item).map(|i| (name, i)))
                else {
                    continue;
                };
                out.push(GrantListing {
                    id: hex(gid),
                    owner: owner.to_string(),
                    collection: cname.clone(),
                    item: hex(&g.item),
                    label: item.label.clone(),
                    grantee: g.grantee.to_string(),
                    write: g.write,
                    created: g.created,
                });
            }
        }
        out.sort_by(|a, b| {
            (&a.owner, &a.collection, &a.item, &a.grantee).cmp(&(&b.owner, &b.collection, &b.item, &b.grantee))
        });
        Ok(out)
    }
}
