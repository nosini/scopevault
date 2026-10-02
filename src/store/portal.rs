//! The Secret portal's per-app keys.
//!
//! The Secret portal backend ([`crate::portal_backend`]) serves one key per
//! application, which the app uses to encrypt its own private files. The
//! keys live in the reserved [`Scope::Portal`], in which no Secret Service
//! caller ever acts; only the portal backend and the administrative
//! interface reach them.
//!
//! The keys must move byte for byte when the provider changes: an
//! application's files stay encrypted with the old key, and a replacement
//! key makes them unreadable. [`split_portal_keys`] therefore separates them
//! from a provider's ordinary data during migration, and
//! [`Vault::import_portal_keys`] refuses to replace an existing key with
//! different bytes.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::{
    AdminAuthority, DEFAULT_ALIAS, ImportReport, PortableCollection, PortableItem, ScopedVault, Secret, StoreError,
    Vault,
};
use crate::crypto::random_array;
use crate::identity::Scope;
use crate::portal_backend::PortalAuthority;

/// The schema of the portal's per-app keys, as gnome-keyring stores them.
pub const PORTAL_SCHEMA: &str = "org.freedesktop.portal.Secret";

/// The keys' length: gnome-keyring generates 64 random bytes per app, and
/// the applications' files are encrypted with exactly these.
pub const PORTAL_KEY_BYTES: usize = 64;

/// Label and path name of the portal keys' collection, aliased `default` so
/// a generic export puts the keys into the other provider's default
/// collection, where gnome-keyring looks for them.
const COLLECTION_LABEL: &str = "Portal";
const COLLECTION_NAME: &str = "portal";

/// Whether `s` is an app ID a portal key may be served for. The frontend
/// forwards Flatpak, snap and host app IDs, which are all ASCII; this also
/// refuses anything that could escape the app data directory (path
/// separators, `.` and `..`) or that no app would be called.
pub fn is_valid_portal_app_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    let first_ok = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let rest_ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    let mut chars = s.chars();
    if !first_ok(chars.next().expect("not empty")) {
        return false;
    }
    chars.all(rest_ok)
}

/// A provider's data with the portal keys split out (see
/// [`split_portal_keys`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalSplit {
    /// What goes into the target scope.
    pub collections: Vec<PortableCollection>,
    /// The portal keys, unchanged, for [`Vault::import_portal_keys`].
    pub keys: Vec<PortableItem>,
    /// Why items were left where they are.
    pub notes: Vec<String>,
}

/// Splits the portal keys out of a provider's collections, so they are
/// imported into [`Scope::Portal`] instead of the target scope.
///
/// Only the collection the provider's `default` alias points to is
/// examined: gnome-keyring keeps its per-app keys there and serves the
/// first item with a matching `app_id`, whatever its schema. Two items for
/// one app ID make the key undefined, so the whole import is refused with
/// the affected app IDs, before anything is changed.
pub fn split_portal_keys(cols: Vec<PortableCollection>) -> Result<PortalSplit, String> {
    let mut split = PortalSplit { collections: cols, keys: Vec::new(), notes: Vec::new() };
    let Some(idx) = split.collections.iter().position(|c| c.aliases.iter().any(|a| a == DEFAULT_ALIAS)) else {
        return Ok(split);
    };
    let mut per_app: BTreeMap<&str, usize> = BTreeMap::new();
    for item in &split.collections[idx].items {
        if let Some(id) = item.attributes.get("app_id") {
            *per_app.entry(id).or_default() += 1;
        }
    }
    // Only app IDs that have a portal key: gnome-keyring could hand out any
    // of their items. Others stay ordinary items (with a note below).
    let has_key = |id: &str| {
        split.collections[idx].items.iter().any(|i| {
            i.attributes.get("app_id").map(String::as_str) == Some(id)
                && i.attributes.get("xdg:schema").map(String::as_str) == Some(PORTAL_SCHEMA)
        })
    };
    let ambiguous: Vec<&str> = per_app
        .into_iter()
        .filter(|(id, n)| *n > 1 && is_valid_portal_app_id(id) && has_key(id))
        .map(|(id, _)| id)
        .collect();
    if !ambiguous.is_empty() {
        return Err(format!(
            "the default collection holds several items for the app ID{} {}: which of them is \
             the portal key is undefined",
            if ambiguous.len() == 1 { "" } else { "s" },
            ambiguous.join(", ")
        ));
    }
    let default = &mut split.collections[idx];
    for item in std::mem::take(&mut default.items) {
        let schema = item.attributes.get("xdg:schema").map(String::as_str) == Some(PORTAL_SCHEMA);
        let id = item.attributes.get("app_id").cloned();
        match (schema, id.as_deref()) {
            (true, Some(id)) if is_valid_portal_app_id(id) => split.keys.push(item),
            (true, _) => {
                split.notes.push(format!(
                    "the item {:?} has the {PORTAL_SCHEMA} schema but an invalid or missing \
                     app_id; it is imported as an ordinary item",
                    item.label
                ));
                default.items.push(item);
            }
            (false, Some(id)) => {
                split.notes.push(format!(
                    "the item {:?} has app_id={id} but not the {PORTAL_SCHEMA} schema: \
                     gnome-keyring would have served it as a portal key, but it is imported as \
                     an ordinary item",
                    item.label
                ));
                default.items.push(item);
            }
            (false, None) => default.items.push(item),
        }
    }
    Ok(split)
}

/// What an import of portal keys did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortalImportReport {
    pub imported: usize,
    /// Keys already there with the same bytes, for example from an earlier
    /// run.
    pub skipped: usize,
}

/// The portal scope's view. Like the administrative one it ignores logical
/// collection locks: nothing else can lock these collections anyway.
fn portal_view(v: &mut Vault) -> Result<ScopedVault<'_>, StoreError> {
    if v.unlocked.is_none() {
        return Err(StoreError::Locked);
    }
    Ok(ScopedVault { vault: v, scope: Scope::Portal, admin: true })
}

/// Creates a key with a fresh random value (see [`Vault::create_portal_key`]).
/// Lookup and creation are one transaction, so two calls cannot both succeed.
fn create_key(v: &mut Vault, app_id: &str) -> Result<Secret, StoreError> {
    if !is_valid_portal_app_id(app_id) {
        return Err(StoreError::Invalid("invalid app ID"));
    }
    if !v.portal_initialised()? {
        return Err(StoreError::Invalid("the Secret portal keys were neither imported nor initialised"));
    }
    let attributes =
        BTreeMap::from([("app_id".to_owned(), app_id.to_owned()), ("xdg:schema".to_owned(), PORTAL_SCHEMA.to_owned())]);
    let key = Zeroizing::new(random_array::<PORTAL_KEY_BYTES>()?);
    let secret = Secret::new(key.as_slice().to_vec(), "application/octet-stream");
    v.transaction(|v| {
        let mut s = portal_view(v)?;
        let found = s.search(&[("app_id".to_owned(), app_id.to_owned())].into());
        match found.as_slice() {
            [] => {}
            [_] => return Err(StoreError::Invalid("the app already has a portal key")),
            _ => return Err(StoreError::Corrupt("several portal keys for one app".into())),
        }
        let col = s
            .alias(DEFAULT_ALIAS)
            .ok_or_else(|| StoreError::Corrupt("the portal scope has no default collection".into()))?;
        s.create_item(&col, &format!("Application key for {app_id}"), attributes, &secret, false)?;
        Ok(())
    })?;
    Ok(secret)
}

impl Vault {
    /// Whether the portal scope exists, considering changes staged inside
    /// [`Vault::transaction`] (as [`ScopedVault`] does). The vault must be
    /// unlocked.
    pub fn portal_initialised(&self) -> Result<bool, StoreError> {
        let u = self.unlocked.as_ref().ok_or(StoreError::Locked)?;
        Ok(match u.staged.as_ref().and_then(|st| st.namespaces.get(&Scope::Portal)) {
            Some(staged) => staged.is_some(),
            None => u.namespaces.contains_key(&Scope::Portal),
        })
    }

    /// Creates the portal scope if it does not exist yet; returns whether it
    /// created it.
    pub fn init_portal(&mut self, _: &AdminAuthority) -> Result<bool, StoreError> {
        self.transaction(|v| v.init_body())
    }

    fn init_body(&mut self) -> Result<bool, StoreError> {
        if self.portal_initialised()? {
            return Ok(false);
        }
        let mut s = portal_view(self)?;
        let (name, _) = s.create_collection(COLLECTION_LABEL, DEFAULT_ALIAS)?;
        debug_assert_eq!(name, COLLECTION_NAME);
        Ok(true)
    }

    /// The app's portal key, if there is one. More than one key for an app
    /// is vault damage: gnome-keyring would have served an arbitrary one of
    /// them.
    pub fn portal_key(&mut self, _: &PortalAuthority, app_id: &str) -> Result<Option<Secret>, StoreError> {
        if !is_valid_portal_app_id(app_id) {
            return Err(StoreError::Invalid("invalid app ID"));
        }
        let s = portal_view(self)?;
        let found = s.search(&[("app_id".to_owned(), app_id.to_owned())].into());
        match found.as_slice() {
            [] => Ok(None),
            [(col, item, _)] => Ok(Some(s.read_secret(col, item)?)),
            _ => Err(StoreError::Corrupt("several portal keys for one app".into())),
        }
    }

    /// Creates the app's portal key. Only for an app without a key already;
    /// the portal backend additionally refuses apps that have a keyring file
    /// of their own (see [`crate::portal_backend`]).
    pub fn create_portal_key(&mut self, _: &PortalAuthority, app_id: &str) -> Result<Secret, StoreError> {
        create_key(self, app_id)
    }

    /// [`Vault::create_portal_key`] for the administrative interface
    /// (`portal new-key`), which creates a key the vault is missing, for
    /// example when an app's keyring file appeared without an import.
    pub fn admin_create_portal_key(&mut self, _: &AdminAuthority, app_id: &str) -> Result<Secret, StoreError> {
        create_key(self, app_id)
    }

    /// Imports portal keys, creating the portal scope if needed. A key that
    /// is already there with the same bytes is skipped; different bytes are
    /// a conflict ([`StoreError::PortalConflict`]), never a replacement: the
    /// app's own files stay encrypted with the old key.
    pub fn import_portal_keys(
        &mut self,
        _: &AdminAuthority,
        keys: &[PortableItem],
    ) -> Result<PortalImportReport, StoreError> {
        self.transaction(|v| v.import_keys_body(keys))
    }

    fn import_keys_body(&mut self, keys: &[PortableItem]) -> Result<PortalImportReport, StoreError> {
        if !self.portal_initialised()? {
            self.init_body()?;
        }
        let mut s = portal_view(self)?;
        let mut report = PortalImportReport::default();
        for key in keys {
            let Some(app_id) = key.attributes.get("app_id").map(String::as_str).filter(|a| is_valid_portal_app_id(a))
            else {
                return Err(StoreError::Invalid("a portal key without a valid app ID"));
            };
            if key.attributes.get("xdg:schema").map(String::as_str) != Some(PORTAL_SCHEMA) {
                return Err(StoreError::Invalid("a portal key without the portal schema"));
            }
            let found = s.search(&[("app_id".to_owned(), app_id.to_owned())].into());
            match found.as_slice() {
                [] => {
                    let col = s
                        .alias(DEFAULT_ALIAS)
                        .ok_or_else(|| StoreError::Corrupt("the portal scope has no default collection".into()))?;
                    let (item, _) = s.create_item(&col, &key.label, key.attributes.clone(), &key.secret, false)?;
                    s.set_item_times(&col, &item, key.created, key.modified)?;
                    report.imported += 1;
                }
                [(col, item, _)] => {
                    if s.read_secret(col, item)? == key.secret {
                        report.skipped += 1;
                    } else {
                        return Err(StoreError::PortalConflict(app_id.to_owned()));
                    }
                }
                _ => return Err(StoreError::Corrupt("several portal keys for one app".into())),
            }
        }
        Ok(report)
    }

    /// [`Vault::import`] and [`Vault::import_portal_keys`] in one
    /// transaction: an import that fails halfway changes nothing, in either
    /// scope.
    pub fn import_with_portal_keys(
        &mut self,
        authority: &AdminAuthority,
        scope: &Scope,
        collections: &[PortableCollection],
        keys: &[PortableItem],
    ) -> Result<(ImportReport, PortalImportReport), StoreError> {
        self.transaction(|v| {
            let report = v.import_body(authority, scope, collections)?;
            let portal = v.import_keys_body(keys)?;
            Ok((report, portal))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids() {
        for ok in ["a", "_x", "1", "org.example.App", "App_1-x", "a".repeat(255).as_str()] {
            assert!(is_valid_portal_app_id(ok), "{ok:?}");
        }
        for bad in ["", ".", "..", "/a", "a/", "a/b", "../x", "-x", ".x", "a b", "ä", "a".repeat(256).as_str()] {
            assert!(!is_valid_portal_app_id(bad), "{bad:?}");
        }
    }
}
