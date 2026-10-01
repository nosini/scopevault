//! In-memory object model used by the caller-aware dispatch.
//!
//! Every accessor takes the caller's [`Scope`]; there is no way to reach a
//! scope's data without naming that scope, and scopes never share entries.
//! The encrypted store will implement the same operations.

use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::identity::Scope;

use super::paths;

pub const MAX_COLLECTIONS_PER_SCOPE: usize = 256;
pub const MAX_LABEL_BYTES: usize = 4096;
pub const MAX_ALIASES_PER_SCOPE: usize = 64;

#[derive(Debug, Clone)]
pub struct ItemState {
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Clone)]
pub struct CollectionState {
    pub label: String,
    pub locked: bool,
    pub created: u64,
    pub modified: u64,
    pub items: BTreeMap<String, ItemState>,
}

#[derive(Debug, Default)]
pub struct ScopeState {
    pub collections: BTreeMap<String, CollectionState>,
    pub aliases: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("no such object")]
    NoSuchObject,
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid argument: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Default)]
pub struct Model {
    scopes: HashMap<Scope, ScopeState>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Turns a label into a readable path element, unique within the scope.
fn collection_name_for(label: &str, existing: &BTreeMap<String, CollectionState>) -> String {
    let mut base: String =
        label.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).take(32).collect();
    if base.is_empty() || base.bytes().all(|b| b == b'_') {
        base = "collection".into();
    }
    if !existing.contains_key(&base) {
        return base;
    }
    (2..).map(|n| format!("{base}_{n}")).find(|n| !existing.contains_key(n)).expect("unbounded")
}

impl Model {
    pub fn scope(&self, scope: &Scope) -> Option<&ScopeState> {
        self.scopes.get(scope)
    }

    pub fn collection_names(&self, scope: &Scope) -> Vec<String> {
        self.scopes.get(scope).map(|s| s.collections.keys().cloned().collect()).unwrap_or_default()
    }

    pub fn collection(&self, scope: &Scope, name: &str) -> Option<&CollectionState> {
        self.scopes.get(scope)?.collections.get(name)
    }

    pub fn collection_mut(&mut self, scope: &Scope, name: &str) -> Option<&mut CollectionState> {
        self.scopes.get_mut(scope)?.collections.get_mut(name)
    }

    pub fn item(&self, scope: &Scope, collection: &str, id: &str) -> Option<&ItemState> {
        self.collection(scope, collection)?.items.get(id)
    }

    /// Resolves an alias to a collection name within `scope`.
    pub fn alias(&self, scope: &Scope, alias: &str) -> Option<&str> {
        let s = self.scopes.get(scope)?;
        let target = s.aliases.get(alias)?;
        s.collections.contains_key(target).then_some(target.as_str())
    }

    pub fn create_collection(&mut self, scope: &Scope, label: &str, alias: &str) -> Result<String, ModelError> {
        if label.len() > MAX_LABEL_BYTES {
            return Err(ModelError::Limit("label too long"));
        }
        if !alias.is_empty() && !paths::is_valid_element(alias) {
            return Err(ModelError::Invalid("alias"));
        }
        let s = self.scopes.entry(scope.clone()).or_default();
        // Per the specification, an existing collection with the requested
        // alias is returned instead of creating a new one.
        if !alias.is_empty()
            && let Some(existing) = s.aliases.get(alias).filter(|t| s.collections.contains_key(*t))
        {
            return Ok(existing.clone());
        }
        if s.collections.len() >= MAX_COLLECTIONS_PER_SCOPE {
            return Err(ModelError::Limit("too many collections"));
        }
        if !alias.is_empty() && s.aliases.len() >= MAX_ALIASES_PER_SCOPE && !s.aliases.contains_key(alias) {
            return Err(ModelError::Limit("too many aliases"));
        }
        let name = collection_name_for(label, &s.collections);
        let t = now();
        s.collections.insert(
            name.clone(),
            CollectionState { label: label.to_owned(), locked: false, created: t, modified: t, items: BTreeMap::new() },
        );
        if !alias.is_empty() {
            s.aliases.insert(alias.to_owned(), name.clone());
        }
        Ok(name)
    }

    pub fn delete_collection(&mut self, scope: &Scope, name: &str) -> Result<(), ModelError> {
        let s = self.scopes.get_mut(scope).ok_or(ModelError::NoSuchObject)?;
        s.collections.remove(name).ok_or(ModelError::NoSuchObject)?;
        s.aliases.retain(|_, target| target != name);
        Ok(())
    }

    /// Sets or (with `None`) removes an alias. Only collections in the same
    /// scope can be targets.
    pub fn set_alias(&mut self, scope: &Scope, alias: &str, target: Option<&str>) -> Result<(), ModelError> {
        if !paths::is_valid_element(alias) {
            return Err(ModelError::Invalid("alias"));
        }
        let s = self.scopes.entry(scope.clone()).or_default();
        match target {
            None => {
                s.aliases.remove(alias);
            }
            Some(t) => {
                if !s.collections.contains_key(t) {
                    return Err(ModelError::NoSuchObject);
                }
                if s.aliases.len() >= MAX_ALIASES_PER_SCOPE && !s.aliases.contains_key(alias) {
                    return Err(ModelError::Limit("too many aliases"));
                }
                s.aliases.insert(alias.to_owned(), t.to_owned());
            }
        }
        Ok(())
    }

    pub fn set_collection_label(&mut self, scope: &Scope, name: &str, label: &str) -> Result<(), ModelError> {
        if label.len() > MAX_LABEL_BYTES {
            return Err(ModelError::Limit("label too long"));
        }
        let c = self.collection_mut(scope, name).ok_or(ModelError::NoSuchObject)?;
        c.label = label.to_owned();
        c.modified = now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AppId;

    fn app(id: &str) -> Scope {
        Scope::Flatpak(AppId::parse(id).unwrap())
    }

    #[test]
    fn scopes_do_not_share_collections_or_aliases() {
        let mut m = Model::default();
        let a = app("org.example.A");
        let b = app("org.example.B");
        let ca = m.create_collection(&a, "Login", "default").unwrap();
        let cb = m.create_collection(&b, "Login", "default").unwrap();
        assert_eq!(ca, "login");
        assert_eq!(cb, "login");
        m.set_collection_label(&a, "login", "A's").unwrap();
        assert_eq!(m.collection(&b, "login").unwrap().label, "Login");
        assert_eq!(m.set_alias(&b, "x", Some("missing")), Err(ModelError::NoSuchObject));
        m.delete_collection(&a, "login").unwrap();
        assert!(m.alias(&a, "default").is_none());
        assert_eq!(m.alias(&b, "default"), Some("login"));
        assert!(m.collection(&Scope::Host, "login").is_none());
    }

    #[test]
    fn existing_alias_is_returned() {
        let mut m = Model::default();
        let first = m.create_collection(&Scope::Host, "One", "default").unwrap();
        let again = m.create_collection(&Scope::Host, "Two", "default").unwrap();
        assert_eq!(first, again);
        let other = m.create_collection(&Scope::Host, "One", "").unwrap();
        assert_eq!(other, "one_2");
    }
}
