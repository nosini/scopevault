//! Object path layout.
//!
//! Collection and item paths are relative to the caller's scope: the same
//! path string names different objects (or nothing) for different scopes,
//! and is only ever resolved against the caller's own scope. There is no
//! global path namespace in which another scope's objects could be guessed.
//!
//! ```text
//! /org/freedesktop/secrets                       Service
//! /org/freedesktop/secrets/collection/<name>     Collection
//! /org/freedesktop/secrets/collection/<name>/<id> Item
//! /org/freedesktop/secrets/aliases/<alias>       Collection, via alias
//! /org/freedesktop/secrets/aliases/<alias>/<id>  Item, via alias
//! /org/freedesktop/secrets/session/<id>          Session (owning connection only)
//! /org/freedesktop/secrets/prompt/<id>           Prompt (owning connection only)
//! ```
//!
//! Item paths are children of their collection path because libsecret
//! derives an item's collection from the parent path.

use zbus::zvariant::{ObjectPath, OwnedObjectPath};

pub const SERVICE: &str = "/org/freedesktop/secrets";
pub const COLLECTION_DIR: &str = "/org/freedesktop/secrets/collection";
pub const ALIAS_DIR: &str = "/org/freedesktop/secrets/aliases";
pub const SESSION_DIR: &str = "/org/freedesktop/secrets/session";
pub const PROMPT_DIR: &str = "/org/freedesktop/secrets/prompt";
/// "No object", used where the specification returns `/` (e.g. no prompt).
pub const NONE: &str = "/";

/// Maximum length of names we generate or accept as path elements.
pub const MAX_ELEMENT_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed<'a> {
    Root,
    Org,
    Freedesktop,
    Service,
    CollectionDir,
    AliasDir,
    SessionDir,
    PromptDir,
    Collection(&'a str),
    AliasedCollection(&'a str),
    Item(&'a str, &'a str),
    AliasedItem(&'a str, &'a str),
    Session(&'a str),
    Prompt(&'a str),
    Unknown,
}

pub fn is_valid_element(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ELEMENT_LEN && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn parse(path: &str) -> Parsed<'_> {
    match path {
        "/" => return Parsed::Root,
        "/org" => return Parsed::Org,
        "/org/freedesktop" => return Parsed::Freedesktop,
        SERVICE => return Parsed::Service,
        COLLECTION_DIR => return Parsed::CollectionDir,
        ALIAS_DIR => return Parsed::AliasDir,
        SESSION_DIR => return Parsed::SessionDir,
        PROMPT_DIR => return Parsed::PromptDir,
        _ => {}
    }
    let Some(rest) = path.strip_prefix("/org/freedesktop/secrets/") else { return Parsed::Unknown };
    let parts: Vec<&str> = rest.split('/').collect();
    if !parts.iter().skip(1).all(|p| is_valid_element(p)) {
        return Parsed::Unknown;
    }
    match parts.as_slice() {
        ["collection", c] => Parsed::Collection(c),
        ["collection", c, i] => Parsed::Item(c, i),
        ["aliases", a] => Parsed::AliasedCollection(a),
        ["aliases", a, i] => Parsed::AliasedItem(a, i),
        ["session", s] => Parsed::Session(s),
        ["prompt", p] => Parsed::Prompt(p),
        _ => Parsed::Unknown,
    }
}

fn owned(s: String) -> OwnedObjectPath {
    OwnedObjectPath::from(ObjectPath::try_from(s).expect("generated path elements are validated"))
}

pub fn collection(name: &str) -> OwnedObjectPath {
    owned(format!("{COLLECTION_DIR}/{name}"))
}

pub fn item(collection: &str, id: &str) -> OwnedObjectPath {
    owned(format!("{COLLECTION_DIR}/{collection}/{id}"))
}

pub fn session(id: &str) -> OwnedObjectPath {
    owned(format!("{SESSION_DIR}/{id}"))
}

pub fn prompt(id: &str) -> OwnedObjectPath {
    owned(format!("{PROMPT_DIR}/{id}"))
}

pub fn none() -> OwnedObjectPath {
    owned(NONE.to_owned())
}

/// A random identifier usable as a path element (128 bits, hex).
pub fn random_id(prefix: char) -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("system randomness unavailable");
    let mut s = String::with_capacity(33);
    s.push(prefix);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_layout() {
        assert_eq!(parse("/org/freedesktop/secrets"), Parsed::Service);
        assert_eq!(parse("/org/freedesktop/secrets/collection/login"), Parsed::Collection("login"));
        assert_eq!(parse("/org/freedesktop/secrets/collection/login/i1"), Parsed::Item("login", "i1"));
        assert_eq!(parse("/org/freedesktop/secrets/aliases/default"), Parsed::AliasedCollection("default"));
        assert_eq!(parse("/org/freedesktop/secrets/aliases/default/i1"), Parsed::AliasedItem("default", "i1"));
        assert_eq!(parse("/org/freedesktop/secrets/session/s1"), Parsed::Session("s1"));
        assert_eq!(parse("/org/freedesktop/secrets/collection/a/b/c"), Parsed::Unknown);
        assert_eq!(parse("/org/freedesktop/secretsx"), Parsed::Unknown);
        assert_eq!(parse("/org/freedesktop/secrets/other/x"), Parsed::Unknown);
    }

    #[test]
    fn random_ids_are_valid_elements() {
        let a = random_id('s');
        assert!(is_valid_element(&a));
        assert_ne!(a, random_id('s'));
    }
}
