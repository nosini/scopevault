//! Object paths from clients, as the dispatcher parses them. Never panics,
//! and every accepted collection or item path is canonical: rebuilding it
//! from its parts gives the same string.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scopevault::service_api::paths::{self, Parsed};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    match paths::parse(s) {
        Parsed::Collection(c) => assert_eq!(paths::collection(c).as_str(), s),
        Parsed::Item(c, i) => assert_eq!(paths::item(c, i).as_str(), s),
        Parsed::Session(id) => assert_eq!(paths::session(id).as_str(), s),
        Parsed::Prompt(id) => assert_eq!(paths::prompt(id).as_str(), s),
        Parsed::AliasedCollection(a) | Parsed::AliasedItem(a, _) => assert!(paths::is_valid_element(a)),
        _ => {}
    }
});
