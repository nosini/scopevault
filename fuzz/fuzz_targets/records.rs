//! Decrypted record payloads (only reachable with the vault key, so this is
//! robustness against corruption rather than an attack surface). Never
//! panics; secret records that decode re-encode to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scopevault::store::payload::{
    CollectionPayload, GrantPayload, ItemPayload, NamespacePayload, decode, decode_secret, encode_secret, unhex,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(secret) = decode_secret(data) {
        assert_eq!(&*encode_secret(&secret), data);
    }
    let _ = decode::<NamespacePayload>(data, "namespace");
    let _ = decode::<CollectionPayload>(data, "collection");
    let _ = decode::<ItemPayload>(data, "item");
    let _ = decode::<GrantPayload>(data, "grant");
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = unhex(s);
    }
});
