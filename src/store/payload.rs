//! Plaintext encodings of the records sealed into the database.
//!
//! Metadata records are JSON. Secret records are a small binary format so
//! secret bytes are never turned into text. Every decoded value is
//! validated; a record that decrypts but does not decode is corrupt.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::StoreError;

pub const KIND_NAMESPACE: u8 = 1;
pub const KIND_COLLECTION: u8 = 2;
pub const KIND_ITEM: u8 = 3;
pub const KIND_SECRET: u8 = 4;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespacePayload {
    /// `host` or `flatpak/<app-id>`.
    pub scope: String,
    /// Alias name to collection record ID (hex).
    pub aliases: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionPayload {
    /// Path element, unique within the namespace.
    pub name: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemPayload {
    /// Collection record ID (hex).
    pub collection: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub created: u64,
    pub modified: u64,
}

pub fn encode<T: Serialize>(value: &T) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(value).expect("payload types always serialize"))
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8], what: &str) -> Result<T, StoreError> {
    serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt(format!("undecodable {what} record")))
}

/// A secret value with its content type. Debug output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    pub value: Zeroizing<Vec<u8>>,
    pub content_type: String,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes, {:?})", self.value.len(), self.content_type)
    }
}

impl Secret {
    pub fn new(value: impl Into<Vec<u8>>, content_type: impl Into<String>) -> Self {
        Secret { value: Zeroizing::new(value.into()), content_type: content_type.into() }
    }
}

const SECRET_FORMAT: u8 = 1;

/// `[format][content-type length: u16 BE][content type][value]`
pub fn encode_secret(s: &Secret) -> Zeroizing<Vec<u8>> {
    let ct = s.content_type.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(3 + ct.len() + s.value.len()));
    out.push(SECRET_FORMAT);
    out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    out.extend_from_slice(ct);
    out.extend_from_slice(&s.value);
    out
}

pub fn decode_secret(bytes: &[u8]) -> Result<Secret, StoreError> {
    let bad = || StoreError::Corrupt("undecodable secret record".into());
    let (&format, rest) = bytes.split_first().ok_or_else(bad)?;
    if format != SECRET_FORMAT || rest.len() < 2 {
        return Err(bad());
    }
    let ct_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let rest = &rest[2..];
    if rest.len() < ct_len {
        return Err(bad());
    }
    let content_type = std::str::from_utf8(&rest[..ct_len]).map_err(|_| bad())?.to_owned();
    Ok(Secret { value: Zeroizing::new(rest[ct_len..].to_vec()), content_type })
}

pub fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrip_and_rejects_garbage() {
        let s = Secret::new(vec![0u8, 255, 10], "application/octet-stream");
        assert_eq!(decode_secret(&encode_secret(&s)).unwrap(), s);
        let empty = Secret::new(Vec::new(), "");
        assert_eq!(decode_secret(&encode_secret(&empty)).unwrap(), empty);
        for bad in [&[][..], &[2, 0, 0], &[1, 0], &[1, 0, 5, b'a'], &[1, 0, 1, 0xff]] {
            assert!(decode_secret(bad).is_err());
        }
        assert!(!format!("{s:?}").contains("255"));
    }

    #[test]
    fn hex_roundtrip() {
        let id = [0xab; 16];
        assert_eq!(unhex(&hex(&id)), Some(id));
        assert_eq!(unhex("AB"), None);
        assert_eq!(unhex(&"AB".repeat(16)), None);
    }

    #[test]
    fn unknown_fields_are_corrupt() {
        assert!(
            decode::<CollectionPayload>(br#"{"name":"a","label":"","created":0,"modified":0,"x":1}"#, "c").is_err()
        );
    }
}
