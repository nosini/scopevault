//! Vault key management and record encryption.
//!
//! - The vault key is 32 random bytes, generated once per vault.
//! - A wrapping key is derived from the master password with Argon2id
//!   (fresh 32-byte salt, recorded parameters) and wraps the vault key with
//!   XChaCha20-Poly1305. Changing the password rewraps the same vault key.
//! - Records are sealed with XChaCha20-Poly1305 under a key derived from the
//!   vault key with HKDF-SHA256. Nonces are 192-bit random values, which
//!   XChaCha20 makes safe to choose at random. The associated data binds the
//!   format version, record kind, namespace ID and record ID, so a
//!   ciphertext cannot be moved to another record, kind or namespace.
//!
//! Primitives come from the RustCrypto crates; nothing here implements one.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Format version bound into every key wrap and record.
pub const FORMAT_VERSION: u16 = 1;
/// Largest plaintext we seal or accept to open (secrets plus metadata).
pub const MAX_PLAINTEXT: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Wrong password, or the vault header was altered. Indistinguishable
    /// by design.
    #[error("wrong password or damaged vault header")]
    Unwrap,
    /// A record failed authentication (tampered, truncated or misplaced).
    #[error("record failed authentication")]
    Record,
    #[error("key derivation parameters out of bounds")]
    Params,
    #[error("data too large")]
    TooLarge,
    #[error("system randomness unavailable")]
    Random,
}

/// Argon2id cost parameters, stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    // Bounds for any parameters we will run, including ones read from a
    // (possibly tampered or imported) vault: low enough not to exhaust the
    // machine, high enough not to be trivially weak.
    pub const MIN_M_KIB: u32 = 19 * 1024;
    pub const MAX_M_KIB: u32 = 2 * 1024 * 1024;
    pub const MAX_T: u32 = 20;
    pub const MAX_P: u32 = 16;

    /// The cheapest parameters accepted. Weak; meant for tests.
    pub const MINIMUM: KdfParams = KdfParams { m_kib: Self::MIN_M_KIB, t: 1, p: 1 };

    /// Default for new vaults: 256 MiB, 3 passes, 1 lane.
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 256 * 1024, t: 3, p: 1 };

    pub fn check(&self) -> Result<(), CryptoError> {
        let ok = (Self::MIN_M_KIB..=Self::MAX_M_KIB).contains(&self.m_kib)
            && (1..=Self::MAX_T).contains(&self.t)
            && (1..=Self::MAX_P).contains(&self.p);
        if ok { Ok(()) } else { Err(CryptoError::Params) }
    }

    /// Picks the pass count for the default memory cost so one derivation
    /// takes at least `target` (bounded by `MAX_T`).
    pub fn calibrate(target: std::time::Duration) -> Result<KdfParams, CryptoError> {
        let mut params = KdfParams { t: 1, ..KdfParams::DEFAULT };
        let salt = random_array::<SALT_LEN>()?;
        let start = std::time::Instant::now();
        derive_wrapping_key(b"calibration", &salt, params)?;
        let one = start.elapsed().max(std::time::Duration::from_millis(1));
        let needed = target.as_nanos().div_ceil(one.as_nanos());
        params.t = (needed as u32).clamp(KdfParams::DEFAULT.t, Self::MAX_T);
        Ok(params)
    }
}

pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| CryptoError::Random)?;
    Ok(b)
}

fn derive_wrapping_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    p: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    p.check()?;
    let params = Params::new(p.m_kib, p.t, p.p, Some(KEY_LEN)).map_err(|_| CryptoError::Params)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| CryptoError::Params)?;
    Ok(out)
}

/// What the vault stores to recover the vault key from the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrap {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted vault key plus tag.
    pub wrapped: Vec<u8>,
}

fn wrap_aad(kdf: KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut aad = b"scopevault/vault-key\0".to_vec();
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    for v in [kdf.m_kib, kdf.t, kdf.p] {
        aad.extend_from_slice(&v.to_be_bytes());
    }
    aad.extend_from_slice(salt);
    aad
}

/// The vault key. Zeroized on drop; never printed.
pub struct VaultKey(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

impl VaultKey {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(VaultKey(Zeroizing::new(random_array()?)))
    }

    /// Wraps this key under `password` with a fresh salt.
    pub fn wrap(&self, password: &[u8], kdf: KdfParams) -> Result<KeyWrap, CryptoError> {
        let salt = random_array::<SALT_LEN>()?;
        let nonce = random_array::<NONCE_LEN>()?;
        let kek = derive_wrapping_key(password, &salt, kdf)?;
        let cipher = XChaCha20Poly1305::new((&*kek).into());
        let mut buf = self.0.to_vec();
        cipher
            .encrypt_in_place(&XNonce::from(nonce), &wrap_aad(kdf, &salt), &mut buf)
            .map_err(|_| CryptoError::Unwrap)?;
        Ok(KeyWrap { kdf, salt, nonce, wrapped: buf })
    }

    pub fn unwrap(wrap: &KeyWrap, password: &[u8]) -> Result<Self, CryptoError> {
        if wrap.wrapped.len() != KEY_LEN + TAG_LEN {
            return Err(CryptoError::Unwrap);
        }
        let kek = derive_wrapping_key(password, &wrap.salt, wrap.kdf)?;
        let cipher = XChaCha20Poly1305::new((&*kek).into());
        let mut buf = Zeroizing::new(wrap.wrapped.clone());
        cipher
            .decrypt_in_place(&XNonce::from(wrap.nonce), &wrap_aad(wrap.kdf, &wrap.salt), &mut *buf)
            .map_err(|_| CryptoError::Unwrap)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&buf);
        Ok(VaultKey(key))
    }

    pub fn record_cipher(&self) -> RecordCipher {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        Hkdf::<Sha256>::new(Some(b"scopevault"), self.0.as_ref())
            .expand(b"record encryption v1", k.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        RecordCipher(XChaCha20Poly1305::new((&*k).into()))
    }
}

/// Identifies what a record is, bound into its associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordAad {
    pub kind: u8,
    pub namespace: [u8; 16],
    pub id: [u8; 16],
}

impl RecordAad {
    fn bytes(&self) -> Vec<u8> {
        let mut aad = b"scopevault/record\0".to_vec();
        aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        aad.push(self.kind);
        aad.extend_from_slice(&self.namespace);
        aad.extend_from_slice(&self.id);
        aad
    }
}

#[derive(Debug)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypts and authenticates records. Its key is zeroized on drop.
pub struct RecordCipher(XChaCha20Poly1305);

impl std::fmt::Debug for RecordCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordCipher(<redacted>)")
    }
}

impl RecordCipher {
    pub fn seal(&self, aad: &RecordAad, plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(CryptoError::TooLarge);
        }
        let nonce = random_array::<NONCE_LEN>()?;
        let mut buf = plaintext.to_vec();
        let result = self.0.encrypt_in_place(&XNonce::from(nonce), &aad.bytes(), &mut buf);
        if result.is_err() {
            buf.zeroize();
            return Err(CryptoError::Record);
        }
        Ok(Sealed { nonce, ciphertext: buf })
    }

    pub fn open(&self, aad: &RecordAad, nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::Record)?;
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::Record);
        }
        if ciphertext.len() > MAX_PLAINTEXT + TAG_LEN {
            return Err(CryptoError::TooLarge);
        }
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        self.0.decrypt_in_place(&nonce, &aad.bytes(), &mut *buf).map_err(|_| CryptoError::Record)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams::MINIMUM;

    #[test]
    fn wrap_roundtrip_and_wrong_password() {
        let key = VaultKey::generate().unwrap();
        let w = key.wrap(b"correct horse", FAST).unwrap();
        let back = VaultKey::unwrap(&w, b"correct horse").unwrap();
        assert_eq!(*back.0, *key.0);
        assert_eq!(VaultKey::unwrap(&w, b"wrong").unwrap_err(), CryptoError::Unwrap);
    }

    #[test]
    fn rewrap_keeps_key_and_uses_fresh_salt() {
        let key = VaultKey::generate().unwrap();
        let a = key.wrap(b"one", FAST).unwrap();
        let b = key.wrap(b"two", FAST).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_eq!(*VaultKey::unwrap(&b, b"two").unwrap().0, *key.0);
    }

    #[test]
    fn tampered_header_fails() {
        let key = VaultKey::generate().unwrap();
        let w = key.wrap(b"pw", FAST).unwrap();
        let mut bad = w.clone();
        bad.kdf.t = 2;
        assert_eq!(VaultKey::unwrap(&bad, b"pw").unwrap_err(), CryptoError::Unwrap);
        let mut bad = w.clone();
        bad.salt[0] ^= 1;
        assert_eq!(VaultKey::unwrap(&bad, b"pw").unwrap_err(), CryptoError::Unwrap);
        let mut bad = w.clone();
        bad.wrapped.pop();
        assert_eq!(VaultKey::unwrap(&bad, b"pw").unwrap_err(), CryptoError::Unwrap);
    }

    #[test]
    fn out_of_bounds_params_are_refused_before_running() {
        let key = VaultKey::generate().unwrap();
        let mut w = key.wrap(b"pw", FAST).unwrap();
        for kdf in [
            KdfParams { m_kib: u32::MAX, ..FAST },
            KdfParams { m_kib: 8, ..FAST },
            KdfParams { t: 0, ..FAST },
            KdfParams { t: 1000, ..FAST },
            KdfParams { p: 255, ..FAST },
        ] {
            w.kdf = kdf;
            assert_eq!(VaultKey::unwrap(&w, b"pw").unwrap_err(), CryptoError::Params);
        }
    }

    #[test]
    fn records_are_bound_to_their_identity() {
        let c = VaultKey::generate().unwrap().record_cipher();
        let aad = RecordAad { kind: 2, namespace: [1; 16], id: [2; 16] };
        let s = c.seal(&aad, b"label").unwrap();
        assert_eq!(&**c.open(&aad, &s.nonce, &s.ciphertext).unwrap(), b"label");

        for other in
            [RecordAad { kind: 3, ..aad }, RecordAad { namespace: [9; 16], ..aad }, RecordAad { id: [9; 16], ..aad }]
        {
            assert_eq!(c.open(&other, &s.nonce, &s.ciphertext).unwrap_err(), CryptoError::Record);
        }
        let mut flipped = s.ciphertext.clone();
        flipped[0] ^= 1;
        assert!(c.open(&aad, &s.nonce, &flipped).is_err());
        assert!(c.open(&aad, &s.nonce, &s.ciphertext[..s.ciphertext.len() - 1]).is_err());
        assert!(c.open(&aad, &s.nonce[..23], &s.ciphertext).is_err());
        let other_key = VaultKey::generate().unwrap().record_cipher();
        assert!(other_key.open(&aad, &s.nonce, &s.ciphertext).is_err());
    }

    #[test]
    fn nonces_differ() {
        let c = VaultKey::generate().unwrap().record_cipher();
        let aad = RecordAad { kind: 1, namespace: [0; 16], id: [0; 16] };
        let a = c.seal(&aad, b"x").unwrap();
        let b = c.seal(&aad, b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn oversized_plaintext_is_refused() {
        let c = VaultKey::generate().unwrap().record_cipher();
        let aad = RecordAad { kind: 1, namespace: [0; 16], id: [0; 16] };
        assert_eq!(c.seal(&aad, &vec![0; MAX_PLAINTEXT + 1]).unwrap_err(), CryptoError::TooLarge);
    }
}
