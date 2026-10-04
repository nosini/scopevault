//! Secret transfer sessions (`OpenSession`).
//!
//! These protect secrets in transit over the bus. They are separate from
//! the at-rest encryption and from scope enforcement. Two algorithms from
//! the Secret Service specification are supported:
//!
//! - `plain`: secrets travel unencrypted.
//! - `dh-ietf1024-sha256-aes128-cbc-pkcs7`: Diffie-Hellman in the 1024-bit
//!   group from RFC 2409 (Oakley group 2, generator 2). The AES-128 key is
//!   HKDF-SHA256(shared secret, no salt, no info), where the shared secret is
//!   big-endian and zero-padded to the prime's length. Secrets are
//!   AES-128-CBC with PKCS#7 padding, and the 16-byte IV travels in the
//!   secret's `parameters`. This matches libsecret (`secret-session.c`,
//!   `egg-dh*.c`).
//!
//! The 1024-bit group is weak by today's standards; the algorithm is fixed
//! by the specification. Anyone able to read bus traffic between client and
//! service already runs as the user.

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U1024, Word};
use zeroize::{Zeroize, Zeroizing};

use super::dispatch::Fault;

pub const PLAIN: &str = "plain";
pub const DH_AES: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 section 6.2 (identical to libsecret's `ietf-ike-grp-modp-1024`).
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
                         EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
                         EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
const PRIME_BYTES: usize = 128;

fn prime() -> U1024 {
    U1024::from_be_hex(PRIME_HEX)
}

/// A negotiated algorithm. The AES key is zeroized on drop.
pub enum Algorithm {
    Plain,
    DhAes(Zeroizing<[u8; 16]>),
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Algorithm::Plain => "Plain",
            Algorithm::DhAes(_) => "DhAes(<key>)",
        })
    }
}

/// Big-endian without leading zeros (how libgcrypt prints USG integers).
fn minimal_be(n: &U1024) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let bytes: &[u8] = bytes.as_ref();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

/// Negotiates a session. Returns the algorithm and the `output` value for
/// the client.
pub fn negotiate(algorithm: &str, input: &zbus::zvariant::Value<'_>) -> Result<(Algorithm, Vec<u8>), Fault> {
    match algorithm {
        PLAIN => Ok((Algorithm::Plain, Vec::new())),
        DH_AES => {
            let peer: Vec<u8> = match input {
                zbus::zvariant::Value::Array(_) => input
                    .try_clone()
                    .ok()
                    .and_then(|v| Vec::<u8>::try_from(v).ok())
                    .ok_or_else(|| Fault::invalid_args("expected a byte array"))?,
                _ => return Err(Fault::invalid_args("expected a byte array")),
            };
            let (key, ours) = dh_agree(&peer)?;
            Ok((Algorithm::DhAes(key), ours))
        }
        _ => Err(Fault::new("org.freedesktop.DBus.Error.NotSupported", "Algorithm not supported")),
    }
}

/// Parses and checks a peer's public value: 1 < y < p - 1.
fn parse_public(peer: &[u8]) -> Result<U1024, Fault> {
    let trimmed: &[u8] = &peer[peer.iter().position(|&b| b != 0).unwrap_or(peer.len())..];
    if trimmed.len() > PRIME_BYTES {
        return Err(Fault::invalid_args("public key too long"));
    }
    let y = U1024::from_be_slice(&{
        let mut buf = [0u8; PRIME_BYTES];
        buf[PRIME_BYTES - trimmed.len()..].copy_from_slice(trimmed);
        buf
    });
    let p_minus_1 = prime().wrapping_sub(&U1024::ONE);
    if y <= U1024::ONE || y >= p_minus_1 {
        return Err(Fault::invalid_args("invalid public key"));
    }
    Ok(y)
}

fn params() -> FixedMontyParams<{ U1024::LIMBS }> {
    FixedMontyParams::new_vartime(Odd::new(prime()).expect("the prime is odd"))
}

/// A random private exponent below 2^1023 (< p).
fn random_exponent() -> Result<U1024, Fault> {
    let mut x_bytes = Zeroizing::new([0u8; PRIME_BYTES]);
    getrandom::fill(x_bytes.as_mut()).map_err(|_| Fault::failed("randomness unavailable"))?;
    x_bytes[0] &= 0x7f;
    Ok(U1024::from_be_slice(x_bytes.as_ref()))
}

/// The AES key both sides derive: HKDF-SHA256 of the shared value, no salt,
/// no info (libsecret's choice).
fn derive_key(y: &U1024, x: &U1024) -> Zeroizing<[u8; 16]> {
    // The shared value, in Montgomery form and as an integer: both copies
    // are wiped. Its big-endian bytes are written straight into `ikm`.
    let mut monty = FixedMontyForm::new(y, &params()).pow(x);
    let mut shared = monty.retrieve();
    monty.zeroize();
    let mut ikm = Zeroizing::new([0u8; PRIME_BYTES]);
    for (chunk, word) in ikm.as_chunks_mut::<{ size_of::<Word>() }>().0.iter_mut().zip(shared.as_words().iter().rev()) {
        *chunk = word.to_be_bytes();
    }
    shared.zeroize();
    let mut key = Zeroizing::new([0u8; 16]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, ikm.as_ref())
        .expand(&[], key.as_mut())
        .expect("16 bytes is a valid HKDF-SHA256 length");
    key
}

fn public_value(x: &U1024) -> Vec<u8> {
    minimal_be(&FixedMontyForm::new(&U1024::from_u8(2), &params()).pow(x).retrieve())
}

/// The service side: our public value and the session key.
fn dh_agree(peer: &[u8]) -> Result<(Zeroizing<[u8; 16]>, Vec<u8>), Fault> {
    let y = parse_public(peer)?;
    let mut x = random_exponent()?;
    let ours = public_value(&x);
    let key = derive_key(&y, &x);
    x.zeroize();
    Ok((key, ours))
}

/// The client side of `dh-ietf1024-sha256-aes128-cbc-pkcs7`, for talking to
/// another Secret Service provider (migration and rollback).
pub struct ClientDh {
    x: U1024,
}

impl Drop for ClientDh {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

impl ClientDh {
    /// A new exchange and the public value to send with `OpenSession`.
    pub fn start() -> Result<(Self, Vec<u8>), Fault> {
        let x = random_exponent()?;
        let public = public_value(&x);
        Ok((ClientDh { x }, public))
    }

    /// The session's algorithm, from the service's `OpenSession` output.
    pub fn finish(self, server_public: &[u8]) -> Result<Algorithm, Fault> {
        let y = parse_public(server_public)?;
        Ok(Algorithm::DhAes(derive_key(&y, &self.x)))
    }
}

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

impl Algorithm {
    /// Decodes a secret sent by the client.
    pub fn decrypt(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>, Fault> {
        match self {
            Algorithm::Plain => {
                if !parameters.is_empty() {
                    return Err(Fault::invalid_args("plain secrets take no parameters"));
                }
                Ok(Zeroizing::new(value.to_vec()))
            }
            Algorithm::DhAes(key) => {
                use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
                let iv: [u8; 16] = parameters.try_into().map_err(|_| Fault::invalid_args("bad IV"))?;
                if value.is_empty() || !value.len().is_multiple_of(16) {
                    return Err(Fault::invalid_args("bad ciphertext length"));
                }
                let dec = Aes128CbcDec::new(&(**key).into(), &iv.into());
                dec.decrypt_padded_vec::<cbc::cipher::block_padding::Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| Fault::invalid_args("bad padding"))
            }
        }
    }

    /// Encodes a secret for the client: `(parameters, value)`.
    pub fn encrypt(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Fault> {
        match self {
            Algorithm::Plain => Ok((Vec::new(), secret.to_vec())),
            Algorithm::DhAes(key) => {
                use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
                let mut iv = [0u8; 16];
                getrandom::fill(&mut iv).map_err(|_| Fault::failed("randomness unavailable"))?;
                let enc = Aes128CbcEnc::new(&(**key).into(), &iv.into());
                Ok((iv.to_vec(), enc.encrypt_padded_vec::<cbc::cipher::block_padding::Pkcs7>(secret)))
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The client side, as libsecret does it, for tests.
    #[test]
    fn both_sides_agree_and_roundtrip() {
        let (client, client_pub) = ClientDh::start().unwrap();
        let (key, server_pub) = dh_agree(&client_pub).unwrap();
        let Algorithm::DhAes(client_key) = client.finish(&server_pub).unwrap() else { panic!("not DH") };
        assert_eq!(*client_key, *key);

        let algo = Algorithm::DhAes(key);
        for secret in [&b""[..], b"x", b"exactly sixteen!", &[0xffu8; 1000][..]] {
            let (iv, ct) = algo.encrypt(secret).unwrap();
            assert_eq!(ct.len() % 16, 0);
            assert!(ct.len() > secret.len(), "PKCS#7 always pads");
            assert_eq!(&algo.decrypt(&iv, &ct).unwrap()[..], secret);
        }
    }

    #[test]
    fn rejects_degenerate_public_keys() {
        let p = prime();
        for bad in [vec![0u8], vec![1u8], minimal_be(&p.wrapping_sub(&U1024::ONE)), minimal_be(&p), vec![0xff; 129]] {
            assert!(dh_agree(&bad).is_err());
        }
        // Leading zeros are fine.
        let mut padded = vec![0u8; 3];
        padded.push(5);
        assert!(dh_agree(&padded).is_ok());
    }

    #[test]
    fn bad_ciphertexts_are_refused() {
        let algo = Algorithm::DhAes(Zeroizing::new([7u8; 16]));
        let (iv, ct) = algo.encrypt(b"secret").unwrap();
        assert!(algo.decrypt(&iv[..15], &ct).is_err());
        assert!(algo.decrypt(&iv, &ct[..15]).is_err());
        assert!(algo.decrypt(&iv, &[]).is_err());
        let wrong = Algorithm::DhAes(Zeroizing::new([8u8; 16]));
        // A wrong key almost always yields bad padding; it must never panic.
        let _ = wrong.decrypt(&iv, &ct);
        assert!(Algorithm::Plain.decrypt(b"x", b"v").is_err());
        assert_eq!(&Algorithm::Plain.decrypt(&[], b"v").unwrap()[..], b"v");
    }

    #[test]
    fn prime_matches_libsecret() {
        // First and last bytes of libsecret's dh_group_1024_prime.
        let b = prime().to_be_bytes();
        let b: &[u8] = b.as_ref();
        assert_eq!(&b[..12], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2]);
        assert_eq!(
            &b[112..],
            &[0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }
}
