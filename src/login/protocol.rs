//! The login socket's protocol, shared by the daemon and
//! `scopevault-pam-helper`.
//!
//! One request per connection. The client sends one byte naming the
//! request, then each password as a 16-bit big-endian length and its bytes:
//!
//! - `D` (deliver): one password, the one the user logged in or unlocked
//!   the screen with;
//! - `C` (change): two passwords, the old and the new one.
//!
//! The daemon answers with one line, an [`Outcome`](super::Outcome) word,
//! and closes. Passwords are binary-framed rather than JSON so that they
//! are never copied into buffers that are not zeroized.

use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

/// The longest password accepted.
pub const MAX_PASSWORD: usize = 1024;
const DELIVER: u8 = b'D';
const CHANGE: u8 = b'C';

pub enum Request {
    Deliver(Zeroizing<Vec<u8>>),
    Change { old: Zeroizing<Vec<u8>>, new: Zeroizing<Vec<u8>> },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Request::Deliver(_) => "Deliver(<redacted>)",
            Request::Change { .. } => "Change(<redacted>)",
        })
    }
}

impl Request {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let (op, passwords): (u8, Vec<&[u8]>) = match self {
            Request::Deliver(p) => (DELIVER, vec![p]),
            Request::Change { old, new } => (CHANGE, vec![old, new]),
        };
        let mut out = Zeroizing::new(vec![op]);
        for p in passwords {
            if p.is_empty() || p.len() > MAX_PASSWORD {
                return Err("password empty or too long");
            }
            out.extend_from_slice(&(p.len() as u16).to_be_bytes());
            out.extend_from_slice(p);
        }
        Ok(out)
    }

    /// Reads one request. Fails on an unknown request, an empty or
    /// oversized password, or a short read.
    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Request> {
        let bad = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_owned());
        let op = r.read_u8().await?;
        let count = match op {
            DELIVER => 1,
            CHANGE => 2,
            _ => return Err(bad("unknown request")),
        };
        let mut passwords = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::from(r.read_u16().await?);
            if len == 0 || len > MAX_PASSWORD {
                return Err(bad("password empty or too long"));
            }
            let mut p = Zeroizing::new(vec![0u8; len]);
            r.read_exact(&mut p).await?;
            passwords.push(p);
        }
        let mut it = passwords.into_iter();
        let first = it.next().expect("count >= 1");
        Ok(match it.next() {
            None => Request::Deliver(first),
            Some(new) => Request::Change { old: first, new },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(req: &Request) -> Request {
        let bytes = req.encode().unwrap();
        Request::read(&mut &bytes[..]).await.unwrap()
    }

    #[tokio::test]
    async fn requests_roundtrip() {
        match roundtrip(&Request::Deliver(Zeroizing::new(b"pw\n\0x".to_vec()))).await {
            Request::Deliver(p) => assert_eq!(&p[..], b"pw\n\0x"),
            other => panic!("{other:?}"),
        }
        let change = Request::Change { old: Zeroizing::new(b"a".to_vec()), new: Zeroizing::new(vec![7; MAX_PASSWORD]) };
        match roundtrip(&change).await {
            Request::Change { old, new } => {
                assert_eq!(&old[..], b"a");
                assert_eq!(new.len(), MAX_PASSWORD);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_requests_are_refused() {
        assert!(Request::Deliver(Zeroizing::new(vec![])).encode().is_err());
        assert!(Request::Deliver(Zeroizing::new(vec![1; MAX_PASSWORD + 1])).encode().is_err());
        for bytes in [&b"X\x00\x01a"[..], b"D\x00\x00", b"D\x04\x01", b"D\x00\x05abc", b"C\x00\x01a", b""] {
            assert!(Request::read(&mut &bytes[..]).await.is_err(), "{bytes:?}");
        }
    }
}
