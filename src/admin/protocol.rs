//! The administrative socket's protocol.
//!
//! One request per connection: the client sends one JSON line, the daemon
//! answers with one JSON line and closes. A backup reply is followed by the
//! announced number of raw bytes. Passwords never travel over the socket:
//! the daemon asks for them in its own dialog.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::store::{CollectionListing, GrantListing, ScopeSummary};

/// Requests are small; this bounds what the daemon reads from a client.
pub const MAX_LINE: usize = 64 * 1024;
/// Largest reply line the client accepts (listings can be long).
pub const MAX_REPLY_LINE: usize = 64 * 1024 * 1024;
/// The error message of a request whose password dialog was cancelled.
pub const CANCELLED: &str = "cancelled in the password dialog";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Status,
    /// Global lock: drops the vault key and all decrypted data.
    Lock,
    /// Opens the unlock dialog if the vault is locked (for example right
    /// after login, before applications ask for their secrets).
    Unlock,
    /// The daemon asks for the old and the new password.
    ChangePassword,
    Scopes,
    List {
        scope: String,
    },
    /// Items as `COLLECTION/ITEM`. Needs the master password.
    Move {
        from: String,
        to: String,
        items: Vec<String>,
    },
    /// Deletes everything a scope holds. Needs the master password.
    ResetScope {
        scope: String,
    },
    /// Creates the Secret portal's key scope if it does not exist yet.
    PortalInit,
    /// Creates a portal key for an application that has none, for example
    /// after its keyring file appeared without an import.
    PortalNewKey {
        app_id: String,
    },
    /// Gives one scope access to one item of another scope. Needs the
    /// master password.
    Share {
        from: String,
        /// The item, as `COLLECTION/ITEM` in the owner's scope.
        item: String,
        to: String,
        write: bool,
    },
    /// Revokes one grant, by its ID as shown by `grants`.
    Unshare {
        grant: String,
    },
    /// All grants, or those where the scope is the owner or the grantee.
    Grants {
        scope: Option<String>,
    },
    /// A copy of the encrypted database, which opens with the password
    /// current when it was made.
    Backup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultState {
    /// No vault yet; the first use creates one.
    Missing,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub vault: VaultState,
    pub data_dir: String,
    pub connections: usize,
    pub sessions: usize,
    pub prompts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Reply {
    Status(Status),
    Done {
        message: String,
    },
    Scopes {
        scopes: Vec<ScopeSummary>,
    },
    Listing {
        collections: Vec<CollectionListing>,
    },
    Moved {
        items: Vec<String>,
    },
    Reset {
        collections: usize,
        items: usize,
    },
    Grants {
        grants: Vec<GrantListing>,
    },
    /// A grant was created or changed; carries its ID.
    Shared {
        grant: String,
    },
    /// Followed by `bytes` raw bytes.
    Backup {
        bytes: u64,
    },
    Error {
        message: String,
    },
}

impl Reply {
    pub fn error(message: impl Into<String>) -> Self {
        Reply::Error { message: message.into() }
    }
}

/// Reads one line of at most `max` bytes (without the newline).
pub async fn read_line<R: AsyncRead + Unpin>(r: &mut BufReader<R>, max: usize) -> std::io::Result<String> {
    let mut buf = Vec::new();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if buf.len() + take > max + 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
        }
        buf.extend_from_slice(&chunk[..take]);
        r.consume(take);
        if done {
            buf.pop();
            return String::from_utf8(buf).map_err(|_| std::io::ErrorKind::InvalidData.into());
        }
    }
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, value: &T) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}
