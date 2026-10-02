//! The administrative interface: management across scopes.
//!
//! Ordinary Secret Service requests are confined to the caller's scope.
//! Administration (inspecting scopes, global lock, changing the password,
//! moving items between scopes, backup, migration) goes through a separate
//! endpoint: a Unix socket whose peers are classified like bus callers and
//! accepted only if they are positively identified as `host` (see
//! [`server`]). Nothing administrative is reachable through
//! `org.freedesktop.secrets`.

use std::path::PathBuf;

pub mod peer;
pub mod protocol;
pub mod provider;
pub mod server;

/// Permission to reach every scope of the vault ([`crate::store::Vault::scoped_admin`]).
///
/// The daemon creates one only in [`server`], for a connection whose peer
/// was verified as a host process. [`AdminAuthority::offline`] is for the
/// `scopevault-admin` tool working on a vault it opened itself, which the
/// daemon never does.
pub struct AdminAuthority {
    _private: (),
}

impl AdminAuthority {
    /// After [`server`] verified a connection's peer as a host process.
    fn verified_host() -> Self {
        AdminAuthority { _private: () }
    }

    /// For a process that opened the vault itself (the daemon is not
    /// running). Never used by the daemon.
    pub fn offline() -> Self {
        AdminAuthority { _private: () }
    }
}

/// The vault directory used when none is given: `$XDG_DATA_HOME/scopevault`,
/// or `~/.local/share/scopevault`.
pub fn default_data_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".local/share"),
    };
    Some(base.join("scopevault"))
}
