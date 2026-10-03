//! Scoped Secret Service: a Secret Service provider that keeps each Flatpak
//! application's secrets in its own namespace.

/// The package version and the git commit the binaries were built from
/// (see `build.rs`), for `--version` and the daemon's startup log.
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("SCOPEVAULT_COMMIT"), ")");

pub mod admin;
pub mod crypto;
pub mod hardening;
pub mod identity;
pub mod login;
pub mod portal_backend;
pub mod prompts;
pub mod service_api;
pub mod store;

/// Prefix for this project's own D-Bus names and object paths.
pub const DBUS_PREFIX: &str = "page.codeberg.nosini.ScopeVault";
