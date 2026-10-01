//! Scoped Secret Service: a Secret Service provider that keeps each Flatpak
//! application's secrets in its own namespace.

pub mod identity;
pub mod service_api;

/// Prefix for this project's own D-Bus names and object paths.
pub const DBUS_PREFIX: &str = "page.codeberg.nosini.ScopeVault";
