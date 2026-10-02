//! Scoped Secret Service: a Secret Service provider that keeps each Flatpak
//! application's secrets in its own namespace.

pub mod admin;
pub mod crypto;
pub mod hardening;
pub mod identity;
pub mod portal_backend;
pub mod prompts;
pub mod service_api;
pub mod store;

/// Prefix for this project's own D-Bus names and object paths.
pub const DBUS_PREFIX: &str = "page.codeberg.nosini.ScopeVault";
