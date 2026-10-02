//! The standard Secret Service API, served with per-caller views.

pub mod dispatch;
pub mod interfaces;
pub mod methods;
pub mod paths;
pub mod transfer;

pub use dispatch::SecretService;
