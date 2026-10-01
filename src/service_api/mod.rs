//! The standard Secret Service API, served with per-caller views.

pub mod dispatch;
pub mod interfaces;
pub mod model;
pub mod paths;

pub use dispatch::SecretService;
