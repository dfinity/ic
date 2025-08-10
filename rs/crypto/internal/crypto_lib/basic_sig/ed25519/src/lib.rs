#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Basic signatures implemented with Ed25519
pub mod api;
pub mod types;
pub use api::*;
