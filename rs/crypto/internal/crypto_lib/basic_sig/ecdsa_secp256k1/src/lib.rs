#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Basic signatures implemented with ECDSA secp256k1.
pub mod api;
pub mod types;
pub use api::*;
