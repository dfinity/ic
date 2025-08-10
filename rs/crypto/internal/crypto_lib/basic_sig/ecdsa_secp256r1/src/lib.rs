#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! ECDSA signatures using the secp256r1 (P-256) group

mod api;
pub mod types;
pub use api::*;

pub mod test_utils;
