#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Internet Computer Canister Signature Algorithm (ICCSA)
pub mod api;
pub mod types;
pub use api::*;
