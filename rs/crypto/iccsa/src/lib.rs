#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Internet Computer Canister Signature Algorithm (ICCSA)
mod api;
pub mod types;
pub use api::*;
