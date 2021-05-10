#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Multisignatures using BLS12-381.
mod api;
mod crypto;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;
pub mod types;
pub use api::*;
