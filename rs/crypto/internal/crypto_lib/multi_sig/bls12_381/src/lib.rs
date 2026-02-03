#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Multisignatures using BLS12-381.
mod api;
mod crypto;
pub mod types;
pub use api::*;

#[cfg(test)]
mod tests;
