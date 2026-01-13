//! Hashing utilities based on SHA-2 standard.
//!
//! Currently this crate delegates the hashing to the RustCrypto sha2
//! crate. That crate supports both a pure Rust implementation
//! (necessary for Wasm) and additionally supports SHA-NI and ARMv8
//! SHA hardware extensions which provide excellent performance on
//! cores which support them (this includes all replica nodes).
//!
//! Clients should not use this crate directly, but rather the crate
//! ic_crypto_sha256, which is a thin layer on top of this internal crate.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

mod context;
pub use context::DomainSeparationContext;

mod sha256;
pub use sha256::Sha256;

mod sha224;
pub use sha224::Sha224;

mod sha512;
pub use sha512::Sha512;
