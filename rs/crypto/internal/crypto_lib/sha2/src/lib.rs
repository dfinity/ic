//! Hashing utilities based on SHA-2 standard.
//!
//! The package works both on Wasm and non-Wasm architectures by using
//! different SHA2-hasher implementations depending on the architecture:
//!
//! * When compiling to Wasm, we use pure Rust implementation (provided by sha2
//!   package).
//!
//! * When compiling to native, we use openssl, which relies on OpenSSL.
//!
//! At the moment, the complexity introduced by architecture-dependent
//! code is worth it:
//!
//! * OpenSSL is big, complicated and is hard to port to Wasm. So it's not
//!   really a viable option to use it in canisters.
//!
//! * sha2 is pure Rust, but it's ~20% slower than OpenSSL on StateManager
//!   benchmarks. Thus it makes sense to use a faster implementation in the
//!   replica code.
//!
//! Clients should not use this crate directly, but rather the crate
//! ic_crypto_sha256, which is a thin layer on top of this internal crate.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

mod context;
pub use context::{Context, DomainSeparationContext};

mod sha256;
pub use sha256::Sha256;

mod sha224;
pub use sha224::Sha224;
