//! Hashing utilities.
//!
//! The package works both on Wasm and non-Wasm architectures by using
//! different hasher implementations depending on the architecture:
//!
//! * When compiling to Wasm, we use pure Rust implementation.
//!
//! * When compiling to native, we use openssl, which relies on OpenSSL.
//!
//! At the moment, the complexity introduced by architecture-dependent
//! code is worth it:
//!
//! * OpenSSL is big, complicated and is hard to port to Wasm. So it's not
//!   really a viable option to use it in canisters.
//!
//! * pure Rust is about 20% slower than OpenSSL on StateManager benchmarks.
//!   Thus it makes sense to use a faster implementation in the replica code.
//!
//! Hashers with fixed algorithms that are guaranteed not to change in the
//! future or across registry versions.
//!
//! The algorithm used by `ic_crypto_sha::Sha256` is SHA256 and
//! has constant output size of 32 bytes.
//!
//! The algorithm used by `ic_crypto_sha::Sha224` is SHA224 and
//! has constant output size of 28 bytes.
//!
//! These hashers can be used, e.g., for creating fingerprints of files that are
//! persisted on disk.
//!
//! # Example for `Sha256` (using state explicitly to hash data piece by piece)
//!
//! ```
//! use ic_crypto_sha::Sha256;
//!
//! let mut state = Sha256::new();
//! state.write(b"some ");
//! state.write(b"data!");
//! let digest: [u8; 32] = state.finish();
//! ```
//!
//! # Example for `Sha256` (using state implicitly with the convenience
//! function)
//!
//! ```
//! use ic_crypto_sha::Sha256;
//!
//! let digest: [u8; 32] = Sha256::hash(b"some data!");
//! ```
//!
//! # Example for `Sha256` (using as an `std::io::Writer`)
//!
//! ```
//! use ic_crypto_sha::Sha256;
//!
//! let mut reader: &[u8] = b"some data";
//! let mut hasher = Sha256::new();
//!
//! std::io::copy(&mut reader, &mut hasher).unwrap();
//! ```
//!
//! # Example for `Sha224` (using state explicitly to hash data piece by piece)
//!
//! ```
//! use ic_crypto_sha::Sha224;
//!
//! let mut state = Sha224::new();
//! state.write(b"some ");
//! state.write(b"data!");
//! let digest: [u8; 28] = state.finish();
//! ```
//!
//! # Example for `Sha224` (using state implicitly with the convenience
//! function)
//!
//! ```
//! use ic_crypto_sha::Sha224;
//!
//! let digest: [u8; 28] = Sha224::hash(b"some data!");
//! ```
//!
//! # Example for `Sha224` (using as an `std::io::Writer`)
//!
//! ```
//! use ic_crypto_sha::Sha224;
//!
//! let mut reader: &[u8] = b"some data";
//! let mut hasher = Sha224::new();
//!
//! std::io::copy(&mut reader, &mut hasher).unwrap();
//! ```

#![forbid(unsafe_code)]
pub use ic_crypto_internal_sha2::{Context, DomainSeparationContext, Sha224, Sha256, Sha512};
