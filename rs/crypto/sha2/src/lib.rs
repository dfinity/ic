//! Hashing utilities.
//!
//! Currently this crate delegates the hashing to the RustCrypto sha2
//! crate. That crate supports both a pure Rust implementation
//! (necessary for Wasm) and additionally supports SHA-NI and ARMv8
//! SHA hardware extensions which provide excellent performance on
//! cores which support them (this includes all replica nodes).
//!
//! Hashers with fixed algorithms that are guaranteed not to change in the
//! future or across registry versions.
//!
//! The algorithm used by `ic_crypto_sha2::Sha256` is SHA256 and
//! has constant output size of 32 bytes.
//!
//! The algorithm used by `ic_crypto_sha2::Sha224` is SHA224 and
//! has constant output size of 28 bytes.
//!
//! These hashers can be used, e.g., for creating fingerprints of files that are
//! persisted on disk.
//!
//! # Example for `Sha256` (using state explicitly to hash data piece by piece)
//!
//! ```
//! use ic_crypto_sha2::Sha256;
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
//! use ic_crypto_sha2::Sha256;
//!
//! let digest: [u8; 32] = Sha256::hash(b"some data!");
//! ```
//!
//! # Example for `Sha256` (using as an `std::io::Writer`)
//!
//! ```
//! use ic_crypto_sha2::Sha256;
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
//! use ic_crypto_sha2::Sha224;
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
//! use ic_crypto_sha2::Sha224;
//!
//! let digest: [u8; 28] = Sha224::hash(b"some data!");
//! ```
//!
//! # Example for `Sha224` (using as an `std::io::Writer`)
//!
//! ```
//! use ic_crypto_sha2::Sha224;
//!
//! let mut reader: &[u8] = b"some data";
//! let mut hasher = Sha224::new();
//!
//! std::io::copy(&mut reader, &mut hasher).unwrap();
//! ```

#![forbid(unsafe_code)]
pub use ic_crypto_internal_sha2::{DomainSeparationContext, Sha224, Sha256, Sha512};
