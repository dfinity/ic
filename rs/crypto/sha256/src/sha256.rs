//! The ic-crypto-sha256 package works both on Wasm and non-Wasm
//! architectures by using different SHA256 hasher implementations depending on
//! the architecture:
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

#[cfg(not(target_arch = "wasm32"))]
mod openssl_sha256;
#[cfg(target_arch = "wasm32")]
mod rust_sha256;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use openssl_sha256::{hash, InternalSha256};
#[cfg(target_arch = "wasm32")]
pub(crate) use rust_sha256::{hash, InternalSha256};

/// Hasher with fixed algorithm that is guaranteed not to change in the future
/// or across registry versions. The algorithm used to generate the hash is
/// SHA256 and therefore has constant output size of 32 bytes.
///
/// This hasher can be used, e.g., for creating fingerprints of files that are
/// persisted on disk.
///
/// # Example (using state explicitly to hash data piece by piece)
///
/// ```
/// use ic_crypto_sha256::Sha256;
///
/// let mut state = Sha256::new();
/// state.write(b"some ");
/// state.write(b"data!");
/// let digest: [u8; 32] = state.finish();
/// ```
///
/// # Example (using state implicitly with the convenience function)
///
/// ```
/// use ic_crypto_sha256::Sha256;
///
/// let digest: [u8; 32] = Sha256::hash(b"some data!");
/// ```
///
/// # Example (using as an `std::io::Writer`)
///
/// ```
/// use ic_crypto_sha256::Sha256;
///
/// let mut reader: &[u8] = b"some data";
/// let mut hasher = Sha256::new();
///
/// std::io::copy(&mut reader, &mut hasher).unwrap();
/// ```
#[derive(Default)]
pub struct Sha256 {
    sha256: InternalSha256,
}

impl Sha256 {
    /// Return a new Sha256 object
    pub fn new() -> Self {
        Self::default()
    }

    /// Hashes some data and returns the digest
    pub fn hash(data: &[u8]) -> [u8; 32] {
        hash(data)
    }

    /// Incrementally update the current hash
    pub fn write(&mut self, data: &[u8]) {
        self.sha256.write(data);
    }

    /// Finishes computing a hash, returning the digest
    pub fn finish(self) -> [u8; 32] {
        self.sha256.finish()
    }
}

impl std::io::Write for Sha256 {
    /// Update an incremental hash
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write(buf);
        Ok(buf.len())
    }

    /// This is a no-op
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::hash::Hasher for Sha256 {
    /// This function will panic; use finish() -> [u8; 32] instead
    fn finish(&self) -> u64 {
        panic!(
            "not supported because the hash values produced by this hasher \
             contain more than just the 64 bits returned by this method"
        )
    }

    /// Update an incremental hash
    fn write(&mut self, bytes: &[u8]) {
        self.write(bytes)
    }
}
