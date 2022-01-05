//! HMAC message authentication code
//!
//! This crate supports HMAC with SHA-224, SHA-256, and SHA-512
//! # Examples
//!
//! ```
//! use ic_crypto_internal_hmac::{Hmac, Sha512};
//!
//! let key = [0x42; 32];
//! let input = "abc".as_bytes();
//!
//! let mut hmac = Hmac::<Sha512>::new(&key);
//! hmac.write(&input);
//! let mac = hmac.finish();
//! ```

pub use ic_crypto_internal_sha2::{Sha224, Sha256, Sha512};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// Represents a hash function which can be used with HMAC
pub trait HmacHashFunction {
    const BLOCK_SIZE: usize;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);

    // Ideally in the future this would return [u8; Self::OUTPUT_LENGTH]
    // but this requires unstable features.
    fn finish(self) -> Vec<u8>;
}

impl HmacHashFunction for Sha224 {
    const BLOCK_SIZE: usize = 64;

    fn new() -> Self {
        Sha224::new()
    }
    fn update(&mut self, data: &[u8]) {
        self.write(data);
    }
    fn finish(self) -> Vec<u8> {
        self.finish().to_vec()
    }
}

impl HmacHashFunction for Sha256 {
    const BLOCK_SIZE: usize = 64;

    fn new() -> Self {
        Sha256::new()
    }
    fn update(&mut self, data: &[u8]) {
        self.write(data);
    }
    fn finish(self) -> Vec<u8> {
        self.finish().to_vec()
    }
}

impl HmacHashFunction for Sha512 {
    const BLOCK_SIZE: usize = 128;

    fn new() -> Self {
        Sha512::new()
    }
    fn update(&mut self, data: &[u8]) {
        self.write(data);
    }
    fn finish(self) -> Vec<u8> {
        self.finish().to_vec()
    }
}

/// HMAC keyed message authentication code
///
/// HMAC uses a cryptographic hash function to generate an authentication code
/// from a key and a message. In addition to providing an authentication code it
/// also functions as a PRF (pseudo-random function), meaning it can also be
/// used for key derivation.
///
/// See also [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)
pub struct Hmac<H: HmacHashFunction> {
    state: H,
    okey: Vec<u8>,
}

impl<H: HmacHashFunction> Hmac<H> {
    /// Perform a one-shot HMAC computation
    ///
    /// A convenience method when the entire input is available in a
    /// single contigious buffer.
    pub fn hmac(key: &[u8], input: &[u8]) -> Vec<u8> {
        let mut hmac = Self::new(key);
        hmac.write(input);
        hmac.finish()
    }

    fn derive(key: &[u8]) -> Self {
        let mut ikey = vec![IPAD; H::BLOCK_SIZE];
        let mut okey = vec![OPAD; H::BLOCK_SIZE];

        // For short keys ikey/okey are left unmodified which is how
        // "zero padding" is handled
        for i in 0..key.len() {
            ikey[i] ^= key[i];
            okey[i] ^= key[i];
        }

        let mut state = H::new();

        state.update(&ikey);

        Self { state, okey }
    }

    /// Create a new HMAC struct
    ///
    /// This allows incremental updating using the write method
    pub fn new(key: &[u8]) -> Self {
        if key.len() > H::BLOCK_SIZE {
            let mut key_hash = H::new();
            key_hash.update(key);
            Self::derive(&key_hash.finish())
        } else {
            Self::derive(key)
        }
    }

    /// Update the HMAC input
    pub fn write(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Complete an HMAC computation, returning the result
    ///
    /// We would rather this return a fixed length array, something
    /// like [u8; H::OUTPUT_LENGTH] but this requires features of Rust
    /// which are currently unavailable in stable.
    pub fn finish(self) -> Vec<u8> {
        let inner_digest = self.state.finish();
        let mut outer_hash = H::new();
        outer_hash.update(&self.okey);
        outer_hash.update(&inner_digest);
        outer_hash.finish()
    }
}
