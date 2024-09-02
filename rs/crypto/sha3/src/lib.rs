//! SHA-3 and related hash functions.
//! Currently supported are:
//! * [`Keccak256`]: Keccak-256 hash function with constant 256-bit (32 bytes) output.
//!   Note that this is not the same as the [SHA-3 standard](https://csrc.nist.gov/pubs/fips/202/final)
//!   which uses a different padding scheme. Keccak-256 is the hash function used for example in Ethereum.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]
#![forbid(missing_docs)]
#![warn(future_incompatible)]

/// Keccak-256 hash function.
///
/// # Examples
///
/// An example of using Keccak-256 to hash data piece by piece:
/// ```
/// use std::io::Write;
/// use ic_crypto_sha3::Keccak256;
///
/// let mut hasher = Keccak256::new();
/// hasher.write("Hello ").write("world!");
/// let result = hasher.finalize();
/// assert_eq!(result[..], hex::decode("ecd0e108a98e192af1d2c25055f4e3bed784b5c877204e73219a5203251feaab")
/// .expect("valid hex string")[..]);
/// ```
///
/// An example of using Keccak-256 to hash an entire buffer in one go:
/// ```
/// use ic_crypto_sha3::Keccak256;
///
/// let result = Keccak256::hash("Hello world!");
/// assert_eq!(result[..], hex::decode("ecd0e108a98e192af1d2c25055f4e3bed784b5c877204e73219a5203251feaab")
/// .expect("valid hex string")[..]);
/// ```
#[derive(Default)]
pub struct Keccak256 {
    state: sha3::Keccak256,
}

impl Keccak256 {
    /// Byte length of the Keccak-256 output.
    pub const DIGEST_LEN: usize = 32;

    /// Creates a new Keccak256 hasher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the state using the provided `data`.
    pub fn write<T: AsRef<[u8]>>(&mut self, data: T) -> &mut Self {
        use sha3::Digest;
        self.state.update(data);
        self
    }

    /// Hashes the given `data`.
    pub fn hash<T: AsRef<[u8]>>(data: T) -> [u8; Self::DIGEST_LEN] {
        let mut hasher = Keccak256::new();
        hasher.write(data);
        hasher.finalize()
    }

    /// Finishes the hashing.
    pub fn finalize(self) -> [u8; Self::DIGEST_LEN] {
        use sha3::Digest;
        self.state.finalize().into()
    }
}

#[derive(Default, Clone)]
/// SHAKE256 hasher state.
pub struct Shake256 {
    state: sha3::Shake256,
}

impl Shake256 {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the state using the provided `data`.
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        use sha3::digest::Update;
        self.state.update(data.as_ref());
        self
    }

    /// Retrieves an XOF reader and consumes the hasher instance.
    pub fn finalize_xof(self) -> Shake256XofReader {
        use sha3::digest::ExtendableOutput;
        Shake256XofReader {
            state: self.state.finalize_xof(),
        }
    }
}

/// SHAKE256 reader state.
pub struct Shake256XofReader {
    state: sha3::Shake256Reader,
}

impl Shake256XofReader {
    /// Reads XOF output into a buffer. Can be called an unlimited number of times.
    pub fn read(&mut self, buf: &mut [u8]) {
        use sha3::digest::XofReader;
        self.state.read(buf)
    }
}
