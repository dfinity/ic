use ic_crypto_sha::Sha256;

/// A wrapper around architecture-dependent SHA256 hasher providing a uniform
/// API.
pub struct Hasher(Sha256);

impl Hasher {
    /// Constructs a new hasher for the given domain.
    pub fn for_domain(domain: &str) -> Self {
        assert!(domain.len() < 256);
        let mut hasher = Self(Sha256::new());
        hasher.update(&[domain.len() as u8][..]);
        hasher.update(domain.as_bytes());
        hasher
    }

    /// Updates the internal state of this hasher by feeding bytes into it.
    #[inline]
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }

    /// Completes hash computation and returns the resulting digest.
    #[inline]
    pub fn finalize(self) -> crate::Digest {
        crate::Digest(self.0.finish())
    }
}
