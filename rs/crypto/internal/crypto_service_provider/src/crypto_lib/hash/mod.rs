//! Hash implementation
use ic_crypto_internal_types::context::Context;

#[cfg(test)]
mod tests;

/// SHA-256 hash function
pub struct Sha256Hasher {
    state: openssl::sha::Sha256,
}

impl Sha256Hasher {
    /// Begin a new hash computation
    pub fn new(context: &dyn Context) -> Self {
        let mut state = Sha256Hasher {
            state: openssl::sha::Sha256::new(),
        };
        state.update(context.as_bytes());
        state
    }

    /// Update the hash computation
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Finalize the digest, consuming self
    pub fn finalize(self) -> [u8; 32] {
        self.state.finish()
    }
}

impl std::hash::Hasher for Sha256Hasher {
    fn finish(&self) -> u64 {
        panic!(
            "not supported because the hash values produced by this hasher \
             contain more than just the 64 bits returned by this method"
        )
    }

    fn write(&mut self, bytes: &[u8]) {
        self.state.update(bytes)
    }
}

/// SHA-512 hash function
pub struct Sha512Hasher {
    state: openssl::sha::Sha512,
}

#[allow(unused)]
impl Sha512Hasher {
    /// Begin a new hash computation
    pub fn new(context: &dyn Context) -> Self {
        let mut state = Sha512Hasher {
            state: openssl::sha::Sha512::new(),
        };
        state.update(context.as_bytes());
        state
    }

    /// Update the hash computation
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Finalize the digest, consuming self
    pub fn finalize(self) -> [u8; 64] {
        self.state.finish()
    }
}
