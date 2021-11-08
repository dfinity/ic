use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

pub struct Seed {
    value: [u8; 32],
}

impl Seed {
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self { value }
    }

    pub fn from_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut value = [0u8; 32];
        rng.fill_bytes(&mut value);
        Self { value }
    }

    pub fn derive(&self, label: &str) -> Self {
        let mut sha256 = Sha256::new();
        sha256.update(self.value);
        sha256.update(label);
        let digest = sha256.finalize();
        Self {
            value: digest.into(),
        }
    }

    pub fn into_rng(self) -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed(self.value)
    }
}
