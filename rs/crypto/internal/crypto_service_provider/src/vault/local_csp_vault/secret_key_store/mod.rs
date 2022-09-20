//! The crypto service provider API for querying secret keys.
use crate::vault::api::{CspSecretKeyStoreContainsError, SecretKeyStoreCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::SecretKeyStore;
use ic_types::crypto::KeyId;

use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> SecretKeyStoreCspVault
    for LocalCspVault<R, S, C>
{
    fn sks_contains(&self, id: &KeyId) -> Result<bool, CspSecretKeyStoreContainsError> {
        Ok(self.sks_read_lock().contains(id))
    }
}
