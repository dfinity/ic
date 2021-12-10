//! The crypto service provider API for querying secret keys.
use crate::vault::api::SecretKeyStoreCspVault;
use crate::vault::local_csp_vault::LocalCspVault;
use crate::SecretKeyStore;
use ic_types::crypto::KeyId;

use crate::secret_key_store::{Scope, SecretKeyStoreError};
use crate::types::CspSecretKey;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> SecretKeyStoreCspVault
    for LocalCspVault<R, S, C>
{
    fn sks_contains(&self, id: &KeyId) -> bool {
        self.sks_read_lock().contains(id)
    }

    fn insert_secret_key(
        &self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError> {
        self.sks_write_lock().insert(id, key, scope)
    }

    fn get_secret_key(&self, id: &KeyId) -> Option<CspSecretKey> {
        self.sks_read_lock().get(id)
    }
}
