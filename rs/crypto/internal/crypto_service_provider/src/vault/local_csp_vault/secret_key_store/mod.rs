//! The crypto service provider API for querying secret keys.
use crate::SecretKeyStore;
use crate::key_id::KeyId;
use crate::vault::api::{CspSecretKeyStoreContainsError, SecretKeyStoreCspVault};
use crate::vault::local_csp_vault::LocalCspVault;

use crate::public_key_store::PublicKeyStore;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    SecretKeyStoreCspVault for LocalCspVault<R, S, C, P>
{
    fn sks_contains(&self, id: KeyId) -> Result<bool, CspSecretKeyStoreContainsError> {
        Ok(self.sks_read_lock().contains(&id))
    }
}
