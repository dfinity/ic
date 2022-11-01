//! The crypto service provider API for querying public keys.
use crate::vault::api::{CspPublicKeyStoreError, PublicKeyStoreCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::SecretKeyStore;

use ic_types::crypto::CurrentNodePublicKeys;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore> PublicKeyStoreCspVault
    for LocalCspVault<R, S, C>
{
    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        Err(CspPublicKeyStoreError::TransientInternalError(
            "TODO: As part of CRP-1719, implement the functionality for returning the current node public keys".to_string()))
    }
}
