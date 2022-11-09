//! The crypto service provider API for querying public keys.
use crate::vault::api::{CspPublicKeyStoreError, PublicKeyStoreCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::SecretKeyStore;

use crate::public_key_store::PublicKeyStore;
use ic_types::crypto::CurrentNodePublicKeys;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    PublicKeyStoreCspVault for LocalCspVault<R, S, C, P>
{
    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        let guard = self.public_key_store_read_lock();
        let node_signing_public_key = guard.node_signing_pubkey().cloned();
        let committee_signing_public_key = guard.committee_signing_pubkey().cloned();
        let tls_certificate = guard.tls_certificate().cloned();
        let dkg_dealing_encryption_public_key = guard.ni_dkg_dealing_encryption_pubkey().cloned();
        let last_idkg_dealing_encryption_public_key =
            guard.idkg_dealing_encryption_pubkeys().last().cloned();

        Ok(CurrentNodePublicKeys {
            node_signing_public_key,
            committee_signing_public_key,
            tls_certificate,
            dkg_dealing_encryption_public_key,
            idkg_dealing_encryption_public_key: last_idkg_dealing_encryption_public_key,
        })
    }
}
