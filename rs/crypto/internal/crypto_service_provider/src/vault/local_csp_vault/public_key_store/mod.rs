//! The crypto service provider API for querying public keys.
use crate::SecretKeyStore;
use crate::vault::api::{CspPublicKeyStoreError, PublicKeyStoreCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use parking_lot::RwLockReadGuard;

use crate::public_key_store::PublicKeyStore;
use ic_types::Time;
use ic_types::crypto::CurrentNodePublicKeys;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    PublicKeyStoreCspVault for LocalCspVault<R, S, C, P>
{
    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        let guard = self.public_key_store_read_lock();
        Ok(current_node_public_keys_internal(&guard))
    }

    fn current_node_public_keys_with_timestamps(
        &self,
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        let (mut keys, timestamps) = {
            let guard = self.public_key_store_read_lock();
            (
                current_node_public_keys_internal(&guard),
                guard.generation_timestamps(),
            )
        };
        if let Some(node_signing_public_key) = &mut keys.node_signing_public_key {
            node_signing_public_key.timestamp = timestamps
                .node_signing_public_key
                .map(Time::as_millis_since_unix_epoch);
        }
        if let Some(committee_signing_public_key) = &mut keys.committee_signing_public_key {
            committee_signing_public_key.timestamp = timestamps
                .committee_signing_public_key
                .map(Time::as_millis_since_unix_epoch);
        }
        if let Some(dkg_public_key) = &mut keys.dkg_dealing_encryption_public_key {
            dkg_public_key.timestamp = timestamps
                .dkg_dealing_encryption_public_key
                .map(Time::as_millis_since_unix_epoch);
        }
        if let Some(idkg_public_key) = &mut keys.idkg_dealing_encryption_public_key {
            idkg_public_key.timestamp = timestamps
                .last_idkg_dealing_encryption_public_key
                .map(Time::as_millis_since_unix_epoch);
        }

        Ok(keys)
    }

    fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError> {
        Ok(self
            .public_key_store_read_lock()
            .idkg_dealing_encryption_pubkeys()
            .len())
    }
}

fn current_node_public_keys_internal<P: PublicKeyStore>(
    pks_lock: &RwLockReadGuard<'_, P>,
) -> CurrentNodePublicKeys {
    let last_idkg_dealing_encryption_public_key =
        pks_lock.idkg_dealing_encryption_pubkeys().last().cloned();
    CurrentNodePublicKeys {
        node_signing_public_key: pks_lock.node_signing_pubkey(),
        committee_signing_public_key: pks_lock.committee_signing_pubkey(),
        tls_certificate: pks_lock.tls_certificate(),
        dkg_dealing_encryption_public_key: pks_lock.ni_dkg_dealing_encryption_pubkey(),
        idkg_dealing_encryption_public_key: last_idkg_dealing_encryption_public_key,
    }
}
