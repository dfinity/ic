//! The crypto service provider API for querying public keys.
use crate::vault::api::{CspPublicKeyStoreError, PublicKeyStoreCspVault};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::SecretKeyStore;

use crate::public_key_store::PublicKeyStore;
use ic_logger::warn;
use ic_protobuf::registry::crypto::v1::{PublicKey as PublicKeyProto, X509PublicKeyCert};
use ic_types::crypto::CurrentNodePublicKeys;
use rand::{CryptoRng, Rng};

#[cfg(test)]
mod tests;

impl<R: Rng + CryptoRng + Send + Sync, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    PublicKeyStoreCspVault for LocalCspVault<R, S, C, P>
{
    fn pks_contains(
        &self,
        public_keys: CurrentNodePublicKeys,
    ) -> Result<bool, CspPublicKeyStoreError> {
        let guard = self.public_key_store_read_lock();
        let node_signing_public_key = guard.node_signing_pubkey().cloned();
        let committee_signing_public_key = guard.committee_signing_pubkey().cloned();
        let tls_certificate = guard.tls_certificate().cloned();
        let dkg_dealing_encryption_public_key = guard.ni_dkg_dealing_encryption_pubkey().cloned();
        let idkg_dealing_encryption_public_keys =
            guard.idkg_dealing_encryption_pubkeys().to_owned();
        drop(guard);
        let keys_match = self.compare_local_and_remote_public_keys(
            node_signing_public_key.as_ref(),
            public_keys.node_signing_public_key.as_ref(),
            "node signing public key",
        ) && self.compare_local_and_remote_public_keys(
            committee_signing_public_key.as_ref(),
            public_keys.committee_signing_public_key.as_ref(),
            "committee signing public key",
        ) && self.compare_local_and_remote_certificates(
            tls_certificate.as_ref(),
            public_keys.tls_certificate.as_ref(),
            "tls certificate",
        ) && self.compare_local_and_remote_public_keys(
            dkg_dealing_encryption_public_key.as_ref(),
            public_keys.dkg_dealing_encryption_public_key.as_ref(),
            "ni-dkg dealing encryption key",
        );
        if keys_match {
            // All the other public keys from the registry are contained in the local public key
            // store. For the iDKG dealing encryption public keys, we need to check if the key
            // from the registry is contained in the local vector of keys.
            if let Some(remote_idkg_dealing_encryption_key) =
                public_keys.idkg_dealing_encryption_public_key
            {
                if idkg_dealing_encryption_public_keys.is_empty() {
                    warn!(
                        self.logger,
                        "remote idkg dealing encryption key exists, but no local keys exist",
                    );
                } else {
                    for local_idkg_dealing_encryption_key in idkg_dealing_encryption_public_keys {
                        if local_idkg_dealing_encryption_key
                            .equal_ignoring_timestamp(&remote_idkg_dealing_encryption_key)
                        {
                            // We found a match; no need to look through the rest of the vector
                            return Ok(true);
                        }
                    }
                    warn!(
                        self.logger,
                        "remote idkg dealing encryption key does not exist locally",
                    );
                }
            } else {
                // If no remote iDKG key was specified, return true, since all previous checks passed
                return Ok(true);
            }
        }
        Ok(false)
    }

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

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    LocalCspVault<R, S, C, P>
{
    /// Compares a local and remote public key.
    ///
    /// # Returns
    /// `true` if the remote key is absent, or if it matches the local key,
    /// `false` otherwise.
    fn compare_local_and_remote_public_keys(
        &self,
        maybe_local_public_obj: Option<&PublicKeyProto>,
        maybe_remote_public_obj: Option<&PublicKeyProto>,
        obj_type: &str,
    ) -> bool {
        match maybe_remote_public_obj {
            // If the remote, registry key was not specified, return true.
            // We should only return false if a remote object is Some, and it is not found locally.
            None => true,
            Some(remote_public_obj) => match maybe_local_public_obj {
                None => {
                    warn!(self.logger, "{} exists remotely but not locally", obj_type,);
                    false
                }
                Some(local_public_obj) => {
                    let key_match = local_public_obj.equal_ignoring_timestamp(remote_public_obj);
                    if !key_match {
                        warn!(
                            self.logger,
                            "{} mismatch between local and remote copies", obj_type,
                        );
                    }
                    key_match
                }
            },
        }
    }

    /// Compares a local and remote certificate.
    ///
    /// # Returns
    /// `true` if the remote certificate is absent, or if it matches the local certificate,
    /// `false` otherwise.
    fn compare_local_and_remote_certificates(
        &self,
        maybe_local_public_obj: Option<&X509PublicKeyCert>,
        maybe_remote_public_obj: Option<&X509PublicKeyCert>,
        obj_type: &str,
    ) -> bool {
        match maybe_remote_public_obj {
            // If the remote, registry certificate was not specified, return true.
            // We should only return false if a remote object is Some, and it is not found locally.
            None => true,
            Some(remote_public_obj) => match maybe_local_public_obj {
                None => {
                    warn!(self.logger, "{} exists remotely but not locally", obj_type,);
                    false
                }
                Some(local_public_obj) => {
                    if local_public_obj != remote_public_obj {
                        warn!(
                            self.logger,
                            "{} mismatch between local and remote copies", obj_type,
                        );
                        return false;
                    }
                    true
                }
            },
        }
    }
}
