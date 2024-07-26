use ic_crypto_node_key_validation::ValidNodePublicKeys;

use crate::vault::api::{CspPublicKeyStoreError, ValidatePksAndSksError};
use crate::{ExternalPublicKeys, PksAndSksContainsErrors};
use ic_types::crypto::CurrentNodePublicKeys;

/// A trait that allows simultaneously checking the public and secret key stores for the
/// availability of a key.
pub trait CspPublicAndSecretKeyStoreChecker {
    /// Checks whether the keys corresponding to the provided external public keys exist locally.
    /// In particular, this means the provided public keys themselves are stored locally, as well
    /// as the corresponding secret keys. Key comparisons will not take timestamps into account.
    ///
    /// # Parameters
    /// The current external node public keys and TLS certificate.
    ///
    /// # Returns
    /// An empty result if all the external public keys, and the corresponding secret keys, were
    /// all found locally.
    ///
    /// # Errors
    /// * `PksAndSksContainsErrors::NodeKeysErrors` if local public or secret keys were not
    ///   consistent with the provided external keys.
    /// * `PksAndSksContainsErrors::TransientInternalError` if a transient internal error, e.g., an RPC
    ///   error, occurred.
    fn pks_and_sks_contains(
        &self,
        external_public_keys: ExternalPublicKeys,
    ) -> Result<(), PksAndSksContainsErrors>;

    /// See documentation in [`crate::vault::api::PublicAndSecretKeyStoreCspVault::validate_pks_and_sks`].
    fn validate_pks_and_sks(&self) -> Result<ValidNodePublicKeys, ValidatePksAndSksError>;
}

/// A trait that exposes the information about the node public key store.
pub trait CspPublicKeyStore {
    /// Returns the node's current public keys where generation timestamps are stripped.
    ///
    /// # Errors
    /// * [`CspPublicKeyStoreError::TransientInternalError`] if there is a transient internal
    ///   error when calling the CSP vault.
    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

    /// Returns the node's current public keys with their associated timestamps.
    ///
    /// If timestamps are not needed, you should use [`Self::current_node_public_keys`].
    ///
    /// # Errors
    /// * [`CspPublicKeyStoreError::TransientInternalError`] if there is a transient internal
    ///   error when calling the CSP vault.
    fn current_node_public_keys_with_timestamps(
        &self,
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

    /// Returns the number of iDKG dealing encryption public keys stored locally.
    ///
    /// # Errors
    /// * if a transient error (e.g., RPC timeout) occurs when accessing the public key store
    fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError>;
}
