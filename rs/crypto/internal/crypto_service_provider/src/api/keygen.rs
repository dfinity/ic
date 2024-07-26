use crate::vault::api::CspPublicKeyStoreError;
use ic_types::crypto::CurrentNodePublicKeys;

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
