use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::CryptoResult;
use ic_types::RegistryVersion;

/// Methods for checking and retrieving key material.
pub trait KeyManager {
    /// Checks whether this crypto component is properly set up, i.e.
    /// whether the registry contains the required public keys,
    /// and whether the crypto component's secret key store
    /// contains the corresponding secret keys. If this is the case,
    /// `Ok(PublicKeyRegistrationStatus::AllKeysRegistered)` is returned.
    ///
    /// If all keys are properly set up but the I-DKG dealing encryption key
    /// still need to be registered, i.e., it is not in the registry but it is
    /// available locally in the public key store, then
    /// `Ok(PublicKeyRegistrationStatus::IDkgDealingEncPubkeyNeedsRegistration)`
    /// is returned.
    fn check_keys_with_registry(
        &self,
        registry_version: RegistryVersion,
    ) -> CryptoResult<PublicKeyRegistrationStatus>;

    /// Collects key count metrics from the local node and the registry, and stores the information
    /// in the metrics component.
    fn collect_and_store_key_count_metrics(&self, registry_version: RegistryVersion);

    /// Returns node public keys that were read when this crypto component was
    /// created. Node public keys stay the same throughout the lifetime of
    /// the component.
    fn node_public_keys(&self) -> NodePublicKeys;

    /// Rotates the I-DKG dealing encryption keys. This function shall only be called if a prior
    /// call to `check_keys_with_registry()` has indicated that the I-DKG dealing encryption keys
    /// shall be rotated. Returns a `PublicKeyProto` containing the new I-DKG dealing encryption
    /// key to be registered, or an error if the key rotation failed.
    ///
    /// # Errors
    /// * `IDkgDealingEncryptionKeyRotationError::LatestLocalRotationTooRecent` if the node local
    ///   I-DKG dealing encryption keys are too recent, and the keys cannot be rotated. The caller
    ///   needs to wait longer before the keys can be rotated. To determine whether or not the
    ///   I-DKG dealing encryption keys can be rotated, inspect the return value of
    ///   `check_keys_with_registry`.
    fn rotate_idkg_dealing_encryption_keys(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<PublicKeyProto, IDkgDealingEncryptionKeyRotationError>;
}

#[derive(Clone, Debug)]
pub enum PublicKeyRegistrationStatus {
    AllKeysRegistered,
    IDkgDealingEncPubkeyNeedsRegistration(PublicKeyProto),
}

#[derive(Clone, Debug)]
pub enum IDkgDealingEncryptionKeyRotationError {
    LatestLocalRotationTooRecent,
}
