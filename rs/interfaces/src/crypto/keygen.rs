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

    /// Returns node public keys that were read when this crypto component was
    /// created. Node public keys stay the same throughout the lifetime of
    /// the component.
    fn node_public_keys(&self) -> NodePublicKeys;
}

#[derive(Clone, Debug)]
pub enum PublicKeyRegistrationStatus {
    AllKeysRegistered,
    IDkgDealingEncPubkeyNeedsRegistration(PublicKeyProto),
}
