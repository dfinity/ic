use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_types::crypto::CryptoResult;
use ic_types::RegistryVersion;

/// Methods for checking and retrieving key material.
pub trait KeyManager {
    /// Checks whether this crypto component is properly set up, i.e.
    /// whether the registry contains the required public keys,
    /// and whether the crypto component's secret key store
    /// contains the corresponding secret keys.
    fn check_keys_with_registry(&self, registry_version: RegistryVersion) -> CryptoResult<()>;

    /// Returns node public keys that were read when this crypto component was
    /// created. Node public keys stay the same throughout the lifetime of
    /// the component.
    fn node_public_keys(&self) -> NodePublicKeys;
}
