use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_types::crypto::{CommitteeMemberPublicKey, CryptoError, CryptoResult, KeyId, UserPublicKey};
use ic_types::RegistryVersion;

/// Functions to generate key material.
pub trait Keygen {
    /// Generates Ed25519 key material for an Internet Computer user.
    ///
    /// Returns the public key and a handle to the secret key, which is
    /// persisted in the secret key store.
    fn generate_user_keys_ed25519(&self) -> Result<(KeyId, UserPublicKey), CryptoError>;

    /// Generates key material for a member of a committee.
    ///
    /// Returns the public key and a handle to the secret key, which is
    /// persisted in the secret key store.
    ///
    /// The generated key material is intended to be used only on a subnet
    /// (and not on the main net).
    fn generate_committee_member_keys(
        &self,
    ) -> Result<(KeyId, CommitteeMemberPublicKey), CryptoError>;
}

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
