use crate::sign::threshold_sig::ni_dkg::utils::DkgEncPubkeyRegistryQueryError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;

impl From<DkgEncPubkeyRegistryQueryError> for DkgKeyRemovalError {
    fn from(registry_query_error: DkgEncPubkeyRegistryQueryError) -> Self {
        match registry_query_error {
            DkgEncPubkeyRegistryQueryError::FsEncryptionPublicKeyNotInRegistry(e) => {
                DkgKeyRemovalError::FsEncryptionPublicKeyNotInRegistry(e)
            }
            DkgEncPubkeyRegistryQueryError::MalformedFsEncryptionPublicKey(e) => {
                DkgKeyRemovalError::MalformedFsEncryptionPublicKey(
                    MalformedFsEncryptionPublicKeyError::from(e),
                )
            }
            DkgEncPubkeyRegistryQueryError::Registry(e) => DkgKeyRemovalError::Registry(e),
        }
    }
}
