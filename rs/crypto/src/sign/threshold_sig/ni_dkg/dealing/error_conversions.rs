#[cfg(test)]
mod tests;

mod create_dealing_error_conversions {
    use crate::sign::threshold_sig::ni_dkg::utils::DkgEncPubkeyRegistryQueryError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;

    impl From<DkgEncPubkeyRegistryQueryError> for DkgCreateDealingError {
        fn from(registry_query_error: DkgEncPubkeyRegistryQueryError) -> Self {
            match registry_query_error {
                DkgEncPubkeyRegistryQueryError::FsEncryptionPublicKeyNotInRegistry(e) => {
                    DkgCreateDealingError::FsEncryptionPublicKeyNotInRegistry(e)
                }
                DkgEncPubkeyRegistryQueryError::MalformedFsEncryptionPublicKey(e) => {
                    DkgCreateDealingError::MalformedFsEncryptionPublicKey(
                        MalformedFsEncryptionPublicKeyError::from(e),
                    )
                }
                DkgEncPubkeyRegistryQueryError::Registry(e) => DkgCreateDealingError::Registry(e),
            }
        }
    }
}

mod verify_dealing_error_conversions {
    use crate::sign::threshold_sig::ni_dkg::utils::DkgEncPubkeyRegistryQueryError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;

    impl From<DkgEncPubkeyRegistryQueryError> for DkgVerifyDealingError {
        fn from(registry_query_error: DkgEncPubkeyRegistryQueryError) -> Self {
            match registry_query_error {
                DkgEncPubkeyRegistryQueryError::FsEncryptionPublicKeyNotInRegistry(e) => {
                    DkgVerifyDealingError::FsEncryptionPublicKeyNotInRegistry(e)
                }
                DkgEncPubkeyRegistryQueryError::MalformedFsEncryptionPublicKey(e) => {
                    DkgVerifyDealingError::MalformedFsEncryptionPublicKey(
                        MalformedFsEncryptionPublicKeyError::from(e),
                    )
                }
                DkgEncPubkeyRegistryQueryError::Registry(e) => DkgVerifyDealingError::Registry(e),
            }
        }
    }
}
