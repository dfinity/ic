mod load_transcript_error_conversions {
    use crate::sign::threshold_sig::ni_dkg::utils::DkgEncPubkeyRegistryQueryError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;

    impl From<DkgEncPubkeyRegistryQueryError> for DkgLoadTranscriptError {
        fn from(registry_query_error: DkgEncPubkeyRegistryQueryError) -> Self {
            match registry_query_error {
                DkgEncPubkeyRegistryQueryError::FsEncryptionPublicKeyNotInRegistry(e) => {
                    DkgLoadTranscriptError::FsEncryptionPublicKeyNotInRegistry(e)
                }
                DkgEncPubkeyRegistryQueryError::MalformedFsEncryptionPublicKey(e) => {
                    DkgLoadTranscriptError::MalformedFsEncryptionPublicKey(
                        MalformedFsEncryptionPublicKeyError::from(e),
                    )
                }
                DkgEncPubkeyRegistryQueryError::Registry(e) => DkgLoadTranscriptError::Registry(e),
            }
        }
    }
}
