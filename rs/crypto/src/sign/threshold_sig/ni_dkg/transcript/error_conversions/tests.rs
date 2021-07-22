mod load_transcript_error_conversions {
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
        InvalidArgumentError, KeyNotFoundError, MalformedSecretKeyError,
    };
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgLoadPrivateKeyError;
    use ic_types::crypto::error::MalformedDataError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
    use ic_types::crypto::{AlgorithmId, KeyId};

    #[test]
    fn should_return_error_on_malformed_transcript_error() {
        let malformed_data_error = MalformedDataError {
            algorithm: AlgorithmId::Placeholder,
            internal_error: "some error".to_string(),
            data: None,
        };
        let csp_error = CspDkgLoadPrivateKeyError::MalformedTranscriptError(malformed_data_error);

        let result = DkgLoadTranscriptError::from(csp_error);

        assert_eq!(
            result,
            DkgLoadTranscriptError::InvalidTranscript(InvalidArgumentError {
                message: "Malformed Placeholder data: 0xNone. Internal error: some error"
                    .to_string()
            })
        );
    }

    #[test]
    fn should_return_error_on_invalid_transcript_error() {
        let invalid_arg_error = InvalidArgumentError {
            message: "some error".to_string(),
        };
        let csp_error =
            CspDkgLoadPrivateKeyError::InvalidTranscriptError(invalid_arg_error.clone());

        let result = DkgLoadTranscriptError::from(csp_error);

        assert_eq!(
            result,
            DkgLoadTranscriptError::InvalidTranscript(invalid_arg_error)
        );
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG load_transcript error on loading private key - KeyNotFoundError: KeyNotFoundError { internal_error: \"some error\", key_id: KeyId(0x0000000000000000000000000000000000000000000000000000000000000000) }"
    )]
    fn should_panic_on_key_not_found_error() {
        let key_not_found_error = KeyNotFoundError {
            internal_error: "some error".to_string(),
            key_id: KeyId::from([0; 32]),
        };
        let csp_error = CspDkgLoadPrivateKeyError::KeyNotFoundError(key_not_found_error);

        let _panic = DkgLoadTranscriptError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG load_transcript error on loading private key - UnsupportedAlgorithmId: The algorithm id Placeholder is unsupported."
    )]
    fn should_panic_on_unsupported_algorithm_id_error() {
        let csp_error = CspDkgLoadPrivateKeyError::UnsupportedAlgorithmId(AlgorithmId::Placeholder);

        let _panic = DkgLoadTranscriptError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG load_transcript error on loading private key - MalformedSecretKeyError: MalformedSecretKeyError { algorithm: Placeholder, internal_error: \"some error\" }"
    )]
    fn should_panic_on_malformed_secret_key_error() {
        let malformed_secret_key_error = MalformedSecretKeyError {
            algorithm: AlgorithmId::Placeholder,
            internal_error: "some error".to_string(),
        };
        let csp_error =
            CspDkgLoadPrivateKeyError::MalformedSecretKeyError(malformed_secret_key_error);

        let _panic = DkgLoadTranscriptError::from(csp_error);
    }
}
