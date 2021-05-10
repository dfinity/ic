mod create_transcript_error_conversions {
    use crate::api::ni_dkg_errors::{
        CspDkgCreateReshareTranscriptError, InvalidArgumentError, MalformedPublicKeyError,
        SizeError,
    };
    use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
    use ic_types::crypto::AlgorithmId;

    #[test]
    #[should_panic(
        expected = "NI-DKG create_transcript error - Precondition violated: dealings have not been verified. InvalidDealingError for dealing with index 7: InvalidArgumentError { message: \"some error\" }"
    )]
    fn should_panic_on_invalid_dealing_error() {
        let csp_error = CspDkgCreateReshareTranscriptError::InvalidDealingError {
            dealer_index: 7,
            error: invalid_arg_error(),
        };

        let _panic = DkgCreateTranscriptError::from(csp_error);
    }

    #[test]
    fn should_return_error_on_malforemd_resharing_coeffs_error() {
        let malformed_pk_error = malformed_pk_error();
        let csp_error = CspDkgCreateReshareTranscriptError::MalformedResharePublicCoefficientsError(
            malformed_pk_error.clone(),
        );

        let result = DkgCreateTranscriptError::from(csp_error);

        assert_eq!(
            result,
            DkgCreateTranscriptError::MalformedResharingTranscriptInConfig(malformed_pk_error)
        );
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG create_transcript error - UnsupportedAlgorithmId: The algorithm id Placeholder is unsupported."
    )]
    fn should_panic_on_unsupported_algorithm_id_error() {
        let csp_error =
            CspDkgCreateReshareTranscriptError::UnsupportedAlgorithmId(AlgorithmId::Placeholder);

        let _panic = DkgCreateTranscriptError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG create_transcript error - InvalidThresholdError: InvalidArgumentError { message: \"some error\" }"
    )]
    fn should_panic_on_invalid_threshold_error() {
        let csp_error =
            CspDkgCreateReshareTranscriptError::InvalidThresholdError(InvalidArgumentError {
                message: "some error".to_string(),
            });

        let _panic = DkgCreateTranscriptError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG create_transcript error - InsufficientDealingsError: InvalidArgumentError { message: \"some error\" }"
    )]
    fn should_panic_on_insufficient_dealings_error() {
        let csp_error =
            CspDkgCreateReshareTranscriptError::InsufficientDealingsError(invalid_arg_error());

        let _panic = DkgCreateTranscriptError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG create_transcript error - Precondition violated: dealings have not been verified. ResharingFailed: ResharingFailed(InvalidArgumentError { message: \"some error\" })"
    )]
    fn should_panic_on_resharing_failed_error() {
        let csp_error = CspDkgCreateReshareTranscriptError::ResharingFailed(invalid_arg_error());

        let _panic = DkgCreateTranscriptError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG create_transcript error - SizeError: SizeError { message: \"some error\" }"
    )]
    fn should_panic_on_size_error() {
        let csp_error = CspDkgCreateReshareTranscriptError::SizeError(SizeError {
            message: "some error".to_string(),
        });

        let _panic = DkgCreateTranscriptError::from(csp_error);
    }

    fn malformed_pk_error() -> MalformedPublicKeyError {
        MalformedPublicKeyError {
            algorithm: AlgorithmId::Placeholder,
            key_bytes: None,
            internal_error: "some error".to_string(),
        }
    }

    fn invalid_arg_error() -> InvalidArgumentError {
        InvalidArgumentError {
            message: "some error".to_string(),
        }
    }
}
