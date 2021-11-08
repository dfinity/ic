mod create_dealing_error_conversions {
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::MalformedSecretKeyError;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
        InvalidArgumentError, KeyNotFoundError, MalformedPublicKeyError, SizeError,
    };
    use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;
    use ic_types::crypto::{AlgorithmId, KeyId};
    use ic_types::NumberOfNodes;

    mod csp_create_dealing {
        use super::*;
        use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateReshareDealingError;

        #[test]
        fn should_return_error_on_malformed_fs_pk_error() {
            let csp_error = CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
                receiver_index: 2,
                error: MalformedPublicKeyError {
                    algorithm: AlgorithmId::Placeholder,
                    key_bytes: None,
                    internal_error: "some error".to_string(),
                },
            };

            let result = DkgCreateDealingError::from(csp_error);

            assert_eq!(
                result,
                DkgCreateDealingError::MalformedFsEncryptionPublicKey(
                    MalformedFsEncryptionPublicKeyError {
                        internal_error: "error for receiver index 2: MalformedPublicKeyError { algorithm: Placeholder, key_bytes: None, internal_error: \"some error\" }".to_string(),
                    },
                )
            );
        }

        #[test]
        fn should_return_error_on_reshare_key_not_in_secret_key_store_error() {
            let key_not_found_error = KeyNotFoundError {
                internal_error: "some error".to_string(),
                key_id: KeyId::from([0; 32]),
            };
            let csp_error = CspDkgCreateReshareDealingError::ReshareKeyNotInSecretKeyStoreError(
                key_not_found_error.clone(),
            );

            let result = DkgCreateDealingError::from(csp_error);

            assert!(matches!(
                result,
                DkgCreateDealingError::ThresholdSigningKeyNotInSecretKeyStore(error)
                if error == key_not_found_error
            ));
        }

        #[test]
        #[should_panic(
            expected = "NI-DKG create_dealing error - UnsupportedAlgorithmId: The algorithm id Placeholder is unsupported."
        )]
        fn should_panic_on_unsupported_algorithm_id_error() {
            let csp_error =
                CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(AlgorithmId::Placeholder);

            let _panic = DkgCreateDealingError::from(csp_error);
        }

        #[test]
        #[should_panic(
            expected = "NI-DKG create_dealing error - InvalidThresholdError: InvalidArgumentError { message: \"some error\" }"
        )]
        fn should_panic_on_invalid_threshold_error() {
            let csp_error =
                CspDkgCreateReshareDealingError::InvalidThresholdError(InvalidArgumentError {
                    message: "some error".to_string(),
                });

            let _panic = DkgCreateDealingError::from(csp_error);
        }

        #[test]
        #[should_panic(
            expected = "NI-DKG create_dealing error - MisnumberedReceiverError: receiver index 3, number of receivers: 4"
        )]
        fn should_panic_on_misnumbered_receiver_error() {
            let csp_error = CspDkgCreateReshareDealingError::MisnumberedReceiverError {
                receiver_index: 3,
                number_of_receivers: NumberOfNodes::new(4),
            };

            let _panic = DkgCreateDealingError::from(csp_error);
        }

        #[test]
        #[should_panic(
            expected = "NI-DKG create_dealing error - SizeError: SizeError { message: \"some error\" }"
        )]
        fn should_panic_on_size_error() {
            let csp_error = CspDkgCreateReshareDealingError::SizeError(SizeError {
                message: "some error".to_string(),
            });

            let _panic = DkgCreateDealingError::from(csp_error);
        }

        #[test]
        #[should_panic(
            expected = "NI-DKG create_dealing error - MalformedReshareSecretKeyError: MalformedSecretKeyError { algorithm: Placeholder, internal_error: \"some error\" }"
        )]
        fn should_panic_on_malformed_reshare_secret_key_error() {
            let csp_error = CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError(
                MalformedSecretKeyError {
                    algorithm: AlgorithmId::Placeholder,
                    internal_error: "some error".to_string(),
                },
            );

            let _panic = DkgCreateDealingError::from(csp_error);
        }
    }
}

mod verify_dealing_error_conversions {
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::SizeError;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgVerifyReshareDealingError;
    use ic_types::crypto::error::{InvalidArgumentError, MalformedPublicKeyError};
    use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::MalformedFsEncryptionPublicKeyError;
    use ic_types::crypto::AlgorithmId;
    use ic_types::NumberOfNodes;

    #[test]
    fn should_return_error_on_malformed_fs_pk_error() {
        let csp_error = CspDkgVerifyReshareDealingError::MalformedFsPublicKeyError {
            receiver_index: 2,
            error: MalformedPublicKeyError {
                algorithm: AlgorithmId::Placeholder,
                key_bytes: None,
                internal_error: "some error".to_string(),
            },
        };

        let result = DkgVerifyDealingError::from(csp_error);

        assert_eq!(
            result,
            DkgVerifyDealingError::MalformedFsEncryptionPublicKey(
                MalformedFsEncryptionPublicKeyError {
                    internal_error: "error for receiver index 2: MalformedPublicKeyError { algorithm: Placeholder, key_bytes: None, internal_error: \"some error\" }".to_string(),
                },
            )
        );
    }

    #[test]
    fn should_return_error_on_malformed_reshare_pub_coeffs_error() {
        let malformed_pk_error = MalformedPublicKeyError {
            algorithm: AlgorithmId::Placeholder,
            key_bytes: None,
            internal_error: "some error".to_string(),
        };
        let csp_error = CspDkgVerifyReshareDealingError::MalformedResharePublicCoefficientsError(
            malformed_pk_error.clone(),
        );

        let result = DkgVerifyDealingError::from(csp_error);

        assert_eq!(
            result,
            DkgVerifyDealingError::MalformedResharingTranscriptInConfig(malformed_pk_error)
        );
    }

    #[test]
    fn should_return_error_on_malformed_dealing_error() {
        let invalid_arg_error = InvalidArgumentError {
            message: "some error".to_string(),
        };
        let csp_error =
            CspDkgVerifyReshareDealingError::MalformedDealingError(invalid_arg_error.clone());

        let result = DkgVerifyDealingError::from(csp_error);

        assert_eq!(
            result,
            DkgVerifyDealingError::InvalidDealingError(invalid_arg_error)
        );
    }

    #[test]
    fn should_return_error_on_invalid_dealing_error() {
        let invalid_arg_error = InvalidArgumentError {
            message: "some error".to_string(),
        };
        let csp_error =
            CspDkgVerifyReshareDealingError::InvalidDealingError(invalid_arg_error.clone());

        let result = DkgVerifyDealingError::from(csp_error);

        assert_eq!(
            result,
            DkgVerifyDealingError::InvalidDealingError(invalid_arg_error)
        );
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG verify_dealing error - UnsupportedAlgorithmId: The algorithm id Placeholder is unsupported."
    )]
    fn should_panic_on_unsupported_algorithm_id_error() {
        let csp_error =
            CspDkgVerifyReshareDealingError::UnsupportedAlgorithmId(AlgorithmId::Placeholder);

        let _panic = DkgVerifyDealingError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG verify_dealing error - InvalidThresholdError: InvalidArgumentError { message: \"some error\" }"
    )]
    fn should_panic_on_invalid_threshold_error() {
        let csp_error =
            CspDkgVerifyReshareDealingError::InvalidThresholdError(InvalidArgumentError {
                message: "some error".to_string(),
            });

        let _panic = DkgVerifyDealingError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG verify_dealing error - MisnumberedReceiverError: receiver index 3, number of receivers: 4"
    )]
    fn should_panic_on_misnumbered_receiver_error() {
        let csp_error = CspDkgVerifyReshareDealingError::MisnumberedReceiverError {
            receiver_index: 3,
            number_of_receivers: NumberOfNodes::new(4),
        };

        let _panic = DkgVerifyDealingError::from(csp_error);
    }

    #[test]
    #[should_panic(
        expected = "NI-DKG verify_dealing error - SizeError: SizeError { message: \"some error\" }"
    )]
    fn should_panic_on_size_error() {
        let csp_error = CspDkgVerifyReshareDealingError::SizeError(SizeError {
            message: "some error".to_string(),
        });

        let _panic = DkgVerifyDealingError::from(csp_error);
    }
}
