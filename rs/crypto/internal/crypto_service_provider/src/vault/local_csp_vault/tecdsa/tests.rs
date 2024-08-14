mod ecdsa_sign_share {
    use crate::key_id::KeyId;
    use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
    use crate::types::CspSecretKey;
    use crate::vault::api::{IDkgTranscriptInternalBytes, ThresholdEcdsaSignerCspVault};
    use crate::LocalCspVault;
    use assert_matches::assert_matches;
    use ic_crypto_internal_threshold_sig_ecdsa::{
        CombinedCommitment, CommitmentOpeningBytes, EccCurveType, EccPoint, EccScalarBytes,
        IDkgTranscriptInternal, PolynomialCommitment, SimpleCommitment,
        ThresholdEcdsaSigShareInternal,
    };
    use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaCreateSigShareError;
    use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
    use ic_types::crypto::AlgorithmId;
    use ic_types::Randomness;
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::proptest;
    use proptest::strategy::Strategy;
    use std::collections::HashSet;

    #[test]
    fn should_error_when_lambda_masked_not_found() {
        let parameters = EcdsaSignShareParameters::default();
        let mut canister_sks = MockSecretKeyStore::new();
        parameters.without_lambda_masked_idkg_commitment(&mut canister_sks);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_canister_secret_key_store(canister_sks)
            .build();

        let result = parameters.ecdsa_sign_share(&vault);

        assert_matches!(
            result,
            Err(ThresholdEcdsaCreateSigShareError::SecretSharesNotFound { commitment_string })
            if commitment_string == format!("{:?}", parameters.lambda_masked.combined_commitment.commitment())
        )
    }

    #[test]
    fn should_error_when_lambda_masked_has_wrong_type() {
        let parameters = EcdsaSignShareParameters::default();
        let lambda_masked_key_id =
            KeyId::from(parameters.lambda_masked.combined_commitment.commitment());

        proptest!(|(lambda_masked_sk in arb_non_commitment_opening_csp_secret_key())| {
            let wrong_secret_key_type = <&'static str>::from(&lambda_masked_sk).to_string();
            let mut canister_sks = MockSecretKeyStore::new();
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == lambda_masked_key_id)
                .return_const(Some(lambda_masked_sk));
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = parameters.ecdsa_sign_share(&vault);

            assert_matches!(
                result,
                Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
                if internal_error == format!("obtained secret key has wrong type: {wrong_secret_key_type}")
            )
        });
    }

    #[test]
    fn should_error_when_kappa_times_lambda_not_found() {
        let parameters = EcdsaSignShareParameters::default();
        let mut canister_sks = MockSecretKeyStore::new();
        parameters.with_lambda_masked_idkg_commitment(&mut canister_sks);
        parameters.without_kappa_times_lambda_idkg_commitment(&mut canister_sks);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_canister_secret_key_store(canister_sks)
            .build();

        let result = parameters.ecdsa_sign_share(&vault);

        assert_matches!(
            result,
            Err(ThresholdEcdsaCreateSigShareError::SecretSharesNotFound { commitment_string })
            if commitment_string == format!("{:?}", parameters.kappa_times_lambda.combined_commitment.commitment())
        )
    }

    #[test]
    fn should_error_when_kappa_times_lambda_has_wrong_type() {
        let parameters = EcdsaSignShareParameters::default();
        let kappa_times_lambda_key_id = KeyId::from(
            parameters
                .kappa_times_lambda
                .combined_commitment
                .commitment(),
        );

        proptest!(|(kappa_times_lambda_sk in arb_non_commitment_opening_csp_secret_key())| {
            let wrong_secret_key_type = <&'static str>::from(&kappa_times_lambda_sk).to_string();
            let mut canister_sks = MockSecretKeyStore::new();
            parameters.with_lambda_masked_idkg_commitment(&mut canister_sks);
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == kappa_times_lambda_key_id)
                .return_const(Some(kappa_times_lambda_sk));
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = parameters.ecdsa_sign_share(&vault);

            assert_matches!(
                result,
                Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
                if internal_error == format!("obtained secret key has wrong type: {wrong_secret_key_type}")
            )
        });
    }

    #[test]
    fn should_error_when_key_times_lambda_not_found() {
        let parameters = EcdsaSignShareParameters::default();
        let mut canister_sks = MockSecretKeyStore::new();
        parameters.with_lambda_masked_idkg_commitment(&mut canister_sks);
        parameters.with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
        parameters.without_key_times_lambda_idkg_commitment(&mut canister_sks);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_canister_secret_key_store(canister_sks)
            .build();

        let result = parameters.ecdsa_sign_share(&vault);

        assert_matches!(
            result,
            Err(ThresholdEcdsaCreateSigShareError::SecretSharesNotFound { commitment_string })
            if commitment_string == format!("{:?}", parameters.key_times_lambda.combined_commitment.commitment())
        )
    }

    #[test]
    fn should_error_when_key_times_lambda_has_wrong_type() {
        let parameters = EcdsaSignShareParameters::default();
        let key_times_lambda_key_id =
            KeyId::from(parameters.key_times_lambda.combined_commitment.commitment());

        proptest!(|(key_times_lambda_sk in arb_non_commitment_opening_csp_secret_key())| {
            let wrong_secret_key_type = <&'static str>::from(&key_times_lambda_sk).to_string();
            let mut canister_sks = MockSecretKeyStore::new();
            parameters.with_lambda_masked_idkg_commitment(&mut canister_sks);
            parameters.with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == key_times_lambda_key_id)
                .return_const(Some(key_times_lambda_sk));
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = parameters.ecdsa_sign_share(&vault);

            assert_matches!(
                result,
                Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
                if internal_error == format!("obtained secret key has wrong type: {wrong_secret_key_type}")
            )
        });
    }

    #[test]
    fn should_error_when_algorithm_id_wrong() {
        use strum::IntoEnumIterator;

        AlgorithmId::iter()
            .filter(|algorithm_id| !algorithm_id.is_threshold_ecdsa())
            .for_each(|wrong_algorithm_id| {
                let parameters = EcdsaSignShareParameters::default();
                let mut canister_sks = MockSecretKeyStore::new();
                parameters.with_lambda_masked_idkg_commitment(&mut canister_sks);
                parameters.with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
                parameters.with_key_times_lambda_idkg_commitment(&mut canister_sks);
                let vault = LocalCspVault::builder_for_test()
                    .with_mock_stores()
                    .with_canister_secret_key_store(canister_sks)
                    .build();

                let parameters_with_wrong_algorithm_id = EcdsaSignShareParameters {
                    algorithm_id: wrong_algorithm_id,
                    ..parameters
                };
                let result = parameters_with_wrong_algorithm_id.ecdsa_sign_share(&vault);

                assert_matches!(
                    result,
                    Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
                    if internal_error.contains("unsupported algorithm")
                )
            });
    }

    #[test]
    fn should_error_when_hashed_message_is_not_32_bytes() {
        proptest!(|(hashed_message in vec(any::<u8>(), 0..100)
            .prop_filter("hashed_message must not be 32 bytes", |s| s.len() != 32))| {
            let parameters = EcdsaSignShareParameters::default();
            let mut canister_sks = MockSecretKeyStore::new();
            parameters.with_lambda_masked_idkg_commitment(&mut canister_sks);
            parameters.with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
            parameters.with_key_times_lambda_idkg_commitment(&mut canister_sks);
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let parameters_with_invalid_hashed_message_length = EcdsaSignShareParameters {
                hashed_message,
                ..parameters
            };
            let result = parameters_with_invalid_hashed_message_length.ecdsa_sign_share(&vault);

            //TODO CRP-1340 add dedicated error type for hash length mismatch
            assert_matches!(
                result,
                Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
                if internal_error.contains("length of hashed_message")
                && internal_error.contains("not matching expected length (32)")
            )
        });
    }

    #[test]
    fn should_error_when_lambda_masked_commitment_is_simple() {
        let params_with_wrong_lambda_masked_commitment = {
            let parameters = EcdsaSignShareParameters::default();
            let simple_opening = match parameters.lambda_masked_commitment {
                CspSecretKey::IDkgCommitmentOpening(ref opening_bytes) => {
                    to_simple_commitment_opening(opening_bytes)
                }
                _ => panic!("Wrong secret key type"),
            };
            let lambda_masked_commitment = CspSecretKey::IDkgCommitmentOpening(simple_opening);
            EcdsaSignShareParameters {
                lambda_masked_commitment,
                ..parameters
            }
        };
        let mut canister_sks = MockSecretKeyStore::new();
        params_with_wrong_lambda_masked_commitment
            .with_lambda_masked_idkg_commitment(&mut canister_sks);
        params_with_wrong_lambda_masked_commitment
            .with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
        params_with_wrong_lambda_masked_commitment
            .with_key_times_lambda_idkg_commitment(&mut canister_sks);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_canister_secret_key_store(canister_sks)
            .build();

        let result = params_with_wrong_lambda_masked_commitment.ecdsa_sign_share(&vault);

        assert_matches!(
            result,
            Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
            if internal_error.contains("UnexpectedCommitmentType")
        )
    }

    #[test]
    fn should_error_when_kappa_times_lambda_commitment_is_simple() {
        let params_with_wrong_kappa_times_lambda_commitment = {
            let parameters = EcdsaSignShareParameters::default();
            let simple_opening = match parameters.kappa_times_lambda_commitment {
                CspSecretKey::IDkgCommitmentOpening(ref opening_bytes) => {
                    to_simple_commitment_opening(opening_bytes)
                }
                _ => panic!("Wrong secret key type"),
            };
            let kappa_times_lambda_commitment = CspSecretKey::IDkgCommitmentOpening(simple_opening);
            EcdsaSignShareParameters {
                kappa_times_lambda_commitment,
                ..parameters
            }
        };
        let mut canister_sks = MockSecretKeyStore::new();
        params_with_wrong_kappa_times_lambda_commitment
            .with_lambda_masked_idkg_commitment(&mut canister_sks);
        params_with_wrong_kappa_times_lambda_commitment
            .with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
        params_with_wrong_kappa_times_lambda_commitment
            .with_key_times_lambda_idkg_commitment(&mut canister_sks);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_canister_secret_key_store(canister_sks)
            .build();

        let result = params_with_wrong_kappa_times_lambda_commitment.ecdsa_sign_share(&vault);

        assert_matches!(
            result,
            Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
            if internal_error.contains("UnexpectedCommitmentType")
        )
    }

    #[test]
    fn should_error_when_key_times_lambda_commitment_is_simple() {
        let params_with_wrong_key_times_lambda_commitment = {
            let parameters = EcdsaSignShareParameters::default();
            let simple_opening = match parameters.key_times_lambda_commitment {
                CspSecretKey::IDkgCommitmentOpening(ref opening_bytes) => {
                    to_simple_commitment_opening(opening_bytes)
                }
                _ => panic!("Wrong secret key type"),
            };
            let key_times_lambda_commitment = CspSecretKey::IDkgCommitmentOpening(simple_opening);
            EcdsaSignShareParameters {
                key_times_lambda_commitment,
                ..parameters
            }
        };
        let mut canister_sks = MockSecretKeyStore::new();
        params_with_wrong_key_times_lambda_commitment
            .with_lambda_masked_idkg_commitment(&mut canister_sks);
        params_with_wrong_key_times_lambda_commitment
            .with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
        params_with_wrong_key_times_lambda_commitment
            .with_key_times_lambda_idkg_commitment(&mut canister_sks);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_canister_secret_key_store(canister_sks)
            .build();

        let result = params_with_wrong_key_times_lambda_commitment.ecdsa_sign_share(&vault);

        assert_matches!(
            result,
            Err(ThresholdEcdsaCreateSigShareError::InternalError { internal_error })
            if internal_error.contains("UnexpectedCommitmentType")
        )
    }

    #[test]
    fn should_sign_share() {
        let parameters = EcdsaSignShareParameters::default();
        let mut canister_sks = MockSecretKeyStore::new();
        parameters.with_lambda_masked_idkg_commitment(&mut canister_sks);
        parameters.with_kappa_times_lambda_idkg_commitment(&mut canister_sks);
        parameters.with_key_times_lambda_idkg_commitment(&mut canister_sks);
        let vault = LocalCspVault::builder_for_test()
            .with_mock_stores()
            .with_canister_secret_key_store(canister_sks)
            .build();

        let result = parameters.ecdsa_sign_share(&vault);

        assert_matches!(result, Ok(_))
    }

    #[test]
    fn should_fail_on_invalid_serialiation_of_transcript() {
        let parameters = EcdsaSignShareParameters::default();
        let vault = LocalCspVault::builder_for_test().build();

        let invalid_serialization = vec![0xFF; 100];

        for i in 0..5 {
            let mut transcript_key = transcript_to_bytes(&parameters.key);
            let mut transcript_kappa_unmasked = transcript_to_bytes(&parameters.kappa_unmasked);
            let mut transcript_lambda_masked = transcript_to_bytes(&parameters.lambda_masked);
            let mut transcript_kappa_times_lambda =
                transcript_to_bytes(&parameters.kappa_times_lambda);
            let mut transcript_key_times_lambda = transcript_to_bytes(&parameters.key_times_lambda);
            // `IDkgTranscriptInternalBytes` is neither `Copy` nor `Clone`, so
            // we can't use a `Vec` to store them.
            let transcripts = [
                &mut transcript_key,
                &mut transcript_kappa_unmasked,
                &mut transcript_lambda_masked,
                &mut transcript_kappa_times_lambda,
                &mut transcript_key_times_lambda,
            ];

            *transcripts[i] = IDkgTranscriptInternalBytes::from(invalid_serialization.clone());

            assert_matches!(
                vault.create_ecdsa_sig_share(
                    parameters.derivation_path.clone(),
                    parameters.hashed_message.clone(),
                    parameters.nonce,
                    transcript_key,
                    transcript_kappa_unmasked,
                    transcript_lambda_masked,
                    transcript_kappa_times_lambda,
                    transcript_key_times_lambda,
                    parameters.algorithm_id,
                ),
                Err(ThresholdEcdsaCreateSigShareError::SerializationError { .. })
            );
        }
    }

    #[test]
    fn should_fail_if_cant_deserialize_commitment_opening_bytes() {
        let parameters = EcdsaSignShareParameters::default();

        let keys_openings = parameters.keys_openings();

        let invalid_scalar_encoding = EccScalarBytes::K256(Box::new([0xFFu8; 32]));
        let invalid_commitment_opening_encoding =
            CommitmentOpeningBytes::Simple(invalid_scalar_encoding);
        let invalid_commitment_opening =
            CspSecretKey::IDkgCommitmentOpening(invalid_commitment_opening_encoding);

        for invalidate_key_index in 0..keys_openings.len() {
            let mut canister_sks = MockSecretKeyStore::new();
            for (key_index, (key_id, opening)) in keys_openings.iter().cloned().enumerate() {
                let return_value = if key_index == invalidate_key_index {
                    invalid_commitment_opening.clone()
                } else {
                    opening.clone()
                };

                canister_sks
                    .expect_get()
                    .times(1)
                    .withf(move |this_key_id| *this_key_id == key_id)
                    .return_const(Some(return_value));

                if key_index == invalidate_key_index {
                    // We return after the first deserializations failure and
                    // thus don't try to fetch and deserialize subsequent
                    // commitment openings, so we need to expect them to not
                    // happen.
                    break;
                }
            }

            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            assert_matches!(
                parameters.ecdsa_sign_share(&vault),
                Err(ThresholdEcdsaCreateSigShareError::SerializationError { internal_error })
                if internal_error == "CanisterThresholdSerializationError(\"failed to deserialize EccScalar: invalid encoding\")"
            );
        }
    }

    fn some_derivation_path() -> ExtendedDerivationPath {
        ExtendedDerivationPath {
            caller: Default::default(),
            derivation_path: vec![],
        }
    }

    struct EcdsaSignShareParameters {
        derivation_path: ExtendedDerivationPath,
        hashed_message: Vec<u8>,
        nonce: Randomness,
        key: IDkgTranscriptInternal,
        kappa_unmasked: IDkgTranscriptInternal,
        lambda_masked: IDkgTranscriptInternal,
        kappa_times_lambda: IDkgTranscriptInternal,
        key_times_lambda: IDkgTranscriptInternal,
        lambda_masked_commitment: CspSecretKey,
        kappa_times_lambda_commitment: CspSecretKey,
        key_times_lambda_commitment: CspSecretKey,
        algorithm_id: AlgorithmId,
    }

    impl Default for EcdsaSignShareParameters {
        fn default() -> Self {
            let [key, kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda] =
                distinct_transcripts();
            let kappa_unmasked = IDkgTranscriptInternal {
                combined_commitment: CombinedCommitment::BySummation(
                    kappa_unmasked.combined_commitment.commitment().clone(),
                ),
            };
            let [lambda_masked_commitment, kappa_times_lambda_commitment, key_times_lambda_commitment] =
                distinct_idkg_commitment_openings();

            EcdsaSignShareParameters {
                derivation_path: some_derivation_path(),
                hashed_message: "hello world on thirty-two bytes!".as_bytes().to_vec(),
                nonce: Randomness::from([0; 32]),
                key,
                kappa_unmasked,
                lambda_masked,
                kappa_times_lambda,
                key_times_lambda,
                lambda_masked_commitment,
                kappa_times_lambda_commitment,
                key_times_lambda_commitment,
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            }
        }
    }

    impl EcdsaSignShareParameters {
        fn ecdsa_sign_share<V: ThresholdEcdsaSignerCspVault>(
            &self,
            vault: &V,
        ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaCreateSigShareError> {
            vault.create_ecdsa_sig_share(
                self.derivation_path.clone(),
                self.hashed_message.clone(),
                self.nonce,
                transcript_to_bytes(&self.key),
                transcript_to_bytes(&self.kappa_unmasked),
                transcript_to_bytes(&self.lambda_masked),
                transcript_to_bytes(&self.kappa_times_lambda),
                transcript_to_bytes(&self.key_times_lambda),
                self.algorithm_id,
            )
        }

        fn without_lambda_masked_idkg_commitment(&self, canister_sks: &mut MockSecretKeyStore) {
            let lambda_masked_key_id =
                KeyId::from(self.lambda_masked.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == lambda_masked_key_id)
                .return_const(None);
        }

        fn without_kappa_times_lambda_idkg_commitment(
            &self,
            canister_sks: &mut MockSecretKeyStore,
        ) {
            let kappa_times_lambda_key_id =
                KeyId::from(self.kappa_times_lambda.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == kappa_times_lambda_key_id)
                .return_const(None);
        }

        fn without_key_times_lambda_idkg_commitment(&self, canister_sks: &mut MockSecretKeyStore) {
            let key_times_lambda_key_id =
                KeyId::from(self.key_times_lambda.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == key_times_lambda_key_id)
                .return_const(None);
        }

        fn with_lambda_masked_idkg_commitment(&self, canister_sks: &mut MockSecretKeyStore) {
            let lambda_masked_key_id =
                KeyId::from(self.lambda_masked.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == lambda_masked_key_id)
                .return_const(Some(self.lambda_masked_commitment.clone()));
        }

        fn with_kappa_times_lambda_idkg_commitment(&self, canister_sks: &mut MockSecretKeyStore) {
            let kappa_times_lambda_key_id =
                KeyId::from(self.kappa_times_lambda.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == kappa_times_lambda_key_id)
                .return_const(Some(self.kappa_times_lambda_commitment.clone()));
        }

        fn with_key_times_lambda_idkg_commitment(&self, canister_sks: &mut MockSecretKeyStore) {
            let key_times_lambda_key_id =
                KeyId::from(self.key_times_lambda.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |key_id| *key_id == key_times_lambda_key_id)
                .return_const(Some(self.key_times_lambda_commitment.clone()));
        }

        /// Returns key-opening pairs for the transcripts of `lambda_masked`,
        /// `kappa_times_lambda`, and `key_times_lambda`.
        fn keys_openings(&self) -> Vec<(KeyId, CspSecretKey)> {
            [
                (&self.lambda_masked, &self.lambda_masked_commitment),
                (
                    &self.kappa_times_lambda,
                    &self.kappa_times_lambda_commitment,
                ),
                (&self.key_times_lambda, &self.key_times_lambda_commitment),
            ]
            .into_iter()
            .map(|(transcript, opening)| {
                (
                    KeyId::from(transcript.combined_commitment.commitment()),
                    opening.clone(),
                )
            })
            .collect()
        }
    }

    fn distinct_transcripts<const N: usize>() -> [IDkgTranscriptInternal; N] {
        // IDkgTranscriptInternal does not implement Hash so
        // to ensure generated transcripts are distinct, we insert their serialized form in a HashSet
        let mut serialized_transcripts = HashSet::with_capacity(N);
        let transcripts: Vec<_> = distinct_ecc_points(N)
            .into_iter()
            .map(|point| {
                let transcript = IDkgTranscriptInternal {
                    combined_commitment: CombinedCommitment::BySummation(
                        PolynomialCommitment::from(SimpleCommitment {
                            points: vec![point],
                        }),
                    ),
                };
                assert!(serialized_transcripts
                    .insert(transcript.serialize().expect("can serialize transcript")));
                transcript
            })
            .collect();
        assert_eq!(
            serialized_transcripts.len(),
            N,
            "Duplicate transcripts generated"
        );

        transcripts
            .try_into()
            .map_err(|_err| "failed to convert to fixed size array")
            .expect("failed to convert to fixed size array")
    }

    fn distinct_ecc_points(num_points: usize) -> Vec<EccPoint> {
        // EccPoint does not implement Hash so
        // to ensure generated EccPoints are distinct, we insert their serialized form in a HashSet
        let mut serialized_points = HashSet::new();
        let mut points = Vec::with_capacity(num_points);
        let mut current_point = some_ecc_point();
        for _ in 0..num_points {
            current_point = current_point
                .add_points(&some_ecc_point())
                .expect("add_points failed");
            assert!(
                serialized_points.insert(current_point.serialize()),
                "Duplicate point {:?} generated",
                current_point
            );
            points.push(current_point.clone());
        }
        assert_eq!(
            serialized_points.len(),
            num_points,
            "Duplicate points generated"
        );
        assert_eq!(points.len(), num_points);
        points
    }

    fn some_ecc_point() -> EccPoint {
        EccPoint::generator_g(EccCurveType::K256)
    }

    fn distinct_idkg_commitment_openings<const N: usize>() -> [CspSecretKey; N] {
        assert!(u8::try_from(N).is_ok(), "N must be less than 256");
        let mut openings = Vec::with_capacity(N);
        for i in 0..N {
            let some_scalar = EccScalarBytes::K256(Box::new(
                [u8::try_from(i).expect("index should fit in u8"); 32],
            ));
            openings.push(CspSecretKey::IDkgCommitmentOpening(
                CommitmentOpeningBytes::Pedersen(some_scalar.clone(), some_scalar),
            ));
        }
        openings
            .try_into()
            .map_err(|_err| "failed to convert to fixed size array")
            .expect("failed to convert to fixed size array")
    }

    fn arb_non_commitment_opening_csp_secret_key() -> impl Strategy<Value = CspSecretKey> {
        any::<CspSecretKey>().prop_filter(
            "Secret key must not be of type IDkgCommitmentOpening",
            |sk| !matches!(sk, CspSecretKey::IDkgCommitmentOpening(_)),
        )
    }

    fn to_simple_commitment_opening(commitment: &CommitmentOpeningBytes) -> CommitmentOpeningBytes {
        let scalar_bytes = match commitment {
            CommitmentOpeningBytes::Simple(bytes) => bytes,
            CommitmentOpeningBytes::Pedersen(bytes, _) => bytes,
        };
        CommitmentOpeningBytes::Simple(scalar_bytes.clone())
    }

    fn transcript_to_bytes(transcript: &IDkgTranscriptInternal) -> IDkgTranscriptInternalBytes {
        IDkgTranscriptInternalBytes::from(
            transcript
                .serialize()
                .expect("should serialize successfully"),
        )
    }
}
