use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::vault::local_csp_vault::{
    tschnorr::{
        IDkgTranscriptInternalBytes, ThresholdSchnorrSigShareBytes, ThresholdSchnorrSignerCspVault,
    },
    CspSecretKey, ThresholdSchnorrCreateSigShareVaultError,
};
use crate::KeyId;
use crate::LocalCspVault;
use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_ecdsa::{
    CombinedCommitment, CommitmentOpeningBytes, EccCurveType, EccPoint, EccScalar, EccScalarBytes,
    IDkgTranscriptInternal, IdkgProtocolAlgorithm, PolynomialCommitment, SimpleCommitment,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::{
    crypto::{canister_threshold_sig::ExtendedDerivationPath, AlgorithmId},
    Randomness,
};
use proptest::{
    prelude::{any, Strategy},
    proptest,
};
use rand::{CryptoRng, Rng};

mod create_schnorr_sig_share {
    use super::utils::*;
    use super::*;

    #[test]
    fn should_error_if_key_opening_not_found_in_csks() {
        let rng = &mut reproducible_rng();
        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
            let mut canister_sks = MockSecretKeyStore::new();
            parameters.without_key_opening_in(&mut canister_sks);
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = parameters.create_schnorr_sig_share(&vault);

            assert_matches!(
                result,
                Err(ThresholdSchnorrCreateSigShareVaultError::SecretSharesNotFound { commitment_string })
                if commitment_string == format!("{:?}", parameters.key.combined_commitment.commitment())
            );
        }
    }

    #[test]
    fn should_error_if_key_opening_has_wrong_type() {
        let rng = &mut reproducible_rng();
        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
            let key_id = KeyId::from(parameters.key.combined_commitment.commitment());
            proptest!(|(invalid_key_opening in arb_non_commitment_opening_csp_secret_key())| {
                    let wrong_secret_key_type = <&'static str>::from(&invalid_key_opening).to_string();
                    let mut canister_sks = MockSecretKeyStore::new();

                    canister_sks
                    .expect_get()
                    .times(1)
                    .withf(move |id| *id == key_id)
                    .return_const(Some(invalid_key_opening));

                    let vault = LocalCspVault::builder_for_test()
                        .with_mock_stores()
                        .with_canister_secret_key_store(canister_sks)
                        .build();

                    let result = parameters.create_schnorr_sig_share(&vault);

                    assert_matches!(
                        result,
                        Err(ThresholdSchnorrCreateSigShareVaultError::InternalError(s))
                        if s == format!("obtained secret key has wrong type: {wrong_secret_key_type}")
                    );
                }
            );
        }
    }

    #[test]
    fn should_error_if_presig_opening_not_found_in_csks() {
        let rng = &mut reproducible_rng();
        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
            let mut canister_sks = MockSecretKeyStore::new();
            parameters.with_key_opening_in(&mut canister_sks);
            parameters.without_presig_opening_in(&mut canister_sks);
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = parameters.create_schnorr_sig_share(&vault);

            assert_matches!(
                result,
                Err(ThresholdSchnorrCreateSigShareVaultError::SecretSharesNotFound { commitment_string })
                if commitment_string == format!("{:?}", parameters.presig.combined_commitment.commitment())
            );
        }
    }

    #[test]
    fn should_error_if_presig_opening_has_wrong_type() {
        let rng = &mut reproducible_rng();
        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
            let presig_id = KeyId::from(parameters.presig.combined_commitment.commitment());
            proptest!(|(invalid_key_opening in arb_non_commitment_opening_csp_secret_key())| {
                    let wrong_secret_key_type = <&'static str>::from(&invalid_key_opening).to_string();
                    let mut canister_sks = MockSecretKeyStore::new();

                    parameters.with_key_opening_in(&mut canister_sks);
                    canister_sks
                    .expect_get()
                    .times(1)
                    .withf(move |id| *id == presig_id)
                    .return_const(Some(invalid_key_opening));

                    let vault = LocalCspVault::builder_for_test()
                        .with_mock_stores()
                        .with_canister_secret_key_store(canister_sks)
                        .build();

                    let result = parameters.create_schnorr_sig_share(&vault);

                    assert_matches!(
                        result,
                        Err(ThresholdSchnorrCreateSigShareVaultError::InternalError(s))
                        if s == format!("obtained secret key has wrong type: {wrong_secret_key_type}")
                    );
                }
            );
        }
    }

    #[test]
    fn should_error_for_invalid_algorithm_id() {
        use strum::IntoEnumIterator;

        let rng = &mut reproducible_rng();

        AlgorithmId::iter()
            .filter(|algorithm_id| !algorithm_id.is_threshold_schnorr())
            .for_each(|wrong_algorithm_id| {
                for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
                    let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
                    let mut canister_sks = MockSecretKeyStore::new();
                    parameters.with_key_opening_in(&mut canister_sks);
                    parameters.with_presig_opening_in(&mut canister_sks);
                    let vault = LocalCspVault::builder_for_test()
                        .with_mock_stores()
                        .with_canister_secret_key_store(canister_sks)
                        .build();

                    let parameters_with_wrong_algorithm_id = SchnorrSignShareParameters {
                        algorithm_id: wrong_algorithm_id,
                        ..parameters
                    };
                    let result =
                        parameters_with_wrong_algorithm_id.create_schnorr_sig_share(&vault);

                    let expected_error_message = format!(
                    "invalid algorithm id for threshold Schnorr signature: {wrong_algorithm_id}"
                );
                    assert_matches!(
                        result,
                        Err(ThresholdSchnorrCreateSigShareVaultError::InvalidArguments(s))
                        if s == expected_error_message
                    );
                }
            });
    }

    #[test]
    fn should_error_if_key_opening_has_wrong_commitment_type() {
        let rng = &mut reproducible_rng();

        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let params_with_wrong_key_opening = {
                let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
                let pedersen_opening = match parameters.key_opening {
                    CspSecretKey::IDkgCommitmentOpening(ref opening_bytes) => {
                        to_pedersen_commitment_opening(opening_bytes)
                    }
                    _ => panic!("Wrong secret key type"),
                };
                let key_opening = CspSecretKey::IDkgCommitmentOpening(pedersen_opening);
                SchnorrSignShareParameters {
                    key_opening,
                    ..parameters
                }
            };

            let mut canister_sks = MockSecretKeyStore::new();
            params_with_wrong_key_opening.with_key_opening_in(&mut canister_sks);
            params_with_wrong_key_opening.with_presig_opening_in(&mut canister_sks);
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = params_with_wrong_key_opening.create_schnorr_sig_share(&vault);

            assert_matches!(
                result,
                Err(ThresholdSchnorrCreateSigShareVaultError::InternalError(s))
                if s.contains("UnexpectedCommitmentType")
            );
        }
    }

    #[test]
    fn should_error_if_presig_opening_has_wrong_commitment_type() {
        let rng = &mut reproducible_rng();

        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let params_with_wrong_presig_opening = {
                let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
                let pedersen_opening = match parameters.presig_opening {
                    CspSecretKey::IDkgCommitmentOpening(ref opening_bytes) => {
                        to_pedersen_commitment_opening(opening_bytes)
                    }
                    _ => panic!("Wrong secret key type"),
                };
                let presig_opening = CspSecretKey::IDkgCommitmentOpening(pedersen_opening);
                SchnorrSignShareParameters {
                    presig_opening,
                    ..parameters
                }
            };

            let mut canister_sks = MockSecretKeyStore::new();
            params_with_wrong_presig_opening.with_key_opening_in(&mut canister_sks);
            params_with_wrong_presig_opening.with_presig_opening_in(&mut canister_sks);
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = params_with_wrong_presig_opening.create_schnorr_sig_share(&vault);

            assert_matches!(
                result,
                Err(ThresholdSchnorrCreateSigShareVaultError::InternalError(s))
                if s.contains("UnexpectedCommitmentType")
            );
        }
    }

    #[test]
    fn should_create_schnorr_sig_share() {
        let rng = &mut reproducible_rng();

        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
            let mut canister_sks = MockSecretKeyStore::new();
            parameters.with_key_opening_in(&mut canister_sks);
            parameters.with_presig_opening_in(&mut canister_sks);
            let vault = LocalCspVault::builder_for_test()
                .with_mock_stores()
                .with_canister_secret_key_store(canister_sks)
                .build();

            let result = parameters.create_schnorr_sig_share(&vault);

            assert_matches!(result, Ok(_))
        }
    }

    #[test]
    fn should_fail_on_invalid_serialiation_of_transcript() {
        let rng = &mut reproducible_rng();

        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);
            let vault = LocalCspVault::builder_for_test().build();

            let invalid_serialization = vec![0xFF; 100];

            for i in 0..2 {
                let mut transcript_key = transcript_to_bytes(&parameters.key);
                let mut transcript_presig = transcript_to_bytes(&parameters.presig);
                // `IDkgTranscriptInternalBytes` is neither `Copy` nor `Clone`, so
                // we can't use a `Vec` to store them.
                let transcripts = [&mut transcript_key, &mut transcript_presig];

                *transcripts[i] = IDkgTranscriptInternalBytes::from(invalid_serialization.clone());

                assert_matches!(
                    vault.create_schnorr_sig_share(
                        parameters.derivation_path.clone(),
                        parameters.message.clone(),
                        parameters.nonce,
                        transcript_key,
                        transcript_presig,
                        parameters.algorithm_id,
                    ),
                    Err(ThresholdSchnorrCreateSigShareVaultError::SerializationError(_))
                );
            }
        }
    }

    #[test]
    fn should_fail_if_cant_deserialize_commitment_opening_bytes() {
        let rng = &mut reproducible_rng();

        for algorithm_id in AlgorithmId::all_threshold_schnorr_algorithms() {
            let parameters = SchnorrSignShareParameters::new_valid(algorithm_id, rng);

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
                    parameters.create_schnorr_sig_share(&vault),
                    Err(ThresholdSchnorrCreateSigShareVaultError::SerializationError(s))
                    if s == "CanisterThresholdSerializationError(\"failed to deserialize EccScalar: invalid encoding\")"
                );
            }
        }
    }
}

mod utils {
    use super::*;

    pub struct SchnorrSignShareParameters {
        pub derivation_path: ExtendedDerivationPath,
        pub message: Vec<u8>,
        pub nonce: Randomness,
        pub key: IDkgTranscriptInternal,
        pub key_opening: CspSecretKey,
        pub presig: IDkgTranscriptInternal,
        pub presig_opening: CspSecretKey,
        pub algorithm_id: AlgorithmId,
    }

    impl SchnorrSignShareParameters {
        pub fn new_valid<R: Rng + CryptoRng>(algorithm_id: AlgorithmId, rng: &mut R) -> Self {
            assert!(algorithm_id.is_threshold_schnorr());
            let curve_type = IdkgProtocolAlgorithm::from_algorithm(algorithm_id)
                .expect("failed to convert algorithm ID to threshold signature type")
                .curve();
            let key = random_transcript(curve_type, rng);
            let presig = random_transcript(curve_type, rng);
            let key_opening = random_commitment_opening(curve_type, rng);
            let presig_opening = random_commitment_opening(curve_type, rng);

            Self {
                derivation_path: some_derivation_path(),
                message: "some message".as_bytes().to_vec(),
                nonce: Randomness::from([0; 32]),
                key,
                key_opening,
                presig,
                presig_opening,
                algorithm_id,
            }
        }

        pub fn create_schnorr_sig_share<V: ThresholdSchnorrSignerCspVault>(
            &self,
            vault: &V,
        ) -> Result<ThresholdSchnorrSigShareBytes, ThresholdSchnorrCreateSigShareVaultError>
        {
            vault.create_schnorr_sig_share(
                self.derivation_path.clone(),
                self.message.clone(),
                self.nonce,
                transcript_to_bytes(&self.key),
                transcript_to_bytes(&self.presig),
                self.algorithm_id,
            )
        }

        pub fn without_key_opening_in(&self, canister_sks: &mut MockSecretKeyStore) {
            let key_id = KeyId::from(self.key.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |id| *id == key_id)
                .return_const(None);
        }

        pub fn with_key_opening_in(&self, canister_sks: &mut MockSecretKeyStore) {
            let key_id = KeyId::from(self.key.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |id| *id == key_id)
                .return_const(Some(self.key_opening.clone()));
        }

        pub fn without_presig_opening_in(&self, canister_sks: &mut MockSecretKeyStore) {
            let presig_id = KeyId::from(self.presig.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |id| *id == presig_id)
                .return_const(None);
        }

        pub fn with_presig_opening_in(&self, canister_sks: &mut MockSecretKeyStore) {
            let presig_id = KeyId::from(self.presig.combined_commitment.commitment());
            canister_sks
                .expect_get()
                .times(1)
                .withf(move |id| *id == presig_id)
                .return_const(Some(self.presig_opening.clone()));
        }

        /// Returns key-opening pairs for the transcripts.
        pub fn keys_openings(&self) -> Vec<(KeyId, CspSecretKey)> {
            [
                (&self.key, &self.key_opening),
                (&self.presig, &self.presig_opening),
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

    pub fn arb_non_commitment_opening_csp_secret_key() -> impl Strategy<Value = CspSecretKey> {
        any::<CspSecretKey>().prop_filter(
            "Secret key must not be of type IDkgCommitmentOpening",
            |sk| !matches!(sk, CspSecretKey::IDkgCommitmentOpening(_)),
        )
    }

    pub fn to_pedersen_commitment_opening(
        commitment: &CommitmentOpeningBytes,
    ) -> CommitmentOpeningBytes {
        let scalar_bytes = match commitment {
            CommitmentOpeningBytes::Simple(bytes) => bytes,
            CommitmentOpeningBytes::Pedersen(_, _) => panic!("unexpected commitment type"),
        };
        CommitmentOpeningBytes::Pedersen(scalar_bytes.clone(), scalar_bytes.clone())
    }

    pub fn transcript_to_bytes(transcript: &IDkgTranscriptInternal) -> IDkgTranscriptInternalBytes {
        IDkgTranscriptInternalBytes::from(
            transcript
                .serialize()
                .expect("should serialize successfully"),
        )
    }

    fn random_transcript<R: Rng + CryptoRng>(
        curve_type: EccCurveType,
        rng: &mut R,
    ) -> IDkgTranscriptInternal {
        IDkgTranscriptInternal {
            combined_commitment: CombinedCommitment::BySummation(PolynomialCommitment::from(
                SimpleCommitment {
                    points: vec![random_ecc_point(curve_type, rng)],
                },
            )),
        }
    }

    fn random_ecc_point<R: Rng + CryptoRng>(curve_type: EccCurveType, rng: &mut R) -> EccPoint {
        EccPoint::generator_g(curve_type)
            .scalar_mul(&EccScalar::random(curve_type, rng))
            .expect("failed to multiply")
    }

    fn random_commitment_opening<R: Rng + CryptoRng>(
        curve_type: EccCurveType,
        rng: &mut R,
    ) -> CspSecretKey {
        let scalar_bytes = EccScalarBytes::try_from(&EccScalar::random(curve_type, rng))
            .expect("failed to serialize EccScalar");
        CspSecretKey::IDkgCommitmentOpening(CommitmentOpeningBytes::Simple(scalar_bytes))
    }

    fn some_derivation_path() -> ExtendedDerivationPath {
        ExtendedDerivationPath {
            caller: Default::default(),
            derivation_path: vec![],
        }
    }
}
