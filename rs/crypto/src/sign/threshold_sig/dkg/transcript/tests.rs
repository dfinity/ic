use super::*;

use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::sign::threshold_sig::dkg::dealings_to_csp_dealings::DealingsToCspDealingsError;
use crate::sign::threshold_sig::dkg::test_utils::{
    any_dealings_to_pass_to_mapper_mock, csp_pk_pop_dealing, dealings_mapper_expecting,
    dealings_mapper_returning, dealings_with, keys_with, pub_coeffs, MockDealingsToCspDealings,
};
use crate::sign::threshold_sig::tests::I_DKG_ID;
use ic_crypto_internal_csp::types::{CspDkgTranscript, CspResponse};
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
    DkgCreateTranscriptError, InvalidArgumentError,
};
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::{
    CLibResponseBytes, CLibTranscriptBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3};
use ic_types::consensus::Threshold;
use ic_types::{IDkgId, NumberOfNodes};

// We use threshold 1 in these tests to get a valid DkgConfig in a simple way.
// Threshold 1 not a common value used in practice, but in these tests we only
// care that it is forwarded to the CSP correctly.
const IDKM_THRESHOLD: usize = 1;
const CSP_THRESHOLD: NodeIndex = 1;

mod create_transcript {
    use super::*;

    #[test]
    fn should_forward_keys_and_dealings_to_dealings_mapper() {
        let dummy_csp = csp_with_create_transcript_returning(Ok(csp_transcript(42)));
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_3, csp_pk, csp_pop);
        let verified_dealings = dealings_with(NODE_3, Dealing::from(&csp_dealing));
        let dummy_verified_responses = responses_with(vec![(NODE_1, response())]);
        let dummy_dkg_config =
            dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_3], IDKM_THRESHOLD);

        let dealings_mapper =
            dealings_mapper_expecting(verified_keys.clone(), verified_dealings.clone());

        let _ = create_transcript(
            &dummy_csp,
            dealings_mapper,
            &dummy_dkg_config,
            &verified_keys,
            &verified_dealings,
            &dummy_verified_responses,
        );
    }

    #[test]
    fn should_call_csp_correctly() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2], IDKM_THRESHOLD);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_2, csp_pk, csp_pop);
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let dealings_mapper = dealings_mapper_returning(Ok(verified_csp_dealings.clone()));
        let csp_response = csp_response();
        let verified_responses = responses_with(vec![(NODE_1, Response::from(&csp_response))]);

        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_csp_responses = vec![Some(csp_response), None];
        csp.expect_dkg_create_transcript()
            .withf(move |threshold, keys, dealings, responses| {
                *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                    && keys == [None, Some((csp_pk, csp_pop))]
                    && dealings == &verified_csp_dealings[..]
                    && responses == &expected_csp_responses[..]
            })
            .times(1)
            .return_const(Ok(csp_transcript(42)));

        let _ = create_transcript(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            &verified_responses,
        );
    }

    #[test]
    fn should_return_correct_transcript() {
        let dkg_config =
            dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_3], IDKM_THRESHOLD);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_1, csp_pk, csp_pop);
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let dealings_mapper = dealings_mapper_returning(Ok(verified_csp_dealings));
        let dummy_verified_responses = responses_with(vec![(NODE_1, response())]);

        let csp_transcript = csp_transcript(42);
        let csp = csp_with_create_transcript_returning(Ok(csp_transcript.clone()));

        let transcript = create_transcript(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            &dummy_verified_responses,
        )
        .expect("failed to create transcript");

        assert_eq!(
            transcript,
            Transcript {
                dkg_id: I_DKG_ID,
                committee: vec![Some(NODE_1), None, None],
                transcript_bytes: TranscriptBytes::from(&csp_transcript)
            }
        );
    }

    #[test]
    fn should_fail_if_responses_empty() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2], IDKM_THRESHOLD);
        let (csp_pk, csp_pop, _csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_2, csp_pk, csp_pop);
        let empty_verified_responses = BTreeMap::new();
        let dummy_csp = MockAllCryptoServiceProvider::new();

        let result = create_transcript(
            &dummy_csp,
            MockDealingsToCspDealings::new(),
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            &empty_verified_responses,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_arg_error("The responses must not be empty.")
        );
    }

    #[test]
    fn should_return_error_if_dealing_mapper_returns_error() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1], IDKM_THRESHOLD);
        let dealings_mapper =
            dealings_mapper_returning(Err(DealingsToCspDealingsError::KeysEmpty {}));
        let dummy_csp = MockAllCryptoServiceProvider::new();
        let dummy_verified_keys = BTreeMap::new();
        let dummy_verified_responses = responses_with(vec![(NODE_1, response())]);

        let result = create_transcript(
            &dummy_csp,
            dealings_mapper,
            &dkg_config,
            &dummy_verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            &dummy_verified_responses,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_arg_error("Error while mapping the dealings: The keys must not be empty.")
        );
    }

    #[test]
    fn should_return_invalid_argument_if_csp_returns_error() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1], IDKM_THRESHOLD);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_1, csp_pk, csp_pop);
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let dealings_mapper = dealings_mapper_returning(Ok(verified_csp_dealings));
        let dummy_verified_responses = responses_with(vec![(NODE_1, response())]);
        let csp = csp_with_create_transcript_returning(Err(
            DkgCreateTranscriptError::InvalidThresholdError(InvalidArgumentError {
                message: "message".to_string(),
            }),
        ));

        let result = create_transcript(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            &dummy_verified_responses,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_arg_error("CSP error: InvalidArgumentError { message: \"message\" }")
        );
    }

    fn csp_with_create_transcript_returning(
        result: Result<CspDkgTranscript, DkgCreateTranscriptError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_transcript()
            .times(1)
            .return_const(result);
        csp
    }
}

// For resharing, we only test the additional code paths to achieve test
// coverage
mod create_transcript_with_resharing {
    use super::*;
    use crate::sign::threshold_sig::tests::RESHARING_TRANSCRIPT_DKG_ID;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::DkgCreateReshareTranscriptError;

    #[test]
    fn should_call_csp_correctly() {
        let csp_resharing_transcript = csp_transcript(42);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let csp_response = csp_response();

        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_csp_responses = vec![Some(csp_response.clone()), None];
        let expected_csp_dealings = verified_csp_dealings.clone();
        let expected_resharing_pub_coeffs = CspPublicCoefficients::from(&csp_resharing_transcript);
        csp.expect_dkg_create_resharing_transcript()
            .withf(
                move |threshold, keys, dealings, responses, dealer_keys, resharing_pub_coeffs| {
                    *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                        && keys == [None, Some((csp_pk, csp_pop))]
                        && *dealings == expected_csp_dealings[..]
                        && *responses == expected_csp_responses[..]
                        && *dealer_keys == [None, None, None, Some((csp_pk, csp_pop)), None]
                        && *resharing_pub_coeffs == expected_resharing_pub_coeffs
                },
            )
            .times(1)
            .return_const(Ok(csp_transcript(43)));

        let dkg_config = dkg_config_with_resharing_transcript(
            I_DKG_ID,
            vec![NODE_1, NODE_2],
            IDKM_THRESHOLD,
            Transcript {
                dkg_id: RESHARING_TRANSCRIPT_DKG_ID,
                committee: vec![None, Some(NODE_1), None, Some(NODE_2), None],
                transcript_bytes: TranscriptBytes::from(&csp_resharing_transcript),
            },
        );
        let _ = create_transcript(
            &csp,
            dealings_mapper_returning(Ok(verified_csp_dealings)),
            &dkg_config,
            &keys_with(NODE_2, csp_pk, csp_pop),
            &any_dealings_to_pass_to_mapper_mock(),
            &responses_with(vec![(NODE_1, Response::from(&csp_response))]),
        );
    }

    #[test]
    fn should_return_correct_transcript() {
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_1, csp_pk, csp_pop);
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let dealings_mapper = dealings_mapper_returning(Ok(verified_csp_dealings));
        let dummy_verified_responses = responses_with(vec![(NODE_1, response())]);
        let csp_transcript = csp_transcript(42);
        let csp = csp_with_create_resharing_transcript_returning(Ok(csp_transcript.clone()));
        let dkg_config = dkg_config_with_resharing_transcript(
            I_DKG_ID,
            vec![NODE_1, NODE_2, NODE_3],
            IDKM_THRESHOLD,
            resharing_transcript(),
        );

        let transcript = create_transcript(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            &dummy_verified_responses,
        )
        .expect("failed to create transcript");

        assert_eq!(
            transcript,
            Transcript {
                dkg_id: I_DKG_ID,
                committee: vec![Some(NODE_1), None, None],
                transcript_bytes: TranscriptBytes::from(&csp_transcript)
            }
        );
    }

    #[test]
    fn should_return_invalid_argument_if_csp_returns_error() {
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_1, csp_pk, csp_pop);
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let dummy_verified_responses = responses_with(vec![(NODE_1, response())]);
        let csp = csp_with_create_resharing_transcript_returning(Err(
            DkgCreateReshareTranscriptError::InvalidThresholdError(InvalidArgumentError {
                message: "message".to_string(),
            }),
        ));
        let dkg_config = dkg_config_with_resharing_transcript(
            I_DKG_ID,
            vec![NODE_1],
            IDKM_THRESHOLD,
            resharing_transcript(),
        );

        let result = create_transcript(
            &csp,
            dealings_mapper_returning(Ok(verified_csp_dealings)),
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            &dummy_verified_responses,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_arg_error("CSP error: InvalidArgumentError { message: \"message\" }")
        );
    }

    fn resharing_transcript() -> Transcript {
        Transcript {
            dkg_id: RESHARING_TRANSCRIPT_DKG_ID,
            committee: vec![None, Some(NODE_1), None, Some(NODE_2), None],
            transcript_bytes: TranscriptBytes::from(&csp_transcript(42)),
        }
    }

    fn csp_with_create_resharing_transcript_returning(
        result: Result<CspDkgTranscript, DkgCreateReshareTranscriptError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_resharing_transcript()
            .times(1)
            .return_const(result);
        csp
    }
}

mod load_transcript {
    use super::*;
    use crate::sign::tests::KEY_ID;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
        InvalidArgumentError, KeyNotFoundError, MalformedSecretKeyError,
    };
    use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::CLibTranscriptBytes;
    use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
    use ic_types::crypto::KeyId;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let transcript = transcript(I_DKG_ID);
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_csp_transcript = CspDkgTranscript::from(&transcript.transcript_bytes);
        csp.expect_dkg_load_private_key()
            .withf(move |dkg_id, csp_transcript| {
                *dkg_id == I_DKG_ID && *csp_transcript == expected_csp_transcript
            })
            .times(1)
            .return_const(Ok(()));

        let _ = load_transcript(
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript,
            NODE_1,
        );
    }

    #[test]
    fn should_insert_transcript_data_into_store() {
        let pub_coeffs = public_coeffs();
        let transcript = Transcript {
            dkg_id: I_DKG_ID,
            committee: vec![Some(NODE_3), None, None, Some(NODE_1), Some(NODE_2)],
            transcript_bytes: TranscriptBytes::from(&csp_transcript(pub_coeffs.clone())),
        };
        let csp = csp_with_load_private_key_returning(Ok(()));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let _ = load_transcript(&threshold_sig_data_store, &csp, &transcript, NODE_1);

        let transcript_data = transcript_data(threshold_sig_data_store);
        assert_eq!(transcript_data.public_coefficients(), &pub_coeffs);
        assert_eq!(transcript_data.index(NODE_3), Some(&0));
        assert_eq!(transcript_data.index(NODE_1), Some(&3));
        assert_eq!(transcript_data.index(NODE_2), Some(&4));
    }

    #[test]
    fn should_return_ok_if_successful() {
        let csp = csp_with_load_private_key_returning(Ok(()));

        let result = load_transcript(
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript(I_DKG_ID),
            NODE_1,
        );

        assert!(result.is_ok());
    }

    #[test]
    // TODO (CRP-362): Improve error handling
    fn should_return_invalid_argument_if_csp_returns_error() {
        let error = DkgLoadPrivateKeyError::InvalidTranscriptError(InvalidArgumentError {
            message: "msg".to_string(),
        });
        let csp = csp_with_load_private_key_returning(Err(error));

        let result = load_transcript(
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript(I_DKG_ID),
            NODE_1,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_argument("CSP error: InvalidArgumentError { message: \"msg\" }")
        );
    }

    #[test]
    // TODO (CRP-362): Improve error handling
    #[should_panic(
        expected = "Internal error from CSP: MalformedSecretKeyError { algorithm: Secp256k1, internal_error: \"error message\" }"
    )]
    fn should_panic_if_csp_returns_malformed_secret_key_error() {
        let error = DkgLoadPrivateKeyError::MalformedSecretKeyError(MalformedSecretKeyError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: "error message".to_string(),
        });
        let csp = csp_with_load_private_key_returning(Err(error));

        let _panic = load_transcript(
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript(I_DKG_ID),
            NODE_1,
        );
    }

    #[test]
    // TODO (CRP-362): Improve error handling
    fn should_return_ok_if_csp_returns_key_not_found_error() {
        let error = DkgLoadPrivateKeyError::KeyNotFoundError(KeyNotFoundError {
            internal_error: "err".to_string(),
            key_id: KeyId::from(KEY_ID),
        });
        let csp = csp_with_load_private_key_returning(Err(error));

        assert!(load_transcript(
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript(I_DKG_ID),
            NODE_1
        )
        .is_ok());
    }

    #[test]
    // TODO (CRP-362): Improve error handling
    fn should_insert_transcript_data_into_store_if_csp_returns_key_not_found_error() {
        let pub_coeffs = public_coeffs();
        let transcript = Transcript {
            dkg_id: I_DKG_ID,
            committee: vec![None, Some(NODE_2), Some(NODE_1)],
            transcript_bytes: TranscriptBytes::from(&csp_transcript(pub_coeffs.clone())),
        };
        let error = DkgLoadPrivateKeyError::KeyNotFoundError(KeyNotFoundError {
            internal_error: "err".to_string(),
            key_id: KeyId::from(KEY_ID),
        });
        let csp = csp_with_load_private_key_returning(Err(error));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let _ = load_transcript(&threshold_sig_data_store, &csp, &transcript, NODE_1);

        let transcript_data = transcript_data(threshold_sig_data_store);
        assert_eq!(transcript_data.public_coefficients(), &pub_coeffs);
        assert_eq!(transcript_data.index(NODE_2), Some(&1));
        assert_eq!(transcript_data.index(NODE_1), Some(&2));
    }

    fn transcript(dkg_id: IDkgId) -> Transcript {
        Transcript {
            dkg_id,
            committee: vec![Some(NODE_1), Some(NODE_2)],
            transcript_bytes: TranscriptBytes::from(&csp_transcript(public_coeffs())),
        }
    }

    fn csp_transcript(public_coefficients: CspPublicCoefficients) -> CspDkgTranscript {
        CspDkgTranscript::Secp256k1(CLibTranscriptBytes {
            dealer_public_keys: vec![],
            public_coefficients: PublicCoefficientsBytes::from(public_coefficients),
            receiver_data: vec![],
            dealer_reshare_indices: None,
        })
    }

    fn public_coeffs() -> CspPublicCoefficients {
        CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
            coefficients: vec![PublicKeyBytes([17; PublicKeyBytes::SIZE])],
        })
    }

    fn csp_with_load_private_key_returning(
        result: Result<(), DkgLoadPrivateKeyError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_load_private_key()
            .times(1)
            .return_const(result);
        csp
    }

    fn invalid_argument(message: &str) -> CryptoError {
        CryptoError::InvalidArgument {
            message: message.to_string(),
        }
    }

    fn transcript_data(
        lockable_threshold_sig_data_store: LockableThresholdSigDataStore,
    ) -> TranscriptData {
        lockable_threshold_sig_data_store
            .read()
            .transcript_data(DkgId::IDkgId(I_DKG_ID))
            .expect("missing transcript data")
            .clone()
    }
}

fn responses_with(data: Vec<(NodeId, Response)>) -> BTreeMap<NodeId, Response> {
    data.into_iter().collect()
}

fn csp_transcript(content: u8) -> CspDkgTranscript {
    CspDkgTranscript::Secp256k1(CLibTranscriptBytes {
        dealer_public_keys: vec![],
        dealer_reshare_indices: None,
        public_coefficients: PublicCoefficientsBytes::from(pub_coeffs(content)),
        receiver_data: vec![],
    })
}

fn csp_response() -> CspResponse {
    CspResponse::Secp256k1(CLibResponseBytes {
        complaints: Default::default(),
    })
}

fn response() -> Response {
    Response::from(&csp_response())
}

fn dkg_config_with_receivers(
    dkg_id: IDkgId,
    receivers: Vec<NodeId>,
    threshold: Threshold,
) -> DkgConfig {
    create_config(DkgConfigData {
        dkg_id,
        // we only add a dealer to obtain a valid config
        dealers: vec![NODE_1],
        receivers,
        threshold,
        resharing_transcript: None,
    })
}

fn dkg_config_with_resharing_transcript(
    dkg_id: IDkgId,
    receivers: Vec<NodeId>,
    threshold: Threshold,
    resharing_transcript: Transcript,
) -> DkgConfig {
    create_config(DkgConfigData {
        dkg_id,
        // we only add a dealer to obtain a valid config
        dealers: vec![NODE_1],
        receivers,
        threshold,
        resharing_transcript: Some(resharing_transcript),
    })
}

fn create_config(config_data: DkgConfigData) -> DkgConfig {
    DkgConfig::new(config_data).expect("unable to create dkg config")
}

fn invalid_arg_error(message: &str) -> CryptoError {
    CryptoError::InvalidArgument {
        message: message.to_string(),
    }
}
