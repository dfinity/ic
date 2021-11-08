#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::sign::tests::REG_V2;
use crate::sign::threshold_sig::ni_dkg::test_utils::{
    csp_dealing, dkg_config, map_of, minimal_dkg_config_data_without_resharing, nodes, DKG_ID,
    THRESHOLD,
};
use crate::sign::threshold_sig::ni_dkg::transcript::create_transcript;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InvalidArgumentError;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    ni_dkg_groth20_bls12_381, CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_test_utilities::crypto::basic_utilities::set_of;
use ic_test_utilities::crypto::empty_ni_csp_dkg_transcript;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, NODE_6};
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::threshold_sig::ni_dkg::config::{NiDkgConfigData, NiDkgThreshold};
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgDealing;
use ic_types::{NodeId, NumberOfNodes};
use std::collections::BTreeMap;

const PK_BYTES_1: PublicKeyBytes = PublicKeyBytes([42; PublicKeyBytes::SIZE]);
const PK_BYTES_2: PublicKeyBytes = PublicKeyBytes([42; PublicKeyBytes::SIZE]);

mod create_transcript {
    use super::*;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateTranscriptError;
    use ic_types::crypto::error::InvalidArgumentError;

    #[test]
    fn should_return_error_if_dealings_empty() {
        let config = dkg_config(minimal_dkg_config_data_without_resharing());
        let csp = MockAllCryptoServiceProvider::new();
        let verified_dealings = BTreeMap::new();

        let result = create_transcript(&csp, &config, &verified_dealings);

        assert_eq!(
            result,
            Err(insufficient_dealings_error(
                "The verified dealings must not be empty"
            ))
        );
    }

    #[test]
    fn should_return_error_if_too_few_dealings_provided() {
        let config = dkg_config(NiDkgConfigData {
            dealers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            max_corrupt_dealers: NumberOfNodes::new(3),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = MockAllCryptoServiceProvider::new();
        let verified_dealings = verified_dealings(&[(NODE_1, dealing_1()), (NODE_2, dealing_2())]);

        let result = create_transcript(&csp, &config, &verified_dealings);

        assert_eq!(result, Err(insufficient_dealings_error("Too few dealings: got 2, need more than 3 (the maximum number of corrupt dealers).")));
    }

    #[test]
    #[should_panic(
        expected = "Missing node ids in dealers: {3jo2y-lqbaa-aaaaa-aaaap-2ai, hr2go-2qeaa-aaaaa-aaaap-2ai}"
    )]
    fn should_panic_if_dealing_node_id_missing_in_dealers() {
        const MISSING_NODE_ID_IN_DEALERS_1: NodeId = NODE_1;
        const MISSING_NODE_ID_IN_DEALERS_2: NodeId = NODE_4;
        let config = dkg_config(NiDkgConfigData {
            receivers: nodes(&[
                MISSING_NODE_ID_IN_DEALERS_1,
                NODE_2,
                NODE_3,
                MISSING_NODE_ID_IN_DEALERS_2,
            ]),
            dealers: nodes(&[NODE_2, NODE_3]),
            max_corrupt_dealers: NumberOfNodes::new(1),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = MockAllCryptoServiceProvider::new();
        let verified_dealings = verified_dealings(&[
            (MISSING_NODE_ID_IN_DEALERS_1, dealing_1()),
            (NODE_2, dealing_2()),
            (NODE_3, dealing_2()),
            (MISSING_NODE_ID_IN_DEALERS_2, dealing_3()),
        ]);

        let _panic = create_transcript(&csp, &config, &verified_dealings).unwrap_err();
    }

    #[test]
    fn should_return_error_if_max_corrupt_dealer_many_dealings_provided() {
        let config = dkg_config(NiDkgConfigData {
            dealers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            max_corrupt_dealers: NumberOfNodes::new(2),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = MockAllCryptoServiceProvider::new();
        let verified_dealings = verified_dealings(&[(NODE_1, dealing_1()), (NODE_2, dealing_2())]);

        let result = create_transcript(&csp, &config, &verified_dealings);

        assert_eq!(result.unwrap_err(), insufficient_dealings_error("Too few dealings: got 2, need more than 2 (the maximum number of corrupt dealers)."));
    }

    #[test]
    fn should_return_ok_if_sufficiently_many_dealings_provided() {
        let config = dkg_config(NiDkgConfigData {
            receivers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            dealers: nodes(&[NODE_1, NODE_2, NODE_3]),
            max_corrupt_dealers: NumberOfNodes::new(2),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = csp_with_create_transcript_returning(Ok(empty_ni_csp_dkg_transcript()));
        let verified_dealings = verified_dealings(&[
            (NODE_1, dealing_1()),
            (NODE_2, dealing_2()),
            (NODE_3, dealing_3()),
        ]);

        let result = create_transcript(&csp, &config, &verified_dealings);

        assert!(result.is_ok())
    }

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let config = dkg_config(NiDkgConfigData {
            receivers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            dealers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            max_corrupt_dealers: NumberOfNodes::new(1),
            threshold: THRESHOLD,
            ..minimal_dkg_config_data_without_resharing()
        });
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_transcript()
            .withf(
                move |algorithm_id, threshold, number_of_receivers, csp_dealings| {
                    *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *threshold == THRESHOLD
                        && *number_of_receivers == NumberOfNodes::new(4)
                        && *csp_dealings == map_of(vec![(0, csp_dealing_1()), (2, csp_dealing_3())])
                },
            )
            .times(1)
            .return_const(Ok(empty_ni_csp_dkg_transcript()));
        let verified_dealings = verified_dealings(&[(NODE_1, dealing_1()), (NODE_3, dealing_3())]);

        let _ = create_transcript(&csp, &config, &verified_dealings);
    }

    #[test]
    fn should_return_correct_transcript_including_csp_transcript() {
        let receivers = nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]);
        let config = dkg_config(NiDkgConfigData {
            dkg_id: DKG_ID,
            threshold: THRESHOLD,
            receivers: receivers.clone(),
            registry_version: REG_V2,
            dealers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            max_corrupt_dealers: NumberOfNodes::new(1),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp_transcript = empty_ni_csp_dkg_transcript();
        let csp = csp_with_create_transcript_returning(Ok(csp_transcript.clone()));
        let verified_dealings = verified_dealings(&[(NODE_1, dealing_1()), (NODE_3, dealing_3())]);

        let transcript = create_transcript(&csp, &config, &verified_dealings).unwrap();

        assert_eq!(
            transcript,
            NiDkgTranscript {
                dkg_id: DKG_ID,
                threshold: NiDkgThreshold::new(THRESHOLD).unwrap(),
                committee: NiDkgReceivers::new(receivers).unwrap(),
                registry_version: REG_V2,
                internal_csp_transcript: csp_transcript
            }
        )
    }

    #[test]
    // We only smoke test this on a single error variant. Since all lead to panic,
    // this tests for a panic.
    #[should_panic(
        expected = "NI-DKG create_transcript error - Precondition violated: dealings have not been verified. InvalidDealingError for dealing with index 7: InvalidArgumentError { message: \"some error\" }"
    )]
    fn should_panic_if_csp_returns_error() {
        let config = dkg_config(NiDkgConfigData {
            receivers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            dealers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            max_corrupt_dealers: NumberOfNodes::new(1),
            threshold: THRESHOLD,
            ..minimal_dkg_config_data_without_resharing()
        });
        let invalid_dealing_error = invalid_dealing_error();
        let csp = csp_with_create_transcript_returning(Err(invalid_dealing_error));

        let verified_dealings = verified_dealings(&[(NODE_1, dealing_1()), (NODE_3, dealing_3())]);

        let _panic = create_transcript(&csp, &config, &verified_dealings).unwrap_err();
    }

    fn csp_with_create_transcript_returning(
        result: Result<CspNiDkgTranscript, CspDkgCreateTranscriptError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_transcript().times(1).return_const(result);
        csp
    }

    fn invalid_dealing_error() -> CspDkgCreateTranscriptError {
        CspDkgCreateTranscriptError::InvalidDealingError {
            dealer_index: 7,
            error: InvalidArgumentError {
                message: "some error".to_string(),
            },
        }
    }
}

mod create_transcript_with_resharing {
    use super::*;
    use crate::sign::threshold_sig::ni_dkg::test_utils::{
        dummy_transcript, minimal_dkg_config_data_with_resharing, RESHARING_TRANSCRIPT_THRESHOLD,
    };
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateReshareTranscriptError;
    use ic_types::crypto::error::MalformedPublicKeyError;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let pub_coeffs = vec![PK_BYTES_1, PK_BYTES_2];
        let resharing_transcript = NiDkgTranscript {
            committee: receivers(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, NODE_6]),
            internal_csp_transcript: csp_ni_dkg_transcript(&pub_coeffs),
            threshold: NiDkgThreshold::new(RESHARING_TRANSCRIPT_THRESHOLD).unwrap(),
            ..dummy_transcript()
        };
        let config = dkg_config(NiDkgConfigData {
            receivers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            dealers: nodes(&[NODE_1, NODE_3, NODE_5, NODE_6]),
            max_corrupt_dealers: NumberOfNodes::new(1),
            threshold: THRESHOLD,
            resharing_transcript: Some(resharing_transcript),
            ..minimal_dkg_config_data_with_resharing()
        });
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_resharing_transcript()
            .withf(
                move |algorithm_id,
                      threshold,
                      number_of_receivers,
                      csp_dealings,
                      resharing_pub_coeffs| {
                    *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *threshold == THRESHOLD
                        && *number_of_receivers == NumberOfNodes::new(4)
                        // the following are the dealer's indices in the re-sharing committee:
                        && *csp_dealings == map_of(vec![(2, csp_dealing_3()), (5, csp_dealing_6())])
                        && *resharing_pub_coeffs == csp_pub_coeffs(pub_coeffs.clone())
                },
            )
            .times(1)
            .return_const(Ok(empty_ni_csp_dkg_transcript()));
        let verified_dealings = verified_dealings(&[(NODE_3, dealing_3()), (NODE_6, dealing_6())]);

        let result = create_transcript(&csp, &config, &verified_dealings);
        assert!(result.is_ok())
    }

    #[test]
    fn should_return_error_if_too_few_dealings_for_resharing() {
        let threshold_requiring_at_least_3_dealings =
            NiDkgThreshold::new(NumberOfNodes::new(3)).unwrap();
        let resharing_transcript = NiDkgTranscript {
            committee: receivers(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, NODE_6]),
            threshold: threshold_requiring_at_least_3_dealings,
            ..dummy_transcript()
        };
        let config = dkg_config(NiDkgConfigData {
            receivers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            dealers: nodes(&[NODE_1, NODE_3, NODE_5, NODE_6]),
            resharing_transcript: Some(resharing_transcript),
            ..minimal_dkg_config_data_with_resharing()
        });
        let csp = MockAllCryptoServiceProvider::new();
        let verified_dealings = verified_dealings(&[(NODE_3, dealing_3()), (NODE_6, dealing_6())]);

        let error = create_transcript(&csp, &config, &verified_dealings).unwrap_err();

        assert_eq!(
            error,
            insufficient_dealings_error("Too few dealings for resharing: got 2, need at least 3 (threshold in re-sharing transcript).")
        )
    }

    #[test]
    fn should_forward_error_from_csp() {
        let pub_coeffs = vec![PK_BYTES_1, PK_BYTES_2];
        let resharing_transcript = NiDkgTranscript {
            committee: receivers(&[NODE_1, NODE_2, NODE_3, NODE_4, NODE_5, NODE_6]),
            internal_csp_transcript: csp_ni_dkg_transcript(&pub_coeffs),
            ..dummy_transcript()
        };
        let config = dkg_config(NiDkgConfigData {
            receivers: nodes(&[NODE_1, NODE_2, NODE_3, NODE_4]),
            dealers: nodes(&[NODE_1, NODE_3, NODE_5, NODE_6]),
            resharing_transcript: Some(resharing_transcript),
            ..minimal_dkg_config_data_with_resharing()
        });
        let malformed_pk_error = malformed_pk_error();
        let csp = csp_with_create_resharing_transcript_returning(Err(
            CspDkgCreateReshareTranscriptError::MalformedResharePublicCoefficientsError(
                malformed_pk_error.clone(),
            ),
        ));
        let verified_dealings = verified_dealings(&[(NODE_3, dealing_3()), (NODE_6, dealing_6())]);

        let error = create_transcript(&csp, &config, &verified_dealings).unwrap_err();

        assert_eq!(
            error,
            DkgCreateTranscriptError::MalformedResharingTranscriptInConfig(malformed_pk_error)
        );
    }

    fn csp_with_create_resharing_transcript_returning(
        result: Result<CspNiDkgTranscript, CspDkgCreateReshareTranscriptError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_resharing_transcript()
            .times(1)
            .return_const(result);
        csp
    }

    fn malformed_pk_error() -> MalformedPublicKeyError {
        MalformedPublicKeyError {
            algorithm: AlgorithmId::Placeholder,
            key_bytes: None,
            internal_error: "some error".to_string(),
        }
    }
}

/// Creates a map of `NodeId` to `NiDkgDealing` that can be used as argument
/// to `create_transcript`. For each entry, the `NodeId` is associated with
/// the `NiDkgDealing`.
fn verified_dealings(dealings: &[(NodeId, NiDkgDealing)]) -> BTreeMap<NodeId, NiDkgDealing> {
    let mut verified_dealings = BTreeMap::new();
    dealings.iter().for_each(|(node_id, dealing)| {
        verified_dealings.insert(*node_id, dealing.clone());
    });
    verified_dealings
}

fn dealing_1() -> NiDkgDealing {
    NiDkgDealing::from(csp_dealing_1())
}

fn dealing_2() -> NiDkgDealing {
    NiDkgDealing::from(csp_dealing_2())
}

fn dealing_3() -> NiDkgDealing {
    NiDkgDealing::from(csp_dealing_3())
}

fn dealing_6() -> NiDkgDealing {
    NiDkgDealing::from(csp_dealing_6())
}

fn csp_dealing_1() -> CspNiDkgDealing {
    let dealing_data = 42;
    csp_dealing(dealing_data)
}

fn csp_dealing_2() -> CspNiDkgDealing {
    let dealing_data = 43;
    csp_dealing(dealing_data)
}

fn csp_dealing_3() -> CspNiDkgDealing {
    let dealing_data = 44;
    csp_dealing(dealing_data)
}

fn csp_dealing_6() -> CspNiDkgDealing {
    let dealing_data = 47;
    csp_dealing(dealing_data)
}

mod load_transcript {
    use super::*;
    use crate::sign::tests::REG_V1;
    use crate::sign::threshold_sig::ni_dkg::test_utils::dummy_transcript;
    use crate::sign::threshold_sig::ni_dkg::utils::epoch;
    use crate::sign::threshold_sig::tests::NI_DKG_ID_1;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgLoadPrivateKeyError;
    use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
    use ic_logger::replica_logger::no_op_logger;
    use ic_types::crypto::error::{InvalidArgumentError, KeyNotFoundError};
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
    use ic_types::crypto::KeyId;

    const PK_BYTES_1: PublicKeyBytes = PublicKeyBytes([42; PublicKeyBytes::SIZE]);
    const PK_BYTES_2: PublicKeyBytes = PublicKeyBytes([43; PublicKeyBytes::SIZE]);

    #[test]
    fn should_insert_transcript_pub_coeffs_into_store() {
        let pub_coeffs = vec![PK_BYTES_1, PK_BYTES_2];
        let transcript = NiDkgTranscript {
            dkg_id: NI_DKG_ID_1,
            internal_csp_transcript: csp_ni_dkg_transcript(&pub_coeffs),
            ..dummy_transcript()
        };
        let csp = csp_with_load_threshold_signing_key_returning(Ok(()));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let result = load_transcript(
            &NODE_1,
            &threshold_sig_data_store,
            &csp,
            &transcript,
            &no_op_logger(),
        );

        let transcript_data = transcript_data_from_store(&threshold_sig_data_store, NI_DKG_ID_1);
        assert_eq!(
            transcript_data.public_coefficients(),
            &csp_pub_coeffs(pub_coeffs)
        );
        assert_eq!(result, Ok(LoadTranscriptResult::SigningKeyAvailable));
    }

    #[test]
    fn should_insert_transcript_data_into_store_and_return_ok_if_csp_returns_key_not_found_error() {
        let transcript = NiDkgTranscript {
            dkg_id: NI_DKG_ID_1,
            ..dummy_transcript()
        };
        let csp = csp_with_load_threshold_signing_key_returning(Err(key_not_found_error()));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let result = load_transcript(
            &NODE_1,
            &threshold_sig_data_store,
            &csp,
            &transcript,
            &no_op_logger(),
        );

        let transcript_data =
            transcript_data_from_store_option(&threshold_sig_data_store, NI_DKG_ID_1);
        assert!(transcript_data.is_some());
        assert_eq!(result, Ok(LoadTranscriptResult::SigningKeyUnavailable));
    }

    #[test]
    fn should_return_node_indices_from_store_in_sorted_order() {
        let transcript = NiDkgTranscript {
            committee: receivers(&[NODE_2, NODE_1, NODE_3]),
            dkg_id: NI_DKG_ID_1,
            ..dummy_transcript()
        };
        let csp = csp_with_load_threshold_signing_key_returning(Ok(()));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let result = load_transcript(
            &NODE_1,
            &threshold_sig_data_store,
            &csp,
            &transcript,
            &no_op_logger(),
        );

        let transcript_data = transcript_data_from_store(&threshold_sig_data_store, NI_DKG_ID_1);
        assert_eq!(transcript_data.index(NODE_1), Some(&0));
        assert_eq!(transcript_data.index(NODE_2), Some(&1));
        assert_eq!(transcript_data.index(NODE_3), Some(&2));
        assert!(result.is_ok());
    }

    #[test]
    fn should_insert_single_node_index_into_store() {
        let transcript = NiDkgTranscript {
            committee: receivers(&[NODE_1]),
            dkg_id: NI_DKG_ID_1,
            ..dummy_transcript()
        };
        let csp = csp_with_load_threshold_signing_key_returning(Ok(()));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let result = load_transcript(
            &NODE_1,
            &threshold_sig_data_store,
            &csp,
            &transcript,
            &no_op_logger(),
        );

        let transcript_data = transcript_data_from_store(&threshold_sig_data_store, NI_DKG_ID_1);
        assert_eq!(transcript_data.index(NODE_1), Some(&0));
        assert!(result.is_ok());
    }

    #[test]
    fn should_not_call_csp_load_threshold_signing_key_and_return_ok_if_not_in_committee() {
        const NODE_NOT_IN_COMMITTEE: NodeId = NODE_2;
        let transcript = NiDkgTranscript {
            committee: receivers(&[NODE_1]),
            ..dummy_transcript()
        };
        let csp = MockAllCryptoServiceProvider::new(); // expect no call!

        let result = load_transcript(
            &NODE_NOT_IN_COMMITTEE,
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript,
            &no_op_logger(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_call_csp_load_threshold_signing_key_correctly_if_in_committee() {
        let csp_transcript = csp_transcript();
        let transcript = NiDkgTranscript {
            dkg_id: NI_DKG_ID_1,
            committee: receivers(&[NODE_3, NODE_1, NODE_2]),
            registry_version: REG_V1,
            internal_csp_transcript: csp_transcript.clone(),
            ..dummy_transcript()
        };
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_load_threshold_signing_key()
            .withf(
                move |algorithm_id, dkg_id, epoch_, transcript, receiver_index| {
                    *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *dkg_id == NI_DKG_ID_1
                        && *epoch_ == epoch(REG_V1)
                        && *transcript == csp_transcript
                        && *receiver_index == 2 // index of NODE_3 in (sorted)
                                                // resharing committee
                },
            )
            .times(1)
            .return_const(Ok(()));

        let _ = load_transcript(
            &NODE_3,
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript,
            &no_op_logger(),
        );
    }

    #[test]
    fn should_return_ok_if_csp_load_threshold_signing_key_was_successful() {
        let transcript = NiDkgTranscript {
            committee: receivers(&[NODE_3, NODE_1, NODE_2]),
            registry_version: REG_V1,
            ..dummy_transcript()
        };
        let csp = csp_with_load_threshold_signing_key_returning(Ok(()));

        let result = load_transcript(
            &NODE_3,
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript,
            &no_op_logger(),
        );

        assert!(result.is_ok());
    }

    #[test]
    // We only smoke test this on a single error variant.
    fn should_forward_error_from_csp() {
        let transcript = NiDkgTranscript {
            committee: receivers(&[NODE_3, NODE_1, NODE_2]),
            registry_version: REG_V1,
            ..dummy_transcript()
        };
        let invalid_arg_error = invalid_arg_error();
        let csp = csp_with_load_threshold_signing_key_returning(Err(
            CspDkgLoadPrivateKeyError::InvalidTranscriptError(invalid_arg_error.clone()),
        ));

        let error = load_transcript(
            &NODE_3,
            &LockableThresholdSigDataStore::new(),
            &csp,
            &transcript,
            &no_op_logger(),
        )
        .unwrap_err();

        assert_eq!(
            error,
            DkgLoadTranscriptError::InvalidTranscript(invalid_arg_error)
        );
    }

    #[test]
    // We only smoke test this on a single error variant.
    fn should_not_insert_transcript_data_into_store_if_csp_returns_error() {
        let transcript = NiDkgTranscript {
            committee: receivers(&[NODE_3, NODE_1, NODE_2]),
            registry_version: REG_V1,
            ..dummy_transcript()
        };
        let csp = csp_with_load_threshold_signing_key_returning(Err(
            CspDkgLoadPrivateKeyError::InvalidTranscriptError(invalid_arg_error()),
        ));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let result = load_transcript(
            &NODE_3,
            &threshold_sig_data_store,
            &csp,
            &transcript,
            &no_op_logger(),
        );

        let transcript_data =
            transcript_data_from_store_option(&threshold_sig_data_store, NI_DKG_ID_1);
        assert!(transcript_data.is_none());
        assert!(result.is_err());
    }

    #[test]
    fn should_insert_transcript_data_into_store_and_return_ok_if_csp_returns_epoch_too_old_error() {
        let transcript = NiDkgTranscript {
            dkg_id: NI_DKG_ID_1,
            ..dummy_transcript()
        };
        let csp = csp_with_load_threshold_signing_key_returning(Err(epoch_too_old_error()));
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let result = load_transcript(
            &NODE_1,
            &threshold_sig_data_store,
            &csp,
            &transcript,
            &no_op_logger(),
        );

        let transcript_data =
            transcript_data_from_store_option(&threshold_sig_data_store, NI_DKG_ID_1);
        assert!(transcript_data.is_some());
        assert_eq!(
            result,
            Ok(LoadTranscriptResult::SigningKeyUnavailableDueToDiscard)
        );
    }

    fn epoch_too_old_error() -> CspDkgLoadPrivateKeyError {
        CspDkgLoadPrivateKeyError::EpochTooOldError {
            ciphertext_epoch: Epoch::from(4),
            secret_key_epoch: Epoch::from(3),
        }
    }

    fn csp_with_load_threshold_signing_key_returning(
        result: Result<(), CspDkgLoadPrivateKeyError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_load_threshold_signing_key()
            .times(1)
            .return_const(result);
        csp
    }

    fn transcript_data_from_store(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        dkg_id: NiDkgId,
    ) -> TranscriptData {
        transcript_data_from_store_option(lockable_threshold_sig_data_store, dkg_id)
            .expect("missing transcript data")
    }

    fn transcript_data_from_store_option(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        dkg_id: NiDkgId,
    ) -> Option<TranscriptData> {
        lockable_threshold_sig_data_store
            .read()
            .transcript_data(DkgId::NiDkgId(dkg_id))
            .cloned()
    }

    fn key_not_found_error() -> CspDkgLoadPrivateKeyError {
        CspDkgLoadPrivateKeyError::KeyNotFoundError(KeyNotFoundError {
            internal_error: "some error".to_string(),
            key_id: KeyId::from([1u8; 32]),
        })
    }

    fn invalid_arg_error() -> InvalidArgumentError {
        InvalidArgumentError {
            message: "some error".to_string(),
        }
    }
}

fn csp_ni_dkg_transcript(pub_coeffs: &[PublicKeyBytes]) -> CspNiDkgTranscript {
    CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
        public_coefficients: PublicCoefficientsBytes {
            coefficients: pub_coeffs.to_vec(),
        },
        receiver_data: Default::default(),
    })
}

fn csp_transcript() -> CspNiDkgTranscript {
    csp_ni_dkg_transcript(&[PK_BYTES_1])
}

fn csp_pub_coeffs(pub_coeffs: Vec<PublicKeyBytes>) -> CspPublicCoefficients {
    CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
        coefficients: pub_coeffs,
    })
}

fn receivers(nodes: &[NodeId]) -> NiDkgReceivers {
    NiDkgReceivers::new(set_of(nodes)).expect("failed to create receivers")
}

fn insufficient_dealings_error(message: &str) -> DkgCreateTranscriptError {
    DkgCreateTranscriptError::InsufficientDealings(InvalidArgumentError {
        message: message.to_string(),
    })
}
