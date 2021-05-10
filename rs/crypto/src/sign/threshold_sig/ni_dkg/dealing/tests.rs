#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::sign::tests::{
    dealing_encryption_pk_record_with, registry_with_records, REG_V1, REG_V2,
};
use crate::sign::threshold_sig::ni_dkg::test_utils::csp_fs_enc_pk;
use crate::sign::threshold_sig::ni_dkg::test_utils::dealing_enc_pk_record;
use crate::sign::threshold_sig::ni_dkg::test_utils::map_of;
use crate::sign::threshold_sig::ni_dkg::test_utils::REGISTRY_FS_ENC_PK_SIZE;
use crate::sign::threshold_sig::ni_dkg::test_utils::{
    csp_dealing, dkg_config, minimal_dkg_config_data_without_resharing, transcript, DKG_ID,
    RESHARING_TRANSCRIPT_DKG_ID, THRESHOLD,
};
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgCreateDealingError;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPublicKey, CspNiDkgDealing, Epoch,
};
use ic_test_utilities::crypto::basic_utilities::set_of;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_42};
use ic_types::crypto::error::InvalidArgumentError;
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfigData;
use ic_types::crypto::threshold_sig::ni_dkg::errors::{
    FsEncryptionPublicKeyNotInRegistryError, MalformedFsEncryptionPublicKeyError, NotADealerError,
};
use ic_types::crypto::AlgorithmId;
use ic_types::registry::RegistryClientError;

const PK_VALUE_1: u8 = 42;
const PK_VALUE_2: u8 = 43;
const PK_VALUE_3: u8 = 44;
const DEALING_VALUE_1: u8 = 22;

mod create_dealing {
    use super::*;
    use ic_types::crypto::error::MalformedPublicKeyError;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let dkg_config = dkg_config(NiDkgConfigData {
            dkg_id: DKG_ID,
            receivers: set_of(&[NODE_1]),
            threshold: THRESHOLD,
            registry_version: REG_V2,
            ..minimal_dkg_config_data_without_resharing()
        });
        let key_record = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_dealing()
            .withf(
                move |algorithm_id, dkg_id, dealer_index, threshold, epoch_, receiver_keys| {
                    *dkg_id == DKG_ID
                        && *dealer_index == 0
                        && *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *threshold == THRESHOLD
                        && *epoch_ == epoch(REG_V2)
                        && *receiver_keys == map_of(vec![(0u32, csp_fs_enc_pk(PK_VALUE_1))])
                },
            )
            .times(1)
            .return_const(Ok(csp_dealing(DEALING_VALUE_1)));

        let _ = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![key_record]),
            &dkg_config,
        );
    }

    #[test]
    fn should_not_call_csp_load_private_key_if_no_resharing_transcript_present() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_dealing()
            .times(1)
            .return_const(Ok(csp_dealing(DEALING_VALUE_1)));
        csp.expect_load_threshold_signing_key().times(0);

        let _ = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1)]),
            &dkg_config,
        );
    }

    #[test]
    fn should_call_csp_correctly_with_multiple_receivers_and_keys() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1, NODE_2, NODE_3]),
            dealers: set_of(&[NODE_1, NODE_4]),
            ..minimal_dkg_config_data_without_resharing()
        });

        let key_record_1 = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let key_record_2 = dealing_enc_pk_record(NODE_2, REG_V2, PK_VALUE_2);
        let key_record_3 = dealing_enc_pk_record(NODE_3, REG_V2, PK_VALUE_3);

        // NODE_1 is the first one in the set of dealers. Note that the nodes are sorted
        // lexicographically.
        let csp = csp_with_create_dealing_expecting_receiver_keys_and_dealer_index(
            0,
            map_of(vec![
                (0u32, csp_fs_enc_pk(PK_VALUE_1)),
                (1u32, csp_fs_enc_pk(PK_VALUE_2)),
                (2u32, csp_fs_enc_pk(PK_VALUE_3)),
            ]),
        );

        let _ = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![key_record_1, key_record_2, key_record_3]),
            &dkg_config,
        );
    }

    #[test]
    fn should_return_error_if_node_is_not_a_dealer() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_2]),
            dealers: set_of(&[NODE_3, NODE_4]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let not_a_dealer_node = NODE_1;
        let csp = MockAllCryptoServiceProvider::new();

        let result = create_dealing(
            &not_a_dealer_node,
            &csp,
            &registry_with_records(vec![dealing_enc_pk_record(NODE_2, REG_V2, PK_VALUE_1)]),
            &dkg_config,
        );

        assert_eq!(
            result.unwrap_err(),
            DkgCreateDealingError::NotADealer(NotADealerError {
                node_id: not_a_dealer_node
            })
        );
    }

    #[test]
    fn should_return_error_if_registry_version_too_old() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            registry_version: REG_V2,
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = MockAllCryptoServiceProvider::new();
        let registry_with_too_old_latest_version =
            registry_with_records(vec![dealing_enc_pk_record(NODE_2, REG_V1, PK_VALUE_1)]);

        let result = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_too_old_latest_version,
            &dkg_config,
        );

        assert_eq!(
            result.unwrap_err(),
            DkgCreateDealingError::Registry(RegistryClientError::VersionNotAvailable {
                version: REG_V2
            })
        );
    }

    #[test]
    fn should_return_error_if_receiver_enc_key_not_in_registry() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            registry_version: REG_V2,
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = MockAllCryptoServiceProvider::new();

        let registry_with_missing_receiver_enc_key =
            registry_with_records(vec![dealing_enc_pk_record(NODE_2, REG_V2, PK_VALUE_1)]);
        let result = create_dealing(
            &NODE_1,
            &csp,
            // NODE_1 key is missing in registry:
            &registry_with_missing_receiver_enc_key,
            &dkg_config,
        );

        assert_eq!(
            result.unwrap_err(),
            DkgCreateDealingError::FsEncryptionPublicKeyNotInRegistry(
                FsEncryptionPublicKeyNotInRegistryError {
                    registry_version: REG_V2,
                    node_id: NODE_1,
                }
            )
        );
    }

    #[test]
    fn should_return_error_if_receiver_enc_key_in_registry_is_malformed() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_without_resharing()
        });
        const WRONG_REGISTRY_FS_ENC_PK_SIZE: usize = REGISTRY_FS_ENC_PK_SIZE - 20;
        let key_record = dealing_encryption_pk_record_with(
            NODE_1,
            vec![PK_VALUE_1; WRONG_REGISTRY_FS_ENC_PK_SIZE],
            REG_V2,
        );
        let csp = MockAllCryptoServiceProvider::new();

        let result = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![key_record]),
            &dkg_config,
        );

        assert_eq!(
            result.unwrap_err(),
            DkgCreateDealingError::MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError {
                internal_error: "MalformedFsEncryptionPublicKeyError {  key_bytes: 0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a, internal_error: Wrong data length 28, expected length 48. }".to_string()
            })
        );
    }

    #[test]
    fn should_return_dealing_from_csp() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp_dealing = csp_dealing(DEALING_VALUE_1);
        let csp = csp_with_create_dealing_returning(Ok(csp_dealing.clone()));

        let dealing = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1)]),
            &dkg_config,
        );

        assert_eq!(dealing.unwrap(), NiDkgDealing::from(csp_dealing));
    }

    #[test]
    // We only smoke test this on a single error variant.
    fn should_forward_error_from_csp() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = csp_with_create_dealing_returning(Err(malformed_fs_pk()));

        let error = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1)]),
            &dkg_config,
        )
        .unwrap_err();

        assert_eq!(
            error,
            DkgCreateDealingError::MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError {
                internal_error: "error for receiver index 0: MalformedPublicKeyError { algorithm: Placeholder, key_bytes: None, internal_error: \"some error\" }".to_string()
            })
        );
    }

    #[test]
    // We only smoke test this on a single error variant.
    #[should_panic(expected = "The algorithm id EcdsaP256 is unsupported.")]
    fn should_panic_if_csp_error_is_mapped_to_panic() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = csp_with_create_dealing_returning(Err(unsupported_algorithm_id()));

        let _panic = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1)]),
            &dkg_config,
        );
    }

    fn csp_with_create_dealing_returning(
        result: Result<CspNiDkgDealing, CspDkgCreateDealingError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_dealing().times(1).return_const(result);
        csp
    }

    fn csp_with_create_dealing_expecting_receiver_keys_and_dealer_index(
        expected_index: NodeIndex,
        expected_receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_create_dealing()
            .withf(
                move |algorithm_id, dkg_id, dealer_index, threshold, epoch_, receiver_keys| {
                    *dkg_id == DKG_ID
                        && *dealer_index == expected_index
                        && *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *threshold == THRESHOLD
                        && *epoch_ == epoch(REG_V2)
                        && *receiver_keys == expected_receiver_keys
                },
            )
            .times(1)
            .return_const(Ok(csp_dealing(DEALING_VALUE_1)));
        csp
    }

    fn malformed_fs_pk() -> CspDkgCreateDealingError {
        CspDkgCreateDealingError::MalformedFsPublicKeyError {
            receiver_index: 0,
            error: MalformedPublicKeyError {
                algorithm: AlgorithmId::Placeholder,
                key_bytes: None,
                internal_error: "some error".to_string(),
            },
        }
    }

    fn unsupported_algorithm_id() -> CspDkgCreateDealingError {
        CspDkgCreateDealingError::UnsupportedAlgorithmId(AlgorithmId::EcdsaP256)
    }
}

// For resharing, we only test the additional code paths to achieve test
// coverage
mod create_dealing_with_resharing_transcript {
    use super::*;
    use crate::sign::threshold_sig::ni_dkg::test_utils::minimal_dkg_config_data_with_resharing;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
        CspDkgCreateReshareDealingError, CspDkgLoadPrivateKeyError,
    };
    use ic_types::crypto::error::{InvalidArgumentError, MalformedPublicKeyError};

    #[test]
    fn should_call_csp_load_private_key_with_correct_parameters() {
        let resharing_transcript = transcript(
            set_of(&[NODE_3, NODE_1, NODE_2]),
            REG_V1,
            RESHARING_TRANSCRIPT_DKG_ID,
        );
        let dkg_config = dkg_config(NiDkgConfigData {
            dkg_id: DKG_ID,
            receivers: set_of(&[NODE_3]),
            dealers: set_of(&[NODE_1, NODE_3]),
            threshold: THRESHOLD,
            registry_version: REG_V2,
            resharing_transcript: Some(resharing_transcript.clone()),
            ..minimal_dkg_config_data_with_resharing()
        });
        let resharing_enc_pk_record = dealing_enc_pk_record(NODE_3, REG_V1, PK_VALUE_1);
        let enc_pk_record = dealing_enc_pk_record(NODE_3, REG_V2, PK_VALUE_2);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_load_threshold_signing_key()
            .withf(
                move |algorithm_id, dkg_id, epoch_, csp_transcript, receiver_index| {
                    *dkg_id == RESHARING_TRANSCRIPT_DKG_ID
                        && *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *epoch_ == epoch(REG_V1)
                        && *csp_transcript == CspNiDkgTranscript::from(&resharing_transcript)
                        && *receiver_index == 2 // index of NODE_3 in (sorted)
                                                // resharing committee
                },
            )
            .times(1)
            .return_const(Ok(()));
        expect_create_resharing_dealing_returning(&mut csp, Ok(csp_dealing(DEALING_VALUE_1)));

        let _ = create_dealing(
            &NODE_3,
            &csp,
            &registry_with_records(vec![resharing_enc_pk_record, enc_pk_record]),
            &dkg_config,
        );
    }

    #[test]
    fn should_call_csp_create_resharing_dealing_with_correct_parameters() {
        let resharing_transcript = transcript(
            set_of(&[NODE_3, NODE_1, NODE_2]),
            REG_V1,
            RESHARING_TRANSCRIPT_DKG_ID,
        );

        let dkg_config = dkg_config(NiDkgConfigData {
            dkg_id: DKG_ID,
            receivers: set_of(&[NODE_3]),
            dealers: set_of(&[NODE_1, NODE_3]),
            threshold: THRESHOLD,
            registry_version: REG_V2,
            resharing_transcript: Some(resharing_transcript.clone()),
            ..minimal_dkg_config_data_with_resharing()
        });
        let resharing_enc_pk_record = dealing_enc_pk_record(NODE_3, REG_V1, PK_VALUE_1);
        let enc_pk_record = dealing_enc_pk_record(NODE_3, REG_V2, PK_VALUE_2);
        let mut csp = MockAllCryptoServiceProvider::new();
        expect_load_threshold_signing_key_returning(&mut csp, Ok(()));
        csp.expect_create_resharing_dealing()
            .withf(
                move |algorithm_id,
                      dkg_id,
                      dealer_index,
                      threshold,
                      epoch_,
                      receiver_keys,
                      resharing_public_coefficients| {
                    *dkg_id == DKG_ID
                        // The dealer index is the index of NODE_3 in the set of dealers.
                        // Note that the nodes are sorted lexicographically.
                        && *dealer_index == 2
                        && *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *threshold == THRESHOLD
                        && *epoch_ == epoch(REG_V2)
                        && *receiver_keys == map_of(vec![(0u32, csp_fs_enc_pk(PK_VALUE_2))])
                        && *resharing_public_coefficients
                            == CspPublicCoefficients::from(&resharing_transcript)
                },
            )
            .times(1)
            .return_const(Ok(csp_dealing(DEALING_VALUE_1)));
        let _ = create_dealing(
            &NODE_3,
            &csp,
            &registry_with_records(vec![resharing_enc_pk_record, enc_pk_record]),
            &dkg_config,
        );
    }

    #[test]
    fn should_forward_error_from_csp_on_load_private_key() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_with_resharing()
        });
        let resharing_enc_pk_record = dealing_enc_pk_record(NODE_1, REG_V1, PK_VALUE_1);
        let enc_pk_record = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_2);
        let mut csp = MockAllCryptoServiceProvider::new();
        let invalid_arg_error = invalid_arg_error();
        expect_load_threshold_signing_key_returning(
            &mut csp,
            Err(CspDkgLoadPrivateKeyError::InvalidTranscriptError(
                invalid_arg_error.clone(),
            )),
        );

        let error = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![resharing_enc_pk_record, enc_pk_record]),
            &dkg_config,
        )
        .unwrap_err();

        assert_eq!(
            error,
            DkgCreateDealingError::InvalidTranscript(invalid_arg_error)
        );
    }

    #[test]
    fn should_forward_error_from_csp_on_create_dealing() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_with_resharing()
        });
        let resharing_enc_pk_record = dealing_enc_pk_record(NODE_1, REG_V1, PK_VALUE_1);
        let enc_pk_record = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_2);
        let mut csp = MockAllCryptoServiceProvider::new();
        expect_load_threshold_signing_key_returning(&mut csp, Ok(()));
        expect_create_resharing_dealing_returning(&mut csp, Err(malformed_fs_pk()));

        let error = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![resharing_enc_pk_record, enc_pk_record]),
            &dkg_config,
        )
        .unwrap_err();

        assert_eq!(
            error,
            DkgCreateDealingError::MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError {
                internal_error: "error for receiver index 0: MalformedPublicKeyError { algorithm: Placeholder, key_bytes: None, internal_error: \"some error\" }".to_string()
            })
        );
    }

    #[test]
    #[should_panic(expected = "The algorithm id EcdsaP256 is unsupported.")]
    fn should_panic_if_csp_error_is_mapped_to_panic() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_with_resharing()
        });
        let resharing_enc_pk_record = dealing_enc_pk_record(NODE_1, REG_V1, PK_VALUE_1);
        let enc_pk_record = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_2);
        let mut csp = MockAllCryptoServiceProvider::new();
        expect_load_threshold_signing_key_returning(&mut csp, Ok(()));
        expect_create_resharing_dealing_returning(&mut csp, Err(unsupported_algorithm_id()));

        let _panic = create_dealing(
            &NODE_1,
            &csp,
            &registry_with_records(vec![resharing_enc_pk_record, enc_pk_record]),
            &dkg_config,
        );
    }

    fn expect_load_threshold_signing_key_returning(
        csp: &mut MockAllCryptoServiceProvider,
        result: Result<(), CspDkgLoadPrivateKeyError>,
    ) {
        csp.expect_load_threshold_signing_key()
            .times(1)
            .return_const(result);
    }

    fn expect_create_resharing_dealing_returning(
        csp: &mut MockAllCryptoServiceProvider,
        result: Result<CspNiDkgDealing, CspDkgCreateReshareDealingError>,
    ) {
        csp.expect_create_resharing_dealing()
            .times(1)
            .return_const(result);
    }

    fn invalid_arg_error() -> InvalidArgumentError {
        InvalidArgumentError {
            message: "some error".to_string(),
        }
    }

    fn malformed_fs_pk() -> CspDkgCreateReshareDealingError {
        CspDkgCreateReshareDealingError::MalformedFsPublicKeyError {
            receiver_index: 0,
            error: MalformedPublicKeyError {
                algorithm: AlgorithmId::Placeholder,
                key_bytes: None,
                internal_error: "some error".to_string(),
            },
        }
    }

    fn unsupported_algorithm_id() -> CspDkgCreateReshareDealingError {
        CspDkgCreateReshareDealingError::UnsupportedAlgorithmId(AlgorithmId::EcdsaP256)
    }
}

mod verify_dealing {
    use super::*;
    use crate::sign::threshold_sig::ni_dkg::test_utils::csp_fs_enc_pk;
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgVerifyDealingError;

    const DEALER: NodeId = NODE_42;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let dkg_config = dkg_config(NiDkgConfigData {
            dkg_id: DKG_ID,
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[DEALER]),
            threshold: THRESHOLD,
            registry_version: REG_V2,
            ..minimal_dkg_config_data_without_resharing()
        });
        let receiver_1_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_verify_dealing()
            .withf(
                move |algorithm_id,
                      dkg_id,
                      dealer_index,
                      threshold,
                      epoch_,
                      receiver_keys,
                      dealing| {
                    *dkg_id == DKG_ID
                        && *dealer_index == 0
                        && *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *threshold == THRESHOLD
                        && *epoch_ == epoch(REG_V2)
                        && *receiver_keys == map_of(vec![(0u32, csp_fs_enc_pk(PK_VALUE_1))])
                        && *dealing == csp_dealing(DEALING_VALUE_1)
                },
            )
            .times(1)
            .return_const(Ok(()));

        let _ = verify_dealing(
            &csp,
            &registry_with_records(vec![receiver_1_enc_pk]),
            &dkg_config,
            &DEALER,
            &ni_dkg_dealing(csp_dealing(DEALING_VALUE_1)),
        );
    }

    #[test]
    fn should_call_csp_correctly_with_multiple_receivers_and_keys() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1, NODE_2, NODE_3]),
            dealers: set_of(&[DEALER]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let receiver_1_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let receiver_2_enc_pk = dealing_enc_pk_record(NODE_2, REG_V2, PK_VALUE_2);
        let receiver_3_enc_pk = dealing_enc_pk_record(NODE_3, REG_V2, PK_VALUE_3);
        let csp = csp_with_verify_dealing_expecting_receiver_keys(map_of(vec![
            (0u32, csp_fs_enc_pk(PK_VALUE_1)),
            (1u32, csp_fs_enc_pk(PK_VALUE_2)),
            (2u32, csp_fs_enc_pk(PK_VALUE_3)),
        ]));

        let _ = verify_dealing(
            &csp,
            &registry_with_records(vec![
                receiver_1_enc_pk,
                receiver_2_enc_pk,
                receiver_3_enc_pk,
            ]),
            &dkg_config,
            &DEALER,
            &dummy_ni_dkg_dealing(),
        );
    }

    #[test]
    fn should_return_error_if_provided_dealer_is_not_a_dealer() {
        let not_a_dealer_node = NODE_3;
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[DEALER]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let receiver_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let csp = MockAllCryptoServiceProvider::new();

        let result = verify_dealing(
            &csp,
            &registry_with_records(vec![receiver_enc_pk]),
            &dkg_config,
            &not_a_dealer_node,
            &dummy_ni_dkg_dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            DkgVerifyDealingError::NotADealer(NotADealerError {
                node_id: not_a_dealer_node
            })
        );
    }

    #[test]
    fn should_return_error_if_registry_version_not_available_locally() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[DEALER]),
            registry_version: REG_V2,
            ..minimal_dkg_config_data_without_resharing()
        });
        let old_version_receiver_enc_pk = dealing_enc_pk_record(NODE_1, REG_V1, PK_VALUE_1);
        let csp = MockAllCryptoServiceProvider::new();

        let result = verify_dealing(
            &csp,
            &registry_with_records(vec![old_version_receiver_enc_pk]),
            &dkg_config,
            &DEALER,
            &dummy_ni_dkg_dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            DkgVerifyDealingError::Registry(RegistryClientError::VersionNotAvailable {
                version: REG_V2
            })
        );
    }

    #[test]
    fn should_return_error_if_receiver_enc_key_not_in_registry() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[DEALER]),
            registry_version: REG_V2,
            ..minimal_dkg_config_data_without_resharing()
        });
        let csp = MockAllCryptoServiceProvider::new();

        let registry_with_missing_receiver_enc_key =
            registry_with_records(vec![dealing_enc_pk_record(NODE_2, REG_V2, PK_VALUE_1)]);

        let result = verify_dealing(
            &csp,
            &registry_with_missing_receiver_enc_key,
            &dkg_config,
            &DEALER,
            &dummy_ni_dkg_dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            DkgVerifyDealingError::FsEncryptionPublicKeyNotInRegistry(
                FsEncryptionPublicKeyNotInRegistryError {
                    registry_version: REG_V2,
                    node_id: NODE_1,
                }
            )
        );
    }

    #[test]
    fn should_return_error_if_receiver_enc_key_in_registry_is_malformed() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[DEALER]),
            registry_version: REG_V2,
            ..minimal_dkg_config_data_without_resharing()
        });
        const WRONG_REGISTRY_FS_ENC_PK_SIZE: usize = REGISTRY_FS_ENC_PK_SIZE - 20;
        let key_record = dealing_encryption_pk_record_with(
            NODE_1,
            vec![PK_VALUE_1; WRONG_REGISTRY_FS_ENC_PK_SIZE],
            REG_V2,
        );
        let csp = MockAllCryptoServiceProvider::new();

        let result = verify_dealing(
            &csp,
            &registry_with_records(vec![key_record]),
            &dkg_config,
            &DEALER,
            &dummy_ni_dkg_dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            DkgVerifyDealingError::MalformedFsEncryptionPublicKey(MalformedFsEncryptionPublicKeyError {
                internal_error: "MalformedFsEncryptionPublicKeyError {  key_bytes: 0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a, internal_error: Wrong data length 28, expected length 48. }".to_string()
            })
        );
    }

    #[test]
    fn should_return_ok_if_csp_returns_ok() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[DEALER]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let receiver_1_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let csp = csp_with_verify_dealing_returning(Ok(()));

        let result = verify_dealing(
            &csp,
            &registry_with_records(vec![receiver_1_enc_pk]),
            &dkg_config,
            &DEALER,
            &dummy_ni_dkg_dealing(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_error_if_csp_returns_error() {
        let dkg_config = dkg_config(NiDkgConfigData {
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[DEALER]),
            ..minimal_dkg_config_data_without_resharing()
        });
        let receiver_1_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);

        let invalid_arg_error = invalid_arg_error();
        let csp = csp_with_verify_dealing_returning(Err(
            CspDkgVerifyDealingError::InvalidDealingError(invalid_arg_error.clone()),
        ));

        let result = verify_dealing(
            &csp,
            &registry_with_records(vec![receiver_1_enc_pk]),
            &dkg_config,
            &DEALER,
            &dummy_ni_dkg_dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            DkgVerifyDealingError::InvalidDealingError(invalid_arg_error)
        );
    }

    fn csp_with_verify_dealing_expecting_receiver_keys(
        expected_receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_verify_dealing()
            .withf(
                move |_algorithm_id,
                      _dkg_id,
                      _dealer_index,
                      _threshold,
                      _epoch,
                      receiver_keys,
                      _dealing| {
                    println!("{:?}", receiver_keys);
                    *receiver_keys == expected_receiver_keys
                },
            )
            .times(1)
            .return_const(Ok(()));
        csp
    }

    fn csp_with_verify_dealing_returning(
        result: Result<(), CspDkgVerifyDealingError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_verify_dealing().times(1).return_const(result);
        csp
    }
}

// For resharing, we only test the additional code paths to achieve test
// coverage
mod verify_dealing_with_resharing_transcript {
    use super::*;
    use crate::sign::threshold_sig::ni_dkg::test_utils::{
        csp_fs_enc_pk, minimal_dkg_config_data_with_resharing,
    };
    use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::CspDkgVerifyReshareDealingError;

    #[test]
    fn should_call_csp_verify_resharing_dealing_with_correct_parameters() {
        let resharing_transcript = transcript(
            set_of(&[NODE_3, NODE_2, NODE_4, NODE_1]),
            REG_V1,
            RESHARING_TRANSCRIPT_DKG_ID,
        );
        let dkg_config = dkg_config(NiDkgConfigData {
            dkg_id: DKG_ID,
            receivers: set_of(&[NODE_1]),
            dealers: set_of(&[NODE_1, NODE_3]),
            threshold: THRESHOLD,
            registry_version: REG_V2,
            resharing_transcript: Some(resharing_transcript.clone()),
            ..minimal_dkg_config_data_with_resharing()
        });

        let receiver_1_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_resharing_pub_coeffs = CspPublicCoefficients::from(&resharing_transcript);
        csp.expect_verify_resharing_dealing()
            .withf(
                move |algorithm_id,
                      dkg_id,
                      dealer_resharing_index,
                      threshold,
                      epoch_,
                      receiver_keys,
                      dealing,
                      resharing_pub_coeffs| {
                    *dkg_id == DKG_ID
                        && *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381
                        && *threshold == THRESHOLD
                        && *epoch_ == epoch(REG_V2)
                        && *receiver_keys == map_of(vec![(0u32, csp_fs_enc_pk(PK_VALUE_1))])
                        && *dealing == csp_dealing(DEALING_VALUE_1)
                        && *resharing_pub_coeffs == expected_resharing_pub_coeffs
                        // The resharing dealer index is the index of NODE_3 in the resharing committee.
                        // Note that the nodes are sorted lexicographically.
                        && *dealer_resharing_index == 2
                },
            )
            .times(1)
            .return_const(Ok(()));

        let _ = verify_dealing(
            &csp,
            &registry_with_records(vec![receiver_1_enc_pk]),
            &dkg_config,
            &NODE_3,
            &ni_dkg_dealing(csp_dealing(DEALING_VALUE_1)),
        );
    }

    #[test]
    fn should_return_ok_if_csp_returns_ok() {
        let dkg_config = dkg_config(NiDkgConfigData {
            dealers: set_of(&[NODE_2]),
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_with_resharing()
        });
        let receiver_1_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);
        let csp = csp_with_verify_resharing_dealing_returning(Ok(()));

        let result = verify_dealing(
            &csp,
            &registry_with_records(vec![receiver_1_enc_pk]),
            &dkg_config,
            &NODE_2,
            &ni_dkg_dealing(csp_dealing(DEALING_VALUE_1)),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_error_if_csp_returns_error() {
        let dkg_config = dkg_config(NiDkgConfigData {
            dealers: set_of(&[NODE_2]),
            receivers: set_of(&[NODE_1]),
            ..minimal_dkg_config_data_with_resharing()
        });

        let receiver_1_enc_pk = dealing_enc_pk_record(NODE_1, REG_V2, PK_VALUE_1);

        let invalid_arg_error = invalid_arg_error();
        let csp = csp_with_verify_resharing_dealing_returning(Err(
            CspDkgVerifyReshareDealingError::InvalidDealingError(invalid_arg_error.clone()),
        ));

        let error = verify_dealing(
            &csp,
            &registry_with_records(vec![receiver_1_enc_pk]),
            &dkg_config,
            &NODE_2,
            &ni_dkg_dealing(csp_dealing(DEALING_VALUE_1)),
        )
        .unwrap_err();

        assert_eq!(
            error,
            DkgVerifyDealingError::InvalidDealingError(invalid_arg_error)
        );
    }

    fn csp_with_verify_resharing_dealing_returning(
        result: Result<(), CspDkgVerifyReshareDealingError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_verify_resharing_dealing()
            .times(1)
            .return_const(result);
        csp
    }
}

fn epoch(registry_version: RegistryVersion) -> Epoch {
    Epoch::new(u32::try_from(registry_version.get()).expect("epoch overflow"))
}

fn ni_dkg_dealing(csp_dealing: CspNiDkgDealing) -> NiDkgDealing {
    NiDkgDealing {
        internal_dealing: csp_dealing,
    }
}

fn dummy_ni_dkg_dealing() -> NiDkgDealing {
    ni_dkg_dealing(csp_dealing(DEALING_VALUE_1))
}

fn invalid_arg_error() -> InvalidArgumentError {
    InvalidArgumentError {
        message: "some error".to_string(),
    }
}
