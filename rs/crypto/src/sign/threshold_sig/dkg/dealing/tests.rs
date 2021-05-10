#![allow(clippy::unwrap_used)]

use super::*;

use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::sign::threshold_sig::dkg::test_utils::csp_transcript;
use crate::sign::threshold_sig::tests::{mock_csp_public_coefficients_from_bytes, I_DKG_ID};
use ic_crypto_internal_csp::types::{CspEncryptedSecretKey, CspPop};
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
    DkgCreateDealingError, DkgCreateReshareDealingError, DkgVerifyDealingError,
    DkgVerifyReshareDealingError, KeyNotFoundError,
};
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::{
    EncryptedShareBytes, EphemeralPopBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::{
    CspEncryptionPublicKey, InternalCspEncryptionPublicKey,
};
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4, NODE_42};
use ic_types::consensus::Threshold;
use ic_types::crypto::dkg::{EncryptionPublicKey, EncryptionPublicKeyPop};
use ic_types::crypto::KeyId;

const DEALER: NodeId = NODE_42;

// We use threshold 1 in these tests to get a valid DkgConfig in a simple way.
// Threshold 1 not a common value used in practice, but in these tests we only
// care that it is forwarded to the CSP correctly.
const IDKM_THRESHOLD: usize = 1;
const CSP_THRESHOLD: NodeIndex = 1;

mod create_dealing {
    use super::*;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
        MalformedSecretKeyError, SizeError,
    };

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_dealing()
            .withf(move |dkg_id, threshold, receiver_keys| {
                *dkg_id == I_DKG_ID
                    && *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                    && *receiver_keys == vec![None][..]
            })
            .times(1)
            .return_const(Ok(csp_dealing()));
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);
        let dkg_config = dkg_config(I_DKG_ID, receivers, IDKM_THRESHOLD, dealers);

        let _ = create_dealing(&csp, &dkg_config, &verified_keys, DEALER);
    }

    #[test]
    fn should_not_call_csp_load_private_key_if_no_resharing_transcript_present() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_dealing()
            .times(1)
            .return_const(Ok(csp_dealing()));
        csp.expect_dkg_load_private_key().times(0);
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);
        let dkg_config = dkg_config(I_DKG_ID, receivers, IDKM_THRESHOLD, dealers);

        let _ = create_dealing(&csp, &dkg_config, &verified_keys, DEALER);
    }

    #[test]
    fn should_call_csp_correctly_with_single_receiver_and_receiver_key() {
        let mut verified_keys = BTreeMap::new();
        let pk_with_pop = pk_with_pop(43, 44);
        verified_keys.insert(DEALER, pk_with_pop.clone());
        let csp = csp_with_create_dealing_expecting_receiver_keys(vec![Some(csp_pk_and_pop(
            &pk_with_pop,
        ))]);
        let (receivers, dealers) = (vec![DEALER], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let _ = create_dealing(&csp, &dkg_config, &verified_keys, DEALER);
    }

    #[test]
    fn should_call_csp_correctly_with_multiple_receivers_and_keys() {
        let mut verified_keys = BTreeMap::new();
        let node_2_pk_with_pop = pk_with_pop(43, 44);
        verified_keys.insert(DEALER, node_2_pk_with_pop.clone());
        let node_4_pk_with_pop = pk_with_pop(45, 46);
        verified_keys.insert(NODE_4, node_4_pk_with_pop.clone());
        let csp = csp_with_create_dealing_expecting_receiver_keys(vec![
            None,
            Some(csp_pk_and_pop(&node_2_pk_with_pop)),
            None,
            Some(csp_pk_and_pop(&node_4_pk_with_pop)),
        ]);
        let (receivers, dealers) = (vec![NODE_1, DEALER, NODE_3, NODE_4], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let _ = create_dealing(&csp, &dkg_config, &verified_keys, DEALER);
    }

    #[test]
    fn should_return_error_if_node_has_no_verified_key() {
        let verified_keys = BTreeMap::new();
        let csp = MockAllCryptoServiceProvider::new();
        let (receivers, dealers) = (vec![DEALER], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let result = create_dealing(&csp, &dkg_config, &verified_keys, DEALER);

        assert_eq!(
            result.unwrap_err(),
            CryptoError::InvalidArgument {
                message: "Missing key for node ID \"nxqfi-cjkaa-aaaaa-aaaap-2ai\".".to_string()
            }
        );
    }

    #[test]
    fn should_return_error_if_node_is_no_dealer() {
        let no_dealer_node = NODE_1;
        let verified_keys = verified_keys_with_key_for(no_dealer_node);
        let csp = MockAllCryptoServiceProvider::new();
        let (receivers, dealers) = (vec![NODE_2], vec![NODE_3, NODE_4]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let result = create_dealing(&csp, &dkg_config, &verified_keys, no_dealer_node);

        assert_eq!(
            result.unwrap_err(),
            CryptoError::InvalidArgument {
                message: "The node with ID \"3jo2y-lqbaa-aaaaa-aaaap-2ai\" is not a dealer."
                    .to_string()
            }
        );
    }

    #[test]
    fn should_return_dealing_from_csp() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let csp_dealing = csp_dealing();
        let csp = csp_with_create_dealing_returning(Ok(csp_dealing.clone()));
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let dealing = create_dealing(&csp, &dkg_config, &verified_keys, DEALER).unwrap();

        assert_eq!(dealing, Dealing::from(&csp_dealing));
    }

    #[test]
    // TODO (CRP-314): Error handling must be improved once the csp errors are
    // defined
    fn should_return_invalid_argument_if_csp_returns_error() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let error = DkgCreateDealingError::SizeError(SizeError {
            message: "message".to_string(),
        });
        let csp = csp_with_create_dealing_returning(Err(error));
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let result = create_dealing(&csp, &dkg_config, &verified_keys, DEALER);

        assert_eq!(
            result.unwrap_err(),
            invalid_argument("CSP error: SizeError { message: \"message\" }")
        );
    }

    #[test]
    #[should_panic(
        expected = "Internal error from CSP: MalformedSecretKeyError { algorithm: Placeholder, internal_error: \"message\" }"
    )]
    fn should_panic_if_csp_returns_malformed_secret_key_error() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let error = DkgCreateDealingError::MalformedSecretKeyError(MalformedSecretKeyError {
            algorithm: AlgorithmId::Placeholder,
            internal_error: "message".to_string(),
        });
        let csp = csp_with_create_dealing_returning(Err(error));
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let _ = create_dealing(&csp, &dkg_config, &verified_keys, DEALER);
    }

    fn csp_with_create_dealing_returning(
        result: Result<CspDealing, DkgCreateDealingError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_dealing()
            .times(1)
            .return_const(result);
        csp
    }

    fn csp_with_create_dealing_expecting_receiver_keys(
        expected_receiver_keys: Vec<Option<(CspEncryptionPublicKey, CspPop)>>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_dealing()
            .withf(move |dkg_id, threshold, receiver_keys| {
                *dkg_id == I_DKG_ID
                    && *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                    && *receiver_keys == expected_receiver_keys[..]
            })
            .times(1)
            .return_const(Ok(csp_dealing()));
        csp
    }
}

mod create_dealing_with_resharing_transcript {
    use super::*;
    use crate::sign::threshold_sig::tests::RESHARING_TRANSCRIPT_DKG_ID;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
        DkgLoadPrivateKeyError, InvalidArgumentError, MalformedSecretKeyError,
    };

    #[test]
    fn should_call_csp_load_private_key_with_correct_parameters() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let csp_transcript = csp_transcript();

        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_csp_transcript = csp_transcript.clone();
        csp.expect_dkg_load_private_key()
            .withf(move |dkg_id, transcript| {
                *dkg_id == RESHARING_TRANSCRIPT_DKG_ID && *transcript == expected_csp_transcript
            })
            .times(1)
            .return_const(Ok(()));
        expect_create_resharing_dealing_returning(&mut csp, Ok(csp_dealing()));

        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);
        let _ = create_dealing(
            &csp,
            &default_dkg_config_with_resharing_transcript(
                receivers,
                dealers,
                Transcript {
                    dkg_id: RESHARING_TRANSCRIPT_DKG_ID,
                    committee: vec![None, Some(DEALER)],
                    transcript_bytes: TranscriptBytes::from(&csp_transcript),
                },
            ),
            &verified_keys,
            DEALER,
        );
    }

    #[test]
    fn should_call_csp_create_resharing_dealing_with_correct_parameters() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let csp_transcript = csp_transcript();

        let mut csp = MockAllCryptoServiceProvider::new();
        expect_load_private_key_returning(&mut csp, Ok(()));
        let expected_pub_coeffs = CspPublicCoefficients::from(&csp_transcript);
        csp.expect_dkg_create_resharing_dealing()
            .withf(move |dkg_id, threshold, pub_coeffs, receiver_keys| {
                *dkg_id == I_DKG_ID
                    && *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                    && *pub_coeffs == expected_pub_coeffs
                    && *receiver_keys == vec![None][..]
            })
            .times(1)
            .return_const(Ok(csp_dealing()));

        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);
        let _ = create_dealing(
            &csp,
            &dkg_config_with_resharing_transcript(
                I_DKG_ID,
                receivers,
                IDKM_THRESHOLD,
                dealers,
                Transcript {
                    dkg_id: RESHARING_TRANSCRIPT_DKG_ID,
                    committee: vec![Some(DEALER), None, Some(NODE_2)],
                    transcript_bytes: TranscriptBytes::from(&csp_transcript),
                },
            ),
            &verified_keys,
            DEALER,
        );
    }

    #[test]
    // TODO (CRP-415): Error handling must be improved once the csp errors are
    // defined
    fn should_return_invalid_argument_if_csp_returns_error_on_load_private_key() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let error = DkgLoadPrivateKeyError::InvalidTranscriptError(InvalidArgumentError {
            message: "msg".to_string(),
        });
        let mut csp = MockAllCryptoServiceProvider::new();
        expect_load_private_key_returning(&mut csp, Err(error));
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);

        let result = create_dealing(
            &csp,
            &default_dkg_config_with_resharing_transcript(
                receivers,
                dealers,
                default_resharing_transcript(DEALER),
            ),
            &verified_keys,
            DEALER,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_argument("CSP error: InvalidArgumentError { message: \"msg\" }")
        );
    }

    #[test]
    // TODO (CRP-415): Error handling must be improved once the csp errors are
    // defined
    fn should_return_invalid_argument_if_csp_returns_error_on_create_dealing() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let error = DkgCreateReshareDealingError::KeyNotFoundError(KeyNotFoundError {
            key_id: KeyId::from([0; 32]),
            internal_error: "msg".to_string(),
        });
        let mut csp = MockAllCryptoServiceProvider::new();
        expect_load_private_key_returning(&mut csp, Ok(()));
        expect_create_resharing_dealing_returning(&mut csp, Err(error));
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);

        let result = create_dealing(
            &csp,
            &default_dkg_config_with_resharing_transcript(
                receivers,
                dealers,
                default_resharing_transcript(DEALER),
            ),
            &verified_keys,
            DEALER,
        );

        assert_eq!(result.unwrap_err(), invalid_argument("CSP error: KeyNotFoundError { internal_error: \"msg\", key_id: KeyId(0x0000000000000000000000000000000000000000000000000000000000000000) }"));
    }

    #[test]
    #[should_panic(
        expected = "Internal error from CSP: MalformedSecretKeyError { algorithm: Placeholder, internal_error: \"message\" }"
    )]
    fn should_panic_if_csp_returns_malformed_secret_key_error() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let error =
            DkgCreateReshareDealingError::MalformedSecretKeyError(MalformedSecretKeyError {
                algorithm: AlgorithmId::Placeholder,
                internal_error: "message".to_string(),
            });
        let mut csp = MockAllCryptoServiceProvider::new();
        expect_load_private_key_returning(&mut csp, Ok(()));
        expect_create_resharing_dealing_returning(&mut csp, Err(error));
        let (receivers, dealers) = (vec![NODE_2], vec![DEALER]);

        let _ = create_dealing(
            &csp,
            &default_dkg_config_with_resharing_transcript(
                receivers,
                dealers,
                default_resharing_transcript(DEALER),
            ),
            &verified_keys,
            DEALER,
        );
    }

    fn expect_load_private_key_returning(
        csp: &mut MockAllCryptoServiceProvider,
        result: Result<(), DkgLoadPrivateKeyError>,
    ) {
        csp.expect_dkg_load_private_key()
            .times(1)
            .return_const(result);
    }

    fn expect_create_resharing_dealing_returning(
        csp: &mut MockAllCryptoServiceProvider,
        result: Result<CspDealing, DkgCreateReshareDealingError>,
    ) {
        csp.expect_dkg_create_resharing_dealing()
            .times(1)
            .return_const(result);
    }

    fn default_resharing_transcript(committee_node: NodeId) -> Transcript {
        Transcript {
            dkg_id: RESHARING_TRANSCRIPT_DKG_ID,
            committee: vec![Some(committee_node)],
            transcript_bytes: TranscriptBytes::from(&csp_transcript()),
        }
    }
}

mod verify_dealing {
    use super::*;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::SizeError;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let dealing = dealing();
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_csp_dealing = CspDealing::from(&dealing);
        csp.expect_dkg_verify_dealing()
            .withf(move |threshold, receiver_keys, csp_dealing| {
                *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                    && *receiver_keys == vec![None][..]
                    && *csp_dealing == expected_csp_dealing
            })
            .times(1)
            .return_const(Ok(()));
        let (dealers, receivers) = (vec![DEALER], vec![NODE_2]);
        let dkg_config = dkg_config(I_DKG_ID, receivers, IDKM_THRESHOLD, dealers);

        let _ = verify_dealing(&csp, &dkg_config, &verified_keys, DEALER, &dealing);
    }

    #[test]
    fn should_call_csp_correctly_with_single_receiver_and_receiver_key() {
        let mut verified_keys = BTreeMap::new();
        let node1_pk_with_pop = pk_with_pop(43, 44);
        verified_keys.insert(DEALER, node1_pk_with_pop.clone());
        let dealing = dealing();
        let csp = csp_with_verify_dealing_expecting_receiver_keys_and_dealing(
            vec![Some(csp_pk_and_pop(&node1_pk_with_pop))],
            &CspDealing::from(&dealing),
        );
        let (receivers, dealers) = (vec![DEALER], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let _ = verify_dealing(&csp, &dkg_config, &verified_keys, DEALER, &dealing);
    }

    #[test]
    fn should_call_csp_correctly_with_multiple_receivers_and_keys() {
        let mut verified_keys = BTreeMap::new();
        let node_2_pk_with_pop = pk_with_pop(43, 44);
        verified_keys.insert(DEALER, node_2_pk_with_pop.clone());
        let node_3_pk_with_pop = pk_with_pop(45, 46);
        verified_keys.insert(NODE_3, node_3_pk_with_pop.clone());
        let dealing = dealing();
        let csp = csp_with_verify_dealing_expecting_receiver_keys_and_dealing(
            vec![
                None,
                Some(csp_pk_and_pop(&node_2_pk_with_pop)),
                Some(csp_pk_and_pop(&node_3_pk_with_pop)),
                None,
            ],
            &CspDealing::from(&dealing),
        );
        let (receivers, dealers) = (vec![NODE_1, DEALER, NODE_3, NODE_4], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let _ = verify_dealing(&csp, &dkg_config, &verified_keys, DEALER, &dealing);
    }

    #[test]
    fn should_return_ok_if_csp_returns_ok() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let csp = csp_with_verify_dealing_returning(Ok(()));
        let (dealers, receivers) = (vec![DEALER], vec![DEALER]);

        let result = verify_dealing(
            &csp,
            &default_dkg_config(receivers, dealers),
            &verified_keys,
            DEALER,
            &dealing(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_error_if_dealer_has_no_verified_key() {
        let verified_keys = BTreeMap::new();
        let csp = MockAllCryptoServiceProvider::new();
        let (receivers, dealers) = (vec![DEALER], vec![DEALER]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let result = verify_dealing(&csp, &dkg_config, &verified_keys, DEALER, &dealing());

        assert_eq!(
            result.unwrap_err(),
            CryptoError::InvalidArgument {
                message: "Missing key for node ID \"nxqfi-cjkaa-aaaaa-aaaap-2ai\".".to_string()
            }
        );
    }

    #[test]
    fn should_return_error_if_dealer_is_not_a_dealer_according_to_config() {
        let no_dealer_node = NODE_1;
        let verified_keys = verified_keys_with_key_for(no_dealer_node);
        let csp = MockAllCryptoServiceProvider::new();
        let (receivers, dealers) = (vec![NODE_2], vec![NODE_3, NODE_4]);
        let dkg_config = default_dkg_config(receivers, dealers);

        let result = verify_dealing(
            &csp,
            &dkg_config,
            &verified_keys,
            no_dealer_node,
            &dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            CryptoError::InvalidArgument {
                message: "The node with ID \"3jo2y-lqbaa-aaaaa-aaaap-2ai\" is not a dealer."
                    .to_string()
            }
        );
    }

    #[test]
    // TODO (CRP-346): Improve error handling once the csp errors are defined
    fn should_return_invalid_argument_if_csp_returns_error() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let error = DkgVerifyDealingError::SizeError(SizeError {
            message: "msg".to_string(),
        });
        let csp = csp_with_verify_dealing_returning(Err(error));
        let (dealers, receivers) = (vec![DEALER], vec![DEALER]);

        let result = verify_dealing(
            &csp,
            &default_dkg_config(receivers, dealers),
            &verified_keys,
            DEALER,
            &dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_argument("CSP error: SizeError { message: \"msg\" }")
        );
    }

    fn csp_with_verify_dealing_expecting_receiver_keys_and_dealing(
        expected_receiver_keys: Vec<Option<(CspEncryptionPublicKey, CspPop)>>,
        csp_dealing: &CspDealing,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_csp_dealing = csp_dealing.clone();
        csp.expect_dkg_verify_dealing()
            .withf(move |threshold, receiver_keys, csp_dealing| {
                *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                    && *receiver_keys == expected_receiver_keys[..]
                    && *csp_dealing == expected_csp_dealing
            })
            .times(1)
            .return_const(Ok(()));
        csp
    }

    fn csp_with_verify_dealing_returning(
        result: Result<(), DkgVerifyDealingError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_verify_dealing()
            .times(1)
            .return_const(result);
        csp
    }
}

// For resharing, we only test the additional code paths to achieve code
// coverage.
mod verify_resharing_dealing {
    use super::*;
    use crate::sign::threshold_sig::dkg::test_utils::csp_transcript;
    use crate::sign::threshold_sig::tests::RESHARING_TRANSCRIPT_DKG_ID;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::SizeError;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let dealing = dealing();
        let csp_resharing_transcript = csp_transcript();

        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_csp_dealing = CspDealing::from(&dealing);
        let expected_pub_coeffs = CspPublicCoefficients::from(&csp_resharing_transcript);
        csp.expect_dkg_verify_resharing_dealing()
            .withf(
                move |threshold, receiver_keys, csp_dealing, dealer_index, pub_coeffs| {
                    *threshold == NumberOfNodes::from(CSP_THRESHOLD)
                        && *receiver_keys == vec![None][..]
                        && *csp_dealing == expected_csp_dealing
                        && *dealer_index == 4 // the index of Some(DEALER) in the committee
                        && *pub_coeffs == expected_pub_coeffs
                },
            )
            .times(1)
            .return_const(Ok(()));
        let (dealers, receivers) = (vec![DEALER], vec![NODE_2]);
        let dkg_config = dkg_config_with_resharing_transcript(
            I_DKG_ID,
            receivers,
            IDKM_THRESHOLD,
            dealers,
            Transcript {
                dkg_id: RESHARING_TRANSCRIPT_DKG_ID,
                committee: vec![None, Some(NODE_2), None, None, Some(DEALER), None],
                transcript_bytes: TranscriptBytes::from(&csp_resharing_transcript),
            },
        );

        let _ = verify_dealing(&csp, &dkg_config, &verified_keys, DEALER, &dealing);
    }

    #[test]
    fn should_return_ok_if_csp_returns_ok() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let csp = csp_with_verify_resharing_dealing_returning(Ok(()));
        let (dealers, receivers) = (vec![DEALER], vec![DEALER]);

        let result = verify_dealing(
            &csp,
            &default_dkg_config_with_resharing_transcript(
                receivers,
                dealers,
                default_resharing_transcript_with_committee(&[Some(NODE_2), None, Some(DEALER)]),
            ),
            &verified_keys,
            DEALER,
            &dealing(),
        );

        assert!(result.is_ok());
    }

    #[test]
    // TODO (CRP-416): Improve error handling once the csp errors are defined
    fn should_return_invalid_argument_if_csp_returns_error() {
        let verified_keys = verified_keys_with_key_for(DEALER);
        let error = DkgVerifyReshareDealingError::SizeError(SizeError {
            message: "msg".to_string(),
        });
        let csp = csp_with_verify_resharing_dealing_returning(Err(error));
        let (dealers, receivers) = (vec![DEALER], vec![DEALER]);

        let result = verify_dealing(
            &csp,
            &default_dkg_config_with_resharing_transcript(
                receivers,
                dealers,
                default_resharing_transcript_with_committee(&[Some(NODE_2), None, Some(DEALER)]),
            ),
            &verified_keys,
            DEALER,
            &dealing(),
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_argument("CSP error: SizeError { message: \"msg\" }")
        );
    }

    fn csp_with_verify_resharing_dealing_returning(
        result: Result<(), DkgVerifyReshareDealingError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_verify_resharing_dealing()
            .times(1)
            .return_const(result);
        csp
    }

    fn default_resharing_transcript_with_committee(committee: &[Option<NodeId>]) -> Transcript {
        Transcript {
            dkg_id: RESHARING_TRANSCRIPT_DKG_ID,
            committee: committee.to_vec(),
            transcript_bytes: TranscriptBytes::from(&csp_transcript()),
        }
    }
}

fn verified_keys_with_key_for(node_id: NodeId) -> BTreeMap<NodeId, EncryptionPublicKeyWithPop> {
    let mut verified_keys = BTreeMap::new();
    verified_keys.insert(node_id, pk_with_pop(43, 44));
    verified_keys
}

fn pk_with_pop(pk_value: u8, pop_value: u8) -> EncryptionPublicKeyWithPop {
    EncryptionPublicKeyWithPop {
        key: EncryptionPublicKey::from(&CspEncryptionPublicKey {
            internal: InternalCspEncryptionPublicKey::Secp256k1(EphemeralPublicKeyBytes(
                [pk_value; EphemeralPublicKeyBytes::SIZE],
            )),
        }),
        proof_of_possession: EncryptionPublicKeyPop::from(&CspPop::Secp256k1(EphemeralPopBytes(
            [pop_value; EphemeralPopBytes::SIZE],
        ))),
    }
}

fn csp_pk_and_pop(pk_with_pop: &EncryptionPublicKeyWithPop) -> (CspEncryptionPublicKey, CspPop) {
    (
        CspEncryptionPublicKey::from(&pk_with_pop.key),
        CspPop::from(&pk_with_pop.proof_of_possession),
    )
}

fn csp_dealing() -> CspDealing {
    CspDealing {
        common_data: pub_coeffs(),
        receiver_data: vec![
            Some(CspEncryptedSecretKey::ThresBls12_381(EncryptedShareBytes(
                [1; EncryptedShareBytes::SIZE],
            ))),
            None,
            Some(CspEncryptedSecretKey::ThresBls12_381(EncryptedShareBytes(
                [2; EncryptedShareBytes::SIZE],
            ))),
        ],
    }
}

fn dealing() -> Dealing {
    Dealing::from(&csp_dealing())
}

fn pub_coeffs() -> CspPublicCoefficients {
    mock_csp_public_coefficients_from_bytes(43)
}

fn default_dkg_config(receivers: Vec<NodeId>, dealers: Vec<NodeId>) -> DkgConfig {
    dkg_config(I_DKG_ID, receivers, IDKM_THRESHOLD, dealers)
}

fn default_dkg_config_with_resharing_transcript(
    receivers: Vec<NodeId>,
    dealers: Vec<NodeId>,
    resharing_transcript: Transcript,
) -> DkgConfig {
    dkg_config_with_resharing_transcript(
        I_DKG_ID,
        receivers,
        IDKM_THRESHOLD,
        dealers,
        resharing_transcript,
    )
}

fn dkg_config(
    dkg_id: IDkgId,
    receivers: Vec<NodeId>,
    threshold: Threshold,
    dealers: Vec<NodeId>,
) -> DkgConfig {
    create_config(DkgConfigData {
        dkg_id,
        dealers,
        receivers,
        threshold,
        resharing_transcript: None,
    })
}

fn create_config(config_data: DkgConfigData) -> DkgConfig {
    DkgConfig::new(config_data).expect("unable to create dkg config")
}

fn dkg_config_with_resharing_transcript(
    dkg_id: IDkgId,
    receivers: Vec<NodeId>,
    threshold: Threshold,
    dealers: Vec<NodeId>,
    resharing_transcript: Transcript,
) -> DkgConfig {
    create_config(DkgConfigData {
        dkg_id,
        dealers,
        receivers,
        threshold,
        resharing_transcript: Some(resharing_transcript),
    })
}

fn invalid_argument(msg: &str) -> CryptoError {
    CryptoError::InvalidArgument {
        message: msg.to_string(),
    }
}
