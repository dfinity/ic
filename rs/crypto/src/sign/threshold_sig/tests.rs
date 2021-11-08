#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::sign::tests::KEY_ID;
use crate::sign::threshold_sig::ThresholdSigDataStore;
use ic_crypto_internal_csp::types::{CspPublicCoefficients, ThresBls12_381_Signature};
use ic_crypto_internal_threshold_sig_bls12381::types::{
    CombinedSignatureBytes, IndividualSignatureBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_interfaces::crypto::SignableMock;
use ic_test_utilities::types::ids::{NODE_1, SUBNET_0, SUBNET_1};
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
};
use ic_types::crypto::ThresholdSigShare;
use ic_types::crypto::{CombinedThresholdSig, KeyId};
use ic_types::Height;
use ic_types::SubnetId;

pub const NODE_ID: NodeId = NODE_1;

pub const NI_DKG_ID_1: NiDkgId = NiDkgId {
    start_block_height: Height::new(3),
    dealer_subnet: SUBNET_1,
    dkg_tag: NiDkgTag::HighThreshold,
    target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new([42; 32])),
};

pub const NI_DKG_ID_2: NiDkgId = NiDkgId {
    start_block_height: Height::new(2),
    dealer_subnet: SUBNET_0,
    dkg_tag: NiDkgTag::HighThreshold,
    target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new([23; 32])),
};

mod sign_threshold {
    use super::*;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let dkg_id = DkgId::NiDkgId(NI_DKG_ID_1);
        let (message, pub_coeffs) = (signable_mock(), pub_coeffs());
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_msg = message.clone();
        let expected_pub_coeffs = pub_coeffs.clone();
        csp.expect_threshold_sign()
            .withf(move |algorithm_id, msg, pub_coeffs| {
                *algorithm_id == AlgorithmId::ThresBls12_381
                    && msg == expected_msg.as_signed_bytes().as_slice()
                    && *pub_coeffs == expected_pub_coeffs
            })
            .times(1)
            .return_const(Ok(individual_csp_threshold_sig(
                [42; IndividualSignatureBytes::SIZE],
            )));
        let threshold_sig_data_store = threshold_sig_data_store_with_coeffs(pub_coeffs, dkg_id);

        let _ = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &message,
            dkg_id,
        );
    }

    #[test]
    fn should_return_signature_from_csp_if_csp_returns_ok() {
        let csp_sig = individual_csp_threshold_sig([42; IndividualSignatureBytes::SIZE]);
        let csp = csp_with_sign_returning_once(Ok(csp_sig.clone()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with_coeffs(pub_coeffs(), DkgId::NiDkgId(NI_DKG_ID_1));

        let sig_share_result = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &signable_mock(),
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert!(sig_share_result.is_ok());
        assert_eq!(
            sig_share_result.unwrap(),
            ThresholdSigShareOf::try_from(csp_sig).unwrap()
        );
    }

    #[test]
    #[should_panic(
        expected = "Illegal state: The algorithm of the public key from the threshold signature data store is not supported: Placeholder"
    )]
    fn should_panic_with_correct_message_if_csp_returns_unsupported_algorithm_error() {
        let csp = csp_with_sign_returning_once(Err(unsupported_algorithm()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with_coeffs(pub_coeffs(), DkgId::NiDkgId(NI_DKG_ID_1));

        let _panic = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &signable_mock(),
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    #[should_panic(expected = "Illegal state: The secret key has a wrong type")]
    fn should_panic_if_csp_returns_wrong_secret_key_type_error() {
        let csp = csp_with_sign_returning_once(Err(wrong_secret_key_type()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with_coeffs(pub_coeffs(), DkgId::NiDkgId(NI_DKG_ID_1));

        let _panic = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &signable_mock(),
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    #[should_panic(
        expected = "Illegal state: Unable to parse the secret key with algorithm id Placeholder"
    )]
    fn should_panic_if_csp_returns_malformed_secret_key_error() {
        let csp = csp_with_sign_returning_once(Err(malformed_secret_key()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with_coeffs(pub_coeffs(), DkgId::NiDkgId(NI_DKG_ID_1));

        let _panic = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &signable_mock(),
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    fn should_return_secret_key_not_found_error_if_csp_returns_secret_key_not_found_error() {
        let csp = csp_with_sign_returning_once(Err(secret_key_not_found()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with_coeffs(pub_coeffs(), DkgId::NiDkgId(NI_DKG_ID_1));

        let sig_share_result = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &signable_mock(),
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(
            sig_share_result,
            Err(ThresholdSignError::SecretKeyNotFound {
                dkg_id: DkgId::NiDkgId(NI_DKG_ID_1),
                algorithm: AlgorithmId::Placeholder,
                key_id: KeyId::from(KEY_ID),
            })
        )
    }

    #[test]
    fn should_return_error_if_transcript_data_not_in_store() {
        let csp = MockAllCryptoServiceProvider::new();
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let sig_share_result = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &signable_mock(),
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(
            sig_share_result,
            Err(ThresholdSignError::ThresholdSigDataNotFound(
                ThresholdSigDataNotFoundError::ThresholdSigDataNotFound {
                    dkg_id: DkgId::NiDkgId(NI_DKG_ID_1)
                }
            ))
        )
    }

    #[test]
    #[should_panic(expected = "This case cannot occur")]
    fn should_panic_if_csp_returns_wrong_signature_type() {
        let csp_sig_with_wrong_type =
            combined_csp_threshold_sig([42; CombinedSignatureBytes::SIZE]);
        let csp = csp_with_sign_returning_once(Ok(csp_sig_with_wrong_type));
        let threshold_sig_data_store =
            threshold_sig_data_store_with_coeffs(pub_coeffs(), DkgId::NiDkgId(NI_DKG_ID_1));

        let _panic = ThresholdSignerInternal::sign_threshold(
            &threshold_sig_data_store,
            &csp,
            &signable_mock(),
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    fn unsupported_algorithm() -> CspThresholdSignError {
        CspThresholdSignError::UnsupportedAlgorithm {
            algorithm: AlgorithmId::Placeholder,
        }
    }

    fn secret_key_not_found() -> CspThresholdSignError {
        CspThresholdSignError::SecretKeyNotFound {
            algorithm: AlgorithmId::Placeholder,
            key_id: KeyId::from(KEY_ID),
        }
    }

    fn wrong_secret_key_type() -> CspThresholdSignError {
        CspThresholdSignError::WrongSecretKeyType {}
    }

    fn malformed_secret_key() -> CspThresholdSignError {
        CspThresholdSignError::MalformedSecretKey {
            algorithm: AlgorithmId::Placeholder,
        }
    }

    fn csp_with_sign_returning_once(
        result: Result<CspSignature, CspThresholdSignError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_sign().times(1).return_const(result);
        csp
    }
}

mod verify_threshold_sig_share {
    use super::*;

    #[test]
    fn should_call_csp_with_correct_params_if_public_key_in_store() {
        let dkg_id = DkgId::NiDkgId(NI_DKG_ID_1);
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store =
            threshold_sig_data_store_with_coeffs_and_pubkey(dkg_id, NODE_ID, csp_public_key);
        let mut csp = MockAllCryptoServiceProvider::new();
        let (expected_msg, expected_sig) = (message.clone(), sig_share.clone());
        csp.expect_threshold_verify_individual_signature()
            .withf(move |alg_id, msg, sig, pubkey| {
                *alg_id == AlgorithmId::from(csp_public_key)
                    && msg == expected_msg.as_signed_bytes().as_slice()
                    && *sig == CspSignature::try_from(&expected_sig).unwrap()
                    && *pubkey == csp_public_key
            })
            .times(1)
            .return_const(Ok(()));

        let _ = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            dkg_id,
            NODE_ID,
        );
    }

    #[test]
    fn should_call_csp_public_key_generation_with_correct_params_if_public_key_not_in_store() {
        let (sig_share, message, csp_public_key, pub_coeffs) =
            (sig_share(), signable_mock(), csp_public_key(), pub_coeffs());
        let threshold_sig_data_store = threshold_sig_data_store_with(
            DkgId::NiDkgId(NI_DKG_ID_1),
            pub_coeffs.clone(),
            indices(vec![(NODE_ID, 3)]),
        );
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_individual_signature()
            .return_const(Ok(()));
        csp.expect_threshold_individual_public_key()
            .withf(move |alg_id, node_index, public_coeffs| {
                *alg_id == AlgorithmId::try_from(&pub_coeffs).unwrap()
                    && *node_index == 3
                    && *public_coeffs == pub_coeffs
            })
            .times(1)
            .return_const(Ok(csp_public_key));

        let _ = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );
    }

    #[test]
    fn should_call_csp_signature_verification_with_correct_params_if_public_key_not_in_store() {
        let (sig_share, message, csp_public_key, public_coeffs) =
            (sig_share(), signable_mock(), csp_public_key(), pub_coeffs());
        let threshold_sig_data_store = threshold_sig_data_store_with(
            DkgId::NiDkgId(NI_DKG_ID_1),
            public_coeffs,
            indices(vec![(NODE_ID, 3)]),
        );
        let mut csp = MockAllCryptoServiceProvider::new();
        let (expected_msg, expected_sig, expected_pk) =
            (message.clone(), sig_share.clone(), csp_public_key);
        csp.expect_threshold_individual_public_key()
            .times(1)
            .return_const(Ok(csp_public_key));
        csp.expect_threshold_verify_individual_signature()
            .withf(move |alg_id, msg, sig, pubkey| {
                *alg_id == AlgorithmId::from(expected_pk)
                    && msg == expected_msg.as_signed_bytes().as_slice()
                    && *sig == CspSignature::try_from(&expected_sig).unwrap()
                    && *pubkey == expected_pk
            })
            .times(1)
            .return_const(Ok(()));

        let _ = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );
    }

    #[test]
    fn should_return_ok_if_sig_verification_ok_and_public_key_in_store() {
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store = threshold_sig_data_store_with_coeffs_and_pubkey(
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
            csp_public_key,
        );
        let csp = csp_with_verify_indiv_sig_returning_once(Ok(()));

        let verification_result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert!(verification_result.is_ok());
    }

    #[test]
    fn should_return_ok_if_sig_verification_ok_and_public_key_not_in_store() {
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store =
            threshold_sig_data_store_with_non_empty_coeffs_and_indices_for_dkg_id(NI_DKG_ID_1);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_individual_public_key()
            .times(1)
            .return_const(Ok(csp_public_key));
        csp.expect_threshold_verify_individual_signature()
            .times(1)
            .return_const(Ok(()));

        let verification_result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert!(verification_result.is_ok());
    }

    #[test]
    fn should_propagate_sig_verification_error_from_csp_if_public_key_in_store() {
        let verification_error = sig_verification_error();
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store = threshold_sig_data_store_with_coeffs_and_pubkey(
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
            csp_public_key,
        );
        let csp = csp_with_verify_indiv_sig_returning_once(Err(verification_error.clone()));

        let verification_result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert!(verification_result.is_err());
        assert_eq!(verification_result.unwrap_err(), verification_error);
    }

    #[test]
    fn should_propagate_sig_verification_error_if_public_key_not_in_store() {
        let verification_error = sig_verification_error();
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store =
            threshold_sig_data_store_with_non_empty_coeffs_and_indices_for_dkg_id(NI_DKG_ID_1);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_individual_public_key()
            .times(1)
            .return_const(Ok(csp_public_key));
        csp.expect_threshold_verify_individual_signature()
            .times(1)
            .return_const(Err(verification_error.clone()));

        let verification_result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert!(verification_result.is_err());
        assert_eq!(verification_result.unwrap_err(), verification_error);
    }

    #[test]
    fn should_have_correct_public_key_in_store_after_sig_verification_if_not_in_store_before() {
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store =
            threshold_sig_data_store_with_non_empty_coeffs_and_indices_for_dkg_id(NI_DKG_ID_1);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_individual_public_key()
            .times(1)
            .return_const(Ok(csp_public_key));
        csp.expect_threshold_verify_individual_signature()
            .times(1)
            .return_const(Ok(()));

        let _ = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert_eq!(
            threshold_sig_data_store
                .read()
                .individual_public_key(DkgId::NiDkgId(NI_DKG_ID_1), NODE_ID),
            Some(&csp_public_key)
        );
    }

    #[test]
    fn should_not_regenerate_public_key_if_in_store_already() {
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store = threshold_sig_data_store_with_coeffs_and_pubkey(
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
            csp_public_key,
        );
        let mut csp = csp_with_verify_indiv_sig_returning_once(Ok(()));
        csp.expect_threshold_individual_public_key().times(0);

        let _ = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );
    }

    #[test]
    fn should_fail_with_data_not_found_if_transcript_data_missing_upon_key_generation() {
        let (sig_share, message) = (sig_share(), signable_mock());
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_individual_public_key().times(0);
        csp.expect_threshold_verify_individual_signature().times(0);

        let verification_result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert!(verification_result.is_err());
        assert_eq!(
            verification_result.unwrap_err(),
            CryptoError::ThresholdSigDataNotFound {
                dkg_id: DkgId::NiDkgId(NI_DKG_ID_1)
            }
        );
    }

    #[test]
    fn should_fail_with_invalid_argument_if_index_missing_upon_key_generation() {
        let (sig_share, message) = (sig_share(), signable_mock());
        let threshold_sig_data_store = threshold_sig_data_store_with(
            DkgId::NiDkgId(NI_DKG_ID_1),
            pub_coeffs(),
            indices(vec![]),
        );
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_individual_public_key().times(0);
        csp.expect_threshold_verify_individual_signature().times(0);

        let verification_result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert!(verification_result.is_err());
        assert_eq!(
            verification_result.unwrap_err(),
            CryptoError::InvalidArgument {
                message: format!(
                    "There is no node index for dkg id \"{:?}\" and node id \"{}\" in the transcript data.",
                    DkgId::NiDkgId(NI_DKG_ID_1), NODE_ID
                )
            }
        );
    }

    #[test]
    fn should_fail_with_malformed_signature_if_signature_has_invalid_length() {
        let (sig_share, message) = (invalid_threshold_sig_share(), signable_mock());
        let threshold_sig_data_store =
            threshold_sig_data_store_with_non_empty_coeffs_and_indices_for_dkg_id(NI_DKG_ID_1);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_individual_public_key().times(0);
        csp.expect_threshold_verify_individual_signature().times(0);

        let verification_result = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );

        assert!(verification_result.unwrap_err().is_malformed_signature());
    }

    #[test]
    #[should_panic(expected = "Calculation of individual threshold public key")]
    fn should_panic_if_calculating_individual_public_key_fails() {
        let (sig_share, message) = (sig_share(), signable_mock());
        let threshold_sig_data_store = threshold_sig_data_store_with(
            DkgId::NiDkgId(NI_DKG_ID_1),
            pub_coeffs(),
            indices(vec![(NODE_ID, 3)]),
        );
        let mut csp = csp_with_indiv_pk_returning_once(Err(invalid_argument()));
        csp.expect_threshold_verify_individual_signature().times(0);

        let _panic = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );
    }

    #[test]
    #[should_panic(
        expected = "Illegal state: the algorithm of the public key from the threshold \
            signature data store (which is based on the algorithm of the public coefficients in \
            the store) is not supported"
    )]
    fn should_panic_if_csp_returns_invalid_argument_error() {
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store = threshold_sig_data_store_with_coeffs_and_pubkey(
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
            csp_public_key,
        );
        let csp = csp_with_verify_indiv_sig_returning_once(Err(invalid_argument()));

        let _panic = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );
    }

    #[test]
    #[should_panic(
        expected = "Illegal state: the algorithm of the public key from the threshold signature data \
            store (which is based on the algorithm of the public coefficients in the store) is \
            not supported"
    )]
    fn should_panic_if_csp_returns_malformed_public_key_error() {
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store = threshold_sig_data_store_with_coeffs_and_pubkey(
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
            csp_public_key,
        );
        let csp = csp_with_verify_indiv_sig_returning_once(Err(malformed_public_key()));

        let _panic = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );
    }

    #[test]
    #[should_panic(expected = "This case cannot occur")]
    fn should_panic_if_csp_returns_malformed_signature_error() {
        let (sig_share, message, csp_public_key) = (sig_share(), signable_mock(), csp_public_key());
        let threshold_sig_data_store = threshold_sig_data_store_with_coeffs_and_pubkey(
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
            csp_public_key,
        );
        let csp = csp_with_verify_indiv_sig_returning_once(Err(malformed_signature()));

        let _panic = ThresholdSigVerifierInternal::verify_threshold_sig_share(
            &threshold_sig_data_store,
            &csp,
            &sig_share,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
            NODE_ID,
        );
    }

    fn csp_with_indiv_pk_returning_once(
        result: CryptoResult<CspThresholdSigPublicKey>,
    ) -> MockAllCryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_individual_public_key()
            .times(1)
            .return_const(result);
        csp
    }

    fn csp_with_verify_indiv_sig_returning_once(
        result: CryptoResult<()>,
    ) -> MockAllCryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_individual_signature()
            .times(1)
            .return_const(result);
        csp
    }
}

mod combine_threshold_sig_shares {
    use super::*;
    use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3};

    #[test]
    fn should_call_csp_with_correct_algorithm_id_and_pub_coeffs() {
        let dkg_id = DkgId::NiDkgId(NI_DKG_ID_1);
        let pub_coeffs = pub_coeffs();
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let indices = indices(vec![(NODE_1, 0)]);
        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_coeffs = pub_coeffs.clone();
        csp.expect_threshold_combine_signatures()
            .withf(move |algorithm_id, signatures, public_coefficients| {
                *algorithm_id == AlgorithmId::ThresBls12_381
                    && *signatures
                        == vec![Some(individual_csp_threshold_sig(
                            [1; IndividualSignatureBytes::SIZE],
                        ))][..]
                    && *public_coefficients == expected_coeffs
            })
            .times(1)
            .return_const(Ok(combined_csp_threshold_sig(
                [42; CombinedSignatureBytes::SIZE],
            )));
        let threshold_sig_data_store = threshold_sig_data_store_with(dkg_id, pub_coeffs, indices);

        let _ = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            dkg_id,
        );
    }

    #[test]
    fn should_return_combined_sig_from_csp() {
        let csp_combined_sig = combined_csp_threshold_sig([42; CombinedSignatureBytes::SIZE]);
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let indices = indices(vec![(NODE_1, 0)]);
        let csp = csp_with_combine_sigs_returning_once(Ok(csp_combined_sig.clone()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(
            result.unwrap(),
            CombinedThresholdSigOf::try_from(csp_combined_sig).unwrap()
        );
    }

    #[test]
    fn should_call_csp_correctly_with_single_share() {
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let indices = indices(vec![(NODE_1, 0)]);
        let csp = csp_expecting_signatures(vec![Some(individual_csp_threshold_sig(
            [1; IndividualSignatureBytes::SIZE],
        ))]);
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let _ = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    fn should_call_csp_correctly_with_multiple_shares() {
        let shares = shares(vec![
            (
                NODE_1,
                threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
            ),
            (
                NODE_2,
                threshold_sig_share(vec![2; IndividualSignatureBytes::SIZE]),
            ),
            (
                NODE_3,
                threshold_sig_share(vec![3; IndividualSignatureBytes::SIZE]),
            ),
        ]);
        let indices = indices(vec![(NODE_1, 0), (NODE_2, 2), (NODE_3, 4)]);
        let csp = csp_expecting_signatures(vec![
            Some(individual_csp_threshold_sig(
                [1; IndividualSignatureBytes::SIZE],
            )),
            None,
            Some(individual_csp_threshold_sig(
                [2; IndividualSignatureBytes::SIZE],
            )),
            None,
            Some(individual_csp_threshold_sig(
                [3; IndividualSignatureBytes::SIZE],
            )),
        ]);
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let _ = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    fn should_return_error_if_shares_empty() {
        let shares = shares(vec![]);
        let indices = indices(vec![]);
        let csp = MockAllCryptoServiceProvider::new();
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(
            result.unwrap_err(),
            CryptoError::InvalidArgument {
                message: "The shares must not be empty.".to_string()
            }
        );
    }

    #[test]
    fn should_return_error_if_no_transcript_data_for_dkg_id_in_store() {
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let csp = MockAllCryptoServiceProvider::new();
        let threshold_sig_data_store = LockableThresholdSigDataStore::new();

        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(
            result.unwrap_err(),
            CryptoError::ThresholdSigDataNotFound {
                dkg_id: DkgId::NiDkgId(NI_DKG_ID_1)
            }
        );
    }

    #[test]
    fn should_return_error_if_index_for_node_id_not_present_in_store() {
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let indices = indices(vec![(NODE_2, 0)]);
        let csp = MockAllCryptoServiceProvider::new();
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(
            result.unwrap_err(),
            CryptoError::InvalidArgument {
                message: format!(
                    "There is no node index for dkg id \"{:?}\" and node id \"{}\" in the transcript data.",
                    DkgId::NiDkgId(NI_DKG_ID_1), NODE_1
                )
            }
        );
    }

    #[test]
    #[should_panic(expected = "The CSP must return a signature of type \
        `CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined)`.")]
    fn should_panic_if_csp_returns_wrong_signature_type() {
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let indices = indices(vec![(NODE_1, 0)]);
        let csp = csp_with_combine_sigs_returning_once(Ok(individual_csp_threshold_sig(
            [42; CombinedSignatureBytes::SIZE],
        )));
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let _panic = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    fn should_return_error_if_threshold_sig_shares_malformed() {
        let wrong_signature_size = IndividualSignatureBytes::SIZE + 1;
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; wrong_signature_size]),
        )]);
        let indices = indices(vec![(NODE_1, 0)]);
        let csp = MockAllCryptoServiceProvider::new();
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert!(result.unwrap_err().is_malformed_signature());
    }

    #[test]
    fn should_return_error_if_csp_returns_malformed_signature_error() {
        let indices = indices(vec![(NODE_1, 0)]);
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let csp = csp_with_combine_sigs_returning_once(Err(malformed_signature()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert!(result.unwrap_err().is_malformed_signature());
    }

    #[test]
    fn should_return_error_if_csp_returns_invalid_argument_error() {
        let indices = indices(vec![(NODE_1, 0)]);
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let csp = csp_with_combine_sigs_returning_once(Err(invalid_argument()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let result = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(result.unwrap_err(), invalid_argument());
    }

    #[test]
    #[should_panic(expected = "Illegal state: unexpected error from the CSP")]
    fn should_panic_if_csp_returns_unexpected_error() {
        let indices = indices(vec![(NODE_1, 0_u32)]);
        let shares = shares(vec![(
            NODE_1,
            threshold_sig_share(vec![1; IndividualSignatureBytes::SIZE]),
        )]);
        let csp = csp_with_combine_sigs_returning_once(Err(sig_verification_error()));
        let threshold_sig_data_store =
            threshold_sig_data_store_with(DkgId::NiDkgId(NI_DKG_ID_1), pub_coeffs(), indices);

        let _panic = ThresholdSigVerifierInternal::combine_threshold_sig_shares(
            &threshold_sig_data_store,
            &csp,
            shares,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    fn csp_with_combine_sigs_returning_once(
        result: CryptoResult<CspSignature>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_combine_signatures()
            .times(1)
            .return_const(result);
        csp
    }

    fn threshold_sig_share(bytes: Vec<u8>) -> ThresholdSigShareOf<SignableMock> {
        ThresholdSigShareOf::new(ThresholdSigShare(bytes))
    }

    fn shares(
        entries: Vec<(NodeId, ThresholdSigShareOf<SignableMock>)>,
    ) -> BTreeMap<NodeId, ThresholdSigShareOf<SignableMock>> {
        btree_map(entries)
    }

    fn csp_expecting_signatures(
        expected_signatures: Vec<Option<CspSignature>>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_combine_signatures()
            .withf(move |algorithm_id, signatures, public_coefficients| {
                *algorithm_id == AlgorithmId::ThresBls12_381
                    && *signatures == expected_signatures[..]
                    && *public_coefficients == pub_coeffs()
            })
            .times(1)
            .return_const(Ok(combined_csp_threshold_sig(
                [42; CombinedSignatureBytes::SIZE],
            )));
        csp
    }
}

mod verify_threshold_sig_combined {
    use super::*;

    #[test]
    fn should_call_csp_with_correct_params() {
        let dkg_id = DkgId::NiDkgId(NI_DKG_ID_1);
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_threshold_verify_combined_signature_expecting_once(
            AlgorithmId::ThresBls12_381,
            message.as_signed_bytes(),
            CspSignature::try_from(&combined_sig).unwrap(),
            pub_coeffs.clone(),
        );

        let _ = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &threshold_sig_data_store_with_coeffs(pub_coeffs, dkg_id),
            &csp,
            &combined_sig,
            &message,
            dkg_id,
        );
    }

    #[test]
    fn should_return_ok_if_sig_verification_ok() {
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_verify_combined_returning_once(Ok(()));

        let result = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &threshold_sig_data_store_with_coeffs(pub_coeffs, DkgId::NiDkgId(NI_DKG_ID_1)),
            &csp,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_with_data_not_found_if_public_coeffs_missing() {
        let (combined_sig, message) = (combined_sig(), signable_mock());
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_combined_signature().times(0);

        let result = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &LockableThresholdSigDataStore::new(),
            &csp,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(
            result.unwrap_err(),
            CryptoError::ThresholdSigDataNotFound {
                dkg_id: DkgId::NiDkgId(NI_DKG_ID_1)
            }
        );
    }

    #[test]
    fn should_fail_with_malformed_signature_if_signature_has_invalid_length() {
        let (invalid_sig, message) = (invalid_combined_threshold_sig(), signable_mock());
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_combined_signature().times(0);

        let result = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &default_threshold_sig_data_store(),
            &csp,
            &invalid_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert!(result.unwrap_err().is_malformed_signature());
    }

    #[test]
    fn should_propagate_sig_verification_error_from_csp() {
        let verification_error = sig_verification_error();
        let (combined_sig, message) = (combined_sig(), signable_mock());
        let csp = csp_with_verify_combined_returning_once(Err(verification_error.clone()));

        let result = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &default_threshold_sig_data_store(),
            &csp,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(result.unwrap_err(), verification_error);
    }

    #[test]
    fn should_propagate_malformed_signature_error_from_csp() {
        let malformed_sig_error = malformed_signature();
        let (combined_sig, message) = (combined_sig(), signable_mock());
        let csp = csp_with_verify_combined_returning_once(Err(malformed_sig_error.clone()));

        let result = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &default_threshold_sig_data_store(),
            &csp,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );

        assert_eq!(result.unwrap_err(), malformed_sig_error);
    }

    #[test]
    #[should_panic(expected = "Illegal state: unsupported algorithm")]
    fn should_panic_if_csp_returns_invalid_argument_error() {
        let (combined_sig, message) = (combined_sig(), signable_mock());
        let csp = csp_with_verify_combined_returning_once(Err(invalid_argument()));

        let _panic = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &default_threshold_sig_data_store(),
            &csp,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    #[should_panic(expected = "Illegal state: the public key computed from the public \
    coefficients is malformed")]
    fn should_panic_if_csp_returns_malformed_public_key_error() {
        let (combined_sig, message) = (combined_sig(), signable_mock());
        let csp = csp_with_verify_combined_returning_once(Err(malformed_public_key()));

        let _panic = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &default_threshold_sig_data_store(),
            &csp,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    #[should_panic(expected = "Illegal state: unexpected error from the CSP")]
    fn should_panic_if_csp_returns_unexpected_error() {
        let (combined_sig, message) = (combined_sig(), signable_mock());
        let csp = csp_with_verify_combined_returning_once(Err(secret_key_not_found()));

        let _panic = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &default_threshold_sig_data_store(),
            &csp,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    fn csp_with_verify_combined_returning_once(
        result: Result<(), CryptoError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_combined_signature()
            .times(1)
            .return_const(result);
        csp
    }
}

mod verify_combined_threshold_sig_by_public_key {
    use super::*;
    use crate::common::utils::ni_dkg::initial_ni_dkg_transcript_record_from_transcript;
    use crate::sign::tests::{registry_returning_none, REG_V1, SUBNET_ID};
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
        ni_dkg_groth20_bls12_381, CspNiDkgTranscript,
    };
    use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
    use ic_registry_client::fake::FakeRegistryClient;
    use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
    use ic_registry_keys::make_catch_up_package_contents_key;
    use ic_test_utilities::crypto::{basic_utilities::set_of, empty_ni_dkg_transcripts};
    use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
    use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgThreshold;
    use ic_types::NumberOfNodes;

    #[test]
    fn should_call_csp_with_correct_params() {
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_threshold_verify_combined_signature_expecting_once(
            AlgorithmId::ThresBls12_381,
            message.as_signed_bytes(),
            CspSignature::try_from(&combined_sig).unwrap(),
            pub_coeffs.clone(),
        );
        let registry = registry_with_dkg_transcript(transcript_with(pub_coeffs), SUBNET_ID, REG_V1);

        let _ = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );
    }

    #[test]
    fn should_call_csp_with_same_params_as_when_verifying_by_dkg_id() {
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let (expected_alg_id, expected_msg, expected_sig, expected_coeffs) = (
            AlgorithmId::ThresBls12_381,
            message.as_signed_bytes(),
            CspSignature::try_from(&combined_sig).unwrap(),
            pub_coeffs.clone(),
        );
        let csp_1 = csp_with_threshold_verify_combined_signature_expecting_once(
            expected_alg_id,
            expected_msg.clone(),
            expected_sig.clone(),
            expected_coeffs.clone(),
        );
        // Ideally, this test would use a single CSP instance. The mock CSP cannot be
        // cloned though, so we resort to creating a second (identical) instance.
        let csp_2 = csp_with_threshold_verify_combined_signature_expecting_once(
            expected_alg_id,
            expected_msg,
            expected_sig,
            expected_coeffs,
        );
        let registry =
            registry_with_dkg_transcript(transcript_with(pub_coeffs.clone()), SUBNET_ID, REG_V1);

        let _ = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp_1,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );
        let _ = ThresholdSigVerifierInternal::verify_threshold_sig_combined(
            &threshold_sig_data_store_with_coeffs(pub_coeffs, DkgId::NiDkgId(NI_DKG_ID_1)),
            &csp_2,
            &combined_sig,
            &message,
            DkgId::NiDkgId(NI_DKG_ID_1),
        );
    }

    #[test]
    fn should_return_ok_if_sig_verification_ok() {
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_verify_combined_returning_once(Ok(()));
        let registry = registry_with_dkg_transcript(transcript_with(pub_coeffs), SUBNET_ID, REG_V1);

        let result = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_fail_with_transcript_not_found_if_transcript_not_found_in_registry() {
        let (combined_sig, message) = (combined_sig(), signable_mock());
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_combined_signature().times(0);

        let result = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry_returning_none(),
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );

        assert_eq!(
            result.unwrap_err(),
            CryptoError::DkgTranscriptNotFound {
                subnet_id: SUBNET_ID,
                registry_version: REG_V1
            }
        );
    }

    #[test]
    fn should_fail_with_malformed_signature_if_signature_has_invalid_length() {
        let (invalid_sig, message) = (invalid_combined_threshold_sig(), signable_mock());
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_combined_signature().times(0);

        let result = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry_returning_none(),
            &invalid_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );

        assert!(result.unwrap_err().is_malformed_signature());
    }

    #[test]
    fn should_propagate_sig_verification_error_from_csp() {
        let verification_error = sig_verification_error();
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_verify_combined_returning_once(Err(verification_error.clone()));
        let registry = registry_with_dkg_transcript(transcript_with(pub_coeffs), SUBNET_ID, REG_V1);

        let result = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );

        assert_eq!(result.unwrap_err(), verification_error);
    }

    #[test]
    fn should_propagate_malformed_signature_error_from_csp() {
        let malformed_sig_error = malformed_signature();
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_verify_combined_returning_once(Err(malformed_sig_error.clone()));
        let registry = registry_with_dkg_transcript(transcript_with(pub_coeffs), SUBNET_ID, REG_V1);

        let result = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );

        assert_eq!(result.unwrap_err(), malformed_sig_error);
    }

    #[test]
    #[should_panic(expected = "Illegal state: unsupported algorithm")]
    fn should_panic_if_csp_returns_invalid_argument_error() {
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_verify_combined_returning_once(Err(invalid_argument()));
        let registry = registry_with_dkg_transcript(transcript_with(pub_coeffs), SUBNET_ID, REG_V1);

        let _panic = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );
    }

    #[test]
    #[should_panic(expected = "Illegal state: the public key computed from \
                               the public coefficients is malformed")]
    fn should_panic_if_csp_returns_malformed_public_key_error() {
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_verify_combined_returning_once(Err(malformed_public_key()));
        let registry = registry_with_dkg_transcript(transcript_with(pub_coeffs), SUBNET_ID, REG_V1);

        let _panic = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );
    }

    #[test]
    #[should_panic(expected = "Illegal state: unexpected error from the CSP")]
    fn should_panic_if_csp_returns_unexpected_error() {
        let (combined_sig, message, pub_coeffs) = (combined_sig(), signable_mock(), pub_coeffs());
        let csp = csp_with_verify_combined_returning_once(Err(secret_key_not_found()));
        let registry = registry_with_dkg_transcript(transcript_with(pub_coeffs), SUBNET_ID, REG_V1);

        let _panic = ThresholdSigVerifierInternal::verify_combined_threshold_sig_by_public_key(
            &csp,
            registry,
            &combined_sig,
            &message,
            SUBNET_ID,
            REG_V1,
        );
    }

    fn csp_with_verify_combined_returning_once(
        result: Result<(), CryptoError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_threshold_verify_combined_signature()
            .times(1)
            .return_const(result);
        csp
    }

    fn registry_with_dkg_transcript(
        transcript: NiDkgTranscript,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Arc<dyn RegistryClient> {
        let cup_contents = CatchUpPackageContents {
            // We store both transcripts as in production scenario.
            initial_ni_dkg_transcript_low_threshold: Some(
                initial_ni_dkg_transcript_record_from_transcript(
                    empty_ni_dkg_transcripts()
                        .remove(&NiDkgTag::LowThreshold)
                        .unwrap(),
                ),
            ),
            initial_ni_dkg_transcript_high_threshold: Some(
                initial_ni_dkg_transcript_record_from_transcript(transcript),
            ),
            ..Default::default()
        };
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        data_provider
            .add(
                &make_catch_up_package_contents_key(subnet_id),
                version,
                Some(cup_contents),
            )
            .expect("failed to add subnet record");

        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        // Need to poll the data provider at least once to update the cache.
        registry_client.update_to_latest_version();
        registry_client
    }

    fn transcript_with(public_coeffs: CspPublicCoefficients) -> NiDkgTranscript {
        NiDkgTranscript {
            dkg_id: NI_DKG_ID_1,
            threshold: NiDkgThreshold::new(NumberOfNodes::new(1)).unwrap(),
            committee: NiDkgReceivers::new(set_of(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            internal_csp_transcript: csp_ni_dkg_transcript_with(public_coeffs),
        }
    }

    fn csp_ni_dkg_transcript_with(
        public_coefficients: CspPublicCoefficients,
    ) -> CspNiDkgTranscript {
        CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
            public_coefficients: ni_dkg_groth20_bls12_381::PublicCoefficientsBytes::from(
                public_coefficients,
            ),
            receiver_data: BTreeMap::default(),
        })
    }
}

fn signable_mock() -> SignableMock {
    SignableMock::new(b"message".to_vec())
}

fn individual_csp_threshold_sig(bytes: [u8; IndividualSignatureBytes::SIZE]) -> CspSignature {
    CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(
        IndividualSignatureBytes(bytes),
    ))
}

fn combined_csp_threshold_sig(bytes: [u8; CombinedSignatureBytes::SIZE]) -> CspSignature {
    CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(CombinedSignatureBytes(
        bytes,
    )))
}

fn secret_key_not_found() -> CryptoError {
    CryptoError::SecretKeyNotFound {
        algorithm: AlgorithmId::Placeholder,
        key_id: KeyId::from(KEY_ID),
    }
}

fn invalid_argument() -> CryptoError {
    CryptoError::InvalidArgument {
        message: "some_error".to_string(),
    }
}

fn malformed_public_key() -> CryptoError {
    CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::Placeholder,
        key_bytes: None,
        internal_error: "some error".to_string(),
    }
}

fn malformed_signature() -> CryptoError {
    CryptoError::MalformedSignature {
        algorithm: AlgorithmId::Placeholder,
        sig_bytes: vec![],
        internal_error: "some error".to_string(),
    }
}

fn sig_verification_error() -> CryptoError {
    CryptoError::SignatureVerification {
        algorithm: AlgorithmId::ThresBls12_381,
        public_key_bytes: vec![],
        sig_bytes: vec![],
        internal_error: "".to_string(),
    }
}

fn csp_public_key() -> CspThresholdSigPublicKey {
    CspThresholdSigPublicKey::ThresBls12_381(PublicKeyBytes([42; PublicKeyBytes::SIZE]))
}

fn sig_share() -> ThresholdSigShareOf<SignableMock> {
    let csp_sig = CspSignature::thres_bls12381_indiv_from_array_of(42);
    ThresholdSigShareOf::try_from(csp_sig).unwrap()
}

fn combined_sig() -> CombinedThresholdSigOf<SignableMock> {
    let csp_sig = CspSignature::thres_bls12381_combined_from_array_of(42);
    CombinedThresholdSigOf::try_from(csp_sig).unwrap()
}

fn pub_coeffs() -> CspPublicCoefficients {
    mock_csp_public_coefficients_from_bytes(43)
}

fn invalid_threshold_sig_share<T>() -> ThresholdSigShareOf<T> {
    ThresholdSigShareOf::new(ThresholdSigShare(vec![]))
}

fn invalid_combined_threshold_sig<T>() -> CombinedThresholdSigOf<T> {
    CombinedThresholdSigOf::new(CombinedThresholdSig(vec![]))
}

fn threshold_sig_data_store_with(
    dkg_id: DkgId,
    public_coeffs: CspPublicCoefficients,
    indices: BTreeMap<NodeId, NodeIndex>,
) -> LockableThresholdSigDataStore {
    let store = LockableThresholdSigDataStore::new();
    store
        .write()
        .insert_transcript_data(dkg_id, public_coeffs, indices);
    store
}

fn threshold_sig_data_store_with_non_empty_coeffs_and_indices_for_dkg_id(
    ni_dkg_id: NiDkgId,
) -> LockableThresholdSigDataStore {
    let store = LockableThresholdSigDataStore::new();
    store.write().insert_transcript_data(
        DkgId::NiDkgId(ni_dkg_id),
        pub_coeffs(),
        indices(vec![(NODE_ID, 1)]),
    );
    store
}

fn threshold_sig_data_store_with_coeffs(
    csp_public_coefficients: CspPublicCoefficients,
    dkg_id: DkgId,
) -> LockableThresholdSigDataStore {
    let threshold_sig_data_store = LockableThresholdSigDataStore::new();
    threshold_sig_data_store.write().insert_transcript_data(
        dkg_id,
        csp_public_coefficients,
        BTreeMap::new(),
    );
    threshold_sig_data_store
}

fn threshold_sig_data_store_with_coeffs_and_pubkey(
    dkg_id: DkgId,
    node_id: NodeId,
    public_key: CspThresholdSigPublicKey,
) -> LockableThresholdSigDataStore {
    let threshold_sig_data_store = LockableThresholdSigDataStore::new();
    {
        let mut locked_store = threshold_sig_data_store.write();
        locked_store.insert_transcript_data(dkg_id, pub_coeffs(), BTreeMap::new());
        locked_store.insert_individual_public_key(dkg_id, node_id, public_key);
    }
    threshold_sig_data_store
}

fn indices(mappings: Vec<(NodeId, NodeIndex)>) -> BTreeMap<NodeId, NodeIndex> {
    btree_map(mappings)
}

fn btree_map<H>(entries: Vec<(NodeId, H)>) -> BTreeMap<NodeId, H> {
    let mut result = BTreeMap::new();
    for entry in entries {
        result.insert(entry.0, entry.1);
    }
    result
}

fn default_threshold_sig_data_store() -> LockableThresholdSigDataStore {
    threshold_sig_data_store_with_coeffs(pub_coeffs(), DkgId::NiDkgId(NI_DKG_ID_1))
}

fn csp_with_threshold_verify_combined_signature_expecting_once(
    algorithm_id: AlgorithmId,
    message: Vec<u8>,
    signature: CspSignature,
    public_coefficients: CspPublicCoefficients,
) -> impl CryptoServiceProvider {
    let mut csp = MockAllCryptoServiceProvider::new();
    csp.expect_threshold_verify_combined_signature()
        .withf(move |alg_id, msg, sig, pub_coeffs| {
            *alg_id == algorithm_id
                && *msg == message[..]
                && *sig == signature
                && *pub_coeffs == public_coefficients
        })
        .times(1)
        .return_const(Ok(()));
    csp
}

pub fn mock_csp_public_coefficients_from_bytes(byte: u8) -> CspPublicCoefficients {
    CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([byte; PublicKeyBytes::SIZE])],
    })
}
