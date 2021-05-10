#![allow(clippy::unwrap_used)]

use super::*;

use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::sign::threshold_sig::tests::I_DKG_ID;
use ic_crypto_internal_csp::types::CspPop;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::EphemeralPopBytes;
use ic_test_utilities::types::ids::{node_test_id, NODE_1, NODE_2, NODE_3};
use ic_types::crypto::AlgorithmId;
use ic_types::{IDkgId, PrincipalId};

pub const NODE_ID: u64 = 1;

mod generate_encryption_keys {
    use super::*;
    use ic_crypto_internal_csp::types::CspPop;
    use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_ephemeral()
            .withf(move |dkg_id, node_id| {
                *dkg_id == I_DKG_ID
                    && PrincipalId::try_from(&node_id[..]).unwrap() == node_test_id(NODE_ID).get()
            })
            .times(1)
            .return_const(Ok((csp_enc_pk(), csp_pop())));

        let _ = generate_encryption_keys(&csp, &dummy_dkg_config(I_DKG_ID), node_test_id(NODE_ID));
    }

    #[test]
    fn should_return_pk_and_pop_from_csp_if_csp_returns_ok() {
        let (csp_enc_pk, csp_pop) = (csp_enc_pk(), csp_pop());
        let csp = mock_csp_with_create_ephemeral_returning(Ok((csp_enc_pk, csp_pop)));

        let pk_with_pop =
            generate_encryption_keys(&csp, &dummy_dkg_config(I_DKG_ID), node_test_id(NODE_ID))
                .unwrap();

        assert_eq!(pk_with_pop.key, EncryptionPublicKey::from(&csp_enc_pk));
        assert_eq!(
            pk_with_pop.proof_of_possession,
            EncryptionPublicKeyPop::from(&csp_pop)
        );
    }

    #[test]
    // TODO (CRP-313): Test the error handling once implemented, see TODO in
    // generate_encryption_keys
    #[should_panic(
        expected = "Internal error from CSP: MalformedSecretKeyError { algorithm: Secp256k1, internal_error: \"\" }"
    )]
    fn should_panic_on_error_from_csp() {
        let some_error = dkg_errors::DkgCreateEphemeralError::MalformedSecretKeyError(
            dkg_errors::MalformedSecretKeyError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "".to_string(),
            },
        );
        let csp = mock_csp_with_create_ephemeral_returning(Err(some_error));

        let _panic =
            generate_encryption_keys(&csp, &dummy_dkg_config(I_DKG_ID), node_test_id(NODE_ID));
    }

    fn mock_csp_with_create_ephemeral_returning(
        result: Result<(CspEncryptionPublicKey, CspPop), dkg_errors::DkgCreateEphemeralError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_ephemeral()
            .times(1)
            .return_const(result);
        csp
    }

    // Creates a dummy DkgConfig with the specified dkg_id
    fn dummy_dkg_config(dkg_id: IDkgId) -> dkg::DkgConfig {
        create_config(DkgConfigData {
            dkg_id,
            dealers: vec![NODE_1],
            receivers: vec![NODE_1],
            threshold: 1,
            resharing_transcript: None,
        })
    }

    fn csp_pop() -> CspPop {
        CspPop::Secp256k1(EphemeralPopBytes([42; EphemeralPopBytes::SIZE]))
    }

    fn csp_enc_pk() -> CspEncryptionPublicKey {
        CspEncryptionPublicKey::default()
    }
}

mod verify_encryption_public_key {
    use super::*;
    use crate::sign::threshold_sig::dkg::test_utils::{csp_enc_pk, csp_pop};
    use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;

    const SENDER: u64 = 42;

    #[test]
    fn should_call_csp_with_correct_parameters() {
        let csp_pk = csp_enc_pk(42);
        let csp_pop = csp_pop(43);
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_verify_ephemeral()
            .withf(move |dkg_id, node_id, key| {
                *dkg_id == I_DKG_ID
                    && PrincipalId::try_from(&node_id[..]).unwrap() == node_test_id(SENDER).get()
                    && *key == (csp_pk, csp_pop)
            })
            .times(1)
            .return_const(Ok(()));

        let _ = verify_encryption_public_key(
            &csp,
            &dkg_config_with_receivers(I_DKG_ID, &[node_test_id(SENDER)]),
            node_test_id(SENDER),
            &enc_pk_with_pop(csp_pk, &csp_pop),
        );
    }

    #[test]
    fn should_return_ok_if_csp_returns_ok_and_sender_in_receivers() {
        let csp = csp_with_dkg_verify_ephemeral_returning(Ok(()));

        let result = verify_encryption_public_key(
            &csp,
            &dkg_config_with_dealers_and_receivers(
                I_DKG_ID,
                &[NODE_1, NODE_2],
                &[node_test_id(SENDER), NODE_3],
            ),
            node_test_id(SENDER),
            &enc_pk_with_pop(csp_enc_pk(42), &csp_pop(43)),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_ok_if_csp_returns_ok_and_sender_in_dealers() {
        let csp = csp_with_dkg_verify_ephemeral_returning(Ok(()));

        let result = verify_encryption_public_key(
            &csp,
            &dkg_config_with_dealers_and_receivers(
                I_DKG_ID,
                &[node_test_id(SENDER)],
                &[NODE_1, NODE_2],
            ),
            node_test_id(SENDER),
            &enc_pk_with_pop(csp_enc_pk(42), &csp_pop(43)),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_ok_if_csp_returns_ok_and_sender_in_both_dealers_and_receivers() {
        let csp = csp_with_dkg_verify_ephemeral_returning(Ok(()));

        let result = verify_encryption_public_key(
            &csp,
            &dkg_config_with_dealers_and_receivers(
                I_DKG_ID,
                &[NODE_1, node_test_id(SENDER)],
                &[NODE_1, node_test_id(SENDER), NODE_2],
            ),
            node_test_id(SENDER),
            &enc_pk_with_pop(csp_enc_pk(42), &csp_pop(43)),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_error_if_sender_not_in_dealers_or_receivers() {
        let csp = MockAllCryptoServiceProvider::new();

        let result = verify_encryption_public_key(
            &csp,
            &dkg_config_with_dealers_and_receivers(I_DKG_ID, &[NODE_1], &[NODE_2]),
            node_test_id(SENDER),
            &enc_pk_with_pop(csp_enc_pk(42), &csp_pop(43)),
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_argument(
                "The sender node ID \"nxqfi-cjkaa-aaaaa-aaaap-2ai\" must be contained in the DKG config's receivers or \
                dealers (or both)."
            )
        );
    }

    #[test]
    // TODO (CRP-342): Distinguish errors returned by CSP
    fn should_return_error_if_csp_returns_error() {
        let csp = csp_with_dkg_verify_ephemeral_returning(Err(
            dkg_errors::DkgVerifyEphemeralError::InvalidPopError(dkg_errors::MalformedPopError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "".to_string(),
                bytes: None,
            }),
        ));

        let result = verify_encryption_public_key(
            &csp,
            &dkg_config_with_receivers(I_DKG_ID, &[node_test_id(SENDER)]),
            node_test_id(SENDER),
            &enc_pk_with_pop(csp_enc_pk(42), &csp_pop(43)),
        );

        assert_eq!(result.unwrap_err(), invalid_argument("CSP error: MalformedPopError { algorithm: Secp256k1, internal_error: \"\", bytes: None }"));
    }

    fn csp_with_dkg_verify_ephemeral_returning(
        result: Result<(), dkg_errors::DkgVerifyEphemeralError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_verify_ephemeral()
            .times(1)
            .return_const(result);
        csp
    }

    fn enc_pk_with_pop(
        csp_pk: CspEncryptionPublicKey,
        csp_pop: &CspPop,
    ) -> EncryptionPublicKeyWithPop {
        EncryptionPublicKeyWithPop {
            key: EncryptionPublicKey::from(&csp_pk),
            proof_of_possession: EncryptionPublicKeyPop::from(csp_pop),
        }
    }

    fn dkg_config_with_dealers_and_receivers(
        dkg_id: IDkgId,
        dealers: &[NodeId],
        receivers: &[NodeId],
    ) -> DkgConfig {
        create_config(DkgConfigData {
            dkg_id,
            dealers: dealers.to_vec(),
            receivers: receivers.to_vec(),
            threshold: 1,
            resharing_transcript: None,
        })
    }

    fn dkg_config_with_receivers(dkg_id: IDkgId, receivers: &[NodeId]) -> DkgConfig {
        dkg_config_with_dealers_and_receivers(dkg_id, &[NODE_1], receivers)
    }

    fn invalid_argument(msg: &str) -> CryptoError {
        CryptoError::InvalidArgument {
            message: msg.to_string(),
        }
    }
}

fn create_config(config_data: DkgConfigData) -> DkgConfig {
    DkgConfig::new(config_data).expect("unable to create dkg config")
}
