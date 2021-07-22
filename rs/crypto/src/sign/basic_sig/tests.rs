#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::crypto_component::crypto_component_with;
use crate::sign::tests::*;
use ic_crypto_internal_csp_test_utils::secret_key_store_test_utils::MockSecretKeyStore;
use ic_interfaces::crypto::SignableMock;
use ic_interfaces::crypto::DOMAIN_IC_REQUEST;
use ic_test_utilities::types::arbitrary as arbitrary_types;
use ic_test_utilities::types::ids::NODE_1;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::messages::MessageId;
use ic_types::registry::RegistryClientError;

mod test_basic_sign {
    use super::*;
    use crate::common::test_utils::basic_sig;
    use crate::common::test_utils::basic_sig::TestVector::ED25519_STABILITY_1;
    mod sign_common {
        use super::*;

        #[test]
        fn should_fail_with_key_not_found_if_public_key_not_found_in_registry() {
            let crypto =
                crypto_component_with(registry_returning_none(), MockSecretKeyStore::new());

            let result = crypto.sign_basic(&SignableMock::new(vec![]), NODE_1, REG_V1);
            assert!(result.unwrap_err().is_public_key_not_found());
        }

        #[test]
        fn should_fail_with_registryerror_if_registry_version_too_new() {
            let crypto = crypto_component_with(
                registry_returning(RegistryClientError::VersionNotAvailable { version: REG_V2 }),
                MockSecretKeyStore::new(),
            );

            let result = crypto.sign_basic(&SignableMock::new(vec![]), NODE_1, REG_V2);

            assert!(result.unwrap_err().is_registry_client_error());
        }

        #[test]
        fn should_fail_with_secret_key_not_found_if_secret_key_not_found_in_key_store() {
            let (_, pk, _, _) = basic_sig::testvec(ED25519_STABILITY_1);
            let key_record = node_signing_record_with(
                NODE_1,
                pk.ed25519_bytes().unwrap().to_vec(),
                KeyId::from(KEY_ID),
                REG_V2,
            );
            let crypto =
                crypto_component_with(registry_with(key_record), secret_key_store_returning_none());

            let result = crypto.sign_basic(&SignableMock::new(vec![]), NODE_1, REG_V2);

            assert!(result.unwrap_err().is_secret_key_not_found());
        }
    }

    mod sign {
        use super::*;
        use crate::common::test_utils::basic_sig;
        use crate::common::test_utils::basic_sig::TestVector::ED25519_STABILITY_1;

        // Here we only test with a single test vector: an extensive test with the
        // entire test vector suite is done at the crypto lib level.
        #[test]
        fn should_correctly_sign() {
            let (sk, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
            let key_id = public_key_hash_as_key_id(&pk);
            let key_record = node_signing_record_with(
                NODE_1,
                pk.ed25519_bytes().unwrap().to_vec(),
                key_id.to_owned(),
                REG_V2,
            );
            let secret_key_store = secret_key_store_with(key_id, sk);
            let crypto = crypto_component_with(registry_with(key_record), secret_key_store);

            assert_eq!(crypto.sign_basic(&msg, NODE_1, REG_V2).unwrap(), sig);
        }
    }
}

mod test_basic_sig_verification {
    use super::*;
    use crate::common::test_utils::basic_sig;
    use crate::common::test_utils::basic_sig::TestVector::{
        ED25519_STABILITY_1, ED25519_STABILITY_2,
    };

    mod verify_common {
        use super::*;
        use crate::sign::tests::REG_V2;
        use ic_test_utilities::types::ids::NODE_1;

        #[test]
        fn should_fail_with_key_not_found_if_public_key_not_found_in_registry() {
            let (_, _, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
            let crypto =
                crypto_component_with(registry_returning_none(), MockSecretKeyStore::new());

            let result = crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V1);
            assert!(result.unwrap_err().is_public_key_not_found());
        }

        #[test]
        fn should_verify_without_using_secret_key_store() {
            let (_, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
            let key_record = node_signing_record_with(
                NODE_1,
                pk.ed25519_bytes().unwrap().to_vec(),
                KeyId::from(KEY_ID),
                REG_V2,
            );
            let crypto = crypto_component_with(
                registry_with(key_record),
                secret_key_store_panicking_on_usage(),
            );

            assert!(crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V2).is_ok());
        }
    }

    mod verify {
        use super::*;
        use crate::sign::tests::{node_signing_record_with, registry_with, KEY_ID, REG_V2};
        use ic_test_utilities::types::ids::NODE_1;

        // Here we only test with a single test vector: an extensive test with the
        // entire test vector suite is done at the crypto lib level.
        #[test]
        fn should_correctly_verify() {
            let (_, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
            let key_record = node_signing_record_with(
                NODE_1,
                pk.ed25519_bytes().unwrap().to_vec(),
                KeyId::from(KEY_ID),
                REG_V2,
            );
            let crypto =
                crypto_component_with(registry_with(key_record), MockSecretKeyStore::new());

            assert!(crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V2).is_ok());
        }

        #[test]
        fn should_fail_to_verify_under_wrong_signature() {
            let (_, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
            let (_, _, _, wrong_sig) = basic_sig::testvec(ED25519_STABILITY_2);
            assert_ne!(sig, wrong_sig);
            let key_record = node_signing_record_with(
                NODE_1,
                pk.ed25519_bytes().unwrap().to_vec(),
                KeyId::from(KEY_ID),
                REG_V2,
            );
            let crypto =
                crypto_component_with(registry_with(key_record), MockSecretKeyStore::new());

            let result = crypto.verify_basic_sig(&wrong_sig, &msg, NODE_1, REG_V2);

            assert!(result.unwrap_err().is_signature_verification_error());
        }

        #[test]
        fn should_fail_to_verify_under_wrong_message() {
            let (_, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
            let wrong_msg = SignableMock::new(b"wrong message".to_vec());
            assert_ne!(msg, wrong_msg);
            let key_record = node_signing_record_with(
                NODE_1,
                pk.ed25519_bytes().unwrap().to_vec(),
                KeyId::from(KEY_ID),
                REG_V2,
            );
            let crypto =
                crypto_component_with(registry_with(key_record), MockSecretKeyStore::new());

            let result = crypto.verify_basic_sig(&sig, &wrong_msg, NODE_1, REG_V2);

            assert!(result.unwrap_err().is_signature_verification_error());
        }

        #[test]
        fn should_fail_to_verify_under_wrong_public_key() {
            let (_, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
            let (_, wrong_pk, _, _) = basic_sig::testvec(ED25519_STABILITY_2);
            assert_ne!(pk, wrong_pk);
            let key_record = node_signing_record_with(
                NODE_1,
                wrong_pk.ed25519_bytes().unwrap().to_vec(),
                KeyId::from(KEY_ID),
                REG_V2,
            );
            let crypto =
                crypto_component_with(registry_with(key_record), MockSecretKeyStore::new());

            let result = crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V2);

            assert!(result.unwrap_err().is_signature_verification_error());
        }

        #[test]
        fn should_fail_with_malformed_signature_if_signature_has_incompatible_length() {
            let (_, pk, msg, _) = basic_sig::testvec(ED25519_STABILITY_1);
            let key_record = node_signing_record_with(
                NODE_1,
                pk.ed25519_bytes().unwrap().to_vec(),
                KeyId::from(KEY_ID),
                REG_V2,
            );
            let crypto =
                crypto_component_with(registry_with(key_record), MockSecretKeyStore::new());
            let incompatible_sig = BasicSigOf::new(BasicSig(vec![1, 2, 3]));

            let err = crypto
                .verify_basic_sig(&incompatible_sig, &msg, NODE_1, REG_V2)
                .unwrap_err();

            assert!(err.is_malformed_signature());
        }

        // TODO(DFN-1220): re-enable this test; need to create a test registry
        //     with invalid public keys.
        // #[test]
        // fn should_fail_with_malformed_public_key_if_pubkey_from_registry_is_invalid() {
        //     let (_, _, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
        //     let invalid_key_rec =
        //         node_signing_record_with(NODE_1, vec![1, 2, 3],
        // KEY_ID, REG_V2);     let crypto =
        //         crypto_component_with(registry_with(invalid_key_rec),
        // MockSecretKeyStore::new());
        //
        //     let result = crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V2);
        //
        //     assert!(result.unwrap_err().is_malformed_public_key());
        // }
    }
}

mod test_request_id_sig_verification {
    use super::*;
    use proptest::prelude::*;
    const REQUEST_SIG_ALGORITHMS: &[AlgorithmId] = &[AlgorithmId::Ed25519, AlgorithmId::EcdsaP256];

    proptest! {
        #[test]
        fn should_fail_with_algorithm_not_supported_if_pubkey_is_not_a_basic_sig (
            not_supported_user_pubkey in arbitrary_types::user_public_key()
                .prop_filter("ed25519 only", |pk|
                (pk.algorithm_id != AlgorithmId::Ed25519) &&
                (pk.algorithm_id != AlgorithmId::RsaSha256) &&
                (pk.algorithm_id != AlgorithmId::EcdsaP256) &&
                (pk.algorithm_id != AlgorithmId::EcdsaSecp256k1))
        ) {
            let request_id = request_id();
            let (sig, _pk) = request_id_signature_and_public_key(&request_id, AlgorithmId::Ed25519);
            let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
            let err = crypto
                .verify_basic_sig_by_public_key(&sig, &request_id, &not_supported_user_pubkey)
                .unwrap_err();

            assert!(err.is_algorithm_not_supported());
        }
    }

    #[test]
    fn should_verify_without_using_registry() {
        let request_id = request_id();
        let (sig, pk) = request_id_signature_and_public_key(&request_id, AlgorithmId::Ed25519);
        let crypto = crypto_component_with(registry_panicking_on_usage(), dummy_secret_key_store());

        assert!(crypto
            .verify_basic_sig_by_public_key(&sig, &request_id, &pk)
            .is_ok());
    }

    #[test]
    fn should_verify_without_using_secret_key_store() {
        let request_id = request_id();
        let (sig, pk) = request_id_signature_and_public_key(&request_id, AlgorithmId::Ed25519);
        let crypto = crypto_component_with(dummy_registry(), secret_key_store_panicking_on_usage());

        assert!(crypto
            .verify_basic_sig_by_public_key(&sig, &request_id, &pk)
            .is_ok());
    }

    // Here we only test with a single test vector per algorithm: an extensive test
    // with the entire test vector suite is done at the crypto lib level.
    #[test]
    fn should_correctly_verify() {
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let request_id = request_id();
            let (sig, pk) = request_id_signature_and_public_key(&request_id, *alg_id);
            let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());

            assert!(crypto
                .verify_basic_sig_by_public_key(&sig, &request_id, &pk)
                .is_ok());
        }
    }

    #[test]
    fn should_verify_with_correct_domain_separator() {
        let domain_separator_according_to_public_spec = b"\x0Aic-request";
        assert_eq!(
            DOMAIN_IC_REQUEST[..],
            domain_separator_according_to_public_spec[..]
        );
        let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let request_id = request_id();
            let (sig, pk) = request_id_signature_and_public_key_with_domain_separator(
                DOMAIN_IC_REQUEST,
                &request_id,
                *alg_id,
            );
            assert!(crypto
                .verify_basic_sig_by_public_key(&sig, &request_id, &pk)
                .is_ok());
        }
    }

    #[test]
    fn should_fail_to_verify_under_wrong_signature() {
        let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let request_id = request_id_1();
            let (sig, pk) = request_id_signature_and_public_key(&request_id, *alg_id);
            let (wrong_sig, _pk) = request_id_signature_and_public_key(&request_id_2(), *alg_id);
            assert_ne!(sig, wrong_sig);

            let result = crypto.verify_basic_sig_by_public_key(&wrong_sig, &request_id, &pk);
            assert!(result.unwrap_err().is_signature_verification_error());
        }
    }

    #[test]
    fn should_fail_to_verify_under_wrong_request_id() {
        let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let request_id = request_id_1();
            let (sig, pk) = request_id_signature_and_public_key(&request_id, *alg_id);
            let wrong_request_id = request_id_2();
            assert_ne!(request_id, wrong_request_id);

            let result = crypto.verify_basic_sig_by_public_key(&sig, &wrong_request_id, &pk);
            assert!(result.unwrap_err().is_signature_verification_error());
        }
    }

    #[test]
    fn should_fail_to_verify_under_wrong_public_key() {
        let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let request_id = request_id_1();
            let (sig, pk) = request_id_signature_and_public_key(&request_id, *alg_id);
            let (_sig, wrong_pk) = request_id_signature_and_public_key(&request_id_2(), *alg_id);
            assert_ne!(pk, wrong_pk);

            let result = crypto.verify_basic_sig_by_public_key(&sig, &request_id, &wrong_pk);
            assert!(result.unwrap_err().is_signature_verification_error());
        }
    }

    #[test]
    fn should_fail_to_verify_under_wrong_domain_separator() {
        let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let wrong_domain_separator = b"wrong_domain_separator";
            let correct_domain_separator = DOMAIN_IC_REQUEST;
            assert_ne!(wrong_domain_separator[..], correct_domain_separator[..]);
            let request_id = request_id();
            let (sig, pk) = request_id_signature_and_public_key_with_domain_separator(
                wrong_domain_separator,
                &request_id,
                *alg_id,
            );

            let result = crypto.verify_basic_sig_by_public_key(&sig, &request_id, &pk);
            assert!(result.unwrap_err().is_signature_verification_error());
        }
    }

    #[test]
    fn should_fail_with_malformed_signature_if_signature_has_incompatible_length() {
        let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let request_id = request_id();
            let (_sig, pk) = request_id_signature_and_public_key(&request_id, *alg_id);
            let incompatible_sig = BasicSigOf::new(BasicSig(b"too short".to_vec()));

            let result = crypto.verify_basic_sig_by_public_key(&incompatible_sig, &request_id, &pk);
            assert!(result.unwrap_err().is_malformed_signature());
        }
    }

    #[test]
    fn should_fail_with_malformed_public_key_if_public_key_has_incompatible_length() {
        let crypto = crypto_component_with(dummy_registry(), dummy_secret_key_store());
        for alg_id in REQUEST_SIG_ALGORITHMS.iter() {
            let request_id = request_id();
            let (sig, _pk) = request_id_signature_and_public_key(&request_id, *alg_id);
            let incompatible_pubkey = UserPublicKey {
                key: b"too short".to_vec(),
                algorithm_id: *alg_id,
            };

            let result =
                crypto.verify_basic_sig_by_public_key(&sig, &request_id, &incompatible_pubkey);
            assert!(result.unwrap_err().is_malformed_public_key());
        }
    }

    fn request_id() -> MessageId {
        request_id_1()
    }

    fn request_id_1() -> MessageId {
        MessageId::from([1; 32])
    }

    fn request_id_2() -> MessageId {
        MessageId::from([2; 32])
    }
}
