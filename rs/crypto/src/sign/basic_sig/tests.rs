use super::*;
use crate::sign::tests::*;
use assert_matches::assert_matches;
use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types::crypto::{AlgorithmId, SignableMock};
use ic_types::messages::MessageId;
use ic_types_test_utils::arbitrary as arbitrary_types;

mod verify_basic_sig {
    use super::*;
    use crate::common::test_utils::basic_sig;
    use crate::common::test_utils::basic_sig::TestVector::ED25519_STABILITY_1;
    use crate::common::test_utils::crypto_component::crypto_component_with_csp;
    use crate::sign::tests::REG_V2;
    use ic_crypto_temp_crypto::NodeKeysToGenerate;
    use ic_crypto_temp_crypto::TempCryptoComponent;
    use ic_types_test_utils::ids::NODE_1;

    #[test]
    fn should_fail_with_key_not_found_if_public_key_not_found_in_registry() {
        let (_, _, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_returning_none(),
        );

        let result = crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V1);

        assert_matches!(result, Err(CryptoError::PublicKeyNotFound { .. }));
    }

    #[test]
    fn should_fail_with_malformed_public_key_if_public_key_from_registry_is_invalid() {
        let (_, _, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
        let invalid_key_rec = node_signing_record_with(NODE_1, vec![1, 2, 3], REG_V2);
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with(invalid_key_rec),
        );

        let result = crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V2);

        assert_matches!(result, Err(CryptoError::MalformedPublicKey { .. }));
    }

    #[test]
    fn should_fail_with_malformed_signature_if_signature_has_incompatible_length() {
        let (_, pk, msg, _) = basic_sig::testvec(ED25519_STABILITY_1);
        let key_record =
            node_signing_record_with(NODE_1, pk.ed25519_bytes().unwrap().to_vec(), REG_V2);
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with(key_record),
        );
        let incompatible_sig = BasicSigOf::new(BasicSig(vec![1, 2, 3]));

        let err = crypto
            .verify_basic_sig(&incompatible_sig, &msg, NODE_1, REG_V2)
            .unwrap_err();

        assert!(err.is_malformed_signature());
    }

    #[test]
    fn should_delegate_to_csp_to_verify() {
        let (_, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
        let key_record =
            node_signing_record_with(NODE_1, pk.ed25519_bytes().unwrap().to_vec(), REG_V2);
        let mut csp = MockAllCryptoServiceProvider::new();
        let msg_clone = msg.clone();
        let expected_signature = SigConverter::for_target(AlgorithmId::Ed25519)
            .try_from_basic(&sig)
            .expect("invalid signature");
        csp.expect_verify()
            .times(1)
            .withf(move |signature, message_bytes, algorithm_id, public_key| {
                *signature == expected_signature
                    && *message_bytes == msg_clone.as_signed_bytes()
                    && *algorithm_id == AlgorithmId::Ed25519
                    && *public_key == pk
            })
            .return_const(Ok(()));
        let crypto = crypto_component_with_csp(csp, registry_with(key_record));

        assert!(crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V2).is_ok());
    }

    #[test]
    fn should_return_error_from_csp() {
        let (_, pk, msg, sig) = basic_sig::testvec(ED25519_STABILITY_1);
        let key_record =
            node_signing_record_with(NODE_1, pk.ed25519_bytes().unwrap().to_vec(), REG_V2);
        let mut csp = MockAllCryptoServiceProvider::new();
        let msg_clone = msg.clone();
        let expected_signature = SigConverter::for_target(AlgorithmId::Ed25519)
            .try_from_basic(&sig)
            .expect("invalid signature");
        let expected_error = CryptoError::InternalError {
            internal_error: "error in CSP".to_string(),
        };
        csp.expect_verify()
            .times(1)
            .withf(move |signature, message_bytes, algorithm_id, public_key| {
                *signature == expected_signature
                    && *message_bytes == msg_clone.as_signed_bytes()
                    && *algorithm_id == AlgorithmId::Ed25519
                    && *public_key == pk
            })
            .return_const(Err(expected_error.clone()));
        let crypto = crypto_component_with_csp(csp, registry_with(key_record));

        let result = crypto.verify_basic_sig(&sig, &msg, NODE_1, REG_V2);

        assert_matches!(result, Err(error) if error == expected_error);
    }

    #[test]
    fn should_sign_and_verify_smoke_test() {
        let crypto_component = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_node_id(NODE_1)
            .with_rng(reproducible_rng())
            .build();
        let msg = SignableMock::new(b"message".to_vec());

        let signature_result = crypto_component.sign_basic(&msg, NODE_1, REG_V2);
        assert_matches!(signature_result, Ok(_));

        let signature = signature_result.unwrap();
        let verification_result =
            crypto_component.verify_basic_sig(&signature, &msg, NODE_1, REG_V2);

        assert_matches!(verification_result, Ok(()))
    }
}

mod combine_basic_sig {
    use super::*;
    use crate::common::test_utils::basic_sig;
    use crate::common::test_utils::basic_sig::TestVector::ED25519_STABILITY_1;
    use crate::common::test_utils::crypto_component::crypto_component_with_csp;
    use crate::sign::tests::REG_V2;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    #[test]
    fn should_correctly_combine_a_single_signature() {
        let (_, pk, _, sig) = basic_sig::testvec(ED25519_STABILITY_1);
        let key_record =
            node_signing_record_with(NODE_1, pk.ed25519_bytes().unwrap().to_vec(), REG_V2);

        let mut signatures = BTreeMap::new();
        signatures.insert(NODE_1, &sig);
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with(key_record),
        );

        assert!(crypto.combine_basic_sig(signatures, REG_V2).is_ok());
    }

    #[test]
    fn should_correctly_combine_multiple_signatures() {
        let (_, pk_1, _, sig_1) = basic_sig::testvec(ED25519_STABILITY_1);
        let (_, pk_2, _, sig_2) = basic_sig::testvec(ED25519_STABILITY_1);

        let key_record_1 =
            node_signing_record_with(NODE_1, pk_1.ed25519_bytes().unwrap().to_vec(), REG_V2);
        let key_record_2 =
            node_signing_record_with(NODE_2, pk_2.ed25519_bytes().unwrap().to_vec(), REG_V2);

        let mut signatures = BTreeMap::new();
        signatures.insert(NODE_1, &sig_1);
        signatures.insert(NODE_2, &sig_2);
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with_records(vec![key_record_1, key_record_2]),
        );

        assert!(crypto.combine_basic_sig(signatures, REG_V2).is_ok());
    }

    #[test]
    fn should_not_combine_zero_signatures() {
        let (_, pk, _, _) = basic_sig::testvec(ED25519_STABILITY_1);
        let key_record =
            node_signing_record_with(NODE_1, pk.ed25519_bytes().unwrap().to_vec(), REG_V2);

        let signatures: BTreeMap<NodeId, &BasicSigOf<SignableMock>> = BTreeMap::new();

        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with(key_record),
        );

        assert_matches!(
            crypto.combine_basic_sig(signatures, REG_V2),
            Err(CryptoError::InvalidArgument { message })
            if message.contains("No signatures to combine in a batch. At least one signature is needed to create a batch")
        );
    }
}

mod verify_sig_batch {
    use super::*;
    use crate::common::test_utils::basic_sig;
    use crate::common::test_utils::basic_sig::TestVector::ED25519_STABILITY_1;
    use crate::common::test_utils::crypto_component::crypto_component_with_csp;
    use crate::sign::tests::REG_V2;
    use ic_crypto_temp_crypto::NodeKeysToGenerate;
    use ic_crypto_temp_crypto::TempCryptoComponent;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    #[test]
    fn should_correctly_verify_batch_with_single_signature() {
        let crypto = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_node_id(NODE_1)
            .with_rng(reproducible_rng())
            .build();

        let msg = SignableMock::new(b"Hello World!".to_vec());
        let sig_node1_on_msg = crypto.sign_basic(&msg, NODE_1, REG_V2).unwrap();

        let mut signatures = BTreeMap::new();
        signatures.insert(NODE_1, &sig_node1_on_msg);

        let sig_batch = crypto.combine_basic_sig(signatures, REG_V2);
        assert!(sig_batch.is_ok());

        assert!(
            crypto
                .verify_basic_sig_batch(&sig_batch.unwrap(), &msg, REG_V2)
                .is_ok()
        );
    }

    #[test]
    fn should_correctly_verify_batch_with_multiple_signatures() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_1)
            .with_rng(rng.fork())
            .build();
        let crypto_2 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_2)
            .with_rng(rng)
            .build();
        registry_client.reload();
        let msg = SignableMock::new(b"message".to_vec());

        let mut signatures = BTreeMap::new();
        let sig_1 = crypto_1.sign_basic(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_basic(&msg, NODE_2, REG_V2).unwrap();
        signatures.insert(NODE_1, &sig_1);
        signatures.insert(NODE_2, &sig_2);

        let sig_batch = crypto_1.combine_basic_sig(signatures, REG_V2);
        assert_matches!(sig_batch, Ok(_));

        let result = crypto_1.verify_basic_sig_batch(&sig_batch.unwrap(), &msg, REG_V2);

        assert_matches!(result, Ok(()))
    }

    #[test]
    fn should_not_verify_batch_on_different_messages() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_1)
            .with_rng(rng.fork())
            .build();
        let crypto_2 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_2)
            .with_rng(rng)
            .build();
        registry_client.reload();

        let msg = SignableMock::new(b"Hello World!".to_vec());
        let sig_node1_on_msg = crypto_1.sign_basic(&msg, NODE_1, REG_V2).unwrap();

        let other_msg = SignableMock::new(b"World Hello! ".to_vec());
        let sig_node2_on_other_msg = crypto_2.sign_basic(&other_msg, NODE_2, REG_V2).unwrap();

        let mut signatures = BTreeMap::new();
        assert!(
            crypto_1
                .verify_basic_sig(&sig_node1_on_msg, &msg, NODE_1, REG_V2)
                .is_ok()
        );
        assert!(
            crypto_1
                .verify_basic_sig(&sig_node2_on_other_msg, &msg, NODE_2, REG_V2)
                .is_err()
        );

        signatures.insert(NODE_1, &sig_node1_on_msg);
        signatures.insert(NODE_2, &sig_node2_on_other_msg);

        let sig_batch = crypto_1.combine_basic_sig(signatures, REG_V2);
        assert!(sig_batch.is_ok());

        assert_matches!(
            crypto_1.verify_basic_sig_batch(&sig_batch.unwrap(), &msg, REG_V2),
            Err(CryptoError::SignatureVerification { .. })
        );
    }

    #[test]
    fn should_not_verify_batch_with_corrupted_signature() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_1)
            .with_rng(rng.fork())
            .build();
        let crypto_2 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_node_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_2)
            .with_rng(rng)
            .build();
        registry_client.reload();

        let msg = SignableMock::new(b"Hello World!".to_vec());
        let sig_node1 = crypto_1.sign_basic(&msg, NODE_1, REG_V2).unwrap();
        let sig_node2 = crypto_2.sign_basic(&msg, NODE_2, REG_V2).unwrap();
        let sig_node2_corrupted = {
            let mut sig = sig_node2.get().0;
            sig[0] ^= 0x80; // flip first bit
            BasicSigOf::new(BasicSig(sig))
        };

        let mut signatures = BTreeMap::new();
        assert!(
            crypto_1
                .verify_basic_sig(&sig_node1, &msg, NODE_1, REG_V2)
                .is_ok()
        );
        assert!(
            crypto_1
                .verify_basic_sig(&sig_node2_corrupted, &msg, NODE_2, REG_V2)
                .is_err()
        );

        signatures.insert(NODE_1, &sig_node1);
        signatures.insert(NODE_2, &sig_node2_corrupted);

        let sig_batch = crypto_1.combine_basic_sig(signatures, REG_V2);
        assert!(sig_batch.is_ok());

        assert_matches!(
            crypto_1.verify_basic_sig_batch(&sig_batch.unwrap(), &msg, REG_V2),
            Err(CryptoError::SignatureVerification { .. })
        );
    }

    #[test]
    fn should_not_verify_an_empty_batch() {
        let (_, pk, msg, _) = basic_sig::testvec(ED25519_STABILITY_1);
        let key_record =
            node_signing_record_with(NODE_1, pk.ed25519_bytes().unwrap().to_vec(), REG_V2);

        let empty_signatures: BTreeMap<NodeId, BasicSigOf<SignableMock>> = BTreeMap::new();
        let empty_batch = BasicSignatureBatch {
            signatures_map: empty_signatures,
        };
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with(key_record),
        );

        assert_matches!(
            crypto.verify_basic_sig_batch(&empty_batch, &msg, REG_V2),
            Err(CryptoError::InvalidArgument { message })
            if message.contains("Empty BasicSignatureBatch. At least one signature should be included in the batch.")
        );
    }
}

mod verify_basic_sig_by_public_key {
    use super::*;
    use crate::common::test_utils::crypto_component::crypto_component_with_csp;
    use proptest::prelude::*;

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
            let crypto = crypto_component_with_csp(MockAllCryptoServiceProvider::new(), dummy_registry());
            let err = crypto
                .verify_basic_sig_by_public_key(&sig, &request_id, &not_supported_user_pubkey)
                .unwrap_err();

            assert!(err.is_algorithm_not_supported());
        }
    }

    #[test]
    fn should_fail_with_malformed_public_key_if_user_public_key_is_invalid() {
        let invalid_user_public_key = UserPublicKey {
            key: vec![1, 2, 3],
            algorithm_id: AlgorithmId::Ed25519,
        };
        let message = SignableMock::new(b"message".to_vec());
        let dummy_signature = BasicSigOf::new(BasicSig(b"signature".to_vec()));
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_panicking_on_usage(),
        );

        let result = crypto.verify_basic_sig_by_public_key(
            &dummy_signature,
            &message,
            &invalid_user_public_key,
        );

        assert_matches!(result, Err(CryptoError::MalformedPublicKey { .. }));
    }

    #[test]
    fn should_fail_with_malformed_signature_if_signature_has_incompatible_length() {
        let valid_user_public_key = UserPublicKey {
            key: hex::decode("58d558c7586efb32f4667ee9a302877da97aa1136cda92af4d7a4f8873f9434f")
                .expect("invalid hex data"),
            algorithm_id: AlgorithmId::Ed25519,
        };
        let message = SignableMock::new(b"message".to_vec());
        let invalid_signature = BasicSigOf::new(BasicSig(vec![1, 2, 3]));
        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_panicking_on_usage(),
        );

        let result = crypto.verify_basic_sig_by_public_key(
            &invalid_signature,
            &message,
            &valid_user_public_key,
        );

        assert_matches!(result, Err(CryptoError::MalformedSignature { .. }));
    }

    fn request_id() -> MessageId {
        request_id_1()
    }

    fn request_id_1() -> MessageId {
        MessageId::from([1; 32])
    }
}
