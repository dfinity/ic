mod retrieve_mega_public_key_from_registry {
    use crate::sign::canister_threshold_sig::idkg::utils::mega_public_key_from_proto;
    use crate::sign::tests::REG_V1;
    use crate::{retrieve_mega_public_key_from_registry, MegaKeyFromRegistryError};
    use assert_matches::assert_matches;
    use ic_base_types::NodeId;
    use ic_base_types::RegistryVersion;
    use ic_crypto_internal_csp_proptest_utils::registry_client_error::arb_registry_client_error;
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key;
    use ic_interfaces_registry::RegistryClient;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_crypto_node_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::crypto::AlgorithmId;
    use ic_types::crypto::KeyPurpose;
    use ic_types::registry::RegistryClientError;
    use ic_types_test_utils::ids::node_test_id;
    use proptest::proptest;
    use std::sync::Arc;
    use strum::IntoEnumIterator;

    #[test]
    fn should_succeed_when_mega_pubkey_in_registry() {
        let node_id = node_test_id(25);
        let valid_idkg_dealing_encryption_public_key = valid_idkg_dealing_encryption_public_key();
        let mega_pubkey = mega_public_key_from_proto(&valid_idkg_dealing_encryption_public_key)
            .expect("converting proto to mega pubkey should succeed");
        let registry_data =
            registry_data_with_idkg_key(node_id, valid_idkg_dealing_encryption_public_key);
        let registry_client = FakeRegistryClient::new(Arc::new(registry_data));
        registry_client.reload();

        assert_matches!(
            retrieve_mega_public_key_from_registry(&node_id, &registry_client, REG_V1),
            Ok(pk) if pk == mega_pubkey
        );
    }

    #[test]
    fn should_fail_when_mega_pubkey_not_in_registry() {
        let local_node_id = node_test_id(25);
        let registry_data = ProtoRegistryDataProvider::new();
        let registry_client = FakeRegistryClient::new(Arc::new(registry_data));

        assert_matches!(
            retrieve_mega_public_key_from_registry(&local_node_id, &registry_client, registry_client.get_latest_version()),
            Err(MegaKeyFromRegistryError::PublicKeyNotFound { node_id, registry_version })
            if node_id == local_node_id && registry_version == registry_client.get_latest_version()
        );
    }

    #[test]
    fn should_fail_when_mega_pubkey_in_registry_but_with_wrong_key_purpose() {
        let local_node_id = node_test_id(25);
        let registry_data = ProtoRegistryDataProvider::new();
        registry_data
            .add(
                &make_crypto_node_key(local_node_id, KeyPurpose::NodeSigning),
                REG_V1,
                Some(valid_idkg_dealing_encryption_public_key()),
            )
            .expect("adding mega pubkey to registry should succeed");
        let registry_client = FakeRegistryClient::new(Arc::new(registry_data));

        assert_matches!(
            retrieve_mega_public_key_from_registry(&local_node_id, &registry_client, registry_client.get_latest_version()),
            Err(MegaKeyFromRegistryError::PublicKeyNotFound { node_id, registry_version })
            if node_id == local_node_id && registry_version == registry_client.get_latest_version()
        );
    }

    #[test]
    fn should_fail_when_registry_version_not_available() {
        let local_node_id = node_test_id(25);
        let registry_data = ProtoRegistryDataProvider::new();
        let registry_client = FakeRegistryClient::new(Arc::new(registry_data));
        let future_registry_version =
            RegistryVersion::new(registry_client.get_latest_version().get() + 1);

        assert_matches!(
            retrieve_mega_public_key_from_registry(&local_node_id, &registry_client, future_registry_version),
            Err(MegaKeyFromRegistryError::RegistryError(RegistryClientError::VersionNotAvailable { version }))
            if version == future_registry_version
        );
    }

    #[test]
    fn should_fail_when_registry_returns_error() {
        let node_id = node_test_id(25);

        proptest!(|(registry_client_error in arb_registry_client_error())| {
            let registry_key = make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption);
            let registry_version = REG_V1;
            let mut mock_registry_client = MockRegistryClient::new();
            mock_registry_client
                .expect_get_value()
                .times(1)
                .withf(move |key, version| key == registry_key && version == &registry_version)
                .return_const(Err(registry_client_error.clone()));
            assert_matches!(
                retrieve_mega_public_key_from_registry(&node_id, &mock_registry_client, REG_V1),
                Err(MegaKeyFromRegistryError::RegistryError(error))
                if error == registry_client_error
            );
        });
    }

    #[test]
    fn should_fail_when_mega_pubkey_in_registry_has_invalid_algorithm() {
        let node_id = node_test_id(25);
        let mut invalid_algorithm_idkg_dealing_encryption_public_key =
            valid_idkg_dealing_encryption_public_key();

        AlgorithmId::iter()
            .filter(|algorithm_id| *algorithm_id != AlgorithmId::MegaSecp256k1)
            .for_each(|wrong_algorithm_id| {
                invalid_algorithm_idkg_dealing_encryption_public_key.algorithm = wrong_algorithm_id as i32;
                let registry_data = registry_data_with_idkg_key(
                    node_id,
                    invalid_algorithm_idkg_dealing_encryption_public_key.clone(),
                );
                let registry_client = FakeRegistryClient::new(Arc::new(registry_data));
                registry_client.reload();

                assert_matches!(
                    retrieve_mega_public_key_from_registry(&node_id, &registry_client, registry_client.get_latest_version()),
                    Err(MegaKeyFromRegistryError::UnsupportedAlgorithm { algorithm_id })
                    if algorithm_id == AlgorithmIdProto::from_i32(wrong_algorithm_id as i32)
                );
            });
    }

    #[test]
    fn should_fail_when_mega_pubkey_in_registry_is_malformed() {
        let local_node_id = node_test_id(25);
        let mut invalid_key_value_idkg_dealing_encryption_public_key =
            valid_idkg_dealing_encryption_public_key();
        invalid_key_value_idkg_dealing_encryption_public_key.key_value =
            b"malformed public key".to_vec();
        let registry_data = registry_data_with_idkg_key(
            local_node_id,
            invalid_key_value_idkg_dealing_encryption_public_key,
        );
        let registry_client = FakeRegistryClient::new(Arc::new(registry_data));
        registry_client.reload();

        assert_matches!(
            retrieve_mega_public_key_from_registry(&local_node_id, &registry_client, registry_client.get_latest_version()),
            Err(MegaKeyFromRegistryError::MalformedPublicKey { node_id, key_bytes })
            if node_id == local_node_id && key_bytes == b"malformed public key".to_vec()
        );
    }

    fn registry_data_with_idkg_key(
        node_id: NodeId,
        idkg_dealing_encryption_key: PublicKey,
    ) -> ProtoRegistryDataProvider {
        let registry_data = ProtoRegistryDataProvider::new();
        registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
                REG_V1,
                Some(idkg_dealing_encryption_key),
            )
            .expect("adding mega pubkey to registry should succeed");
        registry_data
    }
}
