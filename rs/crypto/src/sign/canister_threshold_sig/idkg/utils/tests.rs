mod index_and_dealing_of_dealer {
    use crate::sign::canister_threshold_sig::idkg::utils::{
        IDkgDealingExtractionError, index_and_dealing_of_dealer,
    };
    use crate::sign::canister_threshold_sig::test_utils::{
        batch_signed_dealing_with, valid_internal_dealing_raw,
    };
    use crate::sign::tests::REG_V1;
    use assert_matches::assert_matches;
    use ic_base_types::{PrincipalId, SubnetId};
    use ic_crypto_internal_threshold_sig_canister_threshold_sig::IDkgDealingInternal;
    use ic_crypto_internal_types::NodeIndex;
    use ic_crypto_test_utils::set_of;
    use ic_types::Height;
    use ic_types::crypto::AlgorithmId;
    use ic_types::crypto::canister_threshold_sig::idkg::{
        BatchSignedIDkgDealing, IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript,
        IDkgTranscriptId, IDkgTranscriptType,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
    use maplit::btreemap;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn should_return_error_for_transcript_without_dealings() {
        let transcript = dummy_transcript_with_verified_dealings(BTreeMap::new());
        let dealer_id = NODE_1;

        assert_matches!(
            index_and_dealing_of_dealer(dealer_id, &transcript),
            Err(IDkgDealingExtractionError::MissingDealingInTranscript {
                dealer_id
            }) if dealer_id == NODE_1
        );
    }

    #[test]
    fn should_return_error_for_transcript_when_dealings_do_not_contain_dealer() {
        let transcript = dummy_transcript_with_verified_dealings(btreemap! {
            0 => batch_signed_dealing_with(vec![], NODE_2),
            1 => batch_signed_dealing_with(vec![], NODE_3),
            2 => batch_signed_dealing_with(vec![], NODE_4)
        });
        let dealer_id = NODE_1;

        assert_matches!(
            index_and_dealing_of_dealer(dealer_id, &transcript),
            Err(IDkgDealingExtractionError::MissingDealingInTranscript {
                dealer_id
            }) if dealer_id == NODE_1
        );
    }

    #[test]
    fn should_fail_if_internal_dealing_cannot_be_deserialized() {
        let transcript = dummy_transcript_with_verified_dealings(btreemap! {
            0 => batch_signed_dealing_with(vec![32; 1usize], NODE_1),
            1 => batch_signed_dealing_with(vec![32; 2usize], NODE_1),
            2 => batch_signed_dealing_with(vec![32; 3usize], NODE_1)
        });
        let dealer_id = NODE_1;

        assert_matches!(
            index_and_dealing_of_dealer(dealer_id, &transcript),
            Err(IDkgDealingExtractionError::SerializationError { internal_error })
            if internal_error.contains("Error deserializing a signed dealing: CanisterThresholdSerializationError")
        );
    }

    #[test]
    fn should_return_first_index_if_dealer_appears_multiple_times_in_dealings() {
        let valid_internal_dealing = valid_internal_dealing_raw();
        let transcript = dummy_transcript_with_verified_dealings(btreemap! {
            0 => batch_signed_dealing_with(valid_internal_dealing.clone(), NODE_1),
            1 => batch_signed_dealing_with(vec![32; 2usize], NODE_1),
            2 => batch_signed_dealing_with(vec![32; 3usize], NODE_1)
        });
        let dealer_id = NODE_1;
        let expected_dealing = IDkgDealingInternal::deserialize(&valid_internal_dealing)
            .expect("deserializing a raw internal dealing should succeed");

        assert_matches!(
            index_and_dealing_of_dealer(dealer_id, &transcript),
            Ok((node_index, dealing_internal)) if node_index == 0 && dealing_internal == expected_dealing
        );
    }

    #[test]
    fn should_return_correct_index_if_dealer_in_dealings() {
        let valid_internal_dealing = valid_internal_dealing_raw();
        let transcript = dummy_transcript_with_verified_dealings(btreemap! {
            0 => batch_signed_dealing_with(vec![32; 2usize], NODE_2),
            1 => batch_signed_dealing_with(valid_internal_dealing.clone(), NODE_1),
            2 => batch_signed_dealing_with(vec![32; 3usize], NODE_3)
        });
        let dealer_id = NODE_1;
        let expected_dealing = IDkgDealingInternal::deserialize(&valid_internal_dealing)
            .expect("deserializing a raw internal dealing should succeed");

        assert_matches!(
            index_and_dealing_of_dealer(dealer_id, &transcript),
            Ok((node_index, dealing_internal)) if node_index == 1 && dealing_internal == expected_dealing
        );
    }

    fn dummy_transcript_with_verified_dealings(
        verified_dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
    ) -> IDkgTranscript {
        IDkgTranscript {
            verified_dealings: Arc::new(verified_dealings),
            transcript_id: IDkgTranscriptId::new(
                SubnetId::from(PrincipalId::new_subnet_test_id(42)),
                0,
                Height::new(0),
            ),
            receivers: IDkgReceivers::new(set_of(&[NODE_1])).expect("failed to create receivers"),
            registry_version: REG_V1,
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        }
    }
}

mod retrieve_mega_public_key_from_registry {
    use crate::sign::canister_threshold_sig::idkg::utils::mega_public_key_from_proto;
    use crate::sign::tests::REG_V1;
    use crate::{MegaKeyFromRegistryError, retrieve_mega_public_key_from_registry};
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
                    if algorithm_id == AlgorithmIdProto::try_from(wrong_algorithm_id as i32).ok()
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
