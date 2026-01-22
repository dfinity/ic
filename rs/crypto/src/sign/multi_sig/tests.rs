use super::*;
use crate::sign::tests::*;
use assert_matches::assert_matches;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_temp_crypto::NodeKeysToGenerate;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::SignableMock;
use ic_types_test_utils::ids::{NODE_1, NODE_2};

mod test_multi_sign {
    use super::*;

    #[test]
    fn should_multi_sign() {
        let crypto = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_committee_signing_key(), REG_V2)
            .with_node_id(NODE_1)
            .with_rng(reproducible_rng())
            .build();
        let msg = SignableMock::new(b"Hello World!".to_vec());

        let result = crypto.sign_multi(&msg, NODE_1, REG_V2);

        assert_matches!(result, Ok(_));
    }
}

mod test_multi_sig_verification {
    use super::*;
    use crate::common::test_utils::crypto_component::crypto_component_with_csp;
    use crate::common::test_utils::hex_to_byte_vec;
    use crate::common::test_utils::multi_bls12_381;
    use crate::common::test_utils::multi_bls12_381::MultiBls12381TestVector::{
        STABILITY_1, STABILITY_2,
    };
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_COMB_SIG_1_2;
    use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
    use ic_types::crypto::SignableMock;

    #[test]
    fn should_verify_multi_sig_individual() {
        let crypto = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_committee_signing_key(), REG_V2)
            .with_node_id(NODE_1)
            .with_rng(reproducible_rng())
            .build();
        let msg = SignableMock::new(b"Hello World!".to_vec());
        let signature = crypto.sign_multi(&msg, NODE_1, REG_V2).unwrap();

        let result = crypto.verify_multi_sig_individual(&signature, &msg, NODE_1, REG_V2);

        assert_matches!(result, Ok(()));
    }

    fn create_crypto_component(
        node_id: NodeId,
        rng: &mut ReproducibleRng,
        registry_data: &Arc<ProtoRegistryDataProvider>,
        registry_client: &Arc<FakeRegistryClient>,
    ) -> ic_crypto_temp_crypto::TempCryptoComponentGeneric<ReproducibleRng> {
        TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_committee_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(registry_client) as Arc<_>,
                Arc::clone(registry_data) as Arc<_>,
            )
            .with_node_id(node_id)
            .with_rng(rng.fork())
            .build()
    }

    #[test]
    fn should_combine_and_verify_multi_sig_individuals() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"Hello World!".to_vec());
        let sig_node1_on_msg = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_node2_on_msg = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();
        let signatures = vec![(NODE_1, sig_node1_on_msg), (NODE_2, sig_node2_on_msg)]
            .into_iter()
            .collect();

        let combined_multi_sig = crypto_1.combine_multi_sig_individuals(signatures, REG_V2);
        assert_matches!(combined_multi_sig, Ok(_));

        let nodes: BTreeSet<NodeId> = vec![NODE_1, NODE_2].into_iter().collect();
        let result =
            crypto_1.verify_multi_sig_combined(&combined_multi_sig.unwrap(), &msg, nodes, REG_V2);
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn should_not_combine_zero_individual_sigs() {
        let (_, pk_1, _, _, _) = multi_bls12_381::testvec(STABILITY_1);
        let pk_rec_1 = committee_signing_record_with(
            NODE_1,
            pk_1.multi_bls12_381_bytes().unwrap().to_vec(),
            KeyId::from(KEY_ID_1),
            REG_V1,
        );
        let empty_signatures: BTreeMap<NodeId, IndividualMultiSigOf<SignableMock>> =
            BTreeMap::new();

        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with_records(vec![pk_rec_1]),
        );

        assert_matches!(
            crypto.combine_multi_sig_individuals(empty_signatures, REG_V1),
            Err(CryptoError::InvalidArgument { message })
                if message.contains("No signatures to combine. At least one signature is needed to combine a multi-signature")
        );
    }

    #[test]
    fn should_not_verify_with_empty_signers() {
        let (_, pk_1, _, msg_1, _) = multi_bls12_381::testvec(STABILITY_1);
        let (_, pk_2, _, msg_2, _) = multi_bls12_381::testvec(STABILITY_2);
        assert_eq!(msg_1, msg_2);
        let pk_rec_1 = committee_signing_record_with(
            NODE_1,
            pk_1.multi_bls12_381_bytes().unwrap().to_vec(),
            KeyId::from(KEY_ID_1),
            REG_V1,
        );
        let pk_rec_2 = committee_signing_record_with(
            NODE_2,
            pk_2.multi_bls12_381_bytes().unwrap().to_vec(),
            KeyId::from(KEY_ID_2),
            REG_V1,
        );
        let empty_nodes: BTreeSet<NodeId> = BTreeSet::new();
        let combined_sig = CombinedMultiSigOf::new(CombinedMultiSig(hex_to_byte_vec(
            TESTVEC_MULTI_BLS12_381_COMB_SIG_1_2,
        )));

        let crypto = crypto_component_with_csp(
            MockAllCryptoServiceProvider::new(),
            registry_with_records(vec![pk_rec_1, pk_rec_2]),
        );

        assert_matches!(
            crypto.verify_multi_sig_combined(&combined_sig, &msg_1, empty_nodes, REG_V1),
            Err(CryptoError::InvalidArgument { message })
                if message.contains("Empty signers. At least one signer is needed to verify a combined multi-signature")
        );
    }

    use ic_types_test_utils::ids::NODE_3;

    #[test]
    fn should_fail_verify_combined_when_signature_omitted_from_combine() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        let crypto_3 = create_crypto_component(NODE_3, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"test message".to_vec());

        // Sign with all 3 nodes
        let sig_1 = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();
        let _sig_3 = crypto_3.sign_multi(&msg, NODE_3, REG_V2).unwrap();

        // Only combine 2 of 3 signatures
        let signatures: BTreeMap<_, _> = vec![
            (NODE_1, sig_1),
            (NODE_2, sig_2),
            // sig_3 omitted
        ]
        .into_iter()
        .collect();

        let combined = crypto_1
            .combine_multi_sig_individuals(signatures, REG_V2)
            .unwrap();

        // Verify with all 3 signers - should fail
        let all_signers: BTreeSet<_> = vec![NODE_1, NODE_2, NODE_3].into_iter().collect();
        let result = crypto_1.verify_multi_sig_combined(&combined, &msg, all_signers, REG_V2);

        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_fail_to_combine_when_individual_signature_is_not_a_valid_point() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"test message".to_vec());

        let sig_1 = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();

        // Corrupt sig_1 by modifying bytes
        let mut corrupted_sig_bytes = sig_1.get_ref().0.clone();
        corrupted_sig_bytes[13] ^= 0x01;
        let corrupted_sig = IndividualMultiSigOf::new(IndividualMultiSig(corrupted_sig_bytes));

        let signatures: BTreeMap<_, _> = vec![(NODE_1, corrupted_sig), (NODE_2, sig_2)]
            .into_iter()
            .collect();

        /*
         * The probability that any random x has a solution (y,x) which is
         * within the prime-order subgroup is, cryptographically speaking, negligible.
         * That being the case, combination should fail.
         *
         * The case where the point encoding is valid but the individual signature
         * is incorrect is checked by should_fail_verify_combined_with_wrong_message
         */
        let combined = crypto_1.combine_multi_sig_individuals(signatures, REG_V2);

        assert_matches!(
            combined,
            Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::MultiBls12_381,
                sig_bytes: _,
                internal_error: _
            })
        );
    }

    #[test]
    fn should_fail_verify_combined_with_corrupted_combined_signature() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"test message".to_vec());

        let sig_1 = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();

        let signatures: BTreeMap<_, _> =
            vec![(NODE_1, sig_1), (NODE_2, sig_2)].into_iter().collect();

        let combined = crypto_1
            .combine_multi_sig_individuals(signatures, REG_V2)
            .unwrap();

        // Corrupt the combined signature
        let mut corrupted_bytes = combined.get_ref().0.clone();
        corrupted_bytes[2] ^= 0xFF;
        let corrupted_combined = CombinedMultiSigOf::new(CombinedMultiSig(corrupted_bytes));

        let signers: BTreeSet<_> = vec![NODE_1, NODE_2].into_iter().collect();
        let result = crypto_1.verify_multi_sig_combined(&corrupted_combined, &msg, signers, REG_V2);

        assert_matches!(
            result,
            Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::MultiBls12_381,
                sig_bytes: _,
                internal_error: _
            })
        );
    }

    #[test]
    fn should_fail_verify_combined_with_wrong_registry_version() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"test message".to_vec());

        let sig_1 = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();

        let signatures: BTreeMap<_, _> =
            vec![(NODE_1, sig_1), (NODE_2, sig_2)].into_iter().collect();

        let combined = crypto_1
            .combine_multi_sig_individuals(signatures, REG_V2)
            .unwrap();

        let signers: BTreeSet<_> = vec![NODE_1, NODE_2].into_iter().collect();
        // Verify with REG_V1 instead of REG_V2 - keys won't be found
        let result = crypto_1.verify_multi_sig_combined(&combined, &msg, signers, REG_V1);

        assert_matches!(
            result,
            Err(CryptoError::PublicKeyNotFound {
                node_id: _,
                key_purpose: KeyPurpose::CommitteeSigning,
                registry_version: _,
            })
        );
    }

    #[test]
    fn should_fail_verify_combined_with_wrong_message() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"correct message".to_vec());
        let wrong_msg = SignableMock::new(b"wrong message".to_vec());

        let sig_1 = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();

        let signatures: BTreeMap<_, _> =
            vec![(NODE_1, sig_1), (NODE_2, sig_2)].into_iter().collect();

        let combined = crypto_1
            .combine_multi_sig_individuals(signatures, REG_V2)
            .unwrap();

        let signers: BTreeSet<_> = vec![NODE_1, NODE_2].into_iter().collect();
        let result = crypto_1.verify_multi_sig_combined(&combined, &wrong_msg, signers, REG_V2);

        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_fail_verify_combined_with_extra_signer_in_list() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        // Node 3 has keys registered but won't sign
        let _crypto_3 = create_crypto_component(NODE_3, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"test message".to_vec());

        // Only 2 nodes sign
        let sig_1 = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();

        let signatures: BTreeMap<_, _> =
            vec![(NODE_1, sig_1), (NODE_2, sig_2)].into_iter().collect();

        let combined = crypto_1
            .combine_multi_sig_individuals(signatures, REG_V2)
            .unwrap();

        // Include all 3 in signers list, but only 2 actually signed
        let signers: BTreeSet<_> = vec![NODE_1, NODE_2, NODE_3].into_iter().collect();
        let result = crypto_1.verify_multi_sig_combined(&combined, &msg, signers, REG_V2);

        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_fail_verify_combined_with_missing_signer_in_list() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        let crypto_3 = create_crypto_component(NODE_3, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"test message".to_vec());

        // All 3 nodes sign
        let sig_1 = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();
        let sig_2 = crypto_2.sign_multi(&msg, NODE_2, REG_V2).unwrap();
        let sig_3 = crypto_3.sign_multi(&msg, NODE_3, REG_V2).unwrap();

        let signatures: BTreeMap<_, _> = vec![(NODE_1, sig_1), (NODE_2, sig_2), (NODE_3, sig_3)]
            .into_iter()
            .collect();

        let combined = crypto_1
            .combine_multi_sig_individuals(signatures, REG_V2)
            .unwrap();

        // Only include 2 of 3 in signers list
        let signers: BTreeSet<_> = vec![NODE_1, NODE_2].into_iter().collect();
        let result = crypto_1.verify_multi_sig_combined(&combined, &msg, signers, REG_V2);

        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_fail_verify_individual_with_wrong_message() {
        let crypto = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_committee_signing_key(), REG_V2)
            .with_node_id(NODE_1)
            .with_rng(reproducible_rng())
            .build();
        let msg = SignableMock::new(b"correct message".to_vec());
        let wrong_msg = SignableMock::new(b"wrong message".to_vec());

        let signature = crypto.sign_multi(&msg, NODE_1, REG_V2).unwrap();

        let result = crypto.verify_multi_sig_individual(&signature, &wrong_msg, NODE_1, REG_V2);

        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }

    #[test]
    fn should_fail_verify_individual_with_wrong_registry_version() {
        let crypto = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_committee_signing_key(), REG_V2)
            .with_node_id(NODE_1)
            .with_rng(reproducible_rng())
            .build();
        let msg = SignableMock::new(b"test message".to_vec());

        let signature = crypto.sign_multi(&msg, NODE_1, REG_V2).unwrap();

        // Verify with REG_V1 instead of REG_V2 - key won't be found
        let result = crypto.verify_multi_sig_individual(&signature, &msg, NODE_1, REG_V1);

        assert_matches!(
            result,
            Err(CryptoError::PublicKeyNotFound {
                node_id: _,
                key_purpose: KeyPurpose::CommitteeSigning,
                registry_version: _,
            })
        );
    }

    #[test]
    fn should_fail_verify_individual_with_wrong_node_id() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = create_crypto_component(NODE_1, &mut rng, &registry_data, &registry_client);
        let _crypto_2 = create_crypto_component(NODE_2, &mut rng, &registry_data, &registry_client);
        registry_client.reload();

        let msg = SignableMock::new(b"test message".to_vec());

        // Node 1 signs
        let signature = crypto_1.sign_multi(&msg, NODE_1, REG_V2).unwrap();

        // Verify with Node 2's ID - should fail
        let result = crypto_1.verify_multi_sig_individual(&signature, &msg, NODE_2, REG_V2);

        assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
    }
}
