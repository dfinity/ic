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

    // TODO: DFN-1229 Add more tests in addition to the above happy-path test.
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

    #[test]
    fn should_combine_and_verify_multi_sig_individuals() {
        let mut rng = reproducible_rng();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));

        let crypto_1 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_committee_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_1)
            .with_rng(rng.fork())
            .build();
        let crypto_2 = TempCryptoComponent::builder()
            .with_keys_in_registry_version(NodeKeysToGenerate::only_committee_signing_key(), REG_V2)
            .with_registry_client_and_data(
                Arc::clone(&registry_client) as Arc<_>,
                Arc::clone(&registry_data) as Arc<_>,
            )
            .with_node_id(NODE_2)
            .with_rng(rng)
            .build();
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
    // TODO: DFN-1233 Add more tests in addition to the above happy-path test.
}
