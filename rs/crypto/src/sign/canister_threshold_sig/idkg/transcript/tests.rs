use super::*;
use assert_matches::assert_matches;
use ic_types::crypto::AlgorithmId;

mod verify_signature_batch {
    use super::*;
    use ic_crypto_internal_csp::types::CspPublicKey;
    use ic_crypto_internal_csp::types::CspSignature;
    use ic_crypto_internal_csp::types::SigConverter;
    use ic_crypto_test_utils_canister_threshold_sigs::node_id;
    use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
    use ic_crypto_test_utils_keys::public_keys::valid_node_signing_public_key;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_crypto_node_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::crypto::canister_threshold_sig::idkg::BatchSignedIDkgDealing;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgDealing;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::crypto::canister_threshold_sig::idkg::SignedIDkgDealing;
    use ic_types::crypto::BasicSig;
    use ic_types::crypto::KeyPurpose;
    use ic_types::crypto::{BasicSigOf, Signable};
    use ic_types::signature::BasicSignature;
    use ic_types::signature::BasicSignatureBatch;
    use ic_types::Height;
    use ic_types_test_utils::ids::SUBNET_42;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn should_fail_if_signers_count_less_than_verification_threshold() {
        const EXPECTED_SIGNERS_COUNT: usize = 1;
        const NUMBER_OF_NODES: u32 = 2;
        let mut mock_csp = MockAllCryptoServiceProvider::new();
        mock_csp.expect_verify().never();
        let mut mock_registry_client = MockRegistryClient::new();
        mock_registry_client.expect_get_value().never();
        let setup = Setup::builder()
            .with_registry_client(Arc::new(mock_registry_client))
            .build();
        let verification_threshold = NumberOfNodes::new(NUMBER_OF_NODES);
        let registry_version = RegistryVersion::from(1);

        assert_eq!(
            setup.batch_signed_idkg_dealing.signers_count(),
            EXPECTED_SIGNERS_COUNT
        );

        assert_matches!(
            verify_signature_batch(
                &mock_csp,
                setup.registry_client.as_ref(),
                &setup.batch_signed_idkg_dealing,
                verification_threshold,
                registry_version
            ),
            Err(VerifySignatureBatchError::UnsatisfiedVerificationThreshold {threshold, signature_count})
            if threshold == NUMBER_OF_NODES && signature_count == EXPECTED_SIGNERS_COUNT
        );
    }

    #[test]
    fn should_succeed_if_all_individual_signatures_verify_correctly() {
        const NUMBER_OF_NODES: u32 = 1;
        let setup = Setup::builder().build();
        let registry_client = Arc::clone(&setup.registry_client);
        let batch_signed_idkg_dealing = setup.batch_signed_idkg_dealing.clone();
        let verification_threshold = NumberOfNodes::new(NUMBER_OF_NODES);
        let mut mock_csp = MockAllCryptoServiceProvider::new();
        let node_id_counter = AtomicU64::new(0);
        mock_csp
            .expect_verify()
            .times(1)
            .withf(move |sig, message, algorithm_id, csp_pub_key| {
                check_input_to_verify(
                    sig,
                    message,
                    algorithm_id,
                    csp_pub_key,
                    &setup,
                    &node_id_counter,
                )
            })
            .return_const(Ok(()));

        assert_matches!(
            verify_signature_batch(
                &mock_csp,
                registry_client.as_ref(),
                &batch_signed_idkg_dealing,
                verification_threshold,
                registry_client.get_latest_version()
            ),
            Ok(())
        );
    }

    #[test]
    fn should_fail_if_single_individual_signature_verification_fails() {
        const NUMBER_OF_NODES: u32 = 1;
        let setup = Setup::builder().with_signature_count(1).build();
        let registry_client = Arc::clone(&setup.registry_client);
        let batch_signed_idkg_dealing = setup.batch_signed_idkg_dealing.clone();
        let mut mock_csp = MockAllCryptoServiceProvider::new();
        let internal_crypto_error = CryptoError::MalformedSignature {
            algorithm: AlgorithmId::Ed25519,
            sig_bytes: vec![0; 64],
            internal_error: "oh no!".to_string(),
        };
        let node_id_counter = AtomicU64::new(0);
        mock_csp
            .expect_verify()
            .times(1)
            .withf(move |sig, message, algorithm_id, csp_pub_key| {
                check_input_to_verify(
                    sig,
                    message,
                    algorithm_id,
                    csp_pub_key,
                    &setup,
                    &node_id_counter,
                )
            })
            .return_const(Err(internal_crypto_error.clone()));
        let verification_threshold = NumberOfNodes::new(NUMBER_OF_NODES);

        assert_matches!(
            verify_signature_batch(
                &mock_csp,
                registry_client.as_ref(),
                &batch_signed_idkg_dealing,
                verification_threshold,
                registry_client.get_latest_version()
            ),
            Err(VerifySignatureBatchError::InvalidSignatureBatch{error, crypto_error})
            if error.contains("Invalid basic signature batch") && crypto_error == internal_crypto_error
        );
    }

    #[test]
    fn should_fail_if_one_of_three_individual_signature_verifications_fail() {
        let setup = Setup::builder().with_signature_count(3).build();
        let registry_client = Arc::clone(&setup.registry_client);
        let batch_signed_idkg_dealing = setup.batch_signed_idkg_dealing.clone();
        let mut mock_csp = MockAllCryptoServiceProvider::new();
        let node_id_counter = AtomicU64::new(0);
        let mut verify_call_counter = 0_u8;
        mock_csp
            .expect_verify()
            .times(3)
            .withf(move |sig, message, algorithm_id, csp_pub_key| {
                check_input_to_verify(
                    sig,
                    message,
                    algorithm_id,
                    csp_pub_key,
                    &setup,
                    &node_id_counter,
                )
            })
            .returning(move |_, _, _, _| match verify_call_counter {
                0 | 1 => {
                    verify_call_counter += 1;
                    Ok(())
                }
                2 => {
                    verify_call_counter += 1;
                    Err(CryptoError::MalformedSignature {
                        algorithm: AlgorithmId::Ed25519,
                        sig_bytes: vec![0; 64],
                        internal_error: "oh no!".to_string(),
                    })
                }
                _ => panic!("verify called too many times!"),
            });
        let verification_threshold = NumberOfNodes::new(2);

        assert_matches!(
            verify_signature_batch(
                &mock_csp,
                registry_client.as_ref(),
                &batch_signed_idkg_dealing,
                verification_threshold,
                registry_client.as_ref().get_latest_version(),
            ),
            Err(VerifySignatureBatchError::InvalidSignatureBatch{error, crypto_error})
            if error.contains("Invalid basic signature batch")
                && crypto_error == CryptoError::MalformedSignature {
                    algorithm: AlgorithmId::Ed25519,
                    sig_bytes: vec![0; 64],
                    internal_error: "oh no!".to_string(),
                }
        );
    }

    fn check_input_to_verify(
        sig: &CspSignature,
        message: &[u8],
        algorithm_id: &AlgorithmId,
        csp_pub_key: &CspPublicKey,
        setup: &Setup,
        node_id_counter: &AtomicU64,
    ) -> bool {
        let node_id_counter_val = node_id_counter.fetch_add(1, Ordering::Relaxed);
        let node_id = node_id(node_id_counter_val);
        sig == setup
            .idkg_dealing_supports
            .get(&node_id)
            .unwrap_or_else(|| {
                panic!(
                    "signature should exist for node_id_counter {}",
                    node_id_counter_val
                )
            })
            && message == setup.message
            && algorithm_id == &setup.algorithm_id
            && csp_pub_key
                == setup.csp_public_keys.get(&node_id).unwrap_or_else(|| {
                    panic!(
                        "public key should exist for node_id_counter {}",
                        node_id_counter_val
                    )
                })
    }

    struct SetupBuilder {
        registry_client_override: Option<Arc<dyn RegistryClient>>,
        signature_count: u64,
    }

    impl SetupBuilder {
        fn new() -> Self {
            SetupBuilder {
                registry_client_override: None,
                signature_count: 1,
            }
        }

        fn with_registry_client(
            mut self,
            registry_client_override: Arc<dyn RegistryClient>,
        ) -> Self {
            self.registry_client_override = Some(registry_client_override);
            self
        }

        fn with_signature_count(mut self, signature_count: u64) -> Self {
            self.signature_count = signature_count;
            self
        }

        fn build(self) -> Setup {
            let dealer_id = node_id(0);
            let mut node_signing_public_keys: HashMap<NodeId, PublicKeyProto> = HashMap::new();
            for i in 0..self.signature_count {
                let mut node_signing_public_key = valid_node_signing_public_key();
                node_signing_public_key.key_value = vec![i as u8; 32];
                node_signing_public_keys.insert(node_id(i), node_signing_public_key);
            }

            let registry_client: Arc<dyn RegistryClient> = match self.registry_client_override {
                None => {
                    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
                    let registry_client =
                        FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>);
                    let registry_version = RegistryVersion::from(1);
                    for (node_id, node_signing_public_key) in &node_signing_public_keys {
                        register_node_signing_public_key(
                            registry_data.as_ref(),
                            &registry_client,
                            registry_version,
                            node_signing_public_key.clone(),
                            NodeId::new(node_id.get()),
                        );
                    }
                    registry_client.reload();
                    Arc::new(registry_client)
                }
                Some(registry_client_override) => registry_client_override,
            };

            let dealing = IDkgDealing {
                transcript_id: IDkgTranscriptId::new(SUBNET_42, 1234, Height::new(123)),
                internal_dealing_raw: vec![1, 2, 3],
            };
            let signed_dealing = SignedIDkgDealing {
                content: dealing,
                signature: BasicSignature {
                    signature: BasicSigOf::new(BasicSig(vec![4, 3, 2, 1])),
                    signer: dealer_id,
                },
            };
            let mut batch_signed_idkg_dealing = BatchSignedIDkgDealing {
                content: signed_dealing,
                signature: BasicSignatureBatch {
                    signatures_map: BTreeMap::new(),
                },
            };
            let mut idkg_dealing_supports = BTreeMap::new();
            let mut csp_public_keys = BTreeMap::new();
            for (signature_byte_val, (node_id, node_signing_public_key)) in
                node_signing_public_keys.into_iter().enumerate()
            {
                let sig: BasicSigOf<SignedIDkgDealing> = BasicSigOf::new(BasicSig(vec![
                signature_byte_val
                    .try_into()
                    .expect("number of nodes in these tests should fit into a u8");
                ic_crypto_internal_basic_sig_ed25519::types::SignatureBytes::SIZE
            ]));
                let csp_sig = SigConverter::for_target(AlgorithmId::Ed25519)
                    .try_from_basic(&sig)
                    .expect("should convert signature successfully");
                idkg_dealing_supports.insert(node_id, csp_sig);
                let csp_public_key = CspPublicKey::try_from(node_signing_public_key)
                    .expect("should successfully convert node signing key proto");
                csp_public_keys.insert(node_id, csp_public_key);
                batch_signed_idkg_dealing
                    .signature
                    .signatures_map
                    .insert(node_id, sig.clone());
            }
            let message = batch_signed_idkg_dealing
                .signed_idkg_dealing()
                .as_signed_bytes();
            let algorithm_id = AlgorithmId::Ed25519;
            Setup {
                batch_signed_idkg_dealing,
                idkg_dealing_supports,
                message,
                algorithm_id,
                csp_public_keys,
                registry_client,
            }
        }
    }

    struct Setup {
        batch_signed_idkg_dealing: BatchSignedIDkgDealing,
        idkg_dealing_supports: BTreeMap<NodeId, CspSignature>,
        message: Vec<u8>,
        algorithm_id: AlgorithmId,
        csp_public_keys: BTreeMap<NodeId, CspPublicKey>,
        registry_client: Arc<dyn RegistryClient>,
    }

    impl Setup {
        fn builder() -> SetupBuilder {
            SetupBuilder::new()
        }
    }

    fn register_node_signing_public_key(
        registry_data: &ProtoRegistryDataProvider,
        registry_client: &FakeRegistryClient,
        registry_version: RegistryVersion,
        node_signing_public_key: PublicKeyProto,
        node_id: NodeId,
    ) {
        registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::NodeSigning),
                registry_version,
                Some(node_signing_public_key),
            )
            .expect("failed to add node signing key to registry");
        registry_client.reload();
    }
}

mod ensure_sufficient_openings {
    use super::*;
    use crate::sign::canister_threshold_sig::idkg::transcript::ensure_sufficient_openings;
    use crate::sign::canister_threshold_sig::idkg::transcript::IDkgTranscriptType;
    use crate::sign::canister_threshold_sig::idkg::IDkgComplaint;
    use crate::sign::canister_threshold_sig::idkg::IDkgOpening;
    use crate::sign::canister_threshold_sig::idkg::IDkgTranscript;
    use crate::sign::canister_threshold_sig::test_utils::batch_signed_dealing_with;
    use crate::sign::canister_threshold_sig::test_utils::node_set;
    use crate::sign::tests::REG_V1;
    use ic_base_types::NodeId;
    use ic_crypto_test_utils::map_of;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_opening_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgMaskedTranscriptOrigin;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgReceivers;
    use ic_types_test_utils::ids::NODE_1;
    use ic_types_test_utils::ids::NODE_2;
    use ic_types_test_utils::ids::NODE_3;
    use ic_types_test_utils::ids::NODE_4;
    use std::collections::BTreeMap;

    const DEALER: NodeId = NODE_2;

    #[test]
    fn should_return_error_if_not_enough_openings() {
        let setup = Setup::new_with_openers(vec![NODE_3]);
        assert_eq!(setup.transcript.reconstruction_threshold().get(), 2);

        let result = ensure_sufficient_openings(&setup.openings, &setup.transcript);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InsufficientOpenings { internal_error })
            if internal_error == "insufficient number of openings: got 1, but required 2"
        );
    }

    #[test]
    fn should_return_ok_if_enough_openings() {
        let setup = Setup::new_with_openers(vec![NODE_3, NODE_4]);
        assert_eq!(setup.transcript.reconstruction_threshold().get(), 2);

        let result = ensure_sufficient_openings(&setup.openings, &setup.transcript);

        assert_matches!(result, Ok(()));
    }

    struct Setup {
        transcript: IDkgTranscript,
        openings: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    }

    impl Setup {
        fn new_with_openers(opener_node_ids: Vec<NodeId>) -> Self {
            let transcript_id = dummy_idkg_transcript_id_for_tests(27);
            let dealer_index = 2;
            let verified_dealings = map_of(vec![(
                dealer_index,
                batch_signed_dealing_with(vec![], DEALER),
            )]);
            let receivers_set = node_set(&[NODE_1, NODE_2, NODE_3, NODE_4]);
            for opener in &opener_node_ids {
                assert!(receivers_set.contains(opener));
            }
            let transcript = IDkgTranscript {
                transcript_id,
                receivers: IDkgReceivers::new(receivers_set)
                    .expect("creation of receivers should succeed"),
                registry_version: REG_V1,
                verified_dealings,
                transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                internal_transcript_raw: vec![],
            };
            let complaint = IDkgComplaint {
                transcript_id,
                dealer_id: DEALER,
                internal_complaint_raw: vec![],
            };
            let opening: IDkgOpening = dummy_idkg_opening_for_tests(&complaint);
            let mut openings_val: BTreeMap<NodeId, IDkgOpening> = BTreeMap::new();
            for node_id in opener_node_ids {
                openings_val.insert(node_id, opening.clone());
            }
            let openings = map_of(vec![(complaint, openings_val.clone())]);
            Self {
                transcript,
                openings,
            }
        }
    }
}
