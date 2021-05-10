#![allow(clippy::unwrap_used)]
use distributed_key_generation::run_dkg;
use ic_crypto::utils::{combined_threshold_signature_and_public_key, TempCryptoComponent};
use ic_interfaces::crypto::{DkgAlgorithm, Signable, SignableMock, ThresholdSigVerifier};
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::crypto::threshold_sigs::{
    initial_dkg_transcript_for_nodes_in_subnet, load_transcript_for_each, sign_threshold_for_each,
};
use ic_test_utilities::crypto::{crypto_for, temp_crypto_components_for};
use ic_test_utilities::types::ids::{node_test_id, NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_1};
use ic_types::crypto::dkg::Transcript;
use ic_types::crypto::threshold_sig::ni_dkg::DkgId;
use ic_types::crypto::{dkg, CombinedThresholdSigOf, ThresholdSigShareOf};
use ic_types::{Height, IDkgId, NodeId, SubnetId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const DKG_ID: IDkgId = IDkgId {
    instance_id: Height::new(1),
    subnet_id: SUBNET_1,
};

#[test]
fn should_successfully_run_distributed_key_generation() {
    let dkg_config = dkg::Config {
        dkg_id: DKG_ID,
        dealers: vec![NODE_1, NODE_2],
        receivers: vec![NODE_1, NODE_2, NODE_3],
        threshold: 2,
        resharing_transcript: None,
    };
    let dealers_and_receivers = dealers_and_receivers(&dkg_config);
    let crypto_components = temp_crypto_components_for(&dealers_and_receivers);

    let transcripts = run_dkg(&dkg_config, &crypto_components);

    assert!(dealers_and_receivers
        .iter()
        .all(|node| transcripts.contains_key(&node)));
}

#[test]
fn should_generate_valid_sig_shares() {
    let dkg_config = dkg::Config {
        dkg_id: DKG_ID,
        dealers: vec![NODE_1, NODE_2],
        receivers: vec![NODE_1, NODE_2, NODE_3],
        threshold: 2,
        resharing_transcript: None,
    };
    let crypto_components = temp_crypto_components_for(&dealers_and_receivers(&dkg_config));
    run_dkg(&dkg_config, &crypto_components);

    let msg = message();

    let sig_shares =
        sign_threshold_for_each(&[NODE_1, NODE_2, NODE_3], &msg, DKG_ID, &crypto_components);

    assert_sig_shares_are_valid(NODE_1, &msg, DKG_ID, &sig_shares, &crypto_components);
    assert_sig_shares_are_valid(NODE_2, &msg, DKG_ID, &sig_shares, &crypto_components);
    assert_sig_shares_are_valid(NODE_3, &msg, DKG_ID, &sig_shares, &crypto_components);
}

#[test]
// Tests (2,3)-threshold signature scheme including DKG with different crypto
// components. Components 1 and 2 are dealers. All 3 components are receivers.
// Components 1 and 2 sign. Component 3 verifies the shares, combines them, and
// verifies the combined signature.
fn should_threshold_sign() {
    let dkg_config = dkg::Config {
        dkg_id: DKG_ID,
        dealers: vec![NODE_1, NODE_2],
        receivers: vec![NODE_1, NODE_2, NODE_3],
        threshold: 2,
        resharing_transcript: None,
    };
    let crypto_components = temp_crypto_components_for(&dealers_and_receivers(&dkg_config));
    run_dkg(&dkg_config, &crypto_components);

    let msg = message();
    let combined_sig = threshold_sign_and_combine(
        SignersAndCombiner {
            signers: vec![NODE_1, NODE_2],
            combiner: NODE_3,
        },
        &msg,
        DKG_ID,
        &crypto_components,
    );
    let verify_combined_result = crypto_for(NODE_3, &crypto_components)
        .verify_threshold_sig_combined(&combined_sig, &msg, DkgId::IDkgId(DKG_ID));

    assert!(verify_combined_result.is_ok());
}

#[test]
// Tests (2,3)-threshold signature scheme based on the initial DKG transcript
// with different crypto components. Components 1 and 2 sign. Component 3
// verifies the shares, combines them, and verifies the combined signature.
fn should_threshold_sign_with_initial_dkg_transcript() {
    let num_of_nodes_in_subnet = 3;
    let nodes_in_subnet: Vec<_> = (1..=num_of_nodes_in_subnet).map(node_test_id).collect();
    let crypto_components = temp_crypto_components_for(&nodes_in_subnet);
    let transcript =
        initial_dkg_transcript_for_nodes_in_subnet(SUBNET_1, &nodes_in_subnet, &crypto_components);

    load_transcript_for_each(&nodes_in_subnet, &transcript, &crypto_components);
    let initial_dkg_id = transcript.dkg_id;
    let msg = message();
    let combined_sig = threshold_sign_and_combine(
        SignersAndCombiner {
            signers: vec![NODE_1, NODE_2],
            combiner: NODE_3,
        },
        &msg,
        initial_dkg_id,
        &crypto_components,
    );
    let verify_combined_result = crypto_for(NODE_3, &crypto_components)
        .verify_threshold_sig_combined(&combined_sig, &msg, DkgId::IDkgId(initial_dkg_id));

    assert!(verify_combined_result.is_ok());
}

#[test]
fn should_threshold_sign_with_initial_dkg_transcript_with_single_node() {
    let nodes_in_subnet = [NODE_1];
    let crypto_components = temp_crypto_components_for(&nodes_in_subnet);
    let transcript =
        initial_dkg_transcript_for_nodes_in_subnet(SUBNET_1, &nodes_in_subnet, &crypto_components);

    load_transcript_for_each(&nodes_in_subnet, &transcript, &crypto_components);
    let initial_dkg_id = transcript.dkg_id;
    let msg = message();
    let combined_sig = threshold_sign_and_combine(
        SignersAndCombiner {
            signers: vec![NODE_1],
            combiner: NODE_1,
        },
        &msg,
        initial_dkg_id,
        &crypto_components,
    );
    let verify_combined_result = crypto_for(NODE_1, &crypto_components)
        .verify_threshold_sig_combined(&combined_sig, &msg, DkgId::IDkgId(initial_dkg_id));

    assert!(verify_combined_result.is_ok());
}

#[test]
fn should_create_initial_dkg_transcript_for_28_nodes() {
    let num_of_nodes_in_subnet = 28;

    let nodes_in_subnet: Vec<_> = (1..=num_of_nodes_in_subnet).map(node_test_id).collect();
    let crypto_components = temp_crypto_components_for(&nodes_in_subnet);
    let _ =
        initial_dkg_transcript_for_nodes_in_subnet(SUBNET_1, &nodes_in_subnet, &crypto_components);
}

#[test]
fn should_allow_reloading_transcript() {
    let dkg_config = dkg::Config {
        dkg_id: DKG_ID,
        dealers: vec![NODE_1, NODE_2],
        receivers: vec![NODE_1, NODE_2, NODE_3],
        threshold: 2,
        resharing_transcript: None,
    };
    let crypto_components = temp_crypto_components_for(&dealers_and_receivers(&dkg_config));
    let transcripts = run_dkg(&dkg_config, &crypto_components);

    let reloading_node = NODE_1;
    assert!(
        transcripts.contains_key(&reloading_node),
        "Cannot re-load transcript for a node that hasn't loaded it yet"
    );
    let transcript = transcripts
        .get(&reloading_node)
        .unwrap_or_else(|| panic!("missing transcript for {:?}", reloading_node));
    let result =
        crypto_for(reloading_node, &crypto_components).load_transcript(&transcript, NODE_1);
    assert!(result.is_ok());
}

#[test]
fn should_allow_loading_transcript_for_non_receiver() {
    let dkg_config = dkg::Config {
        dkg_id: DKG_ID,
        dealers: vec![NODE_1, NODE_4],
        receivers: vec![NODE_1, NODE_2, NODE_3],
        threshold: 2,
        resharing_transcript: None,
    };
    let crypto_components = temp_crypto_components_for(&dealers_and_receivers(&dkg_config));
    let transcripts = run_dkg(&dkg_config, &crypto_components);

    // Load transcript of NODE_1 for non-receiver NODE_4
    let non_receiver_node = NODE_4;
    assert!(!dkg_config.receivers.contains(&non_receiver_node));
    let transcript = transcripts
        .get(&NODE_1)
        .unwrap_or_else(|| panic!("missing transcript for {:?}", NODE_1));
    let result =
        crypto_for(non_receiver_node, &crypto_components).load_transcript(&transcript, NODE_1);
    assert!(result.is_ok());
}

#[test]
fn should_produce_the_same_transcript_for_all_receivers() {
    let dkg_config = dkg::Config {
        dkg_id: DKG_ID,
        dealers: vec![NODE_1, NODE_2],
        receivers: vec![NODE_1, NODE_2, NODE_3],
        threshold: 2,
        resharing_transcript: None,
    };
    let crypto_components = temp_crypto_components_for(&dealers_and_receivers(&dkg_config));

    let transcripts = run_dkg(&dkg_config, &crypto_components);
    let transcripts_set: BTreeSet<_> = transcripts
        .iter()
        .map(|(_node_id, transcript)| transcript)
        .collect();

    assert_eq!(transcripts_set.len(), 1);
}

mod threshold_sigs_with_resharing_dkg {
    use super::*;

    fn dkg_id(height: u64, subnet_id: SubnetId) -> IDkgId {
        IDkgId {
            instance_id: Height::new(height),
            subnet_id,
        }
    }

    #[test]
    // TODO (CRP-397): Can we somehow make sure in this test that the public key
    // (which is the root of trust in the registry) remains valid?
    fn should_run_dkg_and_threshold_sign_in_multiple_dkg_epochs_with_resharing() {
        let num_of_nodes_in_subnet = 5;
        let num_dkg_epochs = 4;
        let threshold = 3; // # it must hold that #receivers >= 2*threshold - 1
        let nodes_in_subnet: Vec<_> = (1..=num_of_nodes_in_subnet).map(node_test_id).collect();
        let crypto_components = temp_crypto_components_for(&nodes_in_subnet);

        // Initial DKG
        let initial_transcript = initial_dkg_transcript_for_nodes_in_subnet(
            SUBNET_1,
            &nodes_in_subnet,
            &crypto_components,
        );
        let initial_dkg_id = initial_transcript.dkg_id;
        load_transcript_for_each(&nodes_in_subnet, &initial_transcript, &crypto_components);
        assert_threshold_sign_works_and_combined_sig_is_valid(
            &crypto_components,
            msg("epoch 1 message"),
            initial_dkg_id,
            SignersAndCombiner {
                signers: all_except_last(&nodes_in_subnet),
                combiner: *nodes_in_subnet.last().unwrap(),
            },
        );

        // Several epochs of resharing DKG
        let mut resharing_transcript = initial_transcript;
        for i in 2..=num_dkg_epochs + 1 {
            let dkg_id = dkg_id(i, SUBNET_1);
            let transcripts = run_dkg(
                &dkg::Config {
                    dkg_id,
                    dealers: nodes_in_subnet[0..threshold].to_vec(),
                    receivers: nodes_in_subnet.clone(),
                    threshold,
                    resharing_transcript: Some(resharing_transcript),
                },
                &crypto_components,
            );
            assert_threshold_sign_works_and_combined_sig_is_valid(
                &crypto_components,
                msg(&format!("epoch {:?} message", i)),
                dkg_id,
                SignersAndCombiner {
                    signers: all_except_last(&nodes_in_subnet),
                    combiner: *nodes_in_subnet.last().unwrap(),
                },
            );
            resharing_transcript = assert_transcripts_equal_and_get_transcript(transcripts);
        }
    }

    fn all_except_last(nodes_in_subnet: &[NodeId]) -> Vec<NodeId> {
        nodes_in_subnet[0..nodes_in_subnet.len() - 1].to_vec()
    }

    fn assert_transcripts_equal_and_get_transcript(
        transcripts: BTreeMap<NodeId, Transcript>,
    ) -> Transcript {
        let transcripts_set: BTreeSet<_> = transcripts
            .iter()
            .map(|(_node_id, transcript)| transcript)
            .collect();
        assert_eq!(transcripts_set.len(), 1);

        transcripts_set.iter().next().copied().unwrap().to_owned()
    }

    fn assert_threshold_sign_works_and_combined_sig_is_valid(
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
        message: SignableMock,
        dkg_id: IDkgId,
        signers_and_combiner: SignersAndCombiner,
    ) {
        let combined_sig = threshold_sign_and_combine(
            signers_and_combiner.clone(),
            &message,
            dkg_id,
            &crypto_components,
        );
        let verify_combined_result = crypto_for(signers_and_combiner.combiner, &crypto_components)
            .verify_threshold_sig_combined(&combined_sig, &message, DkgId::IDkgId(dkg_id));

        assert!(verify_combined_result.is_ok());
    }
}

mod threshold_sig_verification_by_public_key {
    use super::*;
    use ic_crypto::utils::dkg::initial_dkg_transcript_record_from_transcript;
    use ic_crypto::verify_combined_threshold_sig;
    use ic_interfaces::crypto::ThresholdSigVerifierByPublicKey;
    use ic_registry_keys::make_subnet_record_key;
    use ic_test_utilities::registry::test_subnet_record;
    use ic_types::RegistryVersion;

    const REG_V1: RegistryVersion = RegistryVersion::new(1);

    #[test]
    // Tests (2,3)-threshold signature scheme including DKG with different crypto
    // components. Components 1 and 2 are dealers. All 3 components are receivers.
    // Components 1 and 2 sign. Component 3 verifies the shares, combines them, and
    // verifies the combined signature by a subnet's public key
    // Ignoring the test because verify_combined_threshold_sig_by_public_key is now based on
    // non-interactive DKG
    #[ignore]
    fn should_verify_combined_threshold_sig_by_pubkey() {
        let dkg_config = dkg::Config {
            dkg_id: DKG_ID,
            dealers: vec![NODE_1, NODE_2],
            receivers: vec![NODE_1, NODE_2, NODE_3],
            threshold: 2,
            resharing_transcript: None,
        };
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
        let crypto_components = TempCryptoComponent::multiple_new(
            &dealers_and_receivers(&dkg_config),
            Arc::clone(&registry) as Arc<_>,
        );
        let transcripts = run_dkg(&dkg_config, &crypto_components);
        let transcript = transcripts.get(&NODE_1).cloned().unwrap();
        add_dkg_transcript_to_registry(&registry_data, &transcript, SUBNET_1, REG_V1);
        registry.update_to_latest_version(); // Required to update the cache

        let msg = message();
        let combined_sig = threshold_sign_and_combine(
            SignersAndCombiner {
                signers: vec![NODE_1, NODE_2],
                combiner: NODE_3,
            },
            &msg,
            DKG_ID,
            &crypto_components,
        );
        let verify_combined_result = crypto_for(NODE_3, &crypto_components)
            .verify_combined_threshold_sig_by_public_key(&combined_sig, &msg, SUBNET_1, REG_V1);

        assert!(verify_combined_result.is_ok());
    }

    #[test]
    // Tests (2,3)-threshold signature scheme based on the initial DKG transcript
    // with different crypto components. Components 1 and 2 sign. Component 3
    // verifies the shares, combines them, and verifies the combined signature by a
    // subnet's public key
    // Ignoring the test because verify_combined_threshold_sig_by_public_key is now based on
    // non-interactive DKG
    #[ignore]
    fn should_verify_combined_threshold_sig_by_pubkey_with_initial_dkg_transcript() {
        let num_of_nodes_in_subnet = 3;
        let nodes_in_subnet: Vec<_> = (1..=num_of_nodes_in_subnet).map(node_test_id).collect();
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
        let crypto_components =
            TempCryptoComponent::multiple_new(&nodes_in_subnet, Arc::clone(&registry) as Arc<_>);
        let transcript = initial_dkg_transcript_for_nodes_in_subnet(
            SUBNET_1,
            &nodes_in_subnet,
            &crypto_components,
        );
        add_dkg_transcript_to_registry(&registry_data, &transcript, SUBNET_1, REG_V1);
        registry.update_to_latest_version(); // Required to update the cache

        load_transcript_for_each(&nodes_in_subnet, &transcript, &crypto_components);
        let initial_dkg_id = transcript.dkg_id;
        let msg = message();
        let combined_sig = threshold_sign_and_combine(
            SignersAndCombiner {
                signers: vec![NODE_1, NODE_2],
                combiner: NODE_3,
            },
            &msg,
            initial_dkg_id,
            &crypto_components,
        );
        let verify_combined_result = crypto_for(NODE_3, &crypto_components)
            .verify_combined_threshold_sig_by_public_key(&combined_sig, &msg, SUBNET_1, REG_V1);

        assert!(verify_combined_result.is_ok());
    }

    #[test]
    fn should_fail_to_verify_corrupted_combined_threshold_signature() {
        let seed = ic_types::Randomness::new([42; 32]);
        let message = msg("example message");
        let (sig, pk) = combined_threshold_signature_and_public_key(seed, &message);
        let mut corrupted_sig = sig.get();
        corrupted_sig.0[0] += 1;
        let corrupted_sig = CombinedThresholdSigOf::from(corrupted_sig);
        let result = verify_combined_threshold_sig(&message, &corrupted_sig, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_malformed_signature());
    }

    #[test]
    fn should_fail_to_verify_combined_threshold_signature_with_wrong_key() {
        let message = msg("example message");
        let seed1 = ic_types::Randomness::new([42; 32]);
        let (sig1, _pk1) = combined_threshold_signature_and_public_key(seed1, &message);
        let seed2 = ic_types::Randomness::new([10; 32]);
        let (_sig2, pk2) = combined_threshold_signature_and_public_key(seed2, &message);
        let result = verify_combined_threshold_sig(&message, &sig1, &pk2);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_fail_to_verify_combined_threshold_signature_on_wrong_message() {
        let seed = ic_types::Randomness::new([42; 32]);
        let message = msg("example message");
        let (sig, pk) = combined_threshold_signature_and_public_key(seed, &message);
        let wrong_message = msg("wrong message");
        let result = verify_combined_threshold_sig(&wrong_message, &sig, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    }

    #[test]
    fn should_verify_combined_threshold_signature() {
        let seed = ic_types::Randomness::new([42; 32]);
        let message = msg("example message");
        let (sig, pk) = combined_threshold_signature_and_public_key(seed, &message);
        let result = verify_combined_threshold_sig(&message, &sig, &pk);
        assert!(result.is_ok());
    }

    fn add_dkg_transcript_to_registry(
        registry_data_provider: &Arc<ProtoRegistryDataProvider>,
        transcript: &Transcript,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) {
        let mut subnet_record = test_subnet_record();
        subnet_record.initial_dkg_transcript = Some(initial_dkg_transcript_record_from_transcript(
            transcript.clone(),
        ));

        registry_data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                registry_version,
                Some(subnet_record),
            )
            .expect("Failed to add subnet record.");
    }
}

fn dealers_and_receivers(dkg_config: &dkg::Config) -> Vec<NodeId> {
    let dealer_set: BTreeSet<_> = dkg_config.dealers.iter().cloned().collect();
    let receiver_set: BTreeSet<_> = dkg_config.receivers.iter().cloned().collect();
    dealer_set.union(&receiver_set).cloned().collect()
}

#[derive(Clone, Debug)]
struct SignersAndCombiner {
    signers: Vec<NodeId>,
    combiner: NodeId,
}

fn threshold_sign_and_combine<H: Signable>(
    signers_and_combiner: SignersAndCombiner,
    msg: &H,
    dkg_id: IDkgId,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> CombinedThresholdSigOf<H> {
    let sig_shares = sign_threshold_for_each(
        &signers_and_combiner.signers,
        msg,
        dkg_id,
        &crypto_components,
    );
    assert_sig_shares_are_valid(
        signers_and_combiner.combiner,
        msg,
        dkg_id,
        &sig_shares,
        crypto_components,
    );
    crypto_for(signers_and_combiner.combiner, &crypto_components)
        .combine_threshold_sig_shares(sig_shares, DkgId::IDkgId(dkg_id))
        .expect("failed to combine signature shares")
}

fn assert_sig_shares_are_valid<H: Signable>(
    verifying_node: NodeId,
    msg: &H,
    dkg_id: IDkgId,
    sig_shares: &BTreeMap<NodeId, ThresholdSigShareOf<H>>,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
    sig_shares.iter().for_each(|(signer, sig_share)| {
        assert!(
            crypto_for(verifying_node, &crypto_components)
                .verify_threshold_sig_share(&sig_share, msg, DkgId::IDkgId(dkg_id), *signer)
                .is_ok(),
            "the node {:?} failed to verify sig share for node id {:?}",
            verifying_node,
            *signer
        );
    });
}

mod distributed_key_generation {
    use super::*;
    use ic_test_utilities::crypto::threshold_sigs::encryption_public_keys;
    use ic_types::crypto::dkg::{Dealing, EncryptionPublicKeyWithPop, Response, Transcript};
    use std::collections::BTreeMap;

    /// Runs the distributed key generation (DKG) protocol as follows:
    /// * Dealers and receivers generate encryption public keys
    /// * Receivers verify encryption public keys
    /// * Dealers create dealings
    /// * Receivers verify dealings
    /// * Receivers generate responses
    /// * Receivers verify responses
    /// * Dealers and receivers create a transcript and load it
    pub fn run_dkg(
        dkg_config: &dkg::Config,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, Transcript> {
        let keys = generate_and_verify_encryption_public_keys(&dkg_config, crypto_components);
        let dealings = generate_and_verify_dealings(&dkg_config, &keys, crypto_components);
        let responses =
            generate_and_verify_responses(&dkg_config, &keys, &dealings, crypto_components);

        create_and_load_transcripts(
            &dealers_and_receivers(dkg_config),
            dkg_config,
            &keys,
            &dealings,
            &responses,
            crypto_components,
        )
    }

    fn generate_and_verify_encryption_public_keys(
        dkg_config: &dkg::Config,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, dkg::EncryptionPublicKeyWithPop> {
        let dealers_and_receivers = dealers_and_receivers(dkg_config);
        let keys = encryption_public_keys(&dealers_and_receivers, dkg_config, crypto_components);
        verify_encryption_public_keys(&dkg_config.receivers, dkg_config, &keys, crypto_components);
        keys
    }

    fn verify_encryption_public_keys(
        nodes: &[NodeId],
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) {
        for node in nodes {
            for (key_node, key) in keys {
                let result = crypto_for(*node, &crypto_components)
                    .verify_encryption_public_key(dkg_config, *key_node, key);
                assert!(
                    result.is_ok(),
                    "verification of encryption public key from node {:?} failed for {:?}",
                    key_node,
                    node
                );
            }
        }
    }

    fn generate_and_verify_dealings(
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, dkg::Dealing> {
        let dealings = dealings(&dkg_config.dealers, dkg_config, keys, crypto_components);
        verify_dealings(
            &dkg_config.receivers,
            dkg_config,
            &dealings,
            keys,
            crypto_components,
        );
        dealings
    }

    fn dealings(
        nodes: &[NodeId],
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, dkg::Dealing> {
        nodes
            .iter()
            .map(|node| {
                let dealing = crypto_for(*node, &crypto_components)
                    .create_dealing(dkg_config, keys, *node)
                    .unwrap_or_else(|error| {
                        panic!("failed to create dealing for {:?}: {:?}", node, error)
                    });
                (*node, dealing)
            })
            .collect()
    }

    fn verify_dealings(
        nodes: &[NodeId],
        dkg_config: &dkg::Config,
        dealings: &BTreeMap<NodeId, Dealing>,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) {
        for node in nodes {
            for (dealer, dealing) in dealings {
                let result = crypto_for(*node, &crypto_components)
                    .verify_dealing(dkg_config, keys, *dealer, dealing);
                assert!(
                    result.is_ok(),
                    "verification of dealing from dealer {:?} failed for {:?}",
                    dealer,
                    node
                );
            }
        }
    }

    fn generate_and_verify_responses(
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealings: &BTreeMap<NodeId, Dealing>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, Response> {
        let responses = responses(
            &dkg_config.receivers,
            dkg_config,
            keys,
            dealings,
            crypto_components,
        );
        verify_responses(
            &dkg_config.receivers,
            dkg_config,
            &responses,
            dealings,
            keys,
            crypto_components,
        );
        responses
    }

    fn responses(
        nodes: &[NodeId],
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealings: &BTreeMap<NodeId, Dealing>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, Response> {
        nodes
            .iter()
            .map(|node| {
                let response = crypto_for(*node, &crypto_components)
                    .create_response(dkg_config, keys, dealings, *node)
                    .unwrap_or_else(|error| {
                        panic!("failed to create response for {:?}: {:?}", node, error)
                    });
                (*node, response)
            })
            .collect()
    }

    fn verify_responses(
        nodes: &[NodeId],
        dkg_config: &dkg::Config,
        responses: &BTreeMap<NodeId, Response>,
        dealings: &BTreeMap<NodeId, Dealing>,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) {
        for node in nodes {
            for (receiver, response) in responses {
                let result = crypto_for(*node, &crypto_components)
                    .verify_response(dkg_config, keys, dealings, *receiver, response);
                assert!(
                    result.is_ok(),
                    "verification of response from receiver {:?} failed for {:?}",
                    receiver,
                    node
                );
            }
        }
    }

    fn create_and_load_transcripts(
        nodes: &[NodeId],
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealings: &BTreeMap<NodeId, Dealing>,
        responses: &BTreeMap<NodeId, Response>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, Transcript> {
        let transcripts = transcripts(
            nodes,
            dkg_config,
            keys,
            dealings,
            responses,
            crypto_components,
        );
        load_transcripts(nodes, &transcripts, crypto_components);
        transcripts
    }

    fn transcripts(
        nodes: &[NodeId],
        dkg_config: &dkg::Config,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealings: &BTreeMap<NodeId, Dealing>,
        responses: &BTreeMap<NodeId, Response>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, Transcript> {
        nodes
            .iter()
            .map(|node| {
                let transcript = crypto_for(*node, &crypto_components)
                    .create_transcript(dkg_config, keys, dealings, responses)
                    .unwrap_or_else(|error| {
                        panic!("failed to create transcript for {:?}: {:?}", node, error)
                    });
                (*node, transcript)
            })
            .collect()
    }

    fn load_transcripts(
        nodes: &[NodeId],
        transcripts: &BTreeMap<NodeId, Transcript>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) {
        for node in nodes {
            let transcript = transcripts
                .get(node)
                .unwrap_or_else(|| panic!("missing transcript for {:?}", node));
            crypto_for(*node, &crypto_components)
                .load_transcript(&transcript, *node)
                .unwrap_or_else(|error| {
                    panic!("failed to load transcript for {:?}, {:?}", node, error)
                });
        }
    }
}

fn message() -> SignableMock {
    SignableMock::new(b"message".to_vec())
}

fn msg(content: &str) -> SignableMock {
    SignableMock::new(content.as_bytes().to_vec())
}
