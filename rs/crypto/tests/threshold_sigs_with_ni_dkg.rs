#![allow(clippy::unwrap_used)]
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_test_utils_threshold_sigs::non_interactive::{
    create_dealings, run_ni_dkg_and_create_single_transcript, NiDkgTestEnvironment,
    RandomNiDkgConfig,
};
use ic_interfaces::crypto::{
    LoadTranscriptResult, NiDkgAlgorithm, Signable, SignableMock, ThresholdSigVerifier,
    ThresholdSigner,
};
use ic_test_utilities::crypto::crypto_for;
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::{DkgId, NiDkgTag, NiDkgTranscript};
use ic_types::crypto::{CombinedThresholdSigOf, CryptoError, ThresholdSigShareOf};
use ic_types::{NodeId, NumberOfNodes, RegistryVersion};
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryFrom;

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const ONE_NODE: NumberOfNodes = NumberOfNodes::new(1);

#[test]
// Test uses a random NI-DKG config.
// A random receiver is chosen to be both combiner and verifier.
fn should_threshold_sign_if_sufficient_shares() {
    let subnet_size = thread_rng().gen_range(1, 7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size);

    run_ni_dkg_and_load_transcript_for_receivers(&config, &crypto_components);

    let msg = message();
    let random_combiner = random_node_in(config.receivers().get());
    let combined_sig = threshold_sign_and_combine(
        SignersAndCombiner {
            signers: n_random_nodes_in(config.receivers().get(), config.threshold().get()),
            combiner: random_combiner,
        },
        &msg,
        dkg_id,
        &crypto_components,
    );
    let random_verifier = random_node_in(config.receivers().get());
    let verify_combined_result = crypto_for(random_verifier, &crypto_components)
        .verify_threshold_sig_combined(&combined_sig, &msg, dkg_id);

    assert!(verify_combined_result.is_ok());
}

#[test]
// Test uses a random NI-DKG config. A random receiver is chosen as verifier.
fn should_produce_valid_signature_shares() {
    let subnet_size = thread_rng().gen_range(1, 7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size);

    run_ni_dkg_and_load_transcript_for_receivers(&config, &crypto_components);

    let msg = message();
    let sig_shares = sign_threshold_for_each(
        &config.receivers().get().iter().copied().collect::<Vec<_>>(),
        &msg,
        dkg_id,
        &crypto_components,
    );

    let verifier = random_node_in(config.receivers().get());
    sig_shares.iter().for_each(|(signer, sig_share)| {
        assert!(
            crypto_for(verifier, &crypto_components)
                .verify_threshold_sig_share(sig_share, &msg, dkg_id, *signer)
                .is_ok(),
            "node {:?} failed to verify threshold sig share of signer {:?}",
            verifier,
            *signer
        );
    });
}

#[test]
// Test uses a random NI-DKG config. A random receiver is chosen as combiner.
fn should_fail_to_combine_insufficient_shares() {
    // Need >=4 nodes to have >=2 shares to combine in a low-threshold config
    let subnet_size = thread_rng().gen_range(4, 7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size);
    let num_of_shares_to_combine = config.threshold().get() - ONE_NODE;

    run_ni_dkg_and_load_transcript_for_receivers(&config, &crypto_components);

    let sig_shares = sign_threshold_for_each(
        &n_random_nodes_in(config.receivers().get(), num_of_shares_to_combine),
        &message(),
        dkg_id,
        &crypto_components,
    );
    let combination_result =
        crypto_for(random_node_in(config.receivers().get()), &crypto_components)
            .combine_threshold_sig_shares(sig_shares, dkg_id);

    assert_eq!(
        combination_result.unwrap_err(),
        CryptoError::InvalidArgument {
            message: format!(
                "Threshold too high: (threshold={} !<= {}=num_shares)",
                config.threshold().get(),
                num_of_shares_to_combine
            )
        }
    );
}

fn setup_with_random_ni_dkg_config(
    subnet_size: usize,
) -> (NiDkgConfig, DkgId, BTreeMap<NodeId, TempCryptoComponent>) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(subnet_size)
        .build()
        .into_config();
    let dkg_id = DkgId::NiDkgId(config.dkg_id());
    let crypto_components = NiDkgTestEnvironment::new_for_config(&config).crypto_components;
    (config, dkg_id, crypto_components)
}

fn run_ni_dkg_and_load_transcript_for_receivers(
    config: &NiDkgConfig,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
    let transcript = run_ni_dkg_and_create_single_transcript(config, crypto_components);
    load_transcript_for_receivers_expecting_status(
        config,
        &transcript,
        crypto_components,
        Some(LoadTranscriptResult::SigningKeyAvailable),
    );
}

fn load_transcript_for_receivers(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
    load_transcript_for_receivers_expecting_status(config, transcript, crypto_components, None);
}

fn load_transcript_for_receivers_expecting_status(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    expected_status: Option<LoadTranscriptResult>,
) {
    for node_id in config.receivers().get() {
        let result = crypto_for(*node_id, crypto_components).load_transcript(transcript);

        if result.is_err() {
            panic!(
                "failed to load transcript {} for node {}: {}",
                transcript,
                *node_id,
                result.unwrap_err()
            );
        }

        if let Some(expected_status) = expected_status {
            let result = result.unwrap();
            assert_eq!(result, expected_status);
        }
    }
}

#[derive(Clone, Debug)]
struct SignersAndCombiner {
    signers: Vec<NodeId>,
    combiner: NodeId,
}

fn threshold_sign_and_combine<H: Signable>(
    signers_and_combiner: SignersAndCombiner,
    msg: &H,
    dkg_id: DkgId,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> CombinedThresholdSigOf<H> {
    let sig_shares = sign_threshold_for_each(
        &signers_and_combiner.signers,
        msg,
        dkg_id,
        crypto_components,
    );
    crypto_for(signers_and_combiner.combiner, crypto_components)
        .combine_threshold_sig_shares(sig_shares, dkg_id)
        .expect("failed to combine signature shares")
}

fn sign_threshold_for_each<H: Signable>(
    signers: &[NodeId],
    msg: &H,
    dkg_id: DkgId,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, ThresholdSigShareOf<H>> {
    signers
        .iter()
        .map(|signer| {
            let sig_share = crypto_for(*signer, crypto_components)
                .sign_threshold(msg, dkg_id)
                .unwrap_or_else(|e| panic!("signing by node {:?} failed: {}", signer, e));
            (*signer, sig_share)
        })
        .collect()
}

fn random_node_in(nodes: &BTreeSet<NodeId>) -> NodeId {
    let rng = &mut thread_rng();
    *nodes.iter().choose(rng).expect("nodes empty")
}

fn n_random_nodes_in(nodes: &BTreeSet<NodeId>, n: NumberOfNodes) -> Vec<NodeId> {
    let rng = &mut thread_rng();
    let n_usize = usize::try_from(n.get()).expect("conversion to usize failed");
    let chosen = nodes.iter().copied().choose_multiple(rng, n_usize);
    assert_eq!(chosen.len(), n_usize);
    chosen
}

fn message() -> SignableMock {
    SignableMock::new(b"message".to_vec())
}

mod non_interactive_distributed_key_generation {
    use super::*;
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgDealing;

    #[test]
    fn should_produce_valid_dealings_for_all_dealers() {
        let subnet_size = thread_rng().gen_range(1, 7);
        let (config, _dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size);

        let dealings = create_dealings(&config, &crypto_components);
        let verifier = config.receivers().get().iter().next().unwrap();
        let verifier_crypto = crypto_for(*verifier, &crypto_components);

        for (dealer, dealing) in dealings {
            let verification_result = verifier_crypto.verify_dealing(&config, dealer, &dealing);
            assert!(
                verification_result.is_ok(),
                "verification of dealing from dealer {:?} failed for {:?}",
                dealer,
                verifier
            );
        }
    }

    #[test]
    fn should_produce_same_transcript_for_all_receivers() {
        let subnet_size = thread_rng().gen_range(1, 7);
        let (config, _dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size);

        let transcripts = run_ni_dkg_and_create_receiver_transcripts(&config, &crypto_components);

        let transcripts_set: HashSet<_> = transcripts
            .iter()
            .map(|(_node_id, transcript)| transcript)
            .collect();
        assert_eq!(transcripts_set.len(), 1);
    }

    #[test]
    fn should_not_reshare_ni_dkg_without_loaded_transcript() {
        let (initial_subnet_size, max_subnet_size) = (3, 10);

        // In practise, resharing is done only for high threshold configs
        let config = RandomNiDkgConfig::builder()
            .subnet_size(initial_subnet_size)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(REG_V1)
            .build();
        let mut env = NiDkgTestEnvironment::new_for_config(config.get());
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        let reshare_config = RandomNiDkgConfig::reshare(transcript, -2..=2, max_subnet_size);
        env.update_for_config(reshare_config.get());

        for dealer in reshare_config.get().dealers().get() {
            let result = crypto_for(*dealer, &env.crypto_components)
                .create_dealing(reshare_config.get())
                .unwrap_err();

            assert!(matches!(
                result,
                DkgCreateDealingError::ThresholdSigningKeyNotInSecretKeyStore(_)
            ));
        }
    }

    #[test]
    fn should_run_resharing_ni_dkg_over_multiple_epochs() {
        let (initial_subnet_size, max_subnet_size, epochs) = (3, 10, 10);

        // In practise, resharing is done only for high threshold configs
        let mut config = RandomNiDkgConfig::builder()
            .subnet_size(initial_subnet_size)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(REG_V1)
            .build();
        let mut env = NiDkgTestEnvironment::new_for_config(config.get());
        let mut transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        for _i in 1..=epochs {
            config = RandomNiDkgConfig::reshare(transcript, -2..=2, max_subnet_size);
            env.update_for_config(config.get());
            transcript =
                run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);
        }
    }

    // Test different scenarios for FS key deletion
    //
    // First create 3 high threshold epochs, followed by a single low threshold
    // epoch. The low threshold exists only to satisfy a check in
    // retain_only_active_keys that at least one high and one low transcript are
    // retained.
    //
    // Then, verify that nodes can sign in the epochs that they participated in, and
    // that any node added to the subnet later cannot sign in that epoch.
    //
    // For this test to work we must have a new epoch each time, which we force by
    // adding at least 1 node to the subnet with each reshare
    #[test]
    fn should_not_sign_after_resharing_and_pruning_old_keys() {
        let max_subnet_size = 10;
        let mut env = NiDkgTestEnvironment::new();
        let rng = &mut thread_rng();
        let registry_version = RegistryVersion::from(rng.gen_range(1, u32::MAX - 10_000) as u64);

        // epoch 0
        let config0 = RandomNiDkgConfig::builder()
            .subnet_size(3)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(registry_version)
            .build();
        let (transcript0, dkg_id0, epoch0_nodes) = run_dkg_and_load_transcripts(&config0, &mut env);

        // epoch 1
        let config1 = RandomNiDkgConfig::reshare(transcript0.clone(), 1..=2, max_subnet_size);
        let (transcript1, dkg_id1, epoch1_nodes) = run_dkg_and_load_transcripts(&config1, &mut env);
        let new_in_epoch1: HashSet<_> = epoch1_nodes.difference(&epoch0_nodes).cloned().collect();

        // epoch2
        let config2 = RandomNiDkgConfig::reshare(transcript1.clone(), 1..=2, max_subnet_size);
        let (transcript2, dkg_id2, epoch2_nodes) = run_dkg_and_load_transcripts(&config2, &mut env);
        let new_in_epoch2: HashSet<_> = epoch2_nodes.difference(&epoch1_nodes).cloned().collect();

        // A low threshhold transcript just to bypass a check in retain_only_active_keys
        let config3 = config2.new_with_inverted_threshold();
        let (transcript3, _dkg_id3, epoch3_nodes) =
            run_dkg_and_load_transcripts(&config3, &mut env);

        // Test that the subnets increased in size and without removing any nodes
        assert!(!new_in_epoch1.is_empty());
        assert!(!new_in_epoch2.is_empty());
        assert_eq!(epoch0_nodes.difference(&epoch1_nodes).count(), 0);
        assert_eq!(epoch1_nodes.difference(&epoch2_nodes).count(), 0);

        // Test that all nodes can sign in their own epoch
        assert!(nodes_can_sign_in_epoch(&epoch0_nodes, dkg_id0, &env));
        assert!(nodes_can_sign_in_epoch(&epoch1_nodes, dkg_id1, &env));
        assert!(nodes_can_sign_in_epoch(&epoch2_nodes, dkg_id2, &env));

        // Test that nodes added later cannot sign in old epochs
        assert!(
            nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
                &new_in_epoch1,
                dkg_id0,
                &env
            )
        );
        assert!(
            nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
                &new_in_epoch2,
                dkg_id0,
                &env
            )
        );
        assert!(
            nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
                &new_in_epoch2,
                dkg_id1,
                &env
            )
        );

        // Prune epoch0 keys
        retain_only_active_keys_for_transcripts(
            &[transcript1, transcript2, transcript3.clone()],
            &mut env,
        );

        // All nodes can still decrypt transcript3
        load_transcript_for_receivers_expecting_status(
            config3.get(),
            &transcript3,
            &env.crypto_components,
            Some(LoadTranscriptResult::SigningKeyAvailable),
        );

        // Now nobody can sign in epoch0 since the keys have been removed
        assert!(nodes_cannot_sign_in_epoch_due_to_missing_secret_key(
            &epoch0_nodes,
            dkg_id0,
            &env
        ));

        // But the newer epochs can still be used by all nodes
        assert!(nodes_can_sign_in_epoch(&epoch1_nodes, dkg_id1, &env));
        assert!(nodes_can_sign_in_epoch(&epoch2_nodes, dkg_id2, &env));

        // And all nodes can still load the old transcript (but not decrypt it)
        load_transcript_for_receivers(config3.get(), &transcript0, &env.crypto_components);

        // Even after the transcript is loaded again, key is not available
        assert!(nodes_cannot_sign_in_epoch_due_to_missing_secret_key(
            &epoch3_nodes,
            dkg_id0,
            &env
        ));

        // Further DKGs can be run after removing an earlier key
        let config4 = RandomNiDkgConfig::reshare(transcript3, 1..=2, max_subnet_size);
        let (_transcript4, dkg_id4, epoch4_nodes) =
            run_dkg_and_load_transcripts(&config4, &mut env);
        assert!(nodes_can_sign_in_epoch(&epoch4_nodes, dkg_id4, &env));
    }

    #[test]
    fn should_not_reshare_old_transcript_after_pruning_old_keys() {
        let rng = &mut thread_rng();

        let registry_version = RegistryVersion::from(rng.gen_range(1, u32::MAX - 10_000) as u64);

        let mut env = NiDkgTestEnvironment::new();

        let max_subnet_size = 10;

        // epoch 0
        let config0 = RandomNiDkgConfig::builder()
            .subnet_size(3)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(registry_version)
            .build();
        let (transcript0, _dkg_id0, _epoch0_nodes) =
            run_dkg_and_load_transcripts(&config0, &mut env);

        // epoch 1
        let config1 = RandomNiDkgConfig::reshare(transcript0.clone(), 1..=2, max_subnet_size);
        let (transcript1, _dkg_id1, _epoch1_nodes) =
            run_dkg_and_load_transcripts(&config1, &mut env);

        // low threshold
        let config_low = config1.new_with_inverted_threshold();
        let (transcript_low, _dkg_id_low, _epochlow_nodes) =
            run_dkg_and_load_transcripts(&config_low, &mut env);

        retain_only_active_keys_for_transcripts(&[transcript1, transcript_low], &mut env);

        // Now attempt to reshare off of transcript0, should fail in create_dealing:
        let reshare_config = RandomNiDkgConfig::reshare(transcript0, 1..=2, max_subnet_size);

        for dealer in reshare_config.get().dealers().get() {
            let result =
                crypto_for(*dealer, &env.crypto_components).create_dealing(reshare_config.get());

            assert!(matches!(
                result,
                Err(DkgCreateDealingError::FsEncryptionPublicKeyNotInRegistry(_))
            ));
        }
    }

    fn run_dkg_and_load_transcripts(
        config: &RandomNiDkgConfig,
        env: &mut NiDkgTestEnvironment,
    ) -> (NiDkgTranscript, DkgId, HashSet<NodeId>) {
        env.update_for_config(config.get());
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        load_transcript_for_receivers(config.get(), &transcript, &env.crypto_components);

        let dkg_id = DkgId::NiDkgId(config.get().dkg_id());
        let nodes = config.receiver_ids();

        (transcript, dkg_id, nodes)
    }

    fn nodes_can_sign_in_epoch(
        nodes: &HashSet<NodeId>,
        dkg_id: DkgId,
        env: &NiDkgTestEnvironment,
    ) -> bool {
        let msg = message();

        for node in nodes {
            let sig = crypto_for(*node, &env.crypto_components).sign_threshold(&msg, dkg_id);
            if sig.is_err() {
                return false;
            }
        }

        true
    }

    fn nodes_cannot_sign_in_epoch_due_to_missing_secret_key(
        nodes: &HashSet<NodeId>,
        dkg_id: DkgId,
        env: &NiDkgTestEnvironment,
    ) -> bool {
        let msg = message();

        for node in nodes {
            let sig = crypto_for(*node, &env.crypto_components).sign_threshold(&msg, dkg_id);
            match sig {
                Ok(_) => return false,
                Err(CryptoError::SecretKeyNotFound {
                    algorithm: _,
                    key_id: _,
                }) => {}
                Err(e) => {
                    panic!("Unexpected error {}", e);
                }
            }
        }

        true
    }

    fn nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
        nodes: &HashSet<NodeId>,
        dkg_id: DkgId,
        env: &NiDkgTestEnvironment,
    ) -> bool {
        let msg = message();

        for node in nodes {
            let sig = crypto_for(*node, &env.crypto_components).sign_threshold(&msg, dkg_id);
            match sig {
                Ok(_) => return false,
                Err(CryptoError::ThresholdSigDataNotFound {
                    dkg_id: missing_dkg_id,
                }) => {
                    assert_eq!(dkg_id, missing_dkg_id);
                }
                Err(e) => {
                    panic!("Unexpected error {}", e);
                }
            }
        }

        true
    }

    fn retain_only_active_keys_for_transcripts(
        transcripts: &[NiDkgTranscript],
        env: &mut NiDkgTestEnvironment,
    ) {
        let mut retained = HashSet::new();
        for t in transcripts {
            retained.insert(t.clone());
        }

        for c in env.crypto_components.values_mut() {
            c.retain_only_active_keys(retained.clone()).unwrap();
        }
    }

    fn run_ni_dkg_and_create_receiver_transcripts(
        ni_dkg_config: &NiDkgConfig,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, NiDkgTranscript> {
        let dealings = create_dealings(ni_dkg_config, crypto_components);
        create_receiver_transcripts(ni_dkg_config, &dealings, crypto_components)
    }

    fn create_receiver_transcripts(
        ni_dkg_config: &NiDkgConfig,
        dealings: &BTreeMap<NodeId, NiDkgDealing>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, NiDkgTranscript> {
        ni_dkg_config
            .receivers()
            .get()
            .iter()
            .map(|node| {
                let transcript = crypto_for(*node, crypto_components)
                    .create_transcript(ni_dkg_config, dealings)
                    .unwrap_or_else(|error| {
                        panic!("failed to create transcript for {:?}: {:?}", node, error)
                    });
                (*node, transcript)
            })
            .collect()
    }
}
