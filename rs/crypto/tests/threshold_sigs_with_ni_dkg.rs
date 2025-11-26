use assert_matches::assert_matches;
use ic_crypto_temp_crypto::CryptoComponentRng;
use ic_crypto_temp_crypto::TempCryptoComponentGeneric;
use ic_crypto_test_utils::crypto_for;
use ic_crypto_test_utils_ni_dkg::{
    NiDkgTestEnvironment, RandomNiDkgConfig, create_dealings,
    run_ni_dkg_and_create_single_transcript,
};
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_interfaces::crypto::{
    LoadTranscriptResult, NiDkgAlgorithm, ThresholdSigVerifier, ThresholdSigner,
};
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTranscript};
use ic_types::crypto::{
    CombinedThresholdSigOf, CryptoError, Signable, SignableMock, ThresholdSigShareOf,
};
use ic_types::{NodeId, NumberOfNodes, RegistryVersion};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryFrom;

const REG_V1: RegistryVersion = RegistryVersion::new(1);
const ONE_NODE: NumberOfNodes = NumberOfNodes::new(1);

#[test]
// Test uses a random NI-DKG config.
// A random receiver is chosen to be both combiner and verifier.
fn should_threshold_sign_if_sufficient_shares() {
    let rng = &mut reproducible_rng();
    let subnet_size = rng.random_range(1..7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size, rng);

    run_ni_dkg_and_load_transcript_for_receivers(&config, &crypto_components);

    let msg = message();
    let random_combiner = random_node_in(config.receivers().get(), rng);
    let combined_sig = threshold_sign_and_combine(
        SignersAndCombiner {
            signers: n_random_nodes_in(config.receivers().get(), config.threshold().get(), rng),
            combiner: random_combiner,
        },
        &msg,
        dkg_id.clone(),
        &crypto_components,
    );
    let random_verifier = random_node_in(config.receivers().get(), rng);
    let verify_combined_result = crypto_for(random_verifier, &crypto_components)
        .verify_threshold_sig_combined(&combined_sig, &msg, &dkg_id);

    assert_eq!(verify_combined_result, Ok(()));
}

#[test]
// Test uses a random NI-DKG config. A random receiver is chosen as verifier.
fn should_produce_valid_signature_shares() {
    let rng = &mut reproducible_rng();
    let subnet_size = rng.random_range(1..7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size, rng);

    run_ni_dkg_and_load_transcript_for_receivers(&config, &crypto_components);

    let msg = message();
    let sig_shares = sign_threshold_for_each(
        &config.receivers().get().iter().copied().collect::<Vec<_>>(),
        &msg,
        &dkg_id,
        &crypto_components,
    );

    let verifier = random_node_in(config.receivers().get(), rng);
    sig_shares.iter().for_each(|(signer, sig_share)| {
        assert_eq!(
            crypto_for(verifier, &crypto_components)
                .verify_threshold_sig_share(sig_share, &msg, &dkg_id, *signer),
            Ok(()),
            "node {:?} failed to verify threshold sig share of signer {:?}",
            verifier,
            *signer
        );
    });
}

#[test]
fn should_create_same_config_and_transcript_with_same_seed() {
    let generate_transcript = || {
        let rng = &mut ChaCha20Rng::from_seed([0; 32]);
        let subnet_size = rng.random_range(1..7);
        let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size, rng);
        let transcript = run_ni_dkg_and_create_single_transcript(&config, &crypto_components);
        (config, dkg_id, transcript)
    };
    assert_eq!(generate_transcript(), generate_transcript());
}

#[test]
fn should_load_transcript_and_validate_signature_shares_as_non_receiver_without_secret_key() {
    let rng = &mut reproducible_rng();
    let subnet_size = rng.random_range(1..7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size, rng);

    let transcript = run_ni_dkg_and_create_single_transcript(&config, &crypto_components);
    load_transcript_for_receivers_expecting_status(
        &config,
        &transcript,
        &crypto_components,
        Some(LoadTranscriptResult::SigningKeyAvailable),
    );

    let msg = message();
    let sig_shares = sign_threshold_for_each(
        &config.receivers().get().iter().copied().collect::<Vec<_>>(),
        &msg,
        &dkg_id,
        &crypto_components,
    );

    // Create another config with a single node that is not a receiver of the original transcript.
    let (_another_config, _another_dkg_id, another_crypto_components) =
        setup_with_random_ni_dkg_config(1, rng);
    // Load the original transcript with the node that is not a receiver and therefore does not
    // have the secret key.
    let (other_node_id, other_crypto_component) = another_crypto_components
        .first_key_value()
        .expect("should contain a crypto component");
    assert_matches!(
        other_crypto_component.load_transcript(&transcript),
        Ok(LoadTranscriptResult::NodeNotInCommittee)
    );

    // Verify the signature shares with the node that is not a receiver.
    sig_shares.iter().for_each(|(signer, sig_share)| {
        assert_eq!(
            other_crypto_component.verify_threshold_sig_share(sig_share, &msg, &dkg_id, *signer),
            Ok(()),
            "node {:?} failed to verify threshold sig share of signer {:?}",
            other_node_id,
            *signer
        );
    });
}

#[test]
fn should_successfully_reload_the_same_transcript() {
    let rng = &mut reproducible_rng();
    let subnet_size = rng.random_range(1..7);
    let (config, _dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size, rng);

    let transcript = run_ni_dkg_and_create_single_transcript(&config, &crypto_components);
    load_transcript_for_receivers_expecting_status(
        &config,
        &transcript,
        &crypto_components,
        Some(LoadTranscriptResult::SigningKeyAvailable),
    );

    // Try to reload the same transcript
    load_transcript_for_receivers_expecting_status(
        &config,
        &transcript,
        &crypto_components,
        Some(LoadTranscriptResult::SigningKeyAvailable),
    );
}

#[test]
// Test uses a random NI-DKG config. A random receiver is chosen as combiner.
fn should_fail_to_combine_insufficient_shares() {
    let rng = &mut reproducible_rng();
    // Need >=4 nodes to have >=2 shares to combine in a low-threshold config
    let subnet_size = rng.random_range(4..7);
    let (config, dkg_id, crypto_components) = setup_with_random_ni_dkg_config(subnet_size, rng);
    let num_of_shares_to_combine = config.threshold().get() - ONE_NODE;

    run_ni_dkg_and_load_transcript_for_receivers(&config, &crypto_components);

    let sig_shares = sign_threshold_for_each(
        &n_random_nodes_in(config.receivers().get(), num_of_shares_to_combine, rng),
        &message(),
        &dkg_id,
        &crypto_components,
    );
    let combination_result = crypto_for(
        random_node_in(config.receivers().get(), rng),
        &crypto_components,
    )
    .combine_threshold_sig_shares(sig_shares, &dkg_id);

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

fn setup_with_random_ni_dkg_config<R: Rng + CryptoRng>(
    subnet_size: usize,
    rng: &mut R,
) -> (
    NiDkgConfig,
    NiDkgId,
    BTreeMap<NodeId, TempCryptoComponentGeneric<ChaCha20Rng>>,
) {
    let config = RandomNiDkgConfig::builder()
        .subnet_size(subnet_size)
        .build(rng)
        .into_config();
    let dkg_id = config.dkg_id().clone();
    let crypto_components = NiDkgTestEnvironment::new_for_config(&config, rng).crypto_components;
    (config, dkg_id, crypto_components)
}

fn run_ni_dkg_and_load_transcript_for_receivers<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) {
    let transcript = run_ni_dkg_and_create_single_transcript(config, crypto_components);
    load_transcript_for_receivers_expecting_status(
        config,
        &transcript,
        crypto_components,
        Some(LoadTranscriptResult::SigningKeyAvailable),
    );
}

fn load_transcript_for_receivers<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) {
    load_transcript_for_receivers_expecting_status(config, transcript, crypto_components, None);
}

fn load_transcript_for_receivers_expecting_status<C: CryptoComponentRng>(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
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

fn threshold_sign_and_combine<H: Signable, C: CryptoComponentRng>(
    signers_and_combiner: SignersAndCombiner,
    msg: &H,
    dkg_id: NiDkgId,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) -> CombinedThresholdSigOf<H> {
    let sig_shares = sign_threshold_for_each(
        &signers_and_combiner.signers,
        msg,
        &dkg_id,
        crypto_components,
    );
    crypto_for(signers_and_combiner.combiner, crypto_components)
        .combine_threshold_sig_shares(sig_shares, &dkg_id)
        .expect("failed to combine signature shares")
}

fn sign_threshold_for_each<H: Signable, C: CryptoComponentRng>(
    signers: &[NodeId],
    msg: &H,
    dkg_id: &NiDkgId,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
) -> BTreeMap<NodeId, ThresholdSigShareOf<H>> {
    signers
        .iter()
        .map(|signer| {
            let sig_share = crypto_for(*signer, crypto_components)
                .sign_threshold(msg, dkg_id)
                .unwrap_or_else(|e| panic!("signing by node {signer:?} failed: {e}"));
            (*signer, sig_share)
        })
        .collect()
}

fn random_node_in<R: Rng + CryptoRng>(nodes: &BTreeSet<NodeId>, rng: &mut R) -> NodeId {
    *nodes.iter().choose(rng).expect("nodes empty")
}

fn n_random_nodes_in<R: Rng + CryptoRng>(
    nodes: &BTreeSet<NodeId>,
    n: NumberOfNodes,
    rng: &mut R,
) -> Vec<NodeId> {
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
    use ic_crypto_internal_types::NodeIndex;
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgDealing;

    #[test]
    fn should_produce_valid_dealings_for_all_dealers() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..7);
        let (config, _dkg_id, crypto_components) =
            setup_with_random_ni_dkg_config(subnet_size, rng);

        let dealings = create_dealings(&config, &crypto_components);
        let verifier = config.receivers().get().iter().next().unwrap();
        let verifier_crypto = crypto_for(*verifier, &crypto_components);

        for (dealer, dealing) in dealings {
            let verification_result = verifier_crypto.verify_dealing(&config, dealer, &dealing);
            assert_eq!(
                verification_result,
                Ok(()),
                "verification of dealing from dealer {dealer:?} failed for {verifier:?}"
            );
        }
    }

    #[test]
    fn should_produce_same_transcript_for_all_receivers() {
        let rng = &mut reproducible_rng();
        let subnet_size = rng.random_range(1..7);
        let (config, _dkg_id, crypto_components) =
            setup_with_random_ni_dkg_config(subnet_size, rng);

        let transcripts = run_ni_dkg_and_create_receiver_transcripts(&config, &crypto_components);

        let transcripts_set: HashSet<_> = transcripts.values().collect();
        assert_eq!(transcripts_set.len(), 1);
    }

    #[test]
    fn should_not_reshare_ni_dkg_without_loaded_transcript() {
        let rng = &mut reproducible_rng();
        let (initial_subnet_size, max_subnet_size) = (3, 10);

        // In practise, resharing is done only for high threshold configs
        let config = RandomNiDkgConfig::builder()
            .subnet_size(initial_subnet_size)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(REG_V1)
            .build(rng);
        let mut env = NiDkgTestEnvironment::new_for_config(config.get(), rng);
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        let reshare_config = RandomNiDkgConfig::reshare(transcript, -2..=2, max_subnet_size, rng);
        env.update_for_config(reshare_config.get(), rng);

        for dealer in reshare_config.get().dealers().get() {
            let result = crypto_for(*dealer, &env.crypto_components)
                .create_dealing(reshare_config.get())
                .unwrap_err();

            assert_matches!(
                result,
                DkgCreateDealingError::ThresholdSigningKeyNotInSecretKeyStore(_)
            );
        }
    }

    #[test]
    fn should_run_resharing_ni_dkg_over_multiple_epochs() {
        let rng = &mut reproducible_rng();
        let (initial_subnet_size, max_subnet_size, epochs) = (3, 10, 10);

        // In practise, resharing is done only for high threshold configs
        let mut config = RandomNiDkgConfig::builder()
            .subnet_size(initial_subnet_size)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(REG_V1)
            .build(rng);
        let mut env = NiDkgTestEnvironment::new_for_config(config.get(), rng);
        let mut transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        for _i in 1..=epochs {
            config = RandomNiDkgConfig::reshare(transcript, -2..=2, max_subnet_size, rng);
            env.update_for_config(config.get(), rng);
            transcript =
                run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);
        }
    }

    // Test that transcripts have the correct/minimal size, i.e., that they
    // contain exactly the minimal number of required dealings (i.e., the
    // collection threshold) and exactly as many ciphertexts as receivers.
    // This is tested for (1) a (non-reshared) high-threshold transcript, (2) a
    // reshared high-threshold transcript, and (3) a (non-reshared)
    // low-threshold transcript, because these are the cases relevant in
    // practice.
    #[test]
    fn should_produce_transcripts_with_correct_size() {
        let rng = &mut reproducible_rng();
        let (initial_subnet_size, max_subnet_size, epochs) = (3, 5, 1);

        // Test for high-threshold NI-DKG including resharing
        let mut config = RandomNiDkgConfig::builder()
            .subnet_size(initial_subnet_size)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(REG_V1)
            .build(rng);
        let mut env = NiDkgTestEnvironment::new_for_config(config.get(), rng);
        let mut transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        assert_eq!(
            number_of_dealings_in_transcript(&transcript) as NodeIndex,
            config.get().collection_threshold().get()
        );
        assert_transcript_ciphertexts_have_length(
            &transcript,
            config.get().receivers().get().len(),
        );

        for _i in 0..epochs {
            config = RandomNiDkgConfig::reshare(transcript, -2..=2, max_subnet_size, rng);
            env.update_for_config(config.get(), rng);
            transcript =
                run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

            assert_eq!(
                number_of_dealings_in_transcript(&transcript) as NodeIndex,
                config.get().collection_threshold().get()
            );
            assert_transcript_ciphertexts_have_length(
                &transcript,
                config.get().receivers().get().len(),
            );
        }

        // Test for low-threshold NI-DKG without resharing
        let config = RandomNiDkgConfig::builder()
            .subnet_size(initial_subnet_size)
            .dkg_tag(NiDkgTag::LowThreshold)
            .registry_version(REG_V1)
            .build(rng);
        let env = NiDkgTestEnvironment::new_for_config(config.get(), rng);
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        assert_eq!(
            number_of_dealings_in_transcript(&transcript) as NodeIndex,
            config.get().collection_threshold().get()
        );
        assert_transcript_ciphertexts_have_length(
            &transcript,
            config.get().receivers().get().len(),
        );
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
        let rng = &mut reproducible_rng();
        let max_subnet_size = 10;
        let mut env = NiDkgTestEnvironment::new();
        let registry_version = RegistryVersion::from(rng.random_range(1..u32::MAX - 10_000) as u64);

        // epoch 0
        let config0 = RandomNiDkgConfig::builder()
            .subnet_size(3)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(registry_version)
            .build(rng);
        let (transcript0, dkg_id0, epoch0_nodes) =
            run_dkg_and_load_transcripts(&config0, &mut env, rng);

        // epoch 1
        let config1 = RandomNiDkgConfig::reshare(transcript0.clone(), 1..=2, max_subnet_size, rng);
        let (transcript1, dkg_id1, epoch1_nodes) =
            run_dkg_and_load_transcripts(&config1, &mut env, rng);
        let new_in_epoch1: HashSet<_> = epoch1_nodes.difference(&epoch0_nodes).cloned().collect();

        // epoch2
        let config2 = RandomNiDkgConfig::reshare(transcript1.clone(), 1..=2, max_subnet_size, rng);
        let (transcript2, dkg_id2, epoch2_nodes) =
            run_dkg_and_load_transcripts(&config2, &mut env, rng);
        let new_in_epoch2: HashSet<_> = epoch2_nodes.difference(&epoch1_nodes).cloned().collect();

        // A low threshold transcript just to bypass a check in retain_only_active_keys
        let config3 = config2.new_with_inverted_threshold(rng);
        let (transcript3, _dkg_id3, epoch3_nodes) =
            run_dkg_and_load_transcripts(&config3, &mut env, rng);

        // Test that the subnets increased in size and without removing any nodes
        assert!(!new_in_epoch1.is_empty());
        assert!(!new_in_epoch2.is_empty());
        assert_eq!(epoch0_nodes.difference(&epoch1_nodes).count(), 0);
        assert_eq!(epoch1_nodes.difference(&epoch2_nodes).count(), 0);

        // Test that all nodes can sign in their own epoch
        assert!(nodes_can_sign_in_epoch(&epoch0_nodes, &dkg_id0, &env));
        assert!(nodes_can_sign_in_epoch(&epoch1_nodes, &dkg_id1, &env));
        assert!(nodes_can_sign_in_epoch(&epoch2_nodes, &dkg_id2, &env));

        // Test that nodes added later cannot sign in old epochs
        assert!(
            nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
                &new_in_epoch1,
                &dkg_id0,
                &env
            )
        );
        assert!(
            nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
                &new_in_epoch2,
                &dkg_id0,
                &env
            )
        );
        assert!(
            nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
                &new_in_epoch2,
                &dkg_id1,
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
            &dkg_id0,
            &env
        ));

        // But the newer epochs can still be used by all nodes
        assert!(nodes_can_sign_in_epoch(&epoch1_nodes, &dkg_id1, &env));
        assert!(nodes_can_sign_in_epoch(&epoch2_nodes, &dkg_id2, &env));

        // And all nodes can still load the old transcript (but not decrypt it)
        load_transcript_for_receivers(config3.get(), &transcript0, &env.crypto_components);

        // Even after the transcript is loaded again, key is not available
        assert!(nodes_cannot_sign_in_epoch_due_to_missing_secret_key(
            &epoch3_nodes,
            &dkg_id0,
            &env
        ));

        // Further DKGs can be run after removing an earlier key
        let config4 = RandomNiDkgConfig::reshare(transcript3, 1..=2, max_subnet_size, rng);
        let (_transcript4, dkg_id4, epoch4_nodes) =
            run_dkg_and_load_transcripts(&config4, &mut env, rng);
        assert!(nodes_can_sign_in_epoch(&epoch4_nodes, &dkg_id4, &env));
    }

    #[test]
    fn should_not_reshare_old_transcript_after_pruning_old_keys() {
        let rng = &mut reproducible_rng();

        let registry_version = RegistryVersion::from(rng.random_range(1..u32::MAX - 10_000) as u64);

        let mut env = NiDkgTestEnvironment::new();

        let max_subnet_size = 10;

        // epoch 0
        let config0 = RandomNiDkgConfig::builder()
            .subnet_size(3)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(registry_version)
            .build(rng);
        let (transcript0, _dkg_id0, _epoch0_nodes) =
            run_dkg_and_load_transcripts(&config0, &mut env, rng);

        // epoch 1
        let config1 = RandomNiDkgConfig::reshare(transcript0.clone(), 1..=2, max_subnet_size, rng);
        let (transcript1, _dkg_id1, _epoch1_nodes) =
            run_dkg_and_load_transcripts(&config1, &mut env, rng);

        // low threshold
        let config_low = config1.new_with_inverted_threshold(rng);
        let (transcript_low, _dkg_id_low, _epochlow_nodes) =
            run_dkg_and_load_transcripts(&config_low, &mut env, rng);

        retain_only_active_keys_for_transcripts(&[transcript1, transcript_low], &mut env);

        // Now attempt to reshare off of transcript0, should fail in create_dealing:
        let reshare_config = RandomNiDkgConfig::reshare(transcript0, 1..=2, max_subnet_size, rng);
        // Update the environment with the reshare config, which creates crypto components for the
        // new nodes, and registers their NI-DKG dealing encryption keys in the registry.
        env.update_for_config(reshare_config.get(), rng);
        env.registry.reload();

        for dealer in reshare_config.get().dealers().get() {
            let result =
                crypto_for(*dealer, &env.crypto_components).create_dealing(reshare_config.get());

            assert_matches!(
                result,
                Err(DkgCreateDealingError::ThresholdSigningKeyNotInSecretKeyStore(_))
            );
        }
    }

    #[test]
    fn should_not_load_old_transcript_after_pruning_old_keys() {
        let rng = &mut reproducible_rng();
        let registry_version = RegistryVersion::from(rng.random_range(1..u32::MAX - 10_000) as u64);
        let mut env = NiDkgTestEnvironment::new();
        let subnet_size = rng.random_range(4..7);

        // Epoch 0
        let config0 = RandomNiDkgConfig::builder()
            .subnet_size(subnet_size)
            .dkg_tag(NiDkgTag::HighThreshold)
            .registry_version(registry_version)
            .build(rng);
        let (transcript0, _dkg_id0, _epoch0_nodes) =
            run_dkg_and_load_transcripts(&config0, &mut env, rng);

        // Epoch 1
        // Create a new config based on the initial transcript (same dealers and receivers), but
        // no resharing.
        let config1 = RandomNiDkgConfig::new_for_same_subnet_with_incremented_registry_version(
            transcript0.clone(),
        );

        // Add a dummy value into the registry to increment its version.
        env.registry_data
            .add::<PublicKey>("dummy_key", config1.get().registry_version(), None)
            .expect("updating registry should succeed");
        env.registry.reload();
        let (transcript1, _dkg_id1, _epoch1_nodes) =
            run_dkg_and_load_transcripts(&config1, &mut env, rng);

        // low threshold
        let config_low = config1.new_with_inverted_threshold(rng);
        let (transcript_low, _dkg_id_low, _epochlow_nodes) =
            run_dkg_and_load_transcripts(&config_low, &mut env, rng);

        // Retain only keys from the most recent transcripts. Since the registry was updated after
        // the creation of the initial transcript, and the version was incremented, the old keys
        // will be pruned.
        retain_only_active_keys_for_transcripts(&[transcript1, transcript_low], &mut env);

        // Now attempt to load transcript0, which fails since the secret keys were pruned.
        for node_id in config1.receiver_ids() {
            let result = crypto_for(node_id, &env.crypto_components).load_transcript(&transcript0);
            assert_eq!(
                result,
                Ok(LoadTranscriptResult::SigningKeyUnavailableDueToDiscard)
            );
        }
    }

    // This test marked #[ignore] as it is quite expensive to run and
    // it is not necessary to recheck the transcript sizes on every CI build.
    #[test]
    #[ignore]
    fn should_have_expected_size_for_nidkg_transcript_serializations() {
        fn protobuf_encoding_of_initial_dkg_transcript_record(
            rng: &mut ReproducibleRng,
            subnet_size: usize,
            dealer_count: usize,
            threshold: NiDkgTag,
        ) -> usize {
            use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
            use prost::Message;

            let config = RandomNiDkgConfig::builder()
                .dealer_count(dealer_count)
                .subnet_size(subnet_size)
                .max_corrupt_dealers((dealer_count - 1) / 3)
                .dkg_tag(threshold)
                .registry_version(REG_V1)
                .build(rng);

            let env = NiDkgTestEnvironment::new_for_config(config.get(), rng);
            let transcript =
                run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

            let record = InitialNiDkgTranscriptRecord::from(transcript);

            let mut record_pb = vec![];
            record
                .encode(&mut record_pb)
                .expect("Protobuf encoding failed");
            record_pb.len()
        }

        // (dealer_count, subnet_size, expected_transcript_size)
        //
        // Expected sizes are computed using cost_estimator.py
        let config_and_expected_size: [(usize, usize, usize); 5] = [
            (13, 13, 66144),
            (28, 28, 247584),
            (40, 40, 475680),
            (40, 13, 183648),
            (40, 28, 345888),
        ];

        let allowed_overhead = 1.05;

        let rng = &mut reproducible_rng();

        for (dealer_count, subnet_size, expected_size) in config_and_expected_size {
            for threshold in [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold] {
                let record_len = protobuf_encoding_of_initial_dkg_transcript_record(
                    rng,
                    subnet_size,
                    dealer_count,
                    threshold.clone(),
                );
                let overhead = (record_len as f64) / (expected_size as f64);

                println!(
                    "Subnet size {subnet_size} with {dealer_count} dealers, threshold {threshold:?} protobuf transcript size {record_len} (overhead {overhead:.3})",
                );

                assert!(
                    record_len >= expected_size,
                    "Record is smaller than theoretical minimum"
                );

                assert!(
                    overhead < allowed_overhead,
                    "Record exceeds allowed overhead"
                );
            }
        }
    }

    fn run_dkg_and_load_transcripts<R: Rng + CryptoRng>(
        config: &RandomNiDkgConfig,
        env: &mut NiDkgTestEnvironment,
        rng: &mut R,
    ) -> (NiDkgTranscript, NiDkgId, HashSet<NodeId>) {
        env.update_for_config(config.get(), rng);
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        load_transcript_for_receivers(config.get(), &transcript, &env.crypto_components);

        let dkg_id = config.get().dkg_id().clone();
        let nodes = config.receiver_ids();

        (transcript, dkg_id, nodes)
    }

    fn nodes_can_sign_in_epoch(
        nodes: &HashSet<NodeId>,
        dkg_id: &NiDkgId,
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
        dkg_id: &NiDkgId,
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
                    panic!("Unexpected error {e}");
                }
            }
        }

        true
    }

    fn nodes_cannot_sign_in_epoch_due_to_missing_threshold_sig_data(
        nodes: &HashSet<NodeId>,
        dkg_id: &NiDkgId,
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
                    assert_eq!(dkg_id, &missing_dkg_id);
                }
                Err(e) => {
                    panic!("Unexpected error {e}");
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

    fn run_ni_dkg_and_create_receiver_transcripts<C: CryptoComponentRng>(
        ni_dkg_config: &NiDkgConfig,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    ) -> BTreeMap<NodeId, NiDkgTranscript> {
        let dealings = create_dealings(ni_dkg_config, crypto_components);
        create_receiver_transcripts(ni_dkg_config, &dealings, crypto_components)
    }

    fn create_receiver_transcripts<C: CryptoComponentRng>(
        ni_dkg_config: &NiDkgConfig,
        dealings: &BTreeMap<NodeId, NiDkgDealing>,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponentGeneric<C>>,
    ) -> BTreeMap<NodeId, NiDkgTranscript> {
        ni_dkg_config
            .receivers()
            .get()
            .iter()
            .map(|node| {
                let transcript = crypto_for(*node, crypto_components)
                    .create_transcript(ni_dkg_config, dealings)
                    .unwrap_or_else(|error| {
                        panic!("failed to create transcript for {node:?}: {error:?}")
                    });
                (*node, transcript)
            })
            .collect()
    }

    fn number_of_dealings_in_transcript(transcript: &NiDkgTranscript) -> usize {
        match &transcript.internal_csp_transcript {
            CspNiDkgTranscript::Groth20_Bls12_381(t) => t.receiver_data.len(),
        }
    }

    fn assert_transcript_ciphertexts_have_length(transcript: &NiDkgTranscript, length: usize) {
        match &transcript.internal_csp_transcript {
            CspNiDkgTranscript::Groth20_Bls12_381(transcript) => {
                for ciphertext in transcript.receiver_data.values() {
                    assert_eq!(ciphertext.len(), length);
                }
            }
        }
    }
}
