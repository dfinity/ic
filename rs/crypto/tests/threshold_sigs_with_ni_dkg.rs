#![allow(clippy::unwrap_used)]
use ic_crypto::utils::TempCryptoComponent;
use ic_interfaces::crypto::{
    NiDkgAlgorithm, Signable, SignableMock, ThresholdSigVerifier, ThresholdSigner,
};
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::make_crypto_node_key;
use ic_test_utilities::crypto::crypto_for;
use ic_types::consensus::get_faults_tolerated;
use ic_types::crypto::threshold_sig::ni_dkg::config::{NiDkgConfig, NiDkgConfigData};
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::{
    DkgId, NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
};
use ic_types::crypto::{CombinedThresholdSigOf, CryptoError, KeyPurpose, ThresholdSigShareOf};
use ic_types::{Height, NodeId};
use ic_types::{NumberOfNodes, PrincipalId, RegistryVersion};
use non_interactive_distributed_key_generation::run_ni_dkg_and_create_single_transcript;
use rand::prelude::*;
use random_ni_dkg_config::RandomNiDkgConfig;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::sync::Arc;
use test_environment::TestEnvironment;

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
    let random_combiner = random_node_in(&config.receivers().get());
    let combined_sig = threshold_sign_and_combine(
        SignersAndCombiner {
            signers: n_random_nodes_in(&config.receivers().get(), config.threshold().get()),
            combiner: random_combiner,
        },
        &msg,
        dkg_id,
        &crypto_components,
    );
    let random_verifier = random_node_in(&config.receivers().get());
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
        &Vec::from_iter(config.receivers().get().iter().copied()),
        &msg,
        dkg_id,
        &crypto_components,
    );

    let verifier = random_node_in(&config.receivers().get());
    sig_shares.iter().for_each(|(signer, sig_share)| {
        assert!(
            crypto_for(verifier, &crypto_components)
                .verify_threshold_sig_share(&sig_share, &msg, dkg_id, *signer)
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
        &n_random_nodes_in(&config.receivers().get(), num_of_shares_to_combine),
        &message(),
        dkg_id,
        &crypto_components,
    );
    let combination_result = crypto_for(
        random_node_in(&config.receivers().get()),
        &crypto_components,
    )
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
    let config = RandomNiDkgConfig::new(subnet_size).into_config();
    let dkg_id = DkgId::NiDkgId(config.dkg_id());
    let crypto_components = TestEnvironment::new_for_config(&config).crypto_components;
    (config, dkg_id, crypto_components)
}

fn run_ni_dkg_and_load_transcript_for_receivers(
    config: &NiDkgConfig,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
    let transcript = run_ni_dkg_and_create_single_transcript(&config, &crypto_components);
    load_transcript_for_receivers(config, &transcript, &crypto_components);
}

fn load_transcript_for_receivers(
    config: &NiDkgConfig,
    transcript: &NiDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
    config
        .receivers()
        .get()
        .iter()
        .copied()
        .for_each(|node_id| load_transcript(transcript, node_id, crypto_components));
}

fn load_transcript(
    transcript: &NiDkgTranscript,
    node_id: NodeId,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) {
    if let Err(e) = crypto_for(node_id, crypto_components).load_transcript(&transcript) {
        panic!(
            "failed to load transcript {} for node {}: {}",
            transcript, node_id, e
        );
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
        &crypto_components,
    );
    crypto_for(signers_and_combiner.combiner, &crypto_components)
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
            let sig_share = crypto_for(*signer, &crypto_components)
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
    fn should_run_resharing_ni_dkg_over_multiple_epochs() {
        let (initial_subnet_size, max_subnet_size, epochs) = (3, 10, 10);

        // In practise, resharing is done only for high threshold configs
        let mut config = RandomNiDkgConfig::new_with_tag_and_registry_version(
            initial_subnet_size,
            NiDkgTag::HighThreshold,
            REG_V1,
        );
        let mut env = TestEnvironment::new_for_config(&config.get());
        let mut transcript =
            run_ni_dkg_and_create_single_transcript(&config.get(), &env.crypto_components);

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
        let mut env = TestEnvironment::new();
        let rng = &mut thread_rng();
        let registry_version = RegistryVersion::from(rng.gen_range(1, u32::MAX - 10_000) as u64);

        // epoch 0
        let config0 = RandomNiDkgConfig::new_with_tag_and_registry_version(
            3,
            NiDkgTag::HighThreshold,
            registry_version,
        );
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
        load_transcript_for_receivers(&config3.get(), &transcript0, &env.crypto_components);

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

        let mut env = TestEnvironment::new();

        let max_subnet_size = 10;

        // epoch 0
        let config0 = RandomNiDkgConfig::new_with_tag_and_registry_version(
            3,
            NiDkgTag::HighThreshold,
            registry_version,
        );
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
        env: &mut TestEnvironment,
    ) -> (NiDkgTranscript, DkgId, HashSet<NodeId>) {
        env.update_for_config(config.get());
        let transcript =
            run_ni_dkg_and_create_single_transcript(config.get(), &env.crypto_components);

        load_transcript_for_receivers(&config.get(), &transcript, &env.crypto_components);

        let dkg_id = DkgId::NiDkgId(config.get().dkg_id());
        let nodes = config.receiver_ids();

        (transcript, dkg_id, nodes)
    }

    fn nodes_can_sign_in_epoch(
        nodes: &HashSet<NodeId>,
        dkg_id: DkgId,
        env: &TestEnvironment,
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
        env: &TestEnvironment,
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
        env: &TestEnvironment,
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
        env: &mut TestEnvironment,
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

    pub fn run_ni_dkg_and_create_single_transcript(
        ni_dkg_config: &NiDkgConfig,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> NiDkgTranscript {
        let dealings = create_dealings(&ni_dkg_config, crypto_components);
        let transcript_creator = ni_dkg_config.dealers().get().iter().next().unwrap();
        crypto_for(*transcript_creator, &crypto_components)
            .create_transcript(ni_dkg_config, &dealings)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to create transcript for {:?}: {:?}",
                    transcript_creator, error
                )
            })
    }

    fn create_dealings(
        ni_dkg_config: &NiDkgConfig,
        crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    ) -> BTreeMap<NodeId, NiDkgDealing> {
        ni_dkg_config
            .dealers()
            .get()
            .iter()
            .map(|node| {
                let dealing = crypto_for(*node, &crypto_components)
                    .create_dealing(ni_dkg_config)
                    .unwrap_or_else(|error| {
                        panic!("failed to create dealing for {:?}: {:?}", node, error)
                    });
                (*node, dealing)
            })
            .collect()
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
                let transcript = crypto_for(*node, &crypto_components)
                    .create_transcript(ni_dkg_config, dealings)
                    .unwrap_or_else(|error| {
                        panic!("failed to create transcript for {:?}: {:?}", node, error)
                    });
                (*node, transcript)
            })
            .collect()
    }
}

mod test_environment {
    use super::*;

    pub struct TestEnvironment {
        pub crypto_components: BTreeMap<NodeId, TempCryptoComponent>,
        pub registry_data: Arc<ProtoRegistryDataProvider>,
        pub registry: Arc<FakeRegistryClient>,
    }
    impl TestEnvironment {
        /// Creates a new empty test environment.
        pub fn new() -> Self {
            let registry_data = Arc::new(ProtoRegistryDataProvider::new());
            let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
            Self {
                crypto_components: BTreeMap::new(),
                registry_data,
                registry,
            }
        }

        /// Creates a new empty test environment.
        pub fn new_for_config(config: &NiDkgConfig) -> Self {
            let mut env = Self::new();
            env.update_for_config(config);
            env
        }

        /// Ensures that all node IDs appearing in the given `ni_dkg_config`
        /// have (1) a crypto component and (2) a DKG dealing encryption
        /// public key in the registry. If registry entries need to be
        /// added, they are added for the config's registry version.
        ///
        /// Additionally, for all node IDs that no longer appear in the
        /// `ni_dkg_config`, the crypto components are removed.
        pub fn update_for_config(&mut self, ni_dkg_config: &NiDkgConfig) {
            let new_node_ids = self.added_nodes(ni_dkg_config);
            for node_id in new_node_ids {
                self.add_crypto_component_and_registry_entry(ni_dkg_config, node_id);
            }
            self.registry.update_to_latest_version();
            self.cleanup_unused_nodes(ni_dkg_config);
        }

        /// Determines the config's node IDs that are not in the environment
        fn added_nodes(&self, ni_dkg_config: &NiDkgConfig) -> Vec<NodeId> {
            dealers_and_receivers(ni_dkg_config)
                .into_iter()
                .filter(|node_id| !self.crypto_components.contains_key(node_id))
                .collect()
        }

        /// Adds a crypto component and a registry entry for a node
        fn add_crypto_component_and_registry_entry(
            &mut self,
            ni_dkg_config: &NiDkgConfig,
            node_id: NodeId,
        ) {
            // Insert TempCryptoComponent
            let registry = Arc::clone(&self.registry) as Arc<_>;
            let (temp_crypto, dkg_dealing_encryption_pubkey) =
                TempCryptoComponent::new_with_ni_dkg_dealing_encryption_key_generation(
                    registry, node_id,
                );
            self.crypto_components.insert(node_id, temp_crypto);

            // Insert DKG dealing encryption public key into registry
            self.registry_data
                .add(
                    &make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption),
                    ni_dkg_config.registry_version(),
                    Some(dkg_dealing_encryption_pubkey),
                )
                .expect("failed to add DKG dealing encryption key to registry");
        }

        /// Cleans up nodes whose IDs are no longer in use
        fn cleanup_unused_nodes(&mut self, ni_dkg_config: &NiDkgConfig) {
            let dealers_and_receivers = dealers_and_receivers(ni_dkg_config);
            let unused_node_ids: Vec<NodeId> = self
                .crypto_components
                .keys()
                .copied()
                .filter(|node_id| !dealers_and_receivers.contains(node_id))
                .collect();
            for node_id in unused_node_ids {
                self.crypto_components.remove(&node_id);
            }
        }
    }

    fn dealers_and_receivers(config: &NiDkgConfig) -> Vec<NodeId> {
        let dealer_set: BTreeSet<_> = config.dealers().get().iter().copied().collect();
        let receiver_set: BTreeSet<_> = config.receivers().get().iter().copied().collect();
        dealer_set.union(&receiver_set).copied().collect()
    }
}

mod random_ni_dkg_config {
    use super::*;
    use ic_crypto_internal_types::NodeIndex;
    use ic_test_utilities::types::ids::subnet_test_id;
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTargetId;
    use std::cmp;

    const ONE_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct RandomNiDkgConfig(NiDkgConfig);

    impl RandomNiDkgConfig {
        pub fn get(&self) -> &NiDkgConfig {
            &self.0
        }

        pub fn into_config(self) -> NiDkgConfig {
            self.0
        }

        /// Creates a random NI-DKG config satisfying all invariants.
        pub fn new(subnet_size: usize) -> Self {
            let rng = &mut thread_rng();
            let dkg_tag = match rng.gen::<bool>() {
                true => NiDkgTag::LowThreshold,
                false => NiDkgTag::HighThreshold,
            };
            // The registry version is used as DKG epoch and an epoch is u32. Because of
            // this, the maximum registry version we choose is u32::MAX, decreased by a
            // margin that allows for increasing it again sufficiently during tests.
            let registry_version = RegistryVersion::new(rng.gen_range(1, u32::MAX - 10_000) as u64);
            Self::new_with_tag_and_registry_version(subnet_size, dkg_tag, registry_version)
        }

        /// Creates a random NI-DKG config for `dkg_tag` satisfying all
        /// invariants.
        pub fn new_with_tag_and_registry_version(
            subnet_size: usize,
            dkg_tag: NiDkgTag,
            registry_version: RegistryVersion,
        ) -> Self {
            assert!(subnet_size > 0, "subnet must not be empty");
            let rng = &mut thread_rng();

            let receivers = random_node_ids(subnet_size);
            let threshold = dkg_tag.threshold_for_subnet_of_size(subnet_size);
            let dealers = {
                let required_dealer_count = threshold;
                let dealer_surplus = rng.gen_range(0, 3);
                // Exclude receivers from being dealers because initial DKG is done by NNS for
                // another (remote) subnet, which means the dealers and receivers are disjoint.
                random_node_ids_excluding(&receivers, required_dealer_count + dealer_surplus)
            };

            let config_data = NiDkgConfigData {
                dkg_id: NiDkgId {
                    start_block_height: Height::new(random()),
                    dealer_subnet: subnet_test_id(random()),
                    dkg_tag,
                    // The first DKG is always done by NNS for another (remote) subnet
                    target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new(random())),
                },
                max_corrupt_dealers: number_of_nodes_from_usize(rng.gen_range(0, dealers.len())),
                dealers,
                max_corrupt_receivers: {
                    number_of_nodes_from_usize(get_faults_tolerated(subnet_size))
                },
                receivers,
                threshold: number_of_nodes_from_usize(threshold),
                registry_version,
                resharing_transcript: None,
            };
            Self(NiDkgConfig::new(config_data).expect("invariant violated"))
        }

        /// Create a random NI-DKG config that is a peer for another
        /// configuration with the opposite threshold requirements so it
        /// is possible to perform tests where a single subnet has both
        /// high and low threshold transcripts
        pub fn new_with_inverted_threshold(&self) -> Self {
            let rng = &mut thread_rng();

            let dkg_tag = match self.0.dkg_id().dkg_tag {
                NiDkgTag::LowThreshold => NiDkgTag::HighThreshold,
                NiDkgTag::HighThreshold => NiDkgTag::LowThreshold,
            };

            let subnet_size = self.0.receivers().get().len();
            let receivers = self.0.receivers().get().clone();
            let threshold = dkg_tag.threshold_for_subnet_of_size(subnet_size);
            let dealers = {
                let required_dealer_count = threshold;
                let dealer_surplus = rng.gen_range(0, 3);
                // Exclude receivers from being dealers because initial DKG is done by NNS for
                // another (remote) subnet, which means the dealers and receivers are disjoint.
                random_node_ids_excluding(&receivers, required_dealer_count + dealer_surplus)
            };

            let config_data = NiDkgConfigData {
                dkg_id: NiDkgId {
                    start_block_height: self.0.dkg_id().start_block_height,
                    dealer_subnet: self.0.dkg_id().dealer_subnet,
                    dkg_tag,
                    target_subnet: self.0.dkg_id().target_subnet,
                },
                max_corrupt_dealers: number_of_nodes_from_usize(rng.gen_range(0, dealers.len())),
                dealers,
                max_corrupt_receivers: {
                    number_of_nodes_from_usize(get_faults_tolerated(subnet_size))
                },
                receivers,
                threshold: number_of_nodes_from_usize(threshold),
                registry_version: self.0.registry_version() + ONE_REGISTRY_VERSION,
                resharing_transcript: None,
            };

            Self(NiDkgConfig::new(config_data).expect("invariant violated"))
        }

        /// Reshares the config into a new random NI-DKG config with the given
        /// `transcript`.
        ///
        /// The subnet size is changed dynamically based on subnet_size_change
        /// with minimum of 1 and maximum of `max_subnet_size`. If new nodes are
        /// added as part of the resizing, the registry version is increased by
        /// 1.
        pub fn reshare(
            transcript: NiDkgTranscript,
            subnet_size_change: std::ops::RangeInclusive<isize>,
            max_subnet_size: usize,
        ) -> Self {
            let rng = &mut thread_rng();

            // let max_corrupt_dealers = self.0.max_corrupt_receivers();
            let max_corrupt_dealers =
                number_of_nodes_from_usize(get_faults_tolerated(transcript.committee.get().len()));
            let dealers = {
                let lower_bound_u32 = cmp::max(
                    max_corrupt_dealers.get() + 1, // Ensures #dealers > max_corrupt_dealers
                    transcript.threshold.get().get(), // Ensures #dealers >= resharing threshold
                );
                let lower_bound = usize::try_from(lower_bound_u32).expect("conversion error");
                let dealer_count = rng.gen_range(lower_bound, transcript.committee.get().len() + 1);
                let dealers_vec = transcript
                    .committee
                    .get()
                    .iter()
                    .copied()
                    .choose_multiple(rng, dealer_count);
                dealers_vec.into_iter().collect()
            };
            let new_subnet_size = {
                let transcript_committee_len_isize =
                    isize::try_from(transcript.committee.get().len()).expect("conversion error");

                let change_in_subnet_size =
                    rng.gen_range(subnet_size_change.start(), subnet_size_change.end() + 1);

                let new_subnet_size_isize =
                    cmp::max(1, transcript_committee_len_isize + change_in_subnet_size);
                let new_subnet_size =
                    usize::try_from(new_subnet_size_isize).expect("conversion error");
                cmp::min(new_subnet_size, max_subnet_size)
            };
            let mut registry_version = transcript.registry_version;
            let receivers = {
                if new_subnet_size <= transcript.committee.get().len() {
                    // Keep as many receivers as needed from the existing ones
                    let receivers_vec = transcript
                        .committee
                        .get()
                        .iter()
                        .copied()
                        .choose_multiple(rng, new_subnet_size);
                    receivers_vec.into_iter().collect()
                } else {
                    // Keep all existing receivers and add new ones as needed
                    let committee = transcript.committee.get();
                    let additional_receivers_count = new_subnet_size - committee.len();
                    let additional_receivers =
                        random_node_ids_excluding(committee, additional_receivers_count);
                    let receivers = committee.union(&additional_receivers).copied().collect();
                    // Adding of nodes means that new nodes will be added to the registry
                    // which in turn means that the registry version needs to be bumped up
                    registry_version += ONE_REGISTRY_VERSION;
                    receivers
                }
            };
            let dkg_tag = transcript.dkg_id.dkg_tag;
            let config_data = NiDkgConfigData {
                dkg_id: NiDkgId {
                    start_block_height: Height::new(transcript.dkg_id.start_block_height.get() + 1),
                    // Theoretically the subnet ID should change on the _first_ DKG in the new
                    // subnet, but this is not important: relevant is only that
                    // the NiDkgId is different, which is already achieved by
                    // increasing the start_block_height.
                    dealer_subnet: transcript.dkg_id.dealer_subnet,
                    dkg_tag,
                    target_subnet: NiDkgTargetSubnet::Local,
                },
                max_corrupt_dealers,
                dealers,
                max_corrupt_receivers: {
                    number_of_nodes_from_usize(get_faults_tolerated(new_subnet_size))
                },
                receivers,
                threshold: number_of_nodes_from_usize(
                    dkg_tag.threshold_for_subnet_of_size(new_subnet_size),
                ),
                registry_version,
                resharing_transcript: Some(transcript),
            };
            Self(NiDkgConfig::new(config_data).expect("invariant violated"))
        }

        pub fn receiver_ids(&self) -> HashSet<NodeId> {
            self.get().receivers().get().iter().cloned().collect()
        }
    }

    fn random_node_ids(n: usize) -> BTreeSet<NodeId> {
        let rng = &mut thread_rng();
        let mut node_ids = BTreeSet::new();
        while node_ids.len() < n {
            node_ids.insert(node_id(rng.gen()));
        }
        node_ids
    }

    fn random_node_ids_excluding(exclusions: &BTreeSet<NodeId>, n: usize) -> BTreeSet<NodeId> {
        let rng = &mut thread_rng();
        let mut node_ids = BTreeSet::new();
        while node_ids.len() < n {
            let candidate = node_id(rng.gen());
            if !exclusions.contains(&candidate) {
                node_ids.insert(candidate);
            }
        }
        assert!(node_ids.is_disjoint(exclusions));
        node_ids
    }

    fn node_id(id: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(id))
    }

    fn number_of_nodes_from_usize(count: usize) -> NumberOfNodes {
        let count = NodeIndex::try_from(count).expect("node index overflow");
        NumberOfNodes::from(count)
    }
}
