//! States capturing the stages of the non-interactive DKG protocol.

use crate::key_id::KeyId;
use crate::threshold::ni_dkg::static_api as ni_dkg_static_api;
use crate::types::CspPublicCoefficients;
use crate::vault::api::CspVault;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_management_canister_types::{VetKdCurve, VetKdKeyId};
use ic_types::crypto::threshold_sig::ni_dkg::config::dealers::NiDkgDealers;
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgThreshold;
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetSubnet,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{Height, NodeId, NodeIndex, NumberOfNodes, SubnetId};
use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
use rand::{distributions::Alphanumeric, seq::IteratorRandom, Rng};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::sync::Arc;
use strum::{EnumCount, IntoEnumIterator};

// Generate random data structures:
// Alternatively we could implement Distribution for all of these types.
// Deriving Rand may be enough for many.  See: https://stackoverflow.com/questions/48490049/how-do-i-choose-a-random-value-from-an-enum
pub fn random_height(rng: &mut ChaCha20Rng) -> Height {
    Height::from(rng.gen::<u64>())
}
pub fn random_subnet_id(rng: &mut ChaCha20Rng) -> SubnetId {
    subnet_test_id(rng.gen::<u64>())
}
pub fn random_ni_dkg_master_public_key_id(rng: &mut ChaCha20Rng) -> NiDkgMasterPublicKeyId {
    assert_eq!(NiDkgMasterPublicKeyId::COUNT, 1);
    assert_eq!(VetKdCurve::iter().count(), 1);

    let name: String = rng
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();

    NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name,
    })
}
pub fn random_ni_dkg_tag(rng: &mut ChaCha20Rng) -> NiDkgTag {
    use rand::prelude::SliceRandom;
    [
        NiDkgTag::LowThreshold,
        NiDkgTag::HighThreshold,
        NiDkgTag::HighThresholdForKey(random_ni_dkg_master_public_key_id(rng)),
    ]
    .choose(rng)
    .cloned()
    .expect("Could not choose a NiDkgTag")
}
pub fn random_ni_dkg_id(rng: &mut ChaCha20Rng) -> NiDkgId {
    NiDkgId {
        start_block_height: random_height(rng),
        dealer_subnet: random_subnet_id(rng),
        target_subnet: NiDkgTargetSubnet::Local,
        dkg_tag: random_ni_dkg_tag(rng),
    }
}
pub fn random_algorithm_id(rng: &mut ChaCha20Rng) -> AlgorithmId {
    AlgorithmId::iter()
        .choose(rng)
        .expect("Could not choose an AlgorithmId")
}

/// A single node with its CSP
pub struct MockNode {
    pub node_id: NodeId,
    pub fs_key_id: KeyId,
    pub csp_vault: Arc<dyn CspVault>,
}
impl MockNode {
    pub fn random(
        rng: &mut ChaCha20Rng,
        csp_vault_factory: impl Fn() -> Arc<dyn CspVault>,
    ) -> Self {
        let node_id = node_test_id(rng.gen::<u64>());
        Self::from_node_id(node_id, csp_vault_factory)
    }
    pub fn from_node_id(
        node_id: NodeId,
        csp_vault_factory: impl Fn() -> Arc<dyn CspVault>,
    ) -> Self {
        let csp_vault = csp_vault_factory();
        Self {
            node_id,
            fs_key_id: KeyId::from([0; 32]), // dummy value, overwritten during network construction
            csp_vault,
        }
    }
    /// Deal, resharing or not.
    #[allow(clippy::too_many_arguments)]
    pub fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        resharing_public_coefficients: Option<CspPublicCoefficients>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError> {
        let maybe_reshared_secret_id =
            resharing_public_coefficients
                .as_ref()
                .map(|public_coefficients| {
                    KeyId::try_from(public_coefficients)
                        .expect("computing key id from public coefficients should not fail")
                });
        self.csp_vault
            .create_dealing(
                algorithm_id,
                dealer_index,
                threshold,
                epoch,
                receiver_keys,
                maybe_reshared_secret_id,
            )
            .map_err(ni_dkg_errors::CspDkgCreateReshareDealingError::from)
    }
}

/// A collection of nodes, from the perspective of the CSP.
pub struct MockNetwork {
    pub nodes_by_node_id: BTreeMap<NodeId, MockNode>,
    pub forward_secure_keys: BTreeMap<NodeId, CspFsEncryptionPublicKey>,
}
impl MockNetwork {
    // The smallest viable network has a single node that acts as both dealer and
    // receiver.
    pub const MIN_SIZE: usize = 1;
    pub const DEFAULT_MAX_SIZE: usize = 5;

    /// Create N nodes.  No particular roles are attached.
    pub fn random(
        rng: &mut ChaCha20Rng,
        size: usize,
        csp_vault_factory: impl Fn() -> Arc<dyn CspVault>,
    ) -> Self {
        let mut nodes_by_node_id: BTreeMap<NodeId, MockNode> = (0..size)
            .map(|_| MockNode::random(rng, &csp_vault_factory))
            .map(|node| (node.node_id, node))
            .collect();

        let forward_secure_keys: BTreeMap<NodeId, CspFsEncryptionPublicKey> = nodes_by_node_id
            .iter_mut()
            .map(|(node_id, node)| {
                println!("Creating fs keys for {}", node_id);
                let (id, (pubkey, _pop)) = (
                    *node_id,
                    node.csp_vault
                        .gen_dealing_encryption_key_pair(*node_id)
                        .unwrap_or_else(|_| {
                            panic!(
                                "Failed to create forward secure encryption key for NodeId {}",
                                node_id
                            )
                        }),
                );
                node.fs_key_id = KeyId::from(&pubkey);
                (id, pubkey)
            })
            .collect();

        MockNetwork {
            nodes_by_node_id,
            forward_secure_keys,
        }
    }
}

/// A DKG config from the perspective of the CSP.
///
/// Note: The CSP never interacts directly with the NiDKG config, however this
/// structure contains the data from the config relevant to the CSP.
#[derive(Clone, Debug)]
pub struct MockDkgConfig {
    pub algorithm_id: AlgorithmId,
    pub dkg_id: NiDkgId,
    pub max_corrupt_dealers: NumberOfNodes,
    pub dealers: NiDkgDealers,
    pub max_corrupt_receivers: NumberOfNodes,
    pub receivers: NiDkgReceivers,
    pub receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
    pub threshold: NiDkgThreshold,
    pub non_resharing_collection_threshold: NumberOfNodes,
    pub epoch: Epoch,
    // If the transcript of the previous DKG phase is present, resharing DKG is performed.
    pub resharing_transcript: Option<CspNiDkgTranscript>,
}
impl MockDkgConfig {
    /// A random configuration that selects some dealers and some receivers from
    /// a network.
    pub fn from_network(
        rng: &mut ChaCha20Rng,
        network: &MockNetwork,
        last_dkg: Option<(MockDkgConfig, CspNiDkgTranscript)>,
    ) -> MockDkgConfig {
        // Metadata
        let num_nodes = network.nodes_by_node_id.len();
        let min_threshold = 1;
        let min_receivers = 1;
        let min_dealers = 1;
        assert!(
            min_receivers <= num_nodes,
            "min_receivers({}) !<= num_nodes({})",
            min_receivers,
            num_nodes
        );
        assert!(
            min_dealers <= num_nodes,
            "min_dealers({}) !<= num_nodes({})",
            min_dealers,
            num_nodes
        );

        // Node IDs
        let all_node_ids: Vec<NodeId> = network.nodes_by_node_id.keys().cloned().collect();

        let dealers = NiDkgDealers::new(
            if let Some((last_config, _last_transcript)) = last_dkg.as_ref() {
                last_config.receivers.get().clone()
            } else {
                all_node_ids
                    .iter()
                    .take(rng.gen_range(min_dealers..=num_nodes))
                    .cloned()
                    .collect()
            },
        )
        .expect("Could not create NiDkgDealers struct for test");
        let num_dealers = dealers.get().len();

        let num_receivers = rng.gen_range(min_receivers..=num_nodes);
        let receivers =
            NiDkgReceivers::new(all_node_ids.iter().take(num_receivers).cloned().collect())
                .expect("Could not create NiDkgReceivers struct for test");

        // Config values
        let algorithm_id = AlgorithmId::NiDkg_Groth20_Bls12_381;
        let dkg_id = random_ni_dkg_id(rng);
        let max_corrupt_dealers = rng.gen_range(0..num_dealers); // Need at least one honest dealer.
        let threshold = rng.gen_range(min_threshold..=num_receivers); // threshold <= num_receivers
        let max_corrupt_receivers =
            rng.gen_range(0..std::cmp::min(num_receivers + 1 - threshold, threshold)); // (max_corrupt_receivers <= num_receivers - threshold) &&
                                                                                       // (max_corrupt_receivers < threshold)
        let epoch = Epoch::from(rng.gen::<u32>());

        let receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey> = receivers
            .iter()
            .map(|(index, id)| (index, network.forward_secure_keys[&id]))
            .collect();

        let resharing_transcript = last_dkg.map(|(_last_config, last_transcript)| last_transcript);
        MockDkgConfig {
            algorithm_id,
            dkg_id,
            max_corrupt_dealers: NumberOfNodes::from(max_corrupt_dealers as NodeIndex),
            dealers,
            max_corrupt_receivers: NumberOfNodes::from(max_corrupt_receivers as NodeIndex),
            receivers,
            receiver_keys,
            threshold: NiDkgThreshold::new(NumberOfNodes::from(threshold as NodeIndex))
                .expect("Invalid threshold"),
            non_resharing_collection_threshold: NumberOfNodes::from(
                max_corrupt_dealers as NodeIndex + 1,
            ),
            epoch,
            resharing_transcript,
        }
    }
}

/// Initial state of the DKG.
pub struct StateWithConfig {
    pub network: MockNetwork,
    pub config: MockDkgConfig,
}

/// State after dealers have generated keys
pub struct StateWithDealings {
    pub network: MockNetwork,
    pub config: MockDkgConfig,
    pub dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
}

impl StateWithDealings {
    /// Each dealer creates a dealing.
    pub fn from_state_with_config(
        state: StateWithConfig,
    ) -> Result<Self, ni_dkg_errors::CspDkgCreateReshareDealingError> {
        let StateWithConfig {
            mut network,
            config,
        } = state;
        let dealings: Result<
            BTreeMap<NodeIndex, CspNiDkgDealing>,
            ni_dkg_errors::CspDkgCreateReshareDealingError,
        > = config
            .dealers
            .iter()
            .map(|(node_index, node_id)| {
                let node = network
                    .nodes_by_node_id
                    .get_mut(&node_id)
                    .expect("Could not find dealer in nodes");
                let dealing = node.create_dealing(
                    config.algorithm_id,
                    config
                        .dealers
                        .position(node.node_id)
                        .expect("The node is not in the set of Dealers"),
                    config.threshold.get(),
                    config.epoch,
                    config.receiver_keys.clone(),
                    config
                        .resharing_transcript
                        .as_ref()
                        .map(CspPublicCoefficients::from),
                );
                dealing.map(|dealing| (node_index, dealing))
            })
            .collect();
        Ok(StateWithDealings {
            network,
            config,
            dealings: dealings?,
        })
    }
}

/// Dealings should be accepted only if they can be verified
pub struct StateWithVerifiedDealings {
    pub network: MockNetwork,
    pub config: MockDkgConfig,
    pub verification_results: BTreeMap<
        NodeIndex,
        Result<CspNiDkgDealing, ni_dkg_errors::CspDkgVerifyReshareDealingError>,
    >,
}

impl StateWithVerifiedDealings {
    /// Verifies all dealings
    pub fn from_state_with_dealings(state: StateWithDealings) -> Self {
        let StateWithDealings {
            network,
            config,
            dealings,
        } = state;
        let verification_results = dealings
            .into_iter()
            .map(|(dealer_index, dealing)| {
                let test_result = if let Some(transcript) = &config.resharing_transcript {
                    ni_dkg_static_api::verify_resharing_dealing(
                        config.algorithm_id,
                        dealer_index,
                        config.threshold.get(),
                        config.epoch,
                        config.receiver_keys.clone(),
                        dealing.clone(),
                        CspPublicCoefficients::from(transcript),
                    )
                } else {
                    ni_dkg_static_api::verify_dealing(
                        config.algorithm_id,
                        dealer_index,
                        config.threshold.get(),
                        config.epoch,
                        config.receiver_keys.clone(),
                        dealing.clone(),
                    )
                    .map_err(ni_dkg_errors::CspDkgVerifyReshareDealingError::from)
                };

                (dealer_index, test_result.map(|_| dealing))
            })
            .collect();
        StateWithVerifiedDealings {
            network,
            config,
            verification_results,
        }
    }

    /// Gets dealings that passed verification
    pub fn verified_dealings(&self) -> BTreeMap<NodeIndex, CspNiDkgDealing> {
        self.verification_results
            .iter()
            .filter_map(|(index, result)| {
                result
                    .as_ref()
                    .ok()
                    .map(|dealing| (*index, dealing.clone()))
            })
            .collect()
    }
}

/// State in which the dealings have been combined into a single transcript
pub struct StateWithTranscript {
    pub network: MockNetwork,
    pub config: MockDkgConfig,
    pub transcript: CspNiDkgTranscript,
}

impl StateWithTranscript {
    /// Create a CSP transcript
    pub fn create_transcript(
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        number_of_receivers: NumberOfNodes,
        csp_dealings: BTreeMap<NodeIndex, CspNiDkgDealing>,
        non_resharing_collection_threshold: NumberOfNodes,
        resharing_public_coefficients: Option<CspPublicCoefficients>,
    ) -> Result<CspNiDkgTranscript, ni_dkg_errors::CspDkgCreateReshareTranscriptError> {
        if let Some(resharing_public_coefficients) = resharing_public_coefficients {
            ni_dkg_static_api::create_resharing_transcript(
                algorithm_id,
                threshold,
                number_of_receivers,
                csp_dealings,
                resharing_public_coefficients,
            )
        } else {
            ni_dkg_static_api::create_transcript(
                algorithm_id,
                threshold,
                number_of_receivers,
                csp_dealings,
                non_resharing_collection_threshold,
            )
            .map_err(ni_dkg_errors::CspDkgCreateReshareTranscriptError::from)
        }
    }

    /// Receivers validate the dealings and combine them into a single
    /// transcript
    pub fn from_state_with_verified_dealings(state: StateWithVerifiedDealings) -> Self {
        let verified_dealings = state.verified_dealings();
        let StateWithVerifiedDealings {
            network, config, ..
        } = state;
        let transcript = Self::create_transcript(
            config.algorithm_id,
            config.threshold.get(),
            config.receivers.count(),
            verified_dealings,
            config.non_resharing_collection_threshold,
            config
                .resharing_transcript
                .as_ref()
                .map(CspPublicCoefficients::from),
        )
        .expect("Failed to create resharing transcript");
        StateWithTranscript {
            network,
            config,
            transcript,
        }
    }

    /// Receivers decrypt their threshold secret key using their forward secure
    /// secret key.
    pub fn load_keys(&self) {
        let network = &self.network;
        for (node_index, node_id) in self.config.receivers.iter() {
            let node = network
                .nodes_by_node_id
                .get(&node_id)
                .expect("Config refers to a NodeId not in the network");
            node.csp_vault
                .load_threshold_signing_key(
                    self.config.algorithm_id,
                    self.config.epoch,
                    self.transcript.clone(),
                    node.fs_key_id,
                    node_index,
                )
                .expect("Failed to load threshold key");
        }
    }

    /// This should return a generic CspPublicKey, so that the
    /// threshold key is not tied to the specific algorithm, however threshold
    /// public keys are internal types, so cannot be added as a variant without
    /// pulling another bunch of types into internal_types.
    pub fn public_key(&self) -> CspThresholdSigPublicKey {
        match &self.transcript {
            CspNiDkgTranscript::Groth20_Bls12_381(transcript) => {
                CspThresholdSigPublicKey::from(transcript.public_coefficients.coefficients[0])
            }
        }
    }
}
