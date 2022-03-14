//! Utilities for non-interactive Distributed Key Generation (NI-DKG).
use crate::common::utils::temp_crypto::TempCryptoComponentGeneric;
use crate::common::utils::TempCryptoComponent;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_crypto_internal_types::NodeIndex;
use ic_interfaces::crypto::NiDkgAlgorithm;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::consensus::get_faults_tolerated;
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::threshold_sig::ni_dkg::config::{NiDkgConfig, NiDkgConfigData};
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgTargetId};
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
};
use ic_types::crypto::KeyPurpose;
use ic_types::{Height, NodeId, SubnetId};
use ic_types::{NumberOfNodes, RegistryVersion};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// A config used to create an initial NI-DKG transcript. Such a transcript is
/// used to bootstrap a subnet for testing purposes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InitialNiDkgConfig {
    dkg_config: NiDkgConfig,
}

impl InitialNiDkgConfig {
    pub const START_BLOCK_HEIGHT: u64 = 0;

    /// Creates an initial DKG config for a subnet initially containing the
    /// nodes `nodes_in_subnet`.
    ///
    /// The DKG ID contained in the config is for start block `Height` 0 (see
    /// the constant `START_BLOCK_HEIGHT`), a _remote_ target subnet with ID
    /// `target_id`, the given `dealer_subnet`, and `dkg_tag`.
    ///
    /// The config uses the node with the smallest ID (as determined by the
    /// `Ord` trait) in `nodes_in_subnet` as dealer, and the `nodes_in_subnet`
    /// as receivers. The config's threshold is set in accordance with the
    /// `dkg_tag` (low/high).
    ///
    /// # Panics
    /// The function panics if `nodes_in_subnet` is empty.
    pub fn new(
        nodes_in_subnet: &BTreeSet<NodeId>,
        dealer_subnet: SubnetId,
        dkg_tag: NiDkgTag,
        target_id: NiDkgTargetId,
        registry_version: RegistryVersion,
    ) -> Self {
        Self::ensure_subnet_not_empty(nodes_in_subnet);
        let threshold = dkg_tag.threshold_for_subnet_of_size(nodes_in_subnet.len());
        let max_corrupt_receivers = get_faults_tolerated(nodes_in_subnet.len());
        let dkg_config_data = NiDkgConfigData {
            dkg_id: NiDkgId {
                start_block_height: Height::from(Self::START_BLOCK_HEIGHT),
                dealer_subnet,
                dkg_tag,
                target_subnet: NiDkgTargetSubnet::Remote(target_id),
            },
            max_corrupt_dealers: NumberOfNodes::new(0),
            dealers: nodes_in_subnet.iter().copied().take(1).collect(),
            max_corrupt_receivers: number_of_nodes_from_usize(max_corrupt_receivers),
            receivers: nodes_in_subnet.clone(),
            threshold: number_of_nodes_from_usize(threshold),
            registry_version,
            resharing_transcript: None,
        };
        let dkg_config = NiDkgConfig::new(dkg_config_data)
            .expect("internal error: config invariant unexpectedly violated");
        Self { dkg_config }
    }

    pub fn get(&self) -> &NiDkgConfig {
        &self.dkg_config
    }

    fn ensure_subnet_not_empty(nodes_in_subnet: &BTreeSet<NodeId>) {
        if nodes_in_subnet.is_empty() {
            panic!("subnet must not be empty");
        }
    }
}

// TODO (CRP-569): add integration test for signing with initial transcript
/// Creates an initial DKG transcript.
///
/// The transcript is created by performing the DKG protocol in a _centralized_
/// manner. This method must only be used for testing purposes since the
/// transcript is generated in a centralized manner.
///
/// # Panics
/// * If the `receiver_keys` don't match the receivers in the
///   `initial_dkg_config`.
pub fn initial_dkg_transcript(
    initial_dkg_config: InitialNiDkgConfig,
    receiver_keys: &BTreeMap<NodeId, PublicKeyProto>,
) -> NiDkgTranscript {
    let dkg_config = initial_dkg_config.get();
    ensure_matching_node_ids(dkg_config.receivers(), receiver_keys);

    let dealer = first_dealer(dkg_config);
    let registry = fake_registry_with_encryption_keys(receiver_keys, dkg_config.registry_version());
    let dealer_crypto = TempCryptoComponent::new(Arc::new(registry), dealer);

    transcript_with_single_dealing(dkg_config, dealer_crypto)
}

/// Converts an NI-DKG transcript into the corresponding protobuf
/// representation.
pub fn initial_ni_dkg_transcript_record_from_transcript(
    transcript: NiDkgTranscript,
) -> InitialNiDkgTranscriptRecord {
    use ic_protobuf::types::v1::NiDkgId as NiDkgIdProto;

    let dkg_id = NiDkgIdProto::from(transcript.dkg_id);
    InitialNiDkgTranscriptRecord {
        id: Some(dkg_id),
        threshold: transcript.threshold.get().get(),
        committee: transcript
            .committee
            .get()
            .iter()
            .map(|node| node.get().into_vec())
            .collect(),
        registry_version: transcript.registry_version.get(),
        internal_csp_transcript: serde_cbor::to_vec(&transcript.internal_csp_transcript)
            .expect("failed to serialize CSP NI-DKG transript to CBOR"),
    }
}

fn number_of_nodes_from_usize(count: usize) -> NumberOfNodes {
    let count = NodeIndex::try_from(count).expect("node index overflow");
    NumberOfNodes::from(count)
}

fn ensure_matching_node_ids(
    receivers_in_config: &NiDkgReceivers,
    receiver_keys: &BTreeMap<NodeId, PublicKeyProto>,
) {
    let receivers_from_config: &BTreeSet<NodeId> = receivers_in_config.get();
    let receivers_from_keys: &BTreeSet<NodeId> = &receiver_keys.keys().cloned().collect();
    assert_eq!(
        receivers_from_keys, receivers_from_config,
        "the config's receivers must match the keys' receivers"
    );
}

fn first_dealer(dkg_config: &NiDkgConfig) -> NodeId {
    *dkg_config
        .dealers()
        .get()
        .iter()
        .next()
        .expect("internal error: expected the initial DKG config to contain a dealer")
}

fn fake_registry_with_encryption_keys(
    keys: &BTreeMap<NodeId, PublicKeyProto>,
    registry_version: RegistryVersion,
) -> FakeRegistryClient {
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    for (node, key) in keys {
        registry_data
            .add(
                &make_crypto_node_key(*node, KeyPurpose::DkgDealingEncryption),
                registry_version,
                Some(key.clone()),
            )
            .expect("internal error: failed to add DKG dealing encryption key to fake registry");
    }
    let registry = FakeRegistryClient::new(registry_data);
    registry.update_to_latest_version();
    registry
}

fn map_with(dealer: NodeId, dealing: NiDkgDealing) -> BTreeMap<NodeId, NiDkgDealing> {
    let mut map = BTreeMap::new();
    map.insert(dealer, dealing);
    map
}

fn transcript_with_single_dealing<C: CryptoServiceProvider>(
    dkg_config: &NiDkgConfig,
    dealer_crypto: TempCryptoComponentGeneric<C>,
) -> NiDkgTranscript {
    let dealing = dealer_crypto
        .create_dealing(dkg_config)
        .expect("internal error: failed to create dealing");
    dealer_crypto
        .create_transcript(dkg_config, &map_with(dealer_crypto.node_id, dealing))
        .expect("internal error: failed to create transcript")
}
