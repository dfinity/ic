#![allow(clippy::unwrap_used)]

use super::*;
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, InitialNiDkgTranscriptRecord};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_registry_keys::make_catch_up_package_contents_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::crypto::basic_utilities::{map_of, set_of};
use ic_test_utilities::types::ids::{node_test_id, NODE_1, SUBNET_1};
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgThreshold;
use ic_types::{Height, NumberOfNodes, RegistryVersion, SubnetId};
use std::sync::Arc;

const REG_V1: RegistryVersion = RegistryVersion::new(1);

#[test]
#[should_panic(expected = "subnet must not be empty")]
fn should_panic_on_empty_nodes_in_subnet() {
    let nodes = [];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();

    InitialNiDkgConfig::new(
        &nodes_set,
        SUBNET_1,
        NiDkgTag::LowThreshold,
        target_id(),
        REG_V1,
    );
}

#[test]
fn should_correctly_create_initial_dkg_config_for_single_node() {
    let nodes = [node_id(5)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let dealer_subnet = SUBNET_1;
    let dkg_tag = NiDkgTag::LowThreshold;
    let target_id = target_id();

    let config = InitialNiDkgConfig::new(&nodes_set, dealer_subnet, dkg_tag, target_id, REG_V1);

    assert_eq!(
        config.get().dkg_id(),
        NiDkgId {
            start_block_height: Height::new(0),
            dealer_subnet,
            dkg_tag,
            target_subnet: NiDkgTargetSubnet::Remote(target_id),
        }
    );
    assert_eq!(config.get().max_corrupt_dealers(), NumberOfNodes::from(0));
    assert_eq!(config.get().dealers().get().len(), 1);
    assert_eq!(
        config.get().dealers().get().iter().next(),
        Some(&node_id(5))
    );
    assert_eq!(config.get().max_corrupt_receivers(), NumberOfNodes::new(0));
    assert_eq!(config.get().receivers().get().len(), 1);
    assert_eq!(config.get().receivers().get(), &nodes_set);
    assert_eq!(config.get().threshold().get(), NumberOfNodes::new(1));
    assert_eq!(config.get().registry_version(), REG_V1);
    assert_eq!(config.get().resharing_transcript(), &None);
}

#[test]
fn should_correctly_create_initial_dkg_config() {
    let nodes = [node_id(3), node_id(2), node_id(5), node_id(6), node_id(7)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let dealer_subnet = SUBNET_1;
    let dkg_tag = NiDkgTag::LowThreshold;
    let target_id = target_id();

    let config = InitialNiDkgConfig::new(&nodes_set, dealer_subnet, dkg_tag, target_id, REG_V1);

    assert_eq!(
        config.get().dkg_id(),
        NiDkgId {
            start_block_height: Height::new(0),
            dealer_subnet,
            dkg_tag,
            target_subnet: NiDkgTargetSubnet::Remote(target_id),
        }
    );
    assert_eq!(config.get().max_corrupt_dealers(), NumberOfNodes::from(0));
    assert_eq!(config.get().dealers().get().len(), 1);
    assert_eq!(
        config.get().dealers().get().iter().next(),
        Some(&node_id(2))
    );
    assert_eq!(config.get().max_corrupt_receivers(), NumberOfNodes::new(1));
    assert_eq!(config.get().receivers().get().len(), 5);
    assert_eq!(config.get().receivers().get(), &nodes_set);
    assert_eq!(config.get().threshold().get(), NumberOfNodes::new(2));
    assert_eq!(config.get().registry_version(), REG_V1);
    assert_eq!(config.get().resharing_transcript(), &None);
}

#[test]
#[should_panic(expected = "the config's receivers must match the keys' receivers")]
fn should_panic_if_receiver_keys_dont_match_config_receivers() {
    let nodes = [node_id(2)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let dkg_tag = NiDkgTag::LowThreshold;
    let initial_dkg_config =
        InitialNiDkgConfig::new(&nodes_set, SUBNET_1, dkg_tag, target_id(), REG_V1);

    initial_dkg_transcript(initial_dkg_config, &BTreeMap::new());
}

// This test acts as reminder that the CBOR representation of the
// CspNiDkgTranscript is used in the registry and changing it makes it
// impossible to read the initial NI-DKG transcript from the registry.
#[test]
fn should_have_stable_internal_csp_transcript_cbor_serialization() {
    let transcript = transcript_without_empty_or_default_data();
    let transcript_proto = initial_ni_dkg_transcript_record_from_transcript(transcript);

    assert_eq!(
        hex::encode(transcript_proto.internal_csp_transcript),
        "a17147726f746832305f426c7331325f333831a2737075626c69635f636f656666696369656e7473a16c636f656666696369656e74738158602a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a6d72656365697665725f64617461a1182ba46672616e645f729058300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101016672616e645f739058300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c6672616e645f7a9058607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b71636970686572746578745f6368756e6b7381905830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea"
    );
}

#[test]
fn should_correctly_retrieve_initial_low_threshold_ni_dkg_transcript_from_registry() {
    let mut transcript = transcript();
    let dkg_tag = NiDkgTag::LowThreshold;
    transcript.dkg_id.dkg_tag = dkg_tag;
    let registry = registry_with_ni_dkg_transcript(
        initial_ni_dkg_transcript_record_from_transcript(transcript.clone()),
        dkg_tag,
        SUBNET_1,
        REG_V1,
    );

    assert_eq!(
        registry
            .get_initial_dkg_transcripts(SUBNET_1, REG_V1)
            .unwrap()
            .value
            .unwrap()
            .low_threshold,
        transcript
    );
}

#[test]
fn should_correctly_retrieve_initial_high_threshold_ni_dkg_transcript_from_registry() {
    let mut transcript = transcript();
    let dkg_tag = NiDkgTag::HighThreshold;
    transcript.dkg_id.dkg_tag = dkg_tag;
    let registry = registry_with_ni_dkg_transcript(
        initial_ni_dkg_transcript_record_from_transcript(transcript.clone()),
        dkg_tag,
        SUBNET_1,
        REG_V1,
    );

    assert_eq!(
        registry
            .get_initial_dkg_transcripts(SUBNET_1, REG_V1)
            .unwrap()
            .value
            .unwrap()
            .high_threshold,
        transcript
    );
}

/// Returns a transcript without empty or default data so that it can be used
/// for tests whose aim is to detect changes in the serialization of the
/// transcript.
fn transcript_without_empty_or_default_data() -> NiDkgTranscript {
    use ic_crypto_internal_types::curves::bls12_381::{G1, G2};
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
        EncryptedShares, PublicCoefficientsBytes, Transcript, NUM_CHUNKS,
    };
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
    use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;

    let encrypted_shares = EncryptedShares {
        rand_r: [G1([1; G1::SIZE]); NUM_CHUNKS],
        rand_s: [G1([12; G1::SIZE]); NUM_CHUNKS],
        rand_z: [G2([123; G2::SIZE]); NUM_CHUNKS],
        ciphertext_chunks: vec![[G1([234; G1::SIZE]); NUM_CHUNKS]],
    };
    NiDkgTranscript {
        dkg_id: NiDkgId {
            start_block_height: Height::new(0),
            dealer_subnet: SUBNET_1,
            dkg_tag: NiDkgTag::LowThreshold,
            target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new([42; 32])),
        },
        threshold: NiDkgThreshold::new(NumberOfNodes::new(1)).unwrap(),
        committee: NiDkgReceivers::new(set_of(&[NODE_1])).expect("could not create committee"),
        registry_version: REG_V1,
        internal_csp_transcript: CspNiDkgTranscript::Groth20_Bls12_381(Transcript {
            public_coefficients: PublicCoefficientsBytes {
                coefficients: vec![PublicKeyBytes([42; PublicKeyBytes::SIZE])],
            },
            receiver_data: map_of(vec![(43, encrypted_shares)]),
        }),
    }
}

fn transcript() -> NiDkgTranscript {
    transcript_without_empty_or_default_data()
}

fn registry_with_ni_dkg_transcript(
    transcript_record: InitialNiDkgTranscriptRecord,
    dkg_tag: NiDkgTag,
    subnet_id: SubnetId,
    version: RegistryVersion,
) -> impl RegistryClient {
    let mut cup_contents = CatchUpPackageContents::default();
    match dkg_tag {
        // We always store both scripts, just as it happens in production.
        NiDkgTag::LowThreshold => {
            cup_contents.initial_ni_dkg_transcript_low_threshold = Some(transcript_record);
            cup_contents.initial_ni_dkg_transcript_high_threshold = Some(
                initial_ni_dkg_transcript_record_from_transcript(transcript()),
            );
        }
        NiDkgTag::HighThreshold => {
            cup_contents.initial_ni_dkg_transcript_high_threshold = Some(transcript_record);
            cup_contents.initial_ni_dkg_transcript_low_threshold = Some(
                initial_ni_dkg_transcript_record_from_transcript(transcript()),
            );
        }
    }
    let registry_data = ProtoRegistryDataProvider::new();
    registry_data
        .add(
            &make_catch_up_package_contents_key(subnet_id),
            version,
            Some(cup_contents),
        )
        .expect("failed to add subnet record");

    let registry = FakeRegistryClient::new(Arc::new(registry_data));
    registry.update_to_latest_version();
    registry
}

fn node_id(node_id: u64) -> NodeId {
    node_test_id(node_id)
}

fn target_id() -> NiDkgTargetId {
    NiDkgTargetId::new([42u8; 32])
}
