use super::*;
use ic_crypto_internal_bls12_381_type::{G1Affine, G2Affine, verify_bls_signature};
use ic_crypto_test_utils::{map_of, set_of};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, InitialNiDkgTranscriptRecord};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_registry_keys::make_catch_up_package_contents_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgThreshold;
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::{Height, NumberOfNodes, RegistryVersion, SubnetId};
use ic_types_test_utils::ids::{NODE_1, SUBNET_1, node_test_id};
use rand::Rng;
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

    let config = InitialNiDkgConfig::new(
        &nodes_set,
        dealer_subnet,
        dkg_tag.clone(),
        target_id,
        REG_V1,
    );

    assert_eq!(
        config.get().dkg_id(),
        &NiDkgId {
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

    let config = InitialNiDkgConfig::new(
        &nodes_set,
        dealer_subnet,
        dkg_tag.clone(),
        target_id,
        REG_V1,
    );

    assert_eq!(
        config.get().dkg_id(),
        &NiDkgId {
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

    let rng = &mut reproducible_rng();

    initial_dkg_transcript(initial_dkg_config, &BTreeMap::new(), rng);
}

// This test acts as reminder that the CBOR representation of the
// CspNiDkgTranscript is used in the registry and changing it makes it
// impossible to read the initial NI-DKG transcript from the registry.
#[test]
fn should_have_stable_internal_csp_transcript_cbor_serialization() {
    let transcript = transcript_without_empty_or_default_data();
    let transcript_proto = InitialNiDkgTranscriptRecord::from(transcript);

    assert_eq!(
        hex::encode(transcript_proto.internal_csp_transcript),
        "a17147726f746832305f426c7331325f333831a2737075626c69635f636f656666696369656e7473a16c636f656666696369656e74738158602a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a6d72656365697665725f64617461a1182ba46672616e645f729058300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101015830010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101583001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010158300101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101016672616e645f739058300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58300c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c6672616e645f7a9058607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b58607b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b71636970686572746578745f6368756e6b7381905830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea5830eaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaea"
    );
}

#[test]
fn should_correctly_retrieve_initial_low_threshold_ni_dkg_transcript_from_registry() {
    let mut transcript = transcript();
    let dkg_tag = NiDkgTag::LowThreshold;
    transcript.dkg_id.dkg_tag = dkg_tag.clone();
    let registry = registry_with_initial_ni_dkg_transcript(
        InitialNiDkgTranscriptRecord::from(transcript.clone()),
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
    transcript.dkg_id.dkg_tag = dkg_tag.clone();
    let registry = registry_with_initial_ni_dkg_transcript(
        InitialNiDkgTranscriptRecord::from(transcript.clone()),
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

#[test]
fn should_get_master_key_associated_with_transcript_public_key() {
    use ic_interfaces::crypto::KeyManager;

    let nodes = [node_id(3), node_id(5)];
    let nodes_set: BTreeSet<NodeId> = nodes.iter().cloned().collect();
    let dealer_subnet = SUBNET_1;
    let dkg_tag = NiDkgTag::LowThreshold;
    let target_id = target_id();

    let rng = &mut reproducible_rng();

    let config = InitialNiDkgConfig::new(&nodes_set, dealer_subnet, dkg_tag, target_id, REG_V1);

    let mut receiver_keys = BTreeMap::new();

    for node_id in nodes {
        let temp_crypto = TempCryptoComponent::builder()
            .with_node_id(node_id)
            .with_keys(ic_crypto_temp_crypto::NodeKeysToGenerate::only_dkg_dealing_encryption_key())
            .with_rng(ChaCha20Rng::from_seed(rng.r#gen()))
            .build();
        let dkg_dealing_encryption_pubkey = temp_crypto
            .current_node_public_keys()
            .expect("Failed to retrieve node public keys")
            .dkg_dealing_encryption_public_key
            .expect("missing dkg_dealing_encryption_pk");

        receiver_keys.insert(node_id, dkg_dealing_encryption_pubkey);
    }

    let (transcript, secret) = initial_dkg_transcript_and_master_key(config, &receiver_keys, rng);

    let pk = ThresholdSigPublicKey::try_from(&transcript)
        .expect("should extract public key from high threshold transcript");

    let test_message = rng.r#gen::<[u8; 32]>();

    let signature = sign_message(&test_message, &secret);

    let signature_bytes: [u8; 48] = signature.as_ref().try_into().expect("Invalid size");

    let pk_g2 = G2Affine::deserialize(&pk.into_bytes()).expect("Invalid public key point");
    let sig_g1 = G1Affine::deserialize(&signature_bytes).expect("Invalid signature point");

    let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    let msg_g1 = G1Affine::hash(dst, &test_message);

    assert!(verify_bls_signature(&sig_g1, &pk_g2, &msg_g1));
}

/// Returns a transcript without empty or default data so that it can be used
/// for tests whose aim is to detect changes in the serialization of the
/// transcript.
fn transcript_without_empty_or_default_data() -> NiDkgTranscript {
    use ic_crypto_internal_types::curves::bls12_381::{G1Bytes, G2Bytes};
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
    use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
        EncryptedShares, NUM_CHUNKS, PublicCoefficientsBytes, Transcript,
    };

    let encrypted_shares = EncryptedShares {
        rand_r: [G1Bytes([1; G1Bytes::SIZE]); NUM_CHUNKS],
        rand_s: [G1Bytes([12; G1Bytes::SIZE]); NUM_CHUNKS],
        rand_z: [G2Bytes([123; G2Bytes::SIZE]); NUM_CHUNKS],
        ciphertext_chunks: vec![[G1Bytes([234; G1Bytes::SIZE]); NUM_CHUNKS]],
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

fn registry_with_initial_ni_dkg_transcript(
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
            cup_contents.initial_ni_dkg_transcript_high_threshold =
                Some(InitialNiDkgTranscriptRecord::from(transcript()));
        }
        NiDkgTag::HighThreshold => {
            cup_contents.initial_ni_dkg_transcript_high_threshold = Some(transcript_record);
            cup_contents.initial_ni_dkg_transcript_low_threshold =
                Some(InitialNiDkgTranscriptRecord::from(transcript()));
        }
        NiDkgTag::HighThresholdForKey(_master_public_key_id) => {
            unimplemented!("not an initial NI-DKG transcript tag")
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
