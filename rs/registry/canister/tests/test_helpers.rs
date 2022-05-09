use canister_test::{Canister, Runtime};
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_ic00_types::EcdsaKeyId;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::itest_helpers::{set_up_registry_canister, set_up_universal_canister};
use ic_nns_test_utils::registry::get_value;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_node_key, make_node_record_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_subnet_features::EcdsaConfig;
use ic_registry_transport::insert;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript};
use ic_types::crypto::KeyPurpose;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::do_create_subnet::CreateSubnetPayload;
use registry_canister::mutations::node_management::do_add_node::{
    connection_endpoint_from_string, flow_endpoint_from_string,
};
use std::convert::TryFrom;
use std::sync::Arc;

// Test helpers
pub async fn get_subnet_list_record(registry: &Canister<'_>) -> SubnetListRecord {
    get_value::<SubnetListRecord>(registry, make_subnet_list_record_key().as_bytes()).await
}

pub async fn get_subnet_record(registry: &Canister<'_>, subnet_id: SubnetId) -> SubnetRecord {
    get_value::<SubnetRecord>(registry, make_subnet_record_key(subnet_id).as_bytes()).await
}

pub fn get_subnet_holding_ecdsa_keys(
    ecdsa_key_ids: &[EcdsaKeyId],
    node_ids: Vec<NodeId>,
) -> SubnetRecord {
    let mut record: SubnetRecord = CreateSubnetPayload {
        unit_delay_millis: 10,
        gossip_retransmission_request_ms: 10_000,
        gossip_registry_poll_period_ms: 2000,
        gossip_pfn_evaluation_period_ms: 50,
        gossip_receive_check_cache_size: 1,
        gossip_max_duplicity: 1,
        gossip_max_chunk_wait_ms: 200,
        gossip_max_artifact_streams_per_peer: 1,
        node_ids,
        ..Default::default()
    }
    .into();
    record.ecdsa_config = Some(
        EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: ecdsa_key_ids.to_vec(),
        }
        .into(),
    );

    record
}

/// This creates a CatchupPackageContents for nodes that would be part of as subnet
/// which is necessary if the underlying IC test machinery knows about the subnets you added
/// to your registry
pub fn dummy_cup_for_subnet(nodes: Vec<NodeId>) -> CatchUpPackageContents {
    let low_threshold_transcript_record =
        dummy_initial_dkg_transcript(nodes.clone(), NiDkgTag::LowThreshold);
    let high_threshold_transcript_record =
        dummy_initial_dkg_transcript(nodes, NiDkgTag::HighThreshold);

    return CatchUpPackageContents {
        initial_ni_dkg_transcript_low_threshold: Some(low_threshold_transcript_record),
        initial_ni_dkg_transcript_high_threshold: Some(high_threshold_transcript_record),
        ..Default::default()
    };

    // copied from rs/consensus/src/dkg.rs
    fn dummy_initial_dkg_transcript(
        committee: Vec<NodeId>,
        tag: NiDkgTag,
    ) -> InitialNiDkgTranscriptRecord {
        let threshold = committee.len() as u32 / 3 + 1;
        let transcript =
            NiDkgTranscript::dummy_transcript_for_tests_with_params(committee, tag, threshold, 0);
        InitialNiDkgTranscriptRecord {
            id: Some(transcript.dkg_id.into()),
            threshold: transcript.threshold.get().get(),
            committee: transcript
                .committee
                .iter()
                .map(|(_, c)| c.get().to_vec())
                .collect(),
            registry_version: 1,
            internal_csp_transcript: serde_cbor::to_vec(&transcript.internal_csp_transcript)
                .unwrap(),
        }
    }
}

/// This allows us to create a registry canister that is in-sync with the FakeRegistryClient
/// and ProtoRegistryDataProvider used by the underlying IC setup (consensus and execution)
/// Without those being in sync, calls to CanisterId::ic_00 time out waiting for registry versions
/// to get in sync
pub async fn setup_registry_synced_with_fake_client(
    runtime: &'_ Runtime,
    fake_registry_client: Arc<FakeRegistryClient>,
    fake_data_provider: Arc<ProtoRegistryDataProvider>,
    initial_mutations: Vec<RegistryAtomicMutateRequest>,
) -> Canister<'_> {
    let initial_fake_data = fake_data_provider.export_versions_as_atomic_mutation_requests();
    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    for version in initial_fake_data {
        builder.push_init_mutate_request(version);
    }

    for m in initial_mutations {
        let next_version = RegistryVersion::from(fake_data_provider.latest_version().get() + 1);
        fake_data_provider.apply_mutations_as_version(m.mutations.clone(), next_version);
        builder.push_init_mutate_request(m);
    }
    fake_registry_client.update_to_latest_version();

    set_up_registry_canister(runtime, builder.build()).await
}

/// Prepare a mutate request to add the desired number of nodes, and returned the IDs
/// of the nodes to be added.
pub fn prepare_registry_with_nodes(node_count: u64) -> (RegistryAtomicMutateRequest, Vec<NodeId>) {
    // Prepare a transaction to add the nodes to the registry
    let mut mutations = vec![];
    let node_ids: Vec<NodeId> = (0..node_count)
        .map(|_| {
            let temp_dir = temp_dir();
            let (node_pks, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());
            mutations.push(insert(
                &make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
                encode_or_panic(&node_pks.dkg_dealing_encryption_pk.unwrap()),
            ));
            mutations.push(insert(
                &make_crypto_node_key(node_id, KeyPurpose::NodeSigning).as_bytes(),
                encode_or_panic(&node_pks.node_signing_pk.unwrap()),
            ));
            mutations.push(insert(
                &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption).as_bytes(),
                encode_or_panic(&node_pks.idkg_dealing_encryption_pk.unwrap()),
            ));

            let node_key = make_node_record_key(node_id);
            mutations.push(insert(
                node_key.as_bytes(),
                encode_or_panic(&NodeRecord {
                    xnet: Some(connection_endpoint_from_string("128.0.0.1:1234")),
                    http: Some(connection_endpoint_from_string("128.0.0.1:1234")),
                    p2p_flow_endpoints: vec!["123,128.0.0.1:10000"]
                        .iter()
                        .map(|x| flow_endpoint_from_string(x))
                        .collect(),
                    node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
                    ..Default::default()
                }),
            ));
            node_id
        })
        .collect();

    let mutate_request = RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    };

    (mutate_request, node_ids)
}

fn get_added_subnets(
    former_subnet_list_record: &SubnetListRecord,
    current_subnet_list_record: &SubnetListRecord,
) -> Vec<SubnetId> {
    current_subnet_list_record
        .subnets
        .iter()
        .filter(|&x| !former_subnet_list_record.subnets.contains(x))
        .map(|s| SubnetId::new(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
        .collect()
}

// This does not do anything special - just ensures you created the canister in the right position
// so that it gets the governance ID
pub async fn set_up_universal_canister_as_governance(runtime: &'_ Runtime) -> Canister<'_> {
    // Install the universal canister in place of the governance canister
    let fake_governance_canister = set_up_universal_canister(runtime).await;
    // Since it takes the id reserved for the governance canister, it can impersonate
    // it
    assert_eq!(
        fake_governance_canister.canister_id(),
        ic_nns_constants::GOVERNANCE_CANISTER_ID
    );
    fake_governance_canister
}

pub async fn get_added_subnet(
    registry: &Canister<'_>,
    former_subnet_list_record: &SubnetListRecord,
) -> (SubnetId, SubnetRecord) {
    let subnet_list_record = get_subnet_list_record(registry).await;

    let added_subnet_ids = get_added_subnets(former_subnet_list_record, &subnet_list_record);
    // ensure only one subnet was added, or this function won't give expected results
    assert_eq!(added_subnet_ids.len(), 1);
    let subnet_id = added_subnet_ids[0_usize];
    (subnet_id, get_subnet_record(registry, subnet_id).await)
}

pub async fn get_cup_contents(
    registry: &Canister<'_>,
    subnet_id: SubnetId,
) -> CatchUpPackageContents {
    get_value::<CatchUpPackageContents>(
        registry,
        make_catch_up_package_contents_key(subnet_id).as_bytes(),
    )
    .await
}
