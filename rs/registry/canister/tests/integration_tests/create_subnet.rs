use std::convert::TryFrom;
use std::sync::Arc;

use candid::Encode;
use dfn_candid::candid;
use ic_base_types::{PrincipalId, RegistryVersion, SubnetId};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_node_key, make_node_record_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{
    insert,
    pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
};
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_types::p2p::{
    MAX_ARTIFACT_STREAMS_PER_PEER, MAX_CHUNK_SIZE, MAX_CHUNK_WAIT_MS, MAX_DUPLICITY,
    PFN_EVALUATION_PERIOD_MS, RECEIVE_CHECK_PEER_SET_SIZE, REGISTRY_POLL_PERIOD_MS,
    RETRANSMISSION_REQUEST_MS,
};
use ic_types::{crypto::KeyPurpose, NodeId};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_create_subnet::CreateSubnetPayload,
};

use assert_matches::assert_matches;
use canister_test::{Canister, Runtime};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use registry_canister::mutations::node_management::do_add_node::{
    connection_endpoint_from_string, flow_endpoint_from_string,
};

/// Prepare a mutate request to add the desired of nodes, and returned the IDs
/// of the nodes to be added.
fn prepare_registry(nodes: u64) -> (RegistryAtomicMutateRequest, Vec<NodeId>) {
    // Prepare a transaction to add the nodes to the registry
    let mut mutations = Vec::<RegistryMutation>::default();
    let node_ids: Vec<NodeId> = (0..nodes)
        .map(|_| {
            let temp_dir = temp_dir();
            let (node_pks, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());
            mutations.push(insert(
                &make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
                encode_or_panic(&node_pks.dkg_dealing_encryption_pk.unwrap()),
            ));

            let node_key = make_node_record_key(node_id);
            mutations.push(insert(
                &node_key.as_bytes().to_vec(),
                encode_or_panic(&NodeRecord {
                    xnet: Some(connection_endpoint_from_string(
                        &("128.0.0.1:1234".to_string()),
                    )),
                    http: Some(connection_endpoint_from_string(
                        &("128.0.0.1:1234".to_string()),
                    )),
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

#[test]
fn test_the_anonymous_user_cannot_create_a_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        let (init_mutate, node_ids) = prepare_registry(4);
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutate)
                .build(),
        )
        .await;

        let initial_subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;

        let payload = make_create_subnet_payload(node_ids.clone());

        // The anonymous end-user tries to create a subnet, bypassing the proposals
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("create_subnet", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
            Err(s) if s.contains("is not authorized to call this method: create_subnet"));

        // .. And there should therefore be no new subnet record (any, actually)
        let subnet_list_record = get_subnet_list_record(&registry).await;
        assert_eq!(subnet_list_record, initial_subnet_list_record);

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();

        let response: Result<(), String> = registry
            .update_("create_subnet", candid, (payload.clone(),))
            .await;

        assert_matches!(response,
            Err(s) if s.contains("is not authorized to call this method: create_subnet"));

        let subnet_list_record = get_subnet_list_record(&registry).await;
        assert_eq!(subnet_list_record, initial_subnet_list_record);

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_proposals_canister_cannot_create_a_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the proposals
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let (init_mutate, node_ids) = prepare_registry(5);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutate)
                .build(),
        )
        .await;

        let initial_subnet_list_record = get_subnet_list_record(&registry).await;

        let payload = make_create_subnet_payload(node_ids.clone());

        // The attacker canister tries to create a subnet, pretending to be the
        // proposals canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "create_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );
        // .. And there should therefore be no new subnet record (any, actually)
        let subnet_list_record = get_subnet_list_record(&registry).await;
        assert_eq!(subnet_list_record, initial_subnet_list_record);

        Ok(())
    });
}

#[test]
fn test_accepted_proposal_mutates_the_registry_some_subnets_present() {
    local_test_on_nns_subnet(|runtime| async move {
        let (data_provider, fake_client) = match runtime {
            Runtime::Remote(_) => {
                panic!("Cannot run this test on Runtime::Remote at this time");
            }
            Runtime::Local(ref r) => (r.registry_data_provider.clone(), r.registry_client.clone()),
        };

        let (init_mutate, node_ids) = prepare_registry(5);

        let registry = setup_registry_synced_with_fake_client(
            &runtime,
            fake_client,
            data_provider,
            vec![init_mutate],
        )
        .await;

        // Install the universal canister in place of the proposals canister
        let fake_proposal_canister = set_up_universal_canister_as_governance(&runtime).await;

        // first, get current list of subnets created by underlying system
        let initial_subnet_list_record = get_subnet_list_record(&registry).await;
        // create payload message
        let payload = make_create_subnet_payload(node_ids.clone());

        assert!(
            forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "create_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // Now let's check directly in the registry that the mutation actually happened
        // by observing a new subnet in the subnet list
        let (subnet_id, subnet_record) =
            get_added_subnet(&registry, &initial_subnet_list_record).await;

        // Check if some fields are equal
        assert_eq!(subnet_record.replica_version_id, payload.replica_version_id);
        assert_eq!(
            subnet_record.membership,
            node_ids
                .into_iter()
                .map(|n| n.get().into_vec())
                .collect::<::std::vec::Vec<std::vec::Vec<u8>>>()
        );

        let cup_contents = get_cup_contents(&registry, subnet_id).await;

        assert!(cup_contents
            .initial_ni_dkg_transcript_low_threshold
            .is_some());
        assert!(cup_contents
            .initial_ni_dkg_transcript_high_threshold
            .is_some());

        Ok(())
    });
}

// Start helper functions
fn make_create_subnet_payload(node_ids: Vec<NodeId>) -> CreateSubnetPayload {
    // create payload message
    CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
        ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
        max_ingress_bytes_per_message: 60 * 1024 * 1024,
        max_ingress_messages_per_block: 1000,
        max_block_payload_size: 4 * 1024 * 1024,
        unit_delay_millis: 500,
        initial_notary_delay_millis: 1500,
        replica_version_id: "version_42".to_string(),
        dkg_interval_length: 0,
        dkg_dealings_per_block: 1,
        gossip_max_artifact_streams_per_peer: MAX_ARTIFACT_STREAMS_PER_PEER,
        gossip_max_chunk_wait_ms: MAX_CHUNK_WAIT_MS,
        gossip_max_duplicity: MAX_DUPLICITY,
        gossip_max_chunk_size: MAX_CHUNK_SIZE,
        gossip_receive_check_cache_size: RECEIVE_CHECK_PEER_SET_SIZE,
        gossip_pfn_evaluation_period_ms: PFN_EVALUATION_PERIOD_MS,
        gossip_registry_poll_period_ms: REGISTRY_POLL_PERIOD_MS,
        gossip_retransmission_request_ms: RETRANSMISSION_REQUEST_MS,
        advert_best_effort_percentage: Some(10),
        start_as_nns: false,
        subnet_type: SubnetType::Application,
        is_halted: false,
        max_instructions_per_message: 5_000_000_000,
        max_instructions_per_round: 7_000_000_000,
        max_instructions_per_install_code: 200_000_000_000,
        features: SubnetFeatures::default(),
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
    }
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

async fn get_subnet_list_record(registry: &Canister<'_>) -> SubnetListRecord {
    get_value::<SubnetListRecord>(registry, make_subnet_list_record_key().as_bytes()).await
}

async fn get_subnet_record(registry: &Canister<'_>, subnet_id: SubnetId) -> SubnetRecord {
    get_value::<SubnetRecord>(registry, make_subnet_record_key(subnet_id).as_bytes()).await
}

// This does not do anything special - just ensures you created the canister in the right position
// so that it gets the governance ID
async fn set_up_universal_canister_as_governance(runtime: &'_ Runtime) -> Canister<'_> {
    // Install the universal canister in place of the proposals canister
    let fake_proposal_canister = set_up_universal_canister(runtime).await;
    // Since it takes the id reserved for the proposal canister, it can impersonate
    // it
    assert_eq!(
        fake_proposal_canister.canister_id(),
        ic_nns_constants::GOVERNANCE_CANISTER_ID
    );
    fake_proposal_canister
}

async fn get_added_subnet(
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

async fn get_cup_contents(registry: &Canister<'_>, subnet_id: SubnetId) -> CatchUpPackageContents {
    get_value::<CatchUpPackageContents>(
        registry,
        make_catch_up_package_contents_key(subnet_id).as_bytes(),
    )
    .await
}

/// This allows us to create a registry canister that is in-sync with the FakeRegistryClient
/// and ProtoRegistryDataProvider used by the underlying IC setup (consensus and execution)
/// Without those being in sync, calls to CanisterId::ic_00 time out waiting for registry versions
/// to get in sync
async fn setup_registry_synced_with_fake_client(
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
