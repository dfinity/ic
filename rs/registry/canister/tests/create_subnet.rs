use std::convert::TryFrom;

use candid::Encode;
use dfn_candid::candid;

use ic_base_types::{PrincipalId, SubnetId};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, insert_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_node_key, make_node_record_key,
    make_routing_table_record_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_routing_table::RoutingTable;
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
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_add_node::{connection_endpoint_from_string, flow_endpoint_from_string},
        do_create_subnet::CreateSubnetPayload,
    },
};

use assert_matches::assert_matches;

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

        let payload = CreateSubnetPayload {
            node_ids: node_ids.clone(),
            subnet_id_override: None,
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 6 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "1337".to_string(),
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
            advert_best_effort_percentage: None,
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
        };

        // The anonymous end-user tries to create a subnet, bypassing the proposals
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("create_subnet", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
            Err(s) if s.contains("is not authorized to call this method: create_subnet"));

        // .. And there should therefore be no new subnet record (any, actually)
        let subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
        assert_eq!(subnet_list_record, initial_subnet_list_record);

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("create_subnet", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
            Err(s) if s.contains("is not authorized to call this method: create_subnet"));
        let subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
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

        let initial_subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;

        let payload = CreateSubnetPayload {
            node_ids: node_ids.clone(),
            subnet_id_override: None,
            ingress_bytes_per_block_soft_cap: 3 * 1024 * 1024,
            max_ingress_bytes_per_message: 6 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "1337".to_string(),
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
            advert_best_effort_percentage: Some(50),
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
        };

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
        let subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
        assert_eq!(subnet_list_record, initial_subnet_list_record);

        Ok(())
    });
}

// TODO (NNS-79): This test cannot pass with the current fixtures: we use a fake
// registry component to setup the consensus/p2p stack, but then inside this
// test we spin up a registry canister to write all the subnet updates.
// Obviously, there is no connection between both registries, so the consensus
// fails on creating a DKG for a new subnet due to a registry version being not
// available locally.
#[test]
#[ignore]
fn test_accepted_proposal_mutates_the_registry_no_subnet_apriori() {
    local_test_on_nns_subnet(|runtime| async move {
        let (init_mutate, node_ids) = prepare_registry(5);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutate)
                .build(),
        )
        .await;

        // Add an empty routing table to the registry
        let routing_table = PbRoutingTable::from(RoutingTable::default());
        insert_value(
            &registry,
            make_routing_table_record_key().as_bytes(),
            &routing_table,
        )
        .await;

        // Install the universal canister in place of the proposals canister
        let fake_proposal_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_proposal_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // first, ensure there is no subnet yet
        let subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
        assert_eq!(subnet_list_record, SubnetListRecord::default());

        // create payload message
        let payload = CreateSubnetPayload {
            node_ids: node_ids.clone(),
            subnet_id_override: None,
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
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
            advert_best_effort_percentage: None,
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
        };

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
        let subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
        assert_ne!(subnet_list_record, SubnetListRecord::default());

        let subnet_ids: Vec<SubnetId> = subnet_list_record
            .subnets
            .iter()
            .map(|s| SubnetId::new(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
            .collect();
        assert_eq!(subnet_ids.len(), 1);
        let subnet_id = subnet_ids[0_usize];

        // Now let's check directly in the registry that the mutation actually happened
        let subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                .await;
        // Check if some fields are equal
        assert_eq!(subnet_record.replica_version_id, payload.replica_version_id);
        assert_eq!(
            subnet_record.membership,
            node_ids
                .into_iter()
                .map(|n| n.get().into_vec())
                .collect::<::std::vec::Vec<std::vec::Vec<u8>>>()
        );

        let cup_contents = get_value::<CatchUpPackageContents>(
            &registry,
            make_catch_up_package_contents_key(subnet_id).as_bytes(),
        )
        .await;
        assert!(cup_contents
            .initial_ni_dkg_transcript_low_threshold
            .is_some());
        assert!(cup_contents
            .initial_ni_dkg_transcript_high_threshold
            .is_some());

        Ok(())
    });
}

// TODO (NNS-79): This test cannot pass with the current fixtures: we use a fake
// registry component to setup the consensus/p2p stack, but then inside this
// test we spin up a registry canister to write all the subnet updates.
// Obviously, there is no connection between both registries, so the consensus
// fails on creating a DKG for a new subnet due to a registry version being not
// available locally.
#[test]
#[ignore]
fn test_accepted_proposal_mutates_the_registry_some_subnets_present() {
    local_test_on_nns_subnet(|runtime| async move {
        let (init_mutate, node_ids) = prepare_registry(5);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(init_mutate)
                .build(),
        )
        .await;

        // Install the universal canister in place of the proposals canister
        let fake_proposal_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_proposal_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // first, ensure there is no subnet yet
        let subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
        assert_eq!(subnet_list_record, SubnetListRecord::default());

        // then, create a preexisting set of dummy subnets and insert in the
        // subnet list record
        let preexisting_subnets = (117..125)
            .map(|x| PrincipalId::new_subnet_test_id(x).to_vec())
            .collect();
        let subnet_list_record = SubnetListRecord {
            subnets: preexisting_subnets,
        };
        insert_value(
            &registry,
            make_subnet_list_record_key().as_bytes(),
            &subnet_list_record,
        )
        .await;

        // Add an empty routing table to the registry
        // This is needed to satisfy preconditions the create_subnet depends on,
        // when there are other subnets present.
        let routing_table = PbRoutingTable::from(RoutingTable::default());
        insert_value(
            &registry,
            make_routing_table_record_key().as_bytes(),
            &routing_table,
        )
        .await;

        let former_subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
        assert_eq!(former_subnet_list_record.subnets.len(), 8);

        // create payload message
        let payload = CreateSubnetPayload {
            node_ids: node_ids.clone(),
            subnet_id_override: None,
            ingress_bytes_per_block_soft_cap: 2 * 1024 * 1024,
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_block_payload_size: 4 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
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
        };

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
        let subnet_list_record =
            get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                .await;
        assert_eq!(subnet_list_record.subnets.len(), 9);

        let fresh_subnet_ids: Vec<SubnetId> = subnet_list_record
            .subnets
            .iter()
            .filter(|&x| !former_subnet_list_record.subnets.contains(x))
            .map(|s| SubnetId::new(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
            .collect();
        assert_eq!(fresh_subnet_ids.len(), 1);
        let subnet_id = fresh_subnet_ids[0_usize];

        // Now let's check directly in the registry that the mutation actually happened
        let subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                .await;
        // Check if some fields are equal
        assert_eq!(subnet_record.replica_version_id, payload.replica_version_id);
        assert_eq!(
            subnet_record.membership,
            node_ids
                .into_iter()
                .map(|n| n.get().into_vec())
                .collect::<::std::vec::Vec<std::vec::Vec<u8>>>()
        );

        let cup_contents = get_value::<CatchUpPackageContents>(
            &registry,
            make_catch_up_package_contents_key(subnet_id).as_bytes(),
        )
        .await;
        assert!(cup_contents
            .initial_ni_dkg_transcript_low_threshold
            .is_some());
        assert!(cup_contents
            .initial_ni_dkg_transcript_high_threshold
            .is_some());

        Ok(())
    });
}
