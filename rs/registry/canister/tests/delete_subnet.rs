use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::decode_registry_value;
use ic_nns_constants::{
    ENGINE_CONTROLLER_CANISTER_ID, GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, set_up_registry_canister, set_up_universal_canister,
    state_machine_test_on_nns_subnet,
};
use ic_nns_test_utils::registry::{
    INITIAL_MUTATION_ID, invariant_compliant_mutation_as_atomic_req,
};
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::subnet::v1::SubnetListRecord as SubnetListRecordPb;
use ic_registry_keys::make_subnet_list_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_types::{NodeId, ReplicaVersion};
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_create_subnet::{CanisterCyclesCostSchedule, CreateSubnetPayload},
        do_delete_subnet::DeleteSubnetPayload,
    },
};

mod common;

use common::test_helpers::{
    get_subnet_list_record, install_registry_canister_with_payload_builder,
    prepare_registry_with_nodes, prepare_registry_with_nodes_from_template,
};

/// Installs an invariant-compliant registry (which already contains a single,
/// non-CloudEngine subnet) and returns the running `PocketIc` together with the
/// principal of an existing subnet that can be used as a `delete_subnet` target.
async fn setup_with_existing_subnet() -> (PocketIc, Principal) {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0));
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let subnet_list_record =
        decode_registry_value::<SubnetListRecordPb>(&pocket_ic, make_subnet_list_record_key())
            .await;
    let subnet_id = subnet_list_record
        .subnets
        .first()
        .expect("expected the invariant-compliant registry to contain at least one subnet");
    let subnet_id = Principal::try_from(subnet_id.as_slice()).unwrap();

    (pocket_ic, subnet_id)
}

#[tokio::test]
async fn test_the_anonymous_user_cannot_delete_a_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    let payload = DeleteSubnetPayload { subnet_id };

    // The anonymous end-user tries to delete a subnet via an ingress message,
    // bypassing governance. This should be rejected by the authorization check.
    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            PrincipalId::new_anonymous().0,
            "delete_subnet",
            Encode!(&payload).unwrap(),
        )
        .await;

    assert!(
        response.as_ref().is_err_and(|err| err
            .reject_message
            .contains("is not authorized to call this method: delete_subnet")),
        "Expected an authorization rejection, but got {response:?}"
    );
}

#[tokio::test]
async fn test_an_unauthorized_principal_cannot_delete_a_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    // A principal that is neither governance nor the engine controller, calling
    // via an ingress message.
    let unauthorized_caller = PrincipalId::new_user_test_id(1);
    assert_ne!(unauthorized_caller, GOVERNANCE_CANISTER_ID.get());
    assert_ne!(unauthorized_caller, ENGINE_CONTROLLER_CANISTER_ID.get());

    let payload = DeleteSubnetPayload { subnet_id };

    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            unauthorized_caller.0,
            "delete_subnet",
            Encode!(&payload).unwrap(),
        )
        .await;

    assert!(
        response.as_ref().is_err_and(|err| err
            .reject_message
            .contains("is not authorized to call this method: delete_subnet")),
        "Expected an authorization rejection, but got {response:?}"
    );
}

#[test]
fn test_a_canister_other_than_governance_or_engine_controller_cannot_delete_a_subnet() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        // An attacker canister tries to delete a subnet via an inter-canister
        // call. Going through a real canister (rather than an ingress message)
        // ensures the access control cannot be bypassed by, e.g., only guarding
        // ingress messages in `inspect_message`.
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but it has neither the governance nor the engine controller ID.
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::ENGINE_CONTROLLER_CANISTER_ID
        );

        let (init_mutate, _node_ids) = prepare_registry_with_nodes(5, INITIAL_MUTATION_ID);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(
                    5 + INITIAL_MUTATION_ID,
                ))
                .push_init_mutate_request(init_mutate)
                .build(),
        )
        .await;

        let initial_subnet_list_record = get_subnet_list_record(&registry).await;
        let subnet_id = Principal::try_from(
            initial_subnet_list_record
                .subnets
                .first()
                .expect("expected at least one subnet")
                .as_slice(),
        )
        .unwrap();
        let payload = DeleteSubnetPayload { subnet_id };

        // The attacker canister tries to delete a subnet. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "delete_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And the subnet list should be unchanged.
        let subnet_list_record = get_subnet_list_record(&registry).await;
        assert_eq!(subnet_list_record, initial_subnet_list_record);

        Ok(())
    });
}

#[tokio::test]
async fn test_governance_canister_can_delete_a_cloud_engine_subnet() {
    cloud_engine_subnet_can_be_deleted_by(GOVERNANCE_CANISTER_ID.get()).await;
}

#[tokio::test]
async fn test_engine_controller_can_delete_a_cloud_engine_subnet() {
    cloud_engine_subnet_can_be_deleted_by(ENGINE_CONTROLLER_CANISTER_ID.get()).await;
}

#[tokio::test]
async fn test_authorized_callers_cannot_delete_a_non_cloud_engine_subnet() {
    let (pocket_ic, subnet_id) = setup_with_existing_subnet().await;

    let payload = DeleteSubnetPayload { subnet_id };

    // The existing subnet is a system subnet, not a CloudEngine. Even authorized
    // callers must not be able to delete it: the call passes the authorization
    // check but is then rejected by the business logic. Deletion fails, so the
    // subnet is not consumed and both callers can be checked against it.
    for caller in [
        GOVERNANCE_CANISTER_ID.get(),
        ENGINE_CONTROLLER_CANISTER_ID.get(),
    ] {
        let response = pocket_ic
            .update_call(
                REGISTRY_CANISTER_ID.get().0,
                caller.0,
                "delete_subnet",
                Encode!(&payload).unwrap(),
            )
            .await
            .unwrap_or_else(|err| {
                panic!("delete_subnet call by authorized caller {caller} was unexpectedly rejected: {err:?}")
            });

        let result = Decode!(&response, Result<(), String>).unwrap();
        assert_eq!(
            result,
            Err("Only CloudEngines may be deleted".to_string()),
            "caller {caller} should not be able to delete a non-cloud-engine subnet"
        );
    }

    // The subnet should still be present.
    let subnets =
        decode_registry_value::<SubnetListRecordPb>(&pocket_ic, make_subnet_list_record_key())
            .await
            .subnets;
    assert!(
        subnets.contains(&subnet_id.as_slice().to_vec()),
        "the non-cloud-engine subnet should not have been deleted"
    );
}

/// Creates a CloudEngine subnet (the only subnet type that may be deleted) and
/// verifies that `caller` is authorized to delete it and that the subnet is
/// actually removed from the registry.
async fn cloud_engine_subnet_can_be_deleted_by(caller: PrincipalId) {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    // CloudEngine subnets may only consist of type-4 nodes (enforced by the
    // `check_node_type4_iff_cloud_engine` invariant), so provision such nodes.
    let node_template = NodeRecord {
        node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
        node_reward_type: Some(NodeRewardType::Type4 as i32),
        ..Default::default()
    };
    let (init_mutate, node_ids_and_pks) =
        prepare_registry_with_nodes_from_template(4, INITIAL_MUTATION_ID, node_template);
    let node_ids: Vec<NodeId> = node_ids_and_pks.keys().cloned().collect();

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(
        4 + INITIAL_MUTATION_ID,
    ));
    builder.push_init_mutate_request(init_mutate);
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    let initial_subnets =
        decode_registry_value::<SubnetListRecordPb>(&pocket_ic, make_subnet_list_record_key())
            .await
            .subnets;

    // Create the CloudEngine subnet via governance.
    let create_payload = make_cloud_engine_create_subnet_payload(node_ids);
    pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            GOVERNANCE_CANISTER_ID.get().0,
            "create_subnet",
            Encode!(&create_payload).unwrap(),
        )
        .await
        .expect("creating a cloud engine subnet via governance should succeed");

    let subnets_after_create =
        decode_registry_value::<SubnetListRecordPb>(&pocket_ic, make_subnet_list_record_key())
            .await
            .subnets;
    let added_subnets: Vec<_> = subnets_after_create
        .iter()
        .filter(|s| !initial_subnets.contains(s))
        .cloned()
        .collect();
    assert_eq!(added_subnets.len(), 1, "expected exactly one new subnet");
    let cloud_engine_subnet = added_subnets[0].clone();
    let subnet_id = Principal::try_from(cloud_engine_subnet.as_slice()).unwrap();

    // Delete the CloudEngine subnet via the caller under test.
    let delete_payload = DeleteSubnetPayload { subnet_id };
    let response = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            caller.0,
            "delete_subnet",
            Encode!(&delete_payload).unwrap(),
        )
        .await
        .unwrap_or_else(|err| {
            panic!("delete_subnet call by authorized caller {caller} was unexpectedly rejected: {err:?}")
        });

    let result = Decode!(&response, Result<(), String>).unwrap();
    assert_eq!(
        result,
        Ok(()),
        "authorized caller {caller} should be able to delete a cloud engine subnet"
    );

    // The subnet should no longer be in the subnet list.
    let subnets_after_delete =
        decode_registry_value::<SubnetListRecordPb>(&pocket_ic, make_subnet_list_record_key())
            .await
            .subnets;
    assert!(
        !subnets_after_delete.contains(&cloud_engine_subnet),
        "the cloud engine subnet should have been removed from the subnet list"
    );
}

/// Builds a `CreateSubnetPayload` for a CloudEngine subnet. CloudEngine subnets
/// must be on the `Free` cost schedule and consist of type-4 nodes.
fn make_cloud_engine_create_subnet_payload(node_ids: Vec<NodeId>) -> CreateSubnetPayload {
    CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
        initial_dkg_subnet_id: None,
        max_ingress_bytes_per_message: 60 * 1024 * 1024,
        max_ingress_bytes_per_block: None,
        max_ingress_messages_per_block: 1000,
        max_block_payload_size: 4 * 1024 * 1024,
        unit_delay_millis: 500,
        initial_notary_delay_millis: 1500,
        replica_version_id: ReplicaVersion::default().into(),
        dkg_interval_length: 0,
        dkg_dealings_per_block: 1,
        start_as_nns: false,
        subnet_type: SubnetType::CloudEngine,
        is_halted: false,
        features: Default::default(),
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        chain_key_config: None,
        canister_cycles_cost_schedule: Some(CanisterCyclesCostSchedule::Free),
        subnet_admins: Some(vec![]),
        resource_limits: Default::default(),

        // Unused section follows
        ingress_bytes_per_block_soft_cap: Default::default(),
        gossip_max_artifact_streams_per_peer: Default::default(),
        gossip_max_chunk_wait_ms: Default::default(),
        gossip_max_duplicity: Default::default(),
        gossip_max_chunk_size: Default::default(),
        gossip_receive_check_cache_size: Default::default(),
        gossip_pfn_evaluation_period_ms: Default::default(),
        gossip_registry_poll_period_ms: Default::default(),
        gossip_retransmission_request_ms: Default::default(),
    }
}
