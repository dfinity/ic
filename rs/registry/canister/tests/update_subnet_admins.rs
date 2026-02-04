use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_base_types::{PrincipalId, SubnetId};
use ic_nns_test_utils::registry::TEST_ID;
use ic_nns_test_utils::{
    itest_helpers::{
        create_and_install_mock_subnet_rental_canister, forward_call_via_universal_canister,
        set_up_registry_canister, set_up_universal_canister, state_machine_test_on_nns_subnet,
    },
    registry::{get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::subnet::v1::{CanisterCyclesCostSchedule, SubnetRecord};
use ic_protobuf::types::v1::PrincipalId as PrincipalIdPb;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::ReplicaVersion;
use prost::Message;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_update_subnet_admins::{OperationType, UpdateSubnetAdminsPayload},
};
use std::str::FromStr;

#[test]
fn test_the_anonymous_user_cannot_update_a_subnets_subnet_admins() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        // TEST_ID is used as subnet_id also when creating the initial registry state below.
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(TEST_ID));

        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let initial_subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user_test_id(100).get()])),
        };

        // The anonymous end-user tries to update a subnet's subnet admins, bypassing
        // the subnet rental canister. This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_subnet_admins", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_subnet_admins"));

        // .. And no change should have happened to the subnet's subnet admins
        let subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;
        assert_eq!(subnet_admins, initial_subnet_admins);

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("update_subnet_admins", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_subnet_admins"));

        let subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;

        assert_eq!(subnet_admins, initial_subnet_admins);

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_update_a_subnets_subnet_admins() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        // TEST_ID is used as subnet_id also when creating the initial registry state below.
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(TEST_ID));

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let initial_subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;

        // An attacker got a canister that is trying to pass for the subnet rental
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::SUBNET_RENTAL_CANISTER_ID,
        );

        // The attacker canister tries to update a subnet's subnet admins, bypassing
        // the subnet rental canister. This should have no effect.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user_test_id(100).get()])),
        };
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_subnet_admins",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And no change should have happened to the subnet's subnet admins
        let subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;
        assert_eq!(subnet_admins, initial_subnet_admins);

        Ok(())
    });
}

#[test]
fn test_subnet_admins_cannot_be_updated_for_system_subnet() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes(),
                        SubnetRecord {
                            membership: vec![],
                            max_ingress_bytes_per_message: 60 * 1024 * 1024,
                            max_ingress_messages_per_block: 1000,
                            max_block_payload_size: 4 * 1024 * 1024,
                            unit_delay_millis: 500,
                            initial_notary_delay_millis: 1500,
                            replica_version_id: ReplicaVersion::default().into(),
                            dkg_interval_length: 0,
                            dkg_dealings_per_block: 1,
                            start_as_nns: false,
                            subnet_type: SubnetType::System.into(),
                            is_halted: false,
                            halt_at_cup_height: false,
                            features: None,
                            max_number_of_canisters: 0,
                            ssh_readonly_access: vec![],
                            ssh_backup_access: vec![],
                            chain_key_config: None,
                            canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal
                                .into(),
                            subnet_admins: vec![],
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        let initial_subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;

        // Send the update_subnet_admins call via the subnet rental canister...
        let fake_subnet_rental_canister =
            create_and_install_mock_subnet_rental_canister(&runtime).await;
        assert_eq!(
            fake_subnet_rental_canister.canister_id(),
            ic_nns_constants::SUBNET_RENTAL_CANISTER_ID,
        );

        let new_subnet_admin = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![new_subnet_admin])),
        };
        assert!(
            !forward_call_via_universal_canister(
                &fake_subnet_rental_canister,
                &registry,
                "update_subnet_admins",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And no change should have happened to the subnet's subnet admins
        let subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;
        assert_eq!(subnet_admins, initial_subnet_admins);

        Ok(())
    });
}

#[test]
fn test_subnet_admins_cannot_be_updated_for_non_rented_subnet() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes(),
                        SubnetRecord {
                            membership: vec![],
                            max_ingress_bytes_per_message: 60 * 1024 * 1024,
                            max_ingress_messages_per_block: 1000,
                            max_block_payload_size: 4 * 1024 * 1024,
                            unit_delay_millis: 500,
                            initial_notary_delay_millis: 1500,
                            replica_version_id: ReplicaVersion::default().into(),
                            dkg_interval_length: 0,
                            dkg_dealings_per_block: 1,
                            start_as_nns: false,
                            subnet_type: SubnetType::Application.into(),
                            is_halted: false,
                            halt_at_cup_height: false,
                            features: None,
                            max_number_of_canisters: 0,
                            ssh_readonly_access: vec![],
                            ssh_backup_access: vec![],
                            chain_key_config: None,
                            canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal
                                .into(),
                            subnet_admins: vec![],
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        let initial_subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;

        // Send the update_subnet_admins call via the subnet rental canister...
        let fake_subnet_rental_canister =
            create_and_install_mock_subnet_rental_canister(&runtime).await;
        assert_eq!(
            fake_subnet_rental_canister.canister_id(),
            ic_nns_constants::SUBNET_RENTAL_CANISTER_ID,
        );

        let new_subnet_admin = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![new_subnet_admin])),
        };
        assert!(
            !forward_call_via_universal_canister(
                &fake_subnet_rental_canister,
                &registry,
                "update_subnet_admins",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And no change should have happened to the subnet's subnet admins
        let subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;
        assert_eq!(subnet_admins, initial_subnet_admins);

        Ok(())
    });
}

#[test]
fn test_subnet_rental_canister_can_update_a_subnets_subnet_admins() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes(),
                        SubnetRecord {
                            membership: vec![],
                            max_ingress_bytes_per_message: 60 * 1024 * 1024,
                            max_ingress_messages_per_block: 1000,
                            max_block_payload_size: 4 * 1024 * 1024,
                            unit_delay_millis: 500,
                            initial_notary_delay_millis: 1500,
                            replica_version_id: ReplicaVersion::default().into(),
                            dkg_interval_length: 0,
                            dkg_dealings_per_block: 1,
                            start_as_nns: false,
                            subnet_type: SubnetType::Application.into(),
                            is_halted: false,
                            halt_at_cup_height: false,
                            features: None,
                            max_number_of_canisters: 0,
                            ssh_readonly_access: vec![],
                            ssh_backup_access: vec![],
                            chain_key_config: None,
                            canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Free.into(),
                            subnet_admins: vec![],
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Send the update_subnet_admins call via the subnet rental canister...
        let fake_subnet_rental_canister =
            create_and_install_mock_subnet_rental_canister(&runtime).await;
        assert_eq!(
            fake_subnet_rental_canister.canister_id(),
            ic_nns_constants::SUBNET_RENTAL_CANISTER_ID,
        );

        let new_subnet_admin = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![new_subnet_admin])),
        };
        assert!(
            forward_call_via_universal_canister(
                &fake_subnet_rental_canister,
                &registry,
                "update_subnet_admins",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And the new subnet admin should have been added.
        let subnet_admins = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await
        .subnet_admins;
        assert_eq!(subnet_admins, vec![PrincipalIdPb::from(new_subnet_admin)]);

        Ok(())
    });
}
