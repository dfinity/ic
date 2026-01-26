use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_base_types::{PrincipalId, SubnetId, subnet_id_try_from_protobuf};
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
    VetKdKeyId,
};
use ic_nns_test_utils::registry::TEST_ID;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister, try_call_via_universal_canister,
    },
    registry::{get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::crypto::v1::ChainKeyEnabledSubnetList;
use ic_protobuf::registry::subnet::v1::{
    CanisterCyclesCostSchedule, ChainKeyConfig as ChainKeyConfigPb, SubnetRecord,
};
use ic_registry_keys::{make_chain_key_enabled_subnet_list_key, make_subnet_record_key};
use ic_registry_subnet_features::{
    ChainKeyConfig as ChainKeyConfigInternal, DEFAULT_ECDSA_MAX_QUEUE_SIZE,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_types::ReplicaVersion;
use prost::Message;
use registry_canister::mutations::do_update_subnet::{ChainKeyConfig, KeyConfig};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_update_subnet::UpdateSubnetPayload,
};
use std::str::FromStr;

mod common;
use common::test_helpers::get_subnet_record;

#[test]
fn test_the_anonymous_user_cannot_update_a_subnets_configuration() {
    local_test_on_nns_subnet(|runtime| async move {
        // TEST_ID is used as subnet_id also when creating the initial registry state below.
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(TEST_ID));

        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let initial_subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        // update payload message
        let payload = UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            features: None,
            max_number_of_canisters: Some(10),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
            chain_key_config: None,
            chain_key_signing_enable: None,
            chain_key_signing_disable: None,
            // Deprecated/unused values follow
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: Default::default(),
        };

        // The anonymous end-user tries to update a subnet's configuration, bypassing
        // the governance canister. This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_subnet", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_subnet"));

        // .. And no change should have happened to the subnet record
        let subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;
        assert_eq!(subnet_record, initial_subnet_record);

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("update_subnet", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_subnet"));

        let subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        assert_eq!(subnet_record, initial_subnet_record);

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_update_a_subnets_configuration() {
    local_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );
        let initial_subnet_record = SubnetRecord {
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
            canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
        };

        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes(),
                        initial_subnet_record.encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // update payload message
        let payload = UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            features: None,
            max_number_of_canisters: Some(100),
            ssh_readonly_access: None,
            ssh_backup_access: None,
            chain_key_config: None,
            chain_key_signing_enable: None,
            chain_key_signing_disable: None,
            // Deprecated/unused values follow
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: Default::default(),
        };

        // The attacker canister tries to update the subnet's configuration, pretending
        // to be the governance canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        assert_eq!(subnet_record, initial_subnet_record);

        Ok(())
    });
}

#[test]
fn test_the_governance_canister_can_update_a_subnets_configuration() {
    local_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );

        // Just create the registry canister and wait until the subnet_handler ID is
        // known to install and initialize it so that it can be authorized to make
        // mutations to the registry.
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
                                as i32,
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // update payload message
        let payload = UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: Some(100),
            initial_notary_delay_millis: None,
            dkg_interval_length: Some(2),
            dkg_dealings_per_block: Some(1),
            start_as_nns: None,
            subnet_type: Some(SubnetType::Application),
            is_halted: Some(true),
            halt_at_cup_height: Some(true),
            features: None,
            max_number_of_canisters: Some(42),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
            chain_key_config: None,
            chain_key_signing_enable: None,
            chain_key_signing_disable: None,
            // Deprecated/unused values follow
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            set_gossip_config_to_default: Default::default(),
        };

        // Attempt to update the subnet's configuration. Since the update happens from
        // the "fake" governance canister, it should succeed.
        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        assert_eq!(
            subnet_record,
            SubnetRecord {
                membership: vec![],
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_block_payload_size: 4 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                unit_delay_millis: 100,
                initial_notary_delay_millis: 1500,
                replica_version_id: ReplicaVersion::default().into(),
                dkg_interval_length: 2,
                dkg_dealings_per_block: 1,
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: true,
                halt_at_cup_height: true,
                features: None,
                max_number_of_canisters: 42,
                ssh_readonly_access: vec!["pub_key_0".to_string()],
                ssh_backup_access: vec!["pub_key_1".to_string()],
                chain_key_config: None,
                canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
            }
        );

        Ok(())
    });
}

#[test]
fn test_subnets_configuration_ecdsa_fields_are_updated_correctly() {
    let key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key_id_1".to_string(),
    });
    test_subnets_configuration_chain_key_fields_are_updated_correctly(key_id);
}

#[test]
fn test_subnets_configuration_schnorr_fields_are_updated_correctly() {
    let key_id = MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340Secp256k1,
        name: "key_id_1".to_string(),
    });
    test_subnets_configuration_chain_key_fields_are_updated_correctly(key_id);
}

#[test]
fn test_subnets_configuration_vetkd_fields_are_updated_correctly() {
    let key_id = MasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: "key_id_1".to_string(),
    });
    test_subnets_configuration_chain_key_fields_are_updated_correctly(key_id);
}

fn test_subnets_configuration_chain_key_fields_are_updated_correctly(key_id: MasterPublicKeyId) {
    let enable_before_adding_reject_msg = format!(
        "Canister rejected with \
        message: IC0503: Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister \
        called `ic0.trap` with message: 'Panicked at '[Registry] Proposal attempts to enable \
        signing for chain key '{key_id}' on Subnet \
        'bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae', but the \
        subnet does not hold the given key. A proposal to add that key to the subnet \
        must first be separately submitted.'"
    );

    let no_chain_key_config_reject_msg = format!(
        "Canister rejected with message: \
        IC0503: Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister called \
        `ic0.trap` with message: 'Panicked at '[Registry] Proposal attempts to enable signing \
        for chain key '{key_id}' \
        on Subnet 'bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae', \
        but the subnet does not hold the given key. A proposal to add that key to the subnet \
        must first be separately submitted.'"
    );

    local_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );

        let initial_subnet_record = SubnetRecord {
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
            canister_cycles_cost_schedule: CanisterCyclesCostSchedule::Normal as i32,
        };

        // Just create the registry canister and wait until the subnet_handler ID is
        // known to install and initialize it so that it can be authorized to make
        // mutations to the registry.
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes(),
                        initial_subnet_record.encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let signature_request_timeout_ns = Some(12345);
        let idkg_key_rotation_period_ms = Some(12345);
        let max_parallel_pre_signature_transcripts_in_creation = Some(12345);

        let chain_key_config = ChainKeyConfig {
            key_configs: vec![KeyConfig {
                key_id: Some(key_id.clone()),
                pre_signatures_to_create_in_advance: key_id.requires_pre_signatures().then_some(10),
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
            max_parallel_pre_signature_transcripts_in_creation,
        };

        // update payload message
        let mut payload = UpdateSubnetPayload {
            chain_key_config: Some(chain_key_config.clone()),
            chain_key_signing_enable: Some(vec![key_id.clone()]),
            ..empty_update_subnet_payload(subnet_id)
        };

        let response = try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "update_subnet",
            Encode!(&payload).unwrap(),
        )
        .await;
        let error_text = assert_matches!(response, Err(error_text) => error_text);
        assert!(
            error_text.starts_with(&enable_before_adding_reject_msg),
            "Unexpected error: `{error_text}` (does not start with `{enable_before_adding_reject_msg}`).",
        );

        let subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        // There should be no change
        assert_eq!(subnet_record, initial_subnet_record);

        // Change one field at a time in this payload
        payload = UpdateSubnetPayload {
            chain_key_config: None,
            chain_key_signing_enable: Some(vec![key_id.clone()]),
            ..empty_update_subnet_payload(subnet_id)
        };

        let response = try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "update_subnet",
            Encode!(&payload).unwrap(),
        )
        .await;

        let err_text = assert_matches!(response, Err(err_text) => err_text);

        assert!(
            err_text.contains(&no_chain_key_config_reject_msg),
            "Error `{err_text}` does not contain expected substring\n{no_chain_key_config_reject_msg}",
        );

        let subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        // There should be no change
        assert_eq!(subnet_record, initial_subnet_record);

        // Finally, exercise the happy case (this time changes are in the correct order).
        let expected_chain_key_config_pb = ChainKeyConfigPb::from(
            ChainKeyConfigInternal::try_from(chain_key_config.clone()).unwrap(),
        );

        // First call to Registry.update_subnet sets the chain key; the second call enables it.

        // First call:
        {
            let payload_1 = UpdateSubnetPayload {
                chain_key_config: Some(chain_key_config.clone()),
                ..empty_update_subnet_payload(subnet_id)
            };

            try_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_subnet",
                Encode!(&payload_1).unwrap(),
            )
            .await
            .expect("1st call to update_subnet to set chain_key_config must succeed.");

            // Inspect the subnet record
            let subnet_record_1 = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await;

            // Should see the new value for the config reflected
            assert_eq!(
                subnet_record_1,
                SubnetRecord {
                    chain_key_config: Some(expected_chain_key_config_pb),
                    ..initial_subnet_record
                }
            );
        }
        // Second call:
        {
            // This update should enable signing on our subnet for the given key.
            let payload_2 = UpdateSubnetPayload {
                chain_key_signing_enable: Some(vec![key_id.clone()]),
                ..empty_update_subnet_payload(subnet_id)
            };

            try_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_subnet",
                Encode!(&payload_2).unwrap(),
            )
            .await
            .expect("2nd call to update_subnet to set chain_key_signing_enable must succeed.");

            // Inspect the subnet record
            {
                let subnet_record_2 = get_subnet_record(&registry, subnet_id).await;
                let chain_key_config = subnet_record_2.chain_key_config.unwrap();
                let max_queue_size = chain_key_config.key_configs[0].max_queue_size.unwrap();
                assert_eq!(max_queue_size, DEFAULT_ECDSA_MAX_QUEUE_SIZE);
            }

            // Inspect the signing subnet list
            {
                let new_signing_subnet_list: Vec<_> =
                    get_value_or_panic::<ChainKeyEnabledSubnetList>(
                        &registry,
                        make_chain_key_enabled_subnet_list_key(&key_id).as_bytes(),
                    )
                    .await
                    .subnets
                    .into_iter()
                    .map(|subnet_bytes| subnet_id_try_from_protobuf(subnet_bytes).unwrap())
                    .collect();

                // The subnet is now responsible for signing with the key.
                assert_eq!(new_signing_subnet_list, vec![subnet_id]);
            }
        }

        Ok(())
    });
}

/// Returns an update to the given subnet that doesn't change any fields.
fn empty_update_subnet_payload(subnet_id: SubnetId) -> UpdateSubnetPayload {
    UpdateSubnetPayload {
        subnet_id,
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        features: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        // Deprecated/unused values follow
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: Default::default(),
    }
}
