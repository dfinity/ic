use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_base_types::{PrincipalId, SubnetId};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::subnet::v1::{
    EcdsaConfig, GossipAdvertConfig, GossipConfig, SubnetRecord,
};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_types::p2p::{
    build_default_gossip_config, ADVERT_BEST_EFFORT_PERCENTAGE, MAX_ARTIFACT_STREAMS_PER_PEER,
    MAX_CHUNK_SIZE, MAX_CHUNK_WAIT_MS, MAX_DUPLICITY, PFN_EVALUATION_PERIOD_MS,
    RECEIVE_CHECK_PEER_SET_SIZE, REGISTRY_POLL_PERIOD_MS, RETRANSMISSION_REQUEST_MS,
};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_update_subnet::UpdateSubnetPayload,
};
use std::str::FromStr;

#[test]
fn test_the_anonymous_user_cannot_update_a_subnets_configuration() {
    local_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(999));
        let initial_subnet_record = SubnetRecord {
            membership: vec![PrincipalId::new_node_test_id(999).to_vec()],
            subnet_type: i32::from(SubnetType::System),
            replica_version_id: "version_42".to_string(),
            unit_delay_millis: 600,
            gossip_config: Some(build_default_gossip_config()),
            ..Default::default()
        };

        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
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
            max_artifact_streams_per_peer: Some(MAX_ARTIFACT_STREAMS_PER_PEER),
            max_chunk_wait_ms: Some(MAX_CHUNK_WAIT_MS),
            max_duplicity: Some(MAX_DUPLICITY),
            max_chunk_size: Some(MAX_CHUNK_SIZE),
            receive_check_cache_size: Some(RECEIVE_CHECK_PEER_SET_SIZE),
            pfn_evaluation_period_ms: Some(PFN_EVALUATION_PERIOD_MS),
            registry_poll_period_ms: Some(REGISTRY_POLL_PERIOD_MS),
            retransmission_request_ms: Some(RETRANSMISSION_REQUEST_MS),
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            max_number_of_canisters: Some(10),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
        };

        // The anonymous end-user tries to update a subnet's configuration, bypassing
        // the governance canister. This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_subnet", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_subnet"));

        // .. And no change should have happened to the subnet record
        let subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                .await;
        assert_eq!(subnet_record, initial_subnet_record);

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("update_subnet", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_subnet"));

        let subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
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
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(build_default_gossip_config()),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
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
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes().to_vec(),
                        encode_or_panic(&initial_subnet_record),
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
            max_artifact_streams_per_peer: Some(MAX_ARTIFACT_STREAMS_PER_PEER),
            max_chunk_wait_ms: Some(MAX_CHUNK_WAIT_MS),
            max_duplicity: Some(MAX_DUPLICITY),
            max_chunk_size: Some(MAX_CHUNK_SIZE),
            receive_check_cache_size: Some(RECEIVE_CHECK_PEER_SET_SIZE),
            pfn_evaluation_period_ms: Some(PFN_EVALUATION_PERIOD_MS),
            registry_poll_period_ms: Some(REGISTRY_POLL_PERIOD_MS),
            retransmission_request_ms: Some(RETRANSMISSION_REQUEST_MS),
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: true,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            max_number_of_canisters: Some(100),
            ssh_readonly_access: None,
            ssh_backup_access: None,
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

        let subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
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
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes().to_vec(),
                        encode_or_panic(&SubnetRecord {
                            membership: vec![],
                            max_ingress_bytes_per_message: 60 * 1024 * 1024,
                            max_ingress_messages_per_block: 1000,
                            max_block_payload_size: 4 * 1024 * 1024,
                            unit_delay_millis: 500,
                            initial_notary_delay_millis: 1500,
                            replica_version_id: "version_42".to_string(),
                            dkg_interval_length: 0,
                            dkg_dealings_per_block: 1,
                            gossip_config: Some(build_default_gossip_config()),
                            start_as_nns: false,
                            subnet_type: SubnetType::Application.into(),
                            is_halted: false,
                            max_instructions_per_message: 5_000_000_000,
                            max_instructions_per_round: 7_000_000_000,
                            max_instructions_per_install_code: 200_000_000_000,
                            features: None,
                            max_number_of_canisters: 0,
                            ssh_readonly_access: vec![],
                            ssh_backup_access: vec![],
                            ecdsa_config: None,
                        }),
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
            max_artifact_streams_per_peer: Some(MAX_ARTIFACT_STREAMS_PER_PEER),
            max_chunk_wait_ms: Some(MAX_CHUNK_WAIT_MS),
            max_duplicity: Some(MAX_DUPLICITY),
            max_chunk_size: Some(MAX_CHUNK_SIZE),
            receive_check_cache_size: Some(RECEIVE_CHECK_PEER_SET_SIZE),
            pfn_evaluation_period_ms: Some(PFN_EVALUATION_PERIOD_MS),
            registry_poll_period_ms: Some(REGISTRY_POLL_PERIOD_MS),
            retransmission_request_ms: Some(RETRANSMISSION_REQUEST_MS),
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: Some(SubnetType::Application),
            is_halted: Some(true),
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            max_number_of_canisters: Some(42),
            ssh_readonly_access: Some(vec!["pub_key_0".to_string()]),
            ssh_backup_access: Some(vec!["pub_key_1".to_string()]),
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

        let subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
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
                replica_version_id: "version_42".to_string(),
                dkg_interval_length: 2,
                dkg_dealings_per_block: 1,
                gossip_config: Some(GossipConfig {
                    max_artifact_streams_per_peer: MAX_ARTIFACT_STREAMS_PER_PEER,
                    max_chunk_wait_ms: MAX_CHUNK_WAIT_MS,
                    max_duplicity: MAX_DUPLICITY,
                    max_chunk_size: MAX_CHUNK_SIZE,
                    receive_check_cache_size: RECEIVE_CHECK_PEER_SET_SIZE,
                    pfn_evaluation_period_ms: PFN_EVALUATION_PERIOD_MS,
                    registry_poll_period_ms: REGISTRY_POLL_PERIOD_MS,
                    retransmission_request_ms: RETRANSMISSION_REQUEST_MS,
                    advert_config: Some(GossipAdvertConfig {
                        best_effort_percentage: ADVERT_BEST_EFFORT_PERCENTAGE,
                    }),
                }),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: true,
                max_instructions_per_message: 6_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 300_000_000_000,
                features: None,
                max_number_of_canisters: 42,
                ssh_readonly_access: vec!["pub_key_0".to_string()],
                ssh_backup_access: vec!["pub_key_1".to_string()],
                ecdsa_config: None,
            }
        );

        Ok(())
    });
}

#[test]
fn test_subnets_configuration_ecdsa_fields_are_updated_correctly() {
    local_test_on_nns_subnet(|runtime| async move {
        let subnet_id = SubnetId::from(
            PrincipalId::from_str(
                "bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae",
            )
            .unwrap(),
        );

        let subnet_record = SubnetRecord {
            membership: vec![],
            max_ingress_bytes_per_message: 60 * 1024 * 1024,
            max_ingress_messages_per_block: 1000,
            max_block_payload_size: 4 * 1024 * 1024,
            unit_delay_millis: 500,
            initial_notary_delay_millis: 1500,
            replica_version_id: "version_42".to_string(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(build_default_gossip_config()),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
        };

        // Just create the registry canister and wait until the subnet_handler ID is
        // known to install and initialize it so that it can be authorized to make
        // mutations to the registry.
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_subnet_record_key(subnet_id).as_bytes().to_vec(),
                        encode_or_panic(&subnet_record),
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
        let mut payload = UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
            // These are the fields being tested
            // These should fail to change the record
            ecdsa_config: Some(EcdsaConfig {
                quadruples_to_create_in_advance: 10,
                key_ids: vec!["key_id_1".to_string()],
            }),
            ecdsa_key_signing_enable: Some(vec!["key_id_1".to_string()]),
        };

        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let new_subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                .await;

        // There should be no change
        assert_eq!(new_subnet_record, subnet_record);

        // Change one field at a time in this payload
        payload = UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
            // These are the fields being tested
            // These should again fail to change the record
            ecdsa_config: None,
            ecdsa_key_signing_enable: Some(vec!["key_id_1".to_string()]),
        };

        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let new_subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                .await;

        // There should be no change
        assert_eq!(new_subnet_record, subnet_record);

        // Trying again, this time in the correct order
        payload = UpdateSubnetPayload {
            subnet_id,
            max_ingress_bytes_per_message: None,
            max_ingress_messages_per_block: None,
            max_block_payload_size: None,
            unit_delay_millis: None,
            initial_notary_delay_millis: None,
            dkg_interval_length: None,
            dkg_dealings_per_block: None,
            max_artifact_streams_per_peer: None,
            max_chunk_wait_ms: None,
            max_duplicity: None,
            max_chunk_size: None,
            receive_check_cache_size: None,
            pfn_evaluation_period_ms: None,
            registry_poll_period_ms: None,
            retransmission_request_ms: None,
            advert_best_effort_percentage: None,
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            max_instructions_per_message: None,
            max_instructions_per_round: None,
            max_instructions_per_install_code: None,
            features: None,
            max_number_of_canisters: None,
            ssh_readonly_access: None,
            ssh_backup_access: None,
            ecdsa_config: Some(EcdsaConfig {
                quadruples_to_create_in_advance: 10,
                key_ids: vec!["key_id_1".to_string()],
            }),
            ecdsa_key_signing_enable: None,
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_subnet",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let new_subnet_record =
            get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                .await;

        // Should see the new value for the config reflected
        assert_eq!(
            new_subnet_record,
            SubnetRecord {
                ecdsa_config: Some(EcdsaConfig {
                    quadruples_to_create_in_advance: 10,
                    key_ids: vec!["key_id_1".to_string()],
                }),
                ..subnet_record
            }
        );

        Ok(())
    });
}
