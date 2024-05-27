use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_base_types::{subnet_id_try_from_protobuf, PrincipalId, SubnetId};
use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::registry::TEST_ID;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister, try_call_via_universal_canister,
    },
    registry::{get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::{
    crypto::v1::EcdsaSigningSubnetList,
    subnet::v1::{
        ChainKeyConfig as ChainKeyConfigPb, EcdsaConfig as EcdsaConfigPb, GossipConfig,
        SubnetRecord,
    },
};
use ic_registry_keys::{make_ecdsa_signing_subnet_list_key, make_subnet_record_key};
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use ic_types::{
    p2p::{
        build_default_gossip_config, MAX_ARTIFACT_STREAMS_PER_PEER, MAX_CHUNK_SIZE,
        MAX_CHUNK_WAIT_MS, MAX_DUPLICITY, PFN_EVALUATION_PERIOD_MS, RECEIVE_CHECK_PEER_SET_SIZE,
        REGISTRY_POLL_PERIOD_MS, RETRANSMISSION_REQUEST_MS,
    },
    ReplicaVersion,
};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_update_subnet::UpdateSubnetPayload,
};
use std::str::FromStr;

mod common;
use common::test_helpers::get_subnet_record;

// TODO[NNS1-2986]: Remove, replacing with `make_ecdsa_master_public_key`.
fn make_ecdsa_key(name: &str) -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: name.to_string(),
    }
}

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
            max_artifact_streams_per_peer: Some(MAX_ARTIFACT_STREAMS_PER_PEER),
            max_chunk_wait_ms: Some(MAX_CHUNK_WAIT_MS),
            max_duplicity: Some(MAX_DUPLICITY),
            max_chunk_size: Some(MAX_CHUNK_SIZE),
            receive_check_cache_size: Some(RECEIVE_CHECK_PEER_SET_SIZE),
            pfn_evaluation_period_ms: Some(PFN_EVALUATION_PERIOD_MS),
            registry_poll_period_ms: Some(REGISTRY_POLL_PERIOD_MS),
            retransmission_request_ms: Some(RETRANSMISSION_REQUEST_MS),
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
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
            gossip_config: Some(build_default_gossip_config()),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            halt_at_cup_height: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
            chain_key_config: None,
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
            set_gossip_config_to_default: true,
            start_as_nns: None,
            subnet_type: None,
            is_halted: None,
            halt_at_cup_height: None,
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
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
                        encode_or_panic(&SubnetRecord {
                            membership: vec![],
                            max_ingress_bytes_per_message: 60 * 1024 * 1024,
                            max_ingress_messages_per_block: 1000,
                            max_block_payload_size: 4 * 1024 * 1024,
                            unit_delay_millis: 500,
                            initial_notary_delay_millis: 1500,
                            replica_version_id: ReplicaVersion::default().into(),
                            dkg_interval_length: 0,
                            dkg_dealings_per_block: 1,
                            gossip_config: Some(build_default_gossip_config()),
                            start_as_nns: false,
                            subnet_type: SubnetType::Application.into(),
                            is_halted: false,
                            halt_at_cup_height: false,
                            max_instructions_per_message: 5_000_000_000,
                            max_instructions_per_round: 7_000_000_000,
                            max_instructions_per_install_code: 200_000_000_000,
                            features: None,
                            max_number_of_canisters: 0,
                            ssh_readonly_access: vec![],
                            ssh_backup_access: vec![],
                            ecdsa_config: None,
                            chain_key_config: None,
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
            set_gossip_config_to_default: false,
            start_as_nns: None,
            subnet_type: Some(SubnetType::Application),
            is_halted: Some(true),
            halt_at_cup_height: Some(true),
            max_instructions_per_message: Some(6_000_000_000),
            max_instructions_per_round: Some(8_000_000_000),
            max_instructions_per_install_code: Some(300_000_000_000),
            features: None,
            ecdsa_config: None,
            ecdsa_key_signing_enable: None,
            ecdsa_key_signing_disable: None,
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
                gossip_config: Some(GossipConfig {
                    max_artifact_streams_per_peer: MAX_ARTIFACT_STREAMS_PER_PEER,
                    max_chunk_wait_ms: MAX_CHUNK_WAIT_MS,
                    max_duplicity: MAX_DUPLICITY,
                    max_chunk_size: MAX_CHUNK_SIZE,
                    receive_check_cache_size: RECEIVE_CHECK_PEER_SET_SIZE,
                    pfn_evaluation_period_ms: PFN_EVALUATION_PERIOD_MS,
                    registry_poll_period_ms: REGISTRY_POLL_PERIOD_MS,
                    retransmission_request_ms: RETRANSMISSION_REQUEST_MS,
                }),
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: true,
                halt_at_cup_height: true,
                max_instructions_per_message: 6_000_000_000,
                max_instructions_per_round: 8_000_000_000,
                max_instructions_per_install_code: 300_000_000_000,
                features: None,
                max_number_of_canisters: 42,
                ssh_readonly_access: vec!["pub_key_0".to_string()],
                ssh_backup_access: vec!["pub_key_1".to_string()],
                ecdsa_config: None,
                chain_key_config: None,
            }
        );

        Ok(())
    });
}

#[test]
fn test_subnets_configuration_ecdsa_fields_are_updated_correctly() {
    const ENABLE_BEFORE_ADDING_REJECT_MSG: &str = "Canister rejected with \
    message: IC0503: Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister \
    called `ic0.trap` with message: Panicked at '[Registry] Proposal attempts to enable \
    signing for ECDSA key 'Secp256k1:key_id_1' on Subnet \
    'bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae', but the \
    subnet does not hold the given key. A proposal to add that key to the subnet \
    must first be separately submitted.'";

    const NO_ECDSA_CONFIG_REJECT_MSG: &str = "Canister rejected with message: \
    IC0503: Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister called \
    `ic0.trap` with message: Panicked at '[Registry]  invariant check failed with \
    message: The subnet bn3el-jdvcs-a3syn-gyqwo-umlu3-avgud-vq6yl-hunln-3jejb-226vq-mae \
    does not have an ECDSA config'";

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
            replica_version_id: ReplicaVersion::default().into(),
            dkg_interval_length: 0,
            dkg_dealings_per_block: 1,
            gossip_config: Some(build_default_gossip_config()),
            start_as_nns: false,
            subnet_type: SubnetType::Application.into(),
            is_halted: false,
            halt_at_cup_height: false,
            max_instructions_per_message: 5_000_000_000,
            max_instructions_per_round: 7_000_000_000,
            max_instructions_per_install_code: 200_000_000_000,
            features: None,
            max_number_of_canisters: 0,
            ssh_readonly_access: vec![],
            ssh_backup_access: vec![],
            ecdsa_config: None,
            chain_key_config: None,
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

        let signature_request_timeout_ns = Some(12345);
        let idkg_key_rotation_period_ms = Some(12345);

        let ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 10,
            key_ids: vec![make_ecdsa_key("key_id_1")],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns,
            idkg_key_rotation_period_ms,
        });

        // update payload message
        let mut payload = UpdateSubnetPayload {
            ecdsa_config: ecdsa_config.clone(),
            ecdsa_key_signing_enable: Some(vec![make_ecdsa_key("key_id_1")]),
            ..empty_update_subnet_payload(subnet_id)
        };

        assert!(try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "update_subnet",
            Encode!(&payload).unwrap()
        )
        .await
        .unwrap_err()
        .starts_with(ENABLE_BEFORE_ADDING_REJECT_MSG));

        let new_subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        // There should be no change
        assert_eq!(new_subnet_record, subnet_record);

        // Change one field at a time in this payload
        payload = UpdateSubnetPayload {
            ecdsa_config: None,
            ecdsa_key_signing_enable: Some(vec![make_ecdsa_key("key_id_1")]),
            ..empty_update_subnet_payload(subnet_id)
        };

        assert!(try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "update_subnet",
            Encode!(&payload).unwrap()
        )
        .await
        .unwrap_err()
        .starts_with(NO_ECDSA_CONFIG_REJECT_MSG));

        let new_subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        // There should be no change
        assert_eq!(new_subnet_record, subnet_record);

        // Trying again, this time in the correct order
        payload = UpdateSubnetPayload {
            ecdsa_config: ecdsa_config.clone(),
            ecdsa_key_signing_enable: None,
            ..empty_update_subnet_payload(subnet_id)
        };

        assert!(try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "update_subnet",
            Encode!(&payload).unwrap()
        )
        .await
        .is_ok());

        let new_subnet_record = get_value_or_panic::<SubnetRecord>(
            &registry,
            make_subnet_record_key(subnet_id).as_bytes(),
        )
        .await;

        // Should see the new value for the config reflected
        let ecdsa_config_pb = ecdsa_config.clone().map(EcdsaConfigPb::from);
        let chain_key_config_pb = ecdsa_config_pb.clone().map(ChainKeyConfigPb::from);
        assert_eq!(
            new_subnet_record,
            SubnetRecord {
                ecdsa_config: ecdsa_config_pb,
                chain_key_config: chain_key_config_pb,
                ..subnet_record
            }
        );

        // This update should enable signing on our subnet for the given key.
        payload = UpdateSubnetPayload {
            ecdsa_config: ecdsa_config.clone(),
            ecdsa_key_signing_enable: Some(vec![make_ecdsa_key("key_id_1")]),
            ..empty_update_subnet_payload(subnet_id)
        };

        assert!(try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "update_subnet",
            Encode!(&payload).unwrap()
        )
        .await
        .is_ok());

        let subnet_record = get_subnet_record(&registry, subnet_id).await;
        {
            let legacy_ecdsa_config = subnet_record.ecdsa_config.unwrap();
            assert_eq!(
                legacy_ecdsa_config.max_queue_size,
                DEFAULT_ECDSA_MAX_QUEUE_SIZE
            );
        }

        let new_signing_subnet_list: Vec<_> = get_value_or_panic::<EcdsaSigningSubnetList>(
            &registry,
            make_ecdsa_signing_subnet_list_key(&make_ecdsa_key("key_id_1")).as_bytes(),
        )
        .await
        .subnets
        .into_iter()
        .map(|subnet_bytes| subnet_id_try_from_protobuf(subnet_bytes).unwrap())
        .collect();

        // The subnet is now responsible for signing with the key.
        assert_eq!(new_signing_subnet_list, vec![subnet_id]);

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
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: false,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        max_instructions_per_message: None,
        max_instructions_per_round: None,
        max_instructions_per_install_code: None,
        features: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        ecdsa_config: None,
        ecdsa_key_signing_enable: None,
        ecdsa_key_signing_disable: None,
    }
}
