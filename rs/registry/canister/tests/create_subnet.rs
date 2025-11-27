use assert_matches::assert_matches;
use candid::Encode;
use canister_test::Runtime;
use common::test_helpers::{
    get_added_subnet, get_cup_contents, get_subnet_list_record, prepare_registry_with_nodes,
    set_up_universal_canister_as_governance, setup_registry_synced_with_fake_client,
    wait_for_chain_key_setup,
};
use dfn_candid::candid;
use ic_base_types::{PrincipalId, SubnetId};
use ic_config::Config;
use ic_interfaces_registry::RegistryClient;
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
    VetKdKeyId,
};
use ic_nns_test_utils::itest_helpers::try_call_via_universal_canister;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{INITIAL_MUTATION_ID, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::subnet::v1::{
    ChainKeyConfig as ChainKeyConfigPb, SubnetListRecord as SubnetListRecordPb,
    SubnetRecord as SubnetRecordPb,
};
use ic_protobuf::types::v1::MasterPublicKeyId as MasterPublicKeyIdPb;
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_subnet_features::{
    ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE, KeyConfig as KeyConfigInternal,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{pb::v1::RegistryAtomicMutateRequest, upsert};
use ic_replica_tests::{canister_test_with_config_async, get_ic_config};
use ic_types::{NodeId, ReplicaVersion};
use prost::Message;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_create_subnet::{
        CanisterCyclesCostSchedule, CreateSubnetPayload, InitialChainKeyConfig, KeyConfig,
        KeyConfigRequest,
    },
};
use std::convert::TryFrom;

mod common;

#[test]
fn test_the_anonymous_user_cannot_create_a_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        let (init_mutate, node_ids) = prepare_registry_with_nodes(4, INITIAL_MUTATION_ID);
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(
                    4 + INITIAL_MUTATION_ID,
                ))
                .push_init_mutate_request(init_mutate)
                .build(),
        )
        .await;

        let initial_subnet_list_record = get_subnet_list_record(&registry).await;

        let payload = make_create_subnet_payload(node_ids.clone());

        // The anonymous end-user tries to create a subnet, bypassing governance
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
fn test_a_canister_other_than_the_governance_canister_cannot_create_a_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let (init_mutate, node_ids) = prepare_registry_with_nodes(5, INITIAL_MUTATION_ID);
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

        let payload = make_create_subnet_payload(node_ids.clone());

        // The attacker canister tries to create a subnet, pretending to be the
        // governance canister. This should have no effect.
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
            Runtime::Remote(_) | Runtime::StateMachine(_) => {
                panic!(
                    "Cannot run this test on Runtime::Remote or Runtime::StateMachine at this time"
                );
            }
            Runtime::Local(ref r) => (r.registry_data_provider.clone(), r.registry_client.clone()),
        };

        let (init_mutate, node_ids) = prepare_registry_with_nodes(5, INITIAL_MUTATION_ID);

        let registry = setup_registry_synced_with_fake_client(
            &runtime,
            fake_client,
            data_provider,
            vec![init_mutate],
        )
        .await;

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister_as_governance(&runtime).await;

        // first, get current list of subnets created by underlying system
        let initial_subnet_list_record = get_subnet_list_record(&registry).await;
        // create payload message
        let payload = make_create_subnet_payload(node_ids.clone());

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
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

        assert!(
            cup_contents
                .initial_ni_dkg_transcript_low_threshold
                .is_some()
        );
        assert!(
            cup_contents
                .initial_ni_dkg_transcript_high_threshold
                .is_some()
        );

        Ok(())
    });
}

fn test_accepted_proposal_with_chain_key_gets_keys_from_other_subnet(key_id: MasterPublicKeyId) {
    let ic_config = get_ic_config();

    let (config, _tmpdir) = Config::temp_config();
    canister_test_with_config_async(config, ic_config, |local_runtime| async move {
        let data_provider = local_runtime.registry_data_provider.clone();
        let fake_client = local_runtime.registry_client.clone();

        let runtime = Runtime::Local(local_runtime);

        let (init_mutate, node_ids) = prepare_registry_with_nodes(5, INITIAL_MUTATION_ID);

        // Here we discover the IC's subnet ID (from our test harness)
        // and then modify it to hold the key.
        let subnet_list_record = SubnetListRecordPb::decode(
            fake_client
                .get_value(
                    &make_subnet_list_record_key(),
                    fake_client.get_latest_version(),
                )
                .unwrap()
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let subnet_principals = subnet_list_record
            .subnets
            .iter()
            .map(|record| PrincipalId::try_from(record).unwrap())
            .collect::<Vec<_>>();

        let system_subnet_principal = subnet_principals.first().unwrap();

        let system_subnet_id = SubnetId::new(*system_subnet_principal);
        let mut subnet_record = SubnetRecordPb::decode(
            fake_client
                .get_value(
                    &make_subnet_record_key(system_subnet_id),
                    fake_client.get_latest_version(),
                )
                .unwrap()
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        subnet_record.chain_key_config = Some(ChainKeyConfigPb::from(ChainKeyConfig {
            key_configs: vec![KeyConfigInternal {
                key_id: key_id.clone(),
                pre_signatures_to_create_in_advance: key_id
                    .requires_pre_signatures()
                    .then_some(100),
                max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        }));

        let modify_base_subnet_mutate = RegistryAtomicMutateRequest {
            mutations: vec![upsert(
                make_subnet_record_key(system_subnet_id),
                subnet_record.encode_to_vec(),
            )],
            preconditions: vec![],
        };

        let registry = setup_registry_synced_with_fake_client(
            &runtime,
            fake_client.clone(),
            data_provider,
            vec![init_mutate, modify_base_subnet_mutate],
        )
        .await;

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister_as_governance(&runtime).await;

        wait_for_chain_key_setup(&runtime, &fake_governance_canister, &key_id).await;

        // First, we get the initial list of subnets
        let initial_subnet_list_record = get_subnet_list_record(&registry).await;

        // Create payload message with KeyConfigRequest
        let signature_request_timeout_ns = Some(12345);
        let idkg_key_rotation_period_ms = Some(12345);
        let max_parallel_pre_signature_transcripts_in_creation = Some(12345);
        let payload = CreateSubnetPayload {
            chain_key_config: Some(InitialChainKeyConfig {
                key_configs: vec![KeyConfigRequest {
                    key_config: Some(KeyConfig {
                        key_id: Some(key_id.clone()),
                        pre_signatures_to_create_in_advance: key_id
                            .requires_pre_signatures()
                            .then_some(101),
                        max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                    }),
                    subnet_id: Some(*system_subnet_principal),
                }],
                signature_request_timeout_ns,
                idkg_key_rotation_period_ms,
                max_parallel_pre_signature_transcripts_in_creation,
            }),
            ..make_create_subnet_payload(node_ids.clone())
        };

        // When we create subnet with ecdsa_keys enabled
        try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "create_subnet",
            Encode!(&payload).unwrap(),
        )
        .await
        .unwrap();

        // We get a new subnet
        let (subnet_id, subnet_record) =
            get_added_subnet(&registry, &initial_subnet_list_record).await;

        // Registry adds those keys to the CUP
        let cup_contents = get_cup_contents(&registry, subnet_id).await;

        // Check ChainKeyInitializations
        let dealings = cup_contents.chain_key_initializations;
        assert_eq!(dealings.len(), 1);
        assert_eq!(dealings[0].key_id, Some(MasterPublicKeyIdPb::from(&key_id)));

        // Check ChainKeyConfigPb is correctly updated
        let chain_key_config_pb = subnet_record.chain_key_config.unwrap();
        let chain_key_config = ChainKeyConfig::try_from(chain_key_config_pb).unwrap();

        assert_eq!(
            chain_key_config.signature_request_timeout_ns,
            signature_request_timeout_ns
        );
        assert_eq!(
            chain_key_config.idkg_key_rotation_period_ms,
            idkg_key_rotation_period_ms
        );
        assert_eq!(
            chain_key_config.max_parallel_pre_signature_transcripts_in_creation,
            max_parallel_pre_signature_transcripts_in_creation
        );
        assert_eq!(
            chain_key_config.key_configs,
            vec![KeyConfigInternal {
                key_id: key_id.clone(),
                pre_signatures_to_create_in_advance: key_id
                    .requires_pre_signatures()
                    .then_some(101),
                max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            }],
        );
    });
}

#[test]
fn test_accepted_proposal_with_ecdsa_gets_keys_from_other_subnet() {
    let key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "foo-bar".to_string(),
    });
    test_accepted_proposal_with_chain_key_gets_keys_from_other_subnet(key_id);
}

#[test]
fn test_accepted_proposal_with_schnorr_gets_keys_from_other_subnet() {
    let key_id = MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340Secp256k1,
        name: "foo-bar".to_string(),
    });
    test_accepted_proposal_with_chain_key_gets_keys_from_other_subnet(key_id);
}

#[test]
fn test_accepted_proposal_with_vetkd_gets_keys_from_other_subnet() {
    let key_id = MasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: "foo-bar".to_string(),
    });
    test_accepted_proposal_with_chain_key_gets_keys_from_other_subnet(key_id);
}

// Start helper functions
fn make_create_subnet_payload(node_ids: Vec<NodeId>) -> CreateSubnetPayload {
    // create payload message
    CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
        max_ingress_bytes_per_message: 60 * 1024 * 1024,
        max_ingress_messages_per_block: 1000,
        max_block_payload_size: 4 * 1024 * 1024,
        unit_delay_millis: 500,
        initial_notary_delay_millis: 1500,
        replica_version_id: ReplicaVersion::default().into(),
        dkg_interval_length: 0,
        dkg_dealings_per_block: 1,
        start_as_nns: false,
        subnet_type: SubnetType::Application,
        is_halted: false,
        features: Default::default(),
        max_number_of_canisters: 0,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        chain_key_config: None,
        canister_cycles_cost_schedule: Some(CanisterCyclesCostSchedule::Normal),

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
