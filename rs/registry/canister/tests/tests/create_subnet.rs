use candid::Encode;
use dfn_candid::candid;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::invariant_compliant_mutation_as_atomic_req,
};
use ic_protobuf::registry::crypto::v1::{EcdsaCurve as pbEcdsaCurve, EcdsaKeyId as pbEcdsaKeyId};

use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest, upsert};

use ic_types::p2p::{
    MAX_ARTIFACT_STREAMS_PER_PEER, MAX_CHUNK_SIZE, MAX_CHUNK_WAIT_MS, MAX_DUPLICITY,
    PFN_EVALUATION_PERIOD_MS, RECEIVE_CHECK_PEER_SET_SIZE, REGISTRY_POLL_PERIOD_MS,
    RETRANSMISSION_REQUEST_MS,
};
use ic_types::NodeId;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder, mutations::do_create_subnet::CreateSubnetPayload,
};

use crate::test_helpers::{
    dummy_cup_for_subnet, get_added_subnet, get_cup_contents, get_subnet_holding_ecdsa_keys,
    get_subnet_list_record, prepare_registry_with_nodes, set_up_universal_canister_as_governance,
    setup_registry_synced_with_fake_client,
};
use assert_matches::assert_matches;
use canister_test::Runtime;
use ic_config::Config;
use ic_ic00_types::{EcdsaCurve, EcdsaKeyId};
use ic_interfaces::registry::RegistryClient;
use ic_nns_test_utils::itest_helpers::try_call_via_universal_canister;
use ic_replica_tests::{canister_test_with_config_async, get_ic_config};
use ic_test_utilities::types::ids::subnet_test_id;
use registry_canister::mutations::common::decode_registry_value;
use registry_canister::mutations::do_create_subnet::{EcdsaInitialConfig, EcdsaKeyRequest};

#[test]
fn test_the_anonymous_user_cannot_create_a_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        let (init_mutate, node_ids) = prepare_registry_with_nodes(4);
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
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
fn test_a_canister_other_than_the_proposals_canister_cannot_create_a_subnet() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let (init_mutate, node_ids) = prepare_registry_with_nodes(5);
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
            Runtime::Remote(_) => {
                panic!("Cannot run this test on Runtime::Remote at this time");
            }
            Runtime::Local(ref r) => (r.registry_data_provider.clone(), r.registry_client.clone()),
        };

        let (init_mutate, node_ids) = prepare_registry_with_nodes(5);

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

        assert!(cup_contents
            .initial_ni_dkg_transcript_low_threshold
            .is_some());
        assert!(cup_contents
            .initial_ni_dkg_transcript_high_threshold
            .is_some());

        Ok(())
    });
}

#[test]
fn test_accepted_proposal_with_ecdsa_gets_keys_from_other_subnet() {
    let mut ic_config = get_ic_config();
    let mut subnet_config = ic_config.topology_config.get_subnet(0).unwrap();
    subnet_config.features.ecdsa_signatures = true;
    ic_config.topology_config.insert_subnet(0, subnet_config);

    let (config, _tmpdir) = Config::temp_config();
    let subnet_config = ic_config::subnet_config::SubnetConfig::default_system_subnet();
    canister_test_with_config_async(
        config,
        subnet_config,
        ic_config,
        |local_runtime| async move {
            let runtime = Runtime::Local(local_runtime);
            // Given a registry
            let (data_provider, fake_client) = match runtime {
                Runtime::Remote(_) => {
                    panic!("Cannot run this test on Runtime::Remote at this time");
                }
                Runtime::Local(ref r) => {
                    (r.registry_data_provider.clone(), r.registry_client.clone())
                }
            };

            // Here we set up the ECDSA-holding subnets in the registry for the following 2 keys
            let key_1 = EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "foo-bar".to_string(),
            };
            let key_2 = EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "bar-baz".to_string(),
            };

            let (init_mutate, mut node_ids) = prepare_registry_with_nodes(5);

            let key_1_nodes = vec![node_ids.pop().unwrap()];
            let key_2_nodes = vec![node_ids.pop().unwrap()];

            let subnet_holding_key_1 =
                get_subnet_holding_ecdsa_keys(&[key_1.clone()], key_1_nodes.clone());
            let subnet_holding_key_2 =
                get_subnet_holding_ecdsa_keys(&[key_2.clone()], key_2_nodes.clone());

            // Get our base list of subnets
            let mut subnet_list_record = decode_registry_value::<SubnetListRecord>(
                fake_client
                    .get_value(
                        &make_subnet_list_record_key(),
                        fake_client.get_latest_version(),
                    )
                    .unwrap()
                    .unwrap(),
            );

            let key_1_subnet_id = subnet_test_id(1001);
            let key_2_subnet_id = subnet_test_id(1002);

            subnet_list_record
                .subnets
                .push(key_1_subnet_id.get().into_vec());

            subnet_list_record
                .subnets
                .push(key_2_subnet_id.get().into_vec());

            // Add the subnets holding requested keys
            // Note, because these mutations are also synced with underlying IC registry, they
            // need a CUP
            let mutations = vec![
                upsert(
                    make_subnet_record_key(key_1_subnet_id).into_bytes(),
                    encode_or_panic(&subnet_holding_key_1),
                ),
                upsert(
                    make_subnet_record_key(key_2_subnet_id).into_bytes(),
                    encode_or_panic(&subnet_holding_key_2),
                ),
                upsert(
                    make_subnet_list_record_key().into_bytes(),
                    encode_or_panic(&subnet_list_record),
                ),
                insert(
                    make_crypto_threshold_signing_pubkey_key(key_1_subnet_id).as_bytes(),
                    encode_or_panic(&vec![]),
                ),
                insert(
                    make_crypto_threshold_signing_pubkey_key(key_2_subnet_id).as_bytes(),
                    encode_or_panic(&vec![]),
                ),
                insert(
                    make_catch_up_package_contents_key(key_1_subnet_id).as_bytes(),
                    encode_or_panic(&dummy_cup_for_subnet(key_1_nodes)),
                ),
                insert(
                    make_catch_up_package_contents_key(key_2_subnet_id).as_bytes(),
                    encode_or_panic(&dummy_cup_for_subnet(key_2_nodes)),
                ),
            ];

            let add_subnets_mutate = RegistryAtomicMutateRequest {
                preconditions: vec![],
                mutations,
            };

            let registry = setup_registry_synced_with_fake_client(
                &runtime,
                fake_client,
                data_provider,
                vec![init_mutate, add_subnets_mutate],
            )
            .await;

            // Install the universal canister in place of the governance canister
            let fake_governance_canister = set_up_universal_canister_as_governance(&runtime).await;

            // First, we get the initial list of subnets
            let initial_subnet_list_record = get_subnet_list_record(&registry).await;

            // Create payload message with 2 EcdsaKeyRequests
            let payload = {
                let mut payload = make_create_subnet_payload(node_ids.clone());
                payload.ecdsa_config = Some(EcdsaInitialConfig {
                    quadruples_to_create_in_advance: 101,
                    keys: vec![
                        EcdsaKeyRequest {
                            key_id: key_1,
                            // TODO(NNS1-1362) - We need a way to test targeting subnets
                            subnet_id: None, // should be able to test: Some(key_1_subnet_id.get()),
                        },
                        EcdsaKeyRequest {
                            key_id: key_2,
                            subnet_id: None,
                        },
                    ],
                });
                payload
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

            // Check EcdsaInitializations
            let dealings = &cup_contents.ecdsa_initializations;
            assert_eq!(dealings.len(), 2);
            assert_eq!(
                dealings[0_usize].key_id,
                Some(pbEcdsaKeyId {
                    curve: pbEcdsaCurve::Secp256k1.into(),
                    name: "foo-bar".to_string(),
                })
            );
            assert_eq!(
                dealings[1_usize].key_id,
                Some(pbEcdsaKeyId {
                    curve: pbEcdsaCurve::Secp256k1.into(),
                    name: "bar-baz".to_string(),
                })
            );

            // Check EcdsaConfig
            let ecdsa_config = subnet_record.ecdsa_config.unwrap();

            assert_eq!(ecdsa_config.quadruples_to_create_in_advance, 101);
            let key_ids = ecdsa_config.key_ids;
            assert_eq!(key_ids.len(), 2);
            assert_eq!(
                key_ids[0_usize],
                pbEcdsaKeyId {
                    curve: pbEcdsaCurve::Secp256k1.into(),
                    name: "foo-bar".to_string(),
                }
            );
            assert_eq!(
                key_ids[1_usize],
                pbEcdsaKeyId {
                    curve: pbEcdsaCurve::Secp256k1.into(),
                    name: "bar-baz".to_string(),
                }
            );
        },
    );
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
        ecdsa_config: None,
    }
}
