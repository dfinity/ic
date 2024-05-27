use candid::Encode;
use canister_test::{Canister, Runtime};
use ic_base_types::{subnet_id_into_protobuf, NodeId, PrincipalId, SubnetId};
use ic_config::Config;
use ic_interfaces_registry::RegistryClient;
use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId, MasterPublicKeyId};
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet_with_mutations,
        set_up_registry_canister, set_up_universal_canister, try_call_via_universal_canister,
    },
    registry::{get_value_or_panic, prepare_registry},
};
use ic_protobuf::registry::{
    crypto::v1::{
        ChainKeySigningSubnetList, EcdsaCurve as pbEcdsaCurve, EcdsaKeyId as pbEcdsaKeyId,
        EcdsaSigningSubnetList,
    },
    subnet::v1::{CatchUpPackageContents, EcdsaConfig, SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_chain_key_signing_subnet_list_key,
    make_ecdsa_signing_subnet_list_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest, upsert};
use ic_replica_tests::{canister_test_with_config_async, get_ic_config};
use ic_test_utilities_types::ids::subnet_test_id;
use ic_types::ReplicaVersion;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        common::decode_registry_value,
        do_create_subnet::{CreateSubnetPayload, EcdsaInitialConfig, EcdsaKeyRequest},
        do_recover_subnet::RecoverSubnetPayload,
    },
};
use std::convert::TryFrom;

mod common;
use crate::common::test_helpers::prepare_registry_with_nodes_and_valid_pks;
use common::test_helpers::{
    get_cup_contents, get_subnet_holding_ecdsa_keys, get_subnet_record,
    set_up_universal_canister_as_governance, setup_registry_synced_with_fake_client,
    wait_for_ecdsa_setup,
};
use ic_nns_test_utils::registry::create_subnet_threshold_signing_pubkey_and_cup_mutations;

/// Test that calling "recover_subnet" produces the expected Registry mutations,
/// namely that a subnet's `CatchUpPackageContents` and node membership are
/// updated as expected.
///
/// A note on the use of local_test_on_nns_subnet_with_mutations:
///
/// During this test, we stand-up an IC (the NNS subnet), install the Registry
/// canister and Subnet Handler, and call the "recover_subnet" Subnet Handler
/// method. Any instance of the IC needs a Registry to run, and because when we
/// create a new IC there doesn't exist a Registry Canister yet (because there
/// is no IC to run it on), the new IC uses a fake/static Registry. Once we
/// start this IC, we then deploy the Registry _canister_ onto it, because the
/// Subnet Handler needs the Registry _canister_ to function. However, this puts
/// us into an awkward position where there are 2 registries: the fake/static
/// one used by the underlying IC, and the Registry canister installed on top of
/// this IC.
///
/// During this test, we want to assert that nodes can be replaced in a subnet,
/// and that new DKG material is generated for these nodes/subnet. The required
/// set-up for this is to create some node records and node cypto info and store
/// it in the Registry canister. These are the replacement nodes we want to
/// replace the subnet's old nodes. With everything set-up, we call
/// "recover_subnet", which calls ic00's "setup_initial_dkg" to generate the DKG
/// info for these nodes.
///
/// "setup_initial_dkg" is an async call that takes a list of node IDs and
/// eventually delivers these nodes to the Consensus component of the underlying
/// IC. To generate DKG material, Consensus looks up the node records and node
/// crypto info for these nodes in the Registry. HOWEVER, these nodes are not in
/// the IC's fake/static Registry! These nodes were only added to the Registry
/// _canister_, not the IC's fake/static Registry. In order to ensure that
/// Consensus has access to these node records, we use
/// `common::prepare_registry` to get the list of node mutations used by this
/// test. We then use `local_test_on_nns_subnet_with_mutations` to apply these
/// mutations to the fake/static Registry used by the underlying IC, and then in
/// this test, we also apply these same mutations to the Registry _canister_.
/// This ensures that both the fake/static Registry and Registry _canister_ are
/// sync'd on the same node records.
#[test]
fn test_recover_subnet_with_replacement_nodes() {
    let num_nodes_in_subnet = 4_usize;
    let num_unassigned_nodes = 5_usize;
    let (init_mutate, subnet_id, unassigned_node_ids, node_mutations) =
        prepare_registry(num_nodes_in_subnet, num_unassigned_nodes);

    local_test_on_nns_subnet_with_mutations(node_mutations, move |runtime| {
        async move {
            // In order to correctly allow the subnet handler to call atomic_mutate, we
            // must first create canisters to get their IDs, and only then install them.
            // This way, we pass the initial payload to the registry so it would allow
            // mutation by the subnet handler.
            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            // Install the universal canister in place of the governance canister
            let fake_governance_canister = set_up_universal_canister(&runtime).await;
            // Since it takes the id reserved for the governance canister, it can
            // impersonate it
            assert_eq!(
                fake_governance_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            let cup_contents_key = make_catch_up_package_contents_key(subnet_id).into_bytes();
            let initial_cup_contents: CatchUpPackageContents =
                get_value_or_panic(&registry, &cup_contents_key).await;

            // Ensure that the subnet record is there
            let subnet_list_record = get_value_or_panic::<SubnetListRecord>(
                &registry,
                make_subnet_list_record_key().as_bytes(),
            )
            .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);

            let payload = RecoverSubnetPayload {
                subnet_id: subnet_id.get(),
                height: 10,
                time_ns: 1200,
                state_hash: vec![10, 20, 30],
                replacement_nodes: Some(unassigned_node_ids.clone()),
                registry_store_uri: None,
                ecdsa_config: None,
            };

            assert!(
                forward_call_via_universal_canister(
                    &fake_governance_canister,
                    &registry,
                    "recover_subnet",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            let subnet_list_record = get_value_or_panic::<SubnetListRecord>(
                &registry,
                make_subnet_list_record_key().as_bytes(),
            )
            .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record = get_subnet_record(&registry, subnet_id).await;

            // Assert that `membership` has been replaced by `unassigned_node_ids`
            assert_eq!(subnet_record.membership.len(), num_unassigned_nodes);
            for node_id in unassigned_node_ids {
                let node_id = node_id.get().to_vec();
                assert!(subnet_record.membership.iter().any(|x| *x == node_id));
            }

            let updated_cup_contents: CatchUpPackageContents =
                get_value_or_panic(&registry, &cup_contents_key).await;

            // Assert that the CatchUpPackageContents was updated as expected
            assert_eq!(payload.height, updated_cup_contents.height);
            assert_eq!(payload.time_ns, updated_cup_contents.time);
            assert_eq!(payload.state_hash, updated_cup_contents.state_hash);

            // DKG should have been changed
            assert_ne!(
                initial_cup_contents.initial_ni_dkg_transcript_low_threshold,
                updated_cup_contents.initial_ni_dkg_transcript_low_threshold
            );
            assert_ne!(
                initial_cup_contents.initial_ni_dkg_transcript_high_threshold,
                updated_cup_contents.initial_ni_dkg_transcript_high_threshold
            );

            Ok(())
        }
    });
}

#[test]
fn test_recover_subnet_gets_ecdsa_keys_when_needed() {
    let ic_config = get_ic_config();
    let (config, _tmpdir) = Config::temp_config();
    canister_test_with_config_async(config, ic_config, |local_runtime| async move {
        let data_provider = local_runtime.registry_data_provider.clone();
        let fake_client = local_runtime.registry_client.clone();

        let runtime = Runtime::Local(local_runtime);
        // get some nodes for our tests
        let (init_mutate, node_ids_and_valid_pks) = prepare_registry_with_nodes_and_valid_pks(5, 0);
        let mut node_ids: Vec<NodeId> = node_ids_and_valid_pks.keys().cloned().collect();

        let key_1 = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "foo-bar".to_string(),
        };

        let subnet_to_recover_nodes = vec![node_ids.pop().unwrap()];
        let subnet_to_recover: SubnetRecord = CreateSubnetPayload {
            node_ids: subnet_to_recover_nodes.clone(),
            unit_delay_millis: 10,
            gossip_retransmission_request_ms: 10_000,
            gossip_registry_poll_period_ms: 2000,
            gossip_pfn_evaluation_period_ms: 50,
            gossip_receive_check_cache_size: 1,
            gossip_max_duplicity: 1,
            gossip_max_chunk_wait_ms: 200,
            gossip_max_artifact_streams_per_peer: 1,
            replica_version_id: ReplicaVersion::default().into(),
            ..CreateSubnetPayload::default()
        }
        .into();

        // Here we discover the IC's subnet ID (from our test harness)
        // and then modify it to hold the key and sign for it.
        let mut subnet_list_record = decode_registry_value::<SubnetListRecord>(
            fake_client
                .get_value(
                    &make_subnet_list_record_key(),
                    fake_client.get_latest_version(),
                )
                .unwrap()
                .unwrap(),
        );

        let subnet_to_recover_subnet_id = subnet_test_id(1003);

        subnet_list_record
            .subnets
            .push(subnet_to_recover_subnet_id.get().into_vec());

        let subnet_principals = subnet_list_record
            .subnets
            .iter()
            .map(|record| PrincipalId::try_from(record).unwrap())
            .collect::<Vec<_>>();
        let system_subnet_principal = subnet_principals.first().unwrap();

        let system_subnet_id = SubnetId::new(*system_subnet_principal);
        let mut subnet_record = decode_registry_value::<SubnetRecord>(
            fake_client
                .get_value(
                    &make_subnet_record_key(system_subnet_id),
                    fake_client.get_latest_version(),
                )
                .unwrap()
                .unwrap(),
        );
        subnet_record.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![(&key_1).into()],
            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });

        let modify_base_subnet_mutate = RegistryAtomicMutateRequest {
            mutations: vec![upsert(
                make_subnet_record_key(system_subnet_id),
                encode_or_panic(&subnet_record),
            )],
            preconditions: vec![],
        };

        let mut subnet_threshold_signing_pk_and_cup_mutations =
            create_subnet_threshold_signing_pubkey_and_cup_mutations(
                subnet_to_recover_subnet_id,
                &node_ids_and_valid_pks
                    .iter()
                    .map(|(node_id, valid_pks)| {
                        (*node_id, valid_pks.dkg_dealing_encryption_key().clone())
                    })
                    .collect(),
            );

        // Add the subnet we are recovering holding requested keys
        // Note, because these mutations are also synced with underlying IC registry, they
        // need a CUP
        let mut mutations = vec![
            upsert(
                make_subnet_record_key(subnet_to_recover_subnet_id).into_bytes(),
                encode_or_panic(&subnet_to_recover),
            ),
            upsert(
                make_subnet_list_record_key().into_bytes(),
                encode_or_panic(&subnet_list_record),
            ),
        ];
        mutations.append(&mut subnet_threshold_signing_pk_and_cup_mutations);

        let add_subnets_mutate = RegistryAtomicMutateRequest {
            preconditions: vec![],
            mutations,
        };

        let registry = setup_registry_synced_with_fake_client(
            &runtime,
            fake_client,
            data_provider,
            vec![
                init_mutate,
                add_subnets_mutate,
                modify_base_subnet_mutate,
                // ecdsa_signing_subnets_mutate,
            ],
        )
        .await;

        // Then we need to ensure the CUP for our subnet under test
        // does not contain the ecdsa_initializations, since we will be asserting those were added
        let before_recover_cup_contents =
            get_cup_contents(&registry, subnet_to_recover_subnet_id).await;
        assert_eq!(before_recover_cup_contents.ecdsa_initializations.len(), 0);

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister_as_governance(&runtime).await;
        println!("waiting for ecdsa setup");

        wait_for_ecdsa_setup(&runtime, &fake_governance_canister, &key_1).await;

        let signature_request_timeout_ns = Some(12345);
        let idkg_key_rotation_period_ms = Some(12345);
        let payload = RecoverSubnetPayload {
            subnet_id: subnet_to_recover_subnet_id.get(),
            height: 10,
            time_ns: 1200,
            state_hash: vec![10, 20, 30],
            replacement_nodes: None,
            registry_store_uri: None,
            ecdsa_config: Some(EcdsaInitialConfig {
                quadruples_to_create_in_advance: 1,
                keys: vec![EcdsaKeyRequest {
                    key_id: key_1.clone(),
                    subnet_id: Some(system_subnet_id.get()),
                }],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns,
                idkg_key_rotation_period_ms,
            }),
        };

        // When we recover a subnet with specified ecdsa_keys
        try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "recover_subnet",
            Encode!(&payload).unwrap(),
        )
        .await
        .unwrap();

        let cup_contents = get_cup_contents(&registry, subnet_to_recover_subnet_id).await;

        // Check EcdsaInitializations
        let dealings = &cup_contents.ecdsa_initializations;
        assert_eq!(dealings.len(), 1);
        assert_eq!(
            dealings[0_usize].key_id,
            Some(pbEcdsaKeyId {
                curve: pbEcdsaCurve::Secp256k1.into(),
                name: "foo-bar".to_string(),
            })
        );

        // Check EcdsaConfig is correctly updated
        let subnet_record = get_subnet_record(&registry, subnet_to_recover_subnet_id).await;
        let ecdsa_config = subnet_record.ecdsa_config.unwrap();
        assert_eq!(ecdsa_config.max_queue_size, DEFAULT_ECDSA_MAX_QUEUE_SIZE);
        assert_eq!(
            ecdsa_config.signature_request_timeout_ns,
            signature_request_timeout_ns
        );
        assert_eq!(
            ecdsa_config.idkg_key_rotation_period_ms,
            idkg_key_rotation_period_ms
        );

        let key_ids = ecdsa_config.key_ids;
        assert_eq!(key_ids.len(), 1);

        assert_eq!(
            key_ids[0_usize],
            pbEcdsaKeyId {
                curve: pbEcdsaCurve::Secp256k1.into(),
                name: "foo-bar".to_string(),
            }
        );
    });
}

#[test]
fn test_recover_subnet_without_ecdsa_key_removes_it_from_signing_list() {
    let ic_config = get_ic_config();
    let (config, _tmpdir) = Config::temp_config();
    canister_test_with_config_async(config, ic_config, |local_runtime| async move {
        let data_provider = local_runtime.registry_data_provider.clone();
        let fake_client = local_runtime.registry_client.clone();

        let runtime = Runtime::Local(local_runtime);
        // get some nodes for our tests
        let (init_mutate, node_ids_and_valid_pks) = prepare_registry_with_nodes_and_valid_pks(5, 0);
        let mut node_ids: Vec<NodeId> = node_ids_and_valid_pks.keys().cloned().collect();

        let key_1 = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "foo-bar".to_string(),
        };

        let subnet_to_recover_nodes = vec![node_ids.pop().unwrap()];
        let subnet_to_recover =
            get_subnet_holding_ecdsa_keys(&[key_1.clone()], subnet_to_recover_nodes.clone());

        // Here we discover the IC's subnet ID (from our test harness)
        // and then modify it to hold the key and sign for it.
        let mut subnet_list_record = decode_registry_value::<SubnetListRecord>(
            fake_client
                .get_value(
                    &make_subnet_list_record_key(),
                    fake_client.get_latest_version(),
                )
                .unwrap()
                .unwrap(),
        );

        let subnet_to_recover_subnet_id = subnet_test_id(1003);

        subnet_list_record
            .subnets
            .push(subnet_to_recover_subnet_id.get().into_vec());

        let subnet_principals = subnet_list_record
            .subnets
            .iter()
            .map(|record| PrincipalId::try_from(record).unwrap())
            .collect::<Vec<_>>();
        let system_subnet_principal = subnet_principals.first().unwrap();

        let system_subnet_id = SubnetId::new(*system_subnet_principal);
        let mut subnet_record = decode_registry_value::<SubnetRecord>(
            fake_client
                .get_value(
                    &make_subnet_record_key(system_subnet_id),
                    fake_client.get_latest_version(),
                )
                .unwrap()
                .unwrap(),
        );
        subnet_record.ecdsa_config = Some(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![(&key_1).into()],
            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });

        let modify_base_subnet_mutate = RegistryAtomicMutateRequest {
            mutations: vec![upsert(
                make_subnet_record_key(system_subnet_id),
                encode_or_panic(&subnet_record),
            )],
            preconditions: vec![],
        };

        let mut subnet_threshold_signing_pk_and_cup_mutations =
            create_subnet_threshold_signing_pubkey_and_cup_mutations(
                subnet_to_recover_subnet_id,
                &node_ids_and_valid_pks
                    .iter()
                    .map(|(node_id, valid_pks)| {
                        (*node_id, valid_pks.dkg_dealing_encryption_key().clone())
                    })
                    .collect(),
            );

        // Add the subnet we are recovering holding requested keys
        // Note, because these mutations are also synced with underlying IC registry, they
        // need a CUP
        let mut mutations = vec![
            upsert(
                make_subnet_record_key(subnet_to_recover_subnet_id).into_bytes(),
                encode_or_panic(&subnet_to_recover),
            ),
            upsert(
                make_subnet_list_record_key().into_bytes(),
                encode_or_panic(&subnet_list_record),
            ),
        ];
        mutations.append(&mut subnet_threshold_signing_pk_and_cup_mutations);

        let add_subnets_mutate = RegistryAtomicMutateRequest {
            preconditions: vec![],
            mutations,
        };

        // Enable signing with the recovering subnet - we will later check that
        // this subnet is removed from the signing subnet list.
        let ecdsa_signing_subnets_mutate = RegistryAtomicMutateRequest {
            preconditions: vec![],
            mutations: vec![
                insert(
                    make_ecdsa_signing_subnet_list_key(&key_1),
                    encode_or_panic(&EcdsaSigningSubnetList {
                        subnets: vec![subnet_id_into_protobuf(subnet_to_recover_subnet_id)],
                    }),
                ),
                insert(
                    make_chain_key_signing_subnet_list_key(&MasterPublicKeyId::Ecdsa(
                        key_1.clone(),
                    )),
                    encode_or_panic(&ChainKeySigningSubnetList {
                        subnets: vec![subnet_id_into_protobuf(subnet_to_recover_subnet_id)],
                    }),
                ),
            ],
        };

        let registry = setup_registry_synced_with_fake_client(
            &runtime,
            fake_client,
            data_provider,
            vec![
                init_mutate,
                add_subnets_mutate,
                modify_base_subnet_mutate,
                ecdsa_signing_subnets_mutate,
            ],
        )
        .await;

        // Then we need to ensure the CUP for our subnet under test
        // does not contain the ecdsa_initializations, since we will be asserting those were added
        let before_recover_cup_contents =
            get_cup_contents(&registry, subnet_to_recover_subnet_id).await;
        assert_eq!(before_recover_cup_contents.ecdsa_initializations.len(), 0);

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister_as_governance(&runtime).await;

        let signature_request_timeout_ns = Some(12345);
        let idkg_key_rotation_period_ms = Some(12345);
        let payload = RecoverSubnetPayload {
            subnet_id: subnet_to_recover_subnet_id.get(),
            height: 10,
            time_ns: 1200,
            state_hash: vec![10, 20, 30],
            replacement_nodes: None,
            registry_store_uri: None,
            ecdsa_config: Some(EcdsaInitialConfig {
                quadruples_to_create_in_advance: 1,
                keys: vec![],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns,
                idkg_key_rotation_period_ms,
            }),
        };

        // When we recover a subnet with specified ecdsa_keys
        try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "recover_subnet",
            Encode!(&payload).unwrap(),
        )
        .await
        .unwrap();

        let cup_contents = get_cup_contents(&registry, subnet_to_recover_subnet_id).await;

        // Check EcdsaInitializations
        let dealings = &cup_contents.ecdsa_initializations;
        assert_eq!(dealings.len(), 0);

        // Check EcdsaConfig is correctly updated
        let subnet_record = get_subnet_record(&registry, subnet_to_recover_subnet_id).await;
        let ecdsa_config = subnet_record.ecdsa_config.unwrap();
        assert_eq!(ecdsa_config.max_queue_size, DEFAULT_ECDSA_MAX_QUEUE_SIZE);
        assert_eq!(
            ecdsa_config.signature_request_timeout_ns,
            signature_request_timeout_ns
        );
        assert_eq!(
            ecdsa_config.idkg_key_rotation_period_ms,
            idkg_key_rotation_period_ms
        );

        let key_ids = ecdsa_config.key_ids;
        assert_eq!(key_ids.len(), 0);

        // Check ecdsa_signing_subnets_list for key_1 is empty now.
        let ecdsa_signing_subnet_list = ecdsa_signing_subnet_list(&registry, &key_1).await;
        assert_eq!(
            ecdsa_signing_subnet_list,
            EcdsaSigningSubnetList { subnets: vec![] }
        )
    });
}

#[test]
fn test_recover_subnet_resets_the_halt_at_cup_height_flag() {
    let ic_config = get_ic_config();
    let (config, _tmpdir) = Config::temp_config();
    canister_test_with_config_async(config, ic_config, |local_runtime| async move {
        let data_provider = local_runtime.registry_data_provider.clone();
        let fake_client = local_runtime.registry_client.clone();

        let runtime = Runtime::Local(local_runtime);
        // get some nodes for our tests
        let (init_mutate, node_ids_and_valid_pks) = prepare_registry_with_nodes_and_valid_pks(5, 0);
        let mut node_ids: Vec<NodeId> = node_ids_and_valid_pks.keys().cloned().collect();

        let subnet_to_recover_nodes = vec![node_ids.pop().unwrap()];
        let mut subnet_to_recover: SubnetRecord = CreateSubnetPayload {
            unit_delay_millis: 10,
            gossip_retransmission_request_ms: 10_000,
            gossip_registry_poll_period_ms: 2000,
            gossip_pfn_evaluation_period_ms: 50,
            gossip_receive_check_cache_size: 1,
            gossip_max_duplicity: 1,
            gossip_max_chunk_wait_ms: 200,
            gossip_max_artifact_streams_per_peer: 1,
            replica_version_id: ReplicaVersion::default().into(),
            node_ids: subnet_to_recover_nodes.clone(),
            ..Default::default()
        }
        .into();

        // Set the `halt_at_cup_height` to `true`, to verify that it will be later set to `false`.
        subnet_to_recover.halt_at_cup_height = true;
        subnet_to_recover.is_halted = false;

        let mut subnet_list_record = decode_registry_value::<SubnetListRecord>(
            fake_client
                .get_value(
                    &make_subnet_list_record_key(),
                    fake_client.get_latest_version(),
                )
                .unwrap()
                .unwrap(),
        );

        let subnet_to_recover_subnet_id = subnet_test_id(1003);

        subnet_list_record
            .subnets
            .push(subnet_to_recover_subnet_id.get().into_vec());

        let mut subnet_threshold_signing_pk_and_cup_mutations =
            create_subnet_threshold_signing_pubkey_and_cup_mutations(
                subnet_to_recover_subnet_id,
                &node_ids_and_valid_pks
                    .iter()
                    .map(|(node_id, valid_pks)| {
                        (*node_id, valid_pks.dkg_dealing_encryption_key().clone())
                    })
                    .collect(),
            );

        let mut mutations = vec![
            upsert(
                make_subnet_record_key(subnet_to_recover_subnet_id).into_bytes(),
                encode_or_panic(&subnet_to_recover),
            ),
            upsert(
                make_subnet_list_record_key().into_bytes(),
                encode_or_panic(&subnet_list_record),
            ),
        ];
        mutations.append(&mut subnet_threshold_signing_pk_and_cup_mutations);

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

        let payload = RecoverSubnetPayload {
            subnet_id: subnet_to_recover_subnet_id.get(),
            height: 10,
            time_ns: 1200,
            state_hash: vec![10, 20, 30],
            replacement_nodes: None,
            registry_store_uri: None,
            ecdsa_config: None,
        };

        try_call_via_universal_canister(
            &fake_governance_canister,
            &registry,
            "recover_subnet",
            Encode!(&payload).unwrap(),
        )
        .await
        .unwrap();

        // Verify that the `halt_at_cup_height` and `is_halted` flags are correctly set.
        let subnet_record = get_subnet_record(&registry, subnet_to_recover_subnet_id).await;

        assert!(!subnet_record.halt_at_cup_height);
        assert!(subnet_record.is_halted);
    });
}

pub async fn ecdsa_signing_subnet_list(
    registry: &Canister<'_>,
    key_id: &EcdsaKeyId,
) -> EcdsaSigningSubnetList {
    get_value_or_panic::<EcdsaSigningSubnetList>(
        registry,
        make_ecdsa_signing_subnet_list_key(key_id).as_bytes(),
    )
    .await
}
