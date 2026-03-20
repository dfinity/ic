use std::time::Duration;

use common::test_helpers::install_registry_canister_with_payload_builder;
use ic_base_types::PrincipalId;
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::{
    get_value, migrate_node_operator_directly,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_test_utils::registry::invariant_compliant_mutation_as_atomic_req;
use ic_protobuf::registry::{node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord};
use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
use ic_registry_transport::pb::v1::high_capacity_registry_get_value_response::Content;
use ic_registry_transport::{
    deserialize_get_value_response,
    pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
    serialize_get_value_request, upsert,
};
use ic_types::NodeId;
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;
use prost::Message;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_migrate_node_operator_directly::{MigrateError, MigrateNodeOperatorPayload},
        node_management::{
            common::make_add_node_registry_mutations, do_add_node::connection_endpoint_from_string,
        },
    },
};

mod common;

/// Creates registry mutations to add node operator records and node records.
///
/// Returns the mutations and the list of node IDs created.
fn setup_node_operator_mutations(
    node_operators: &[(PrincipalId, NodeOperatorRecord)],
    nodes_per_operator: &[(PrincipalId, usize)],
) -> (Vec<RegistryMutation>, Vec<(PrincipalId, Vec<NodeId>)>) {
    let mut mutations = invariant_compliant_mutation_as_atomic_req(0).mutations;

    // Add node operator records
    for (principal, record) in node_operators {
        mutations.push(upsert(
            make_node_operator_record_key(*principal).as_bytes(),
            record.encode_to_vec(),
        ));
    }

    // Add nodes for each operator
    let mut all_node_ids = vec![];
    let mut node_index = 0usize;
    for (operator_principal, count) in nodes_per_operator {
        let mut operator_node_ids = vec![];
        for _ in 0..*count {
            let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
            let valid_keys = generate_node_keys_once(&config, None).unwrap();
            let node_id = valid_keys.node_id();
            operator_node_ids.push(node_id);

            mutations.extend(make_add_node_registry_mutations(
                node_id,
                NodeRecord {
                    node_operator_id: operator_principal.to_vec(),
                    xnet: Some(connection_endpoint_from_string(&format!(
                        "192.168.{node_index}.1:1234"
                    ))),
                    http: Some(connection_endpoint_from_string(&format!(
                        "192.168.{node_index}.1:1235"
                    ))),
                    ..Default::default()
                },
                valid_keys,
            ));
            node_index += 1;
        }
        all_node_ids.push((*operator_principal, operator_node_ids));
    }

    (mutations, all_node_ids)
}

fn decode_get_value_response<T: Message + Default>(
    response: ic_registry_transport::pb::v1::HighCapacityRegistryGetValueResponse,
) -> T {
    let content = match response.content.unwrap() {
        Content::Value(items) => items,
        Content::LargeValueChunkKeys(_) => {
            panic!("Didn't expect large value chunk keys")
        }
    };
    T::decode(content.as_slice()).unwrap()
}

/// Checks whether a key exists in the registry via a raw `get_value` query.
///
/// Unlike `get_value`, this does not panic when the key is absent.
async fn key_exists_in_registry(pocket_ic: &PocketIc, key: &str) -> bool {
    let result = pocket_ic
        .query_call(
            REGISTRY_CANISTER_ID.get().0,
            PrincipalId::new_anonymous().0,
            "get_value",
            serialize_get_value_request(key.as_bytes().to_vec(), None).unwrap(),
        )
        .await
        .expect("Query call to registry failed");

    deserialize_get_value_response(result)
        .map(|response| response.error.is_none())
        .unwrap_or(false)
}

fn make_node_operator_record(
    operator_id: PrincipalId,
    provider_id: PrincipalId,
    dc: &str,
    node_allowance: u64,
) -> NodeOperatorRecord {
    NodeOperatorRecord {
        node_operator_principal_id: operator_id.to_vec(),
        node_provider_principal_id: provider_id.to_vec(),
        dc_id: dc.to_string(),
        node_allowance,
        ..Default::default()
    }
}

#[tokio::test]
async fn missing_input() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let builder = RegistryCanisterInitPayloadBuilder::new();
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    // Both fields None
    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: None,
            old_node_operator_id: None,
        },
        PrincipalId::new_user_test_id(1),
    )
    .await;

    let expected_err = MigrateError::MissingInput;
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );

    // Only new_node_operator_id set
    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(PrincipalId::new_user_test_id(2)),
            old_node_operator_id: None,
        },
        PrincipalId::new_user_test_id(1),
    )
    .await;

    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );

    // Only old_node_operator_id set
    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: None,
            old_node_operator_id: Some(PrincipalId::new_user_test_id(1)),
        },
        PrincipalId::new_user_test_id(1),
    )
    .await;

    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );
}

#[tokio::test]
async fn same_principals() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let builder = RegistryCanisterInitPayloadBuilder::new();
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    let principal = PrincipalId::new_user_test_id(1);
    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(principal),
            old_node_operator_id: Some(principal),
        },
        principal,
    )
    .await;

    let expected_err = MigrateError::SamePrincipals;
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );
}

#[tokio::test]
async fn missing_old_node_operator() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let builder = RegistryCanisterInitPayloadBuilder::new();
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    let old_operator = PrincipalId::new_user_test_id(1);
    let new_operator = PrincipalId::new_user_test_id(2);

    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_operator),
            old_node_operator_id: Some(old_operator),
        },
        PrincipalId::new_user_test_id(999),
    )
    .await;

    let expected_err = MigrateError::MissingNodeOperator {
        principal: old_operator,
    };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );
}

#[tokio::test]
async fn not_authorized() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let old_operator_id = PrincipalId::new_user_test_id(1);
    let new_operator_id = PrincipalId::new_user_test_id(2);
    let node_provider_id = PrincipalId::new_user_test_id(3);
    let unauthorized_caller = PrincipalId::new_user_test_id(999);

    let (mutations, _) = setup_node_operator_mutations(
        &[(
            old_operator_id,
            make_node_operator_record(old_operator_id, node_provider_id, "dc1", 5),
        )],
        &[],
    );

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_operator_id),
            old_node_operator_id: Some(old_operator_id),
        },
        unauthorized_caller,
    )
    .await;

    let expected_err = MigrateError::NotAuthorized {
        caller: unauthorized_caller,
        expected: node_provider_id,
    };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );
}

#[tokio::test]
async fn old_operator_rate_limit() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let old_operator_id = PrincipalId::new_user_test_id(1);
    let new_operator_id = PrincipalId::new_user_test_id(2);
    let node_provider_id = PrincipalId::new_user_test_id(3);

    let (mutations, _) = setup_node_operator_mutations(
        &[(
            old_operator_id,
            make_node_operator_record(old_operator_id, node_provider_id, "dc1", 5),
        )],
        &[],
    );

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    let payload = MigrateNodeOperatorPayload {
        new_node_operator_id: Some(new_operator_id),
        old_node_operator_id: Some(old_operator_id),
    };

    // The operator was just created, so it should be rate-limited (< 12 hours old).
    let response =
        migrate_node_operator_directly(&pocket_ic, payload.clone(), node_provider_id).await;

    let expected_err = MigrateError::OldOperatorRateLimit {
        principal: old_operator_id,
    };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );

    // Advance time past the 12-hour rate limit (13 hours)
    pocket_ic
        .advance_time(Duration::from_secs(13 * 60 * 60))
        .await;

    // Now the migration should succeed
    let response =
        migrate_node_operator_directly(&pocket_ic, payload.clone(), node_provider_id).await;

    assert!(response.is_ok(), "Expected ok but got {response:?}");
}

#[tokio::test]
async fn node_provider_mismatch() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let old_operator_id = PrincipalId::new_user_test_id(1);
    let new_operator_id = PrincipalId::new_user_test_id(2);
    let old_provider_id = PrincipalId::new_user_test_id(3);
    let new_provider_id = PrincipalId::new_user_test_id(4);

    let (mutations, _) = setup_node_operator_mutations(
        &[
            (
                old_operator_id,
                make_node_operator_record(old_operator_id, old_provider_id, "dc1", 5),
            ),
            (
                new_operator_id,
                make_node_operator_record(new_operator_id, new_provider_id, "dc1", 5),
            ),
        ],
        &[],
    );

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    // Advance time past the rate limit
    pocket_ic
        .advance_time(Duration::from_secs(13 * 60 * 60))
        .await;

    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_operator_id),
            old_node_operator_id: Some(old_operator_id),
        },
        old_provider_id,
    )
    .await;

    let expected_err = MigrateError::NodeProviderMismatch {
        old: old_provider_id,
        new: new_provider_id,
    };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );
}

#[tokio::test]
async fn data_center_mismatch() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let old_operator_id = PrincipalId::new_user_test_id(1);
    let new_operator_id = PrincipalId::new_user_test_id(2);
    let node_provider_id = PrincipalId::new_user_test_id(3);

    let (mutations, _) = setup_node_operator_mutations(
        &[
            (
                old_operator_id,
                make_node_operator_record(old_operator_id, node_provider_id, "dc1", 5),
            ),
            (
                new_operator_id,
                make_node_operator_record(new_operator_id, node_provider_id, "dc2", 5),
            ),
        ],
        &[],
    );

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    // Advance time past the rate limit
    pocket_ic
        .advance_time(Duration::from_secs(13 * 60 * 60))
        .await;

    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_operator_id),
            old_node_operator_id: Some(old_operator_id),
        },
        node_provider_id,
    )
    .await;

    let expected_err = MigrateError::DataCenterMismatch {
        old: "dc1".to_string(),
        new: "dc2".to_string(),
    };
    assert!(
        response
            .as_ref()
            .is_err_and(|err| err.reject_message.contains(&format!("{}", expected_err))),
        "Expected error {expected_err:?}, but got {response:?}"
    );
}

#[tokio::test]
async fn e2e_successful_migration_new_operator_does_not_exist() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let old_operator_id = PrincipalId::new_user_test_id(1);
    let new_operator_id = PrincipalId::new_user_test_id(2);
    let node_provider_id = PrincipalId::new_user_test_id(3);

    let old_record = NodeOperatorRecord {
        node_operator_principal_id: old_operator_id.to_vec(),
        node_provider_principal_id: node_provider_id.to_vec(),
        dc_id: "dc1".to_string(),
        node_allowance: 10,
        rewardable_nodes: [("type1".to_string(), 5)].into_iter().collect(),
        max_rewardable_nodes: [("type1".to_string(), 8)].into_iter().collect(),
        ..Default::default()
    };

    let (mutations, node_ids) = setup_node_operator_mutations(
        &[(old_operator_id, old_record.clone())],
        &[(old_operator_id, 3)],
    );

    let old_operator_node_ids: Vec<NodeId> = node_ids
        .iter()
        .find(|(op, _)| *op == old_operator_id)
        .unwrap()
        .1
        .clone();

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    // Advance time past the rate limit
    pocket_ic
        .advance_time(Duration::from_secs(13 * 60 * 60))
        .await;

    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_operator_id),
            old_node_operator_id: Some(old_operator_id),
        },
        node_provider_id,
    )
    .await;

    assert!(response.is_ok(), "Expected ok but got {response:?}");

    // Verify: new operator record exists with inherited data
    let new_record: NodeOperatorRecord = decode_get_value_response(
        get_value(
            &pocket_ic,
            make_node_operator_record_key(new_operator_id),
            None,
        )
        .await
        .unwrap(),
    );

    assert_eq!(
        new_record.node_provider_principal_id,
        node_provider_id.to_vec()
    );
    assert_eq!(new_record.dc_id, "dc1");
    assert_eq!(new_record.node_allowance, 10);
    assert_eq!(new_record.rewardable_nodes.get("type1"), Some(&5));
    assert_eq!(new_record.max_rewardable_nodes.get("type1"), Some(&8));

    // Verify: old operator record is deleted
    assert!(
        !key_exists_in_registry(&pocket_ic, &make_node_operator_record_key(old_operator_id)).await,
        "Old node operator record should have been deleted"
    );

    // Verify: all nodes now point to the new operator
    for node_id in &old_operator_node_ids {
        let node_record: NodeRecord = decode_get_value_response(
            get_value(&pocket_ic, make_node_record_key(*node_id), None)
                .await
                .unwrap(),
        );

        assert_eq!(
            node_record.node_operator_id,
            new_operator_id.to_vec(),
            "Node {:?} should point to new operator",
            node_id
        );
    }
}

#[tokio::test]
async fn e2e_successful_migration_new_operator_exists() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let old_operator_id = PrincipalId::new_user_test_id(1);
    let new_operator_id = PrincipalId::new_user_test_id(2);
    let node_provider_id = PrincipalId::new_user_test_id(3);

    let old_record = NodeOperatorRecord {
        node_operator_principal_id: old_operator_id.to_vec(),
        node_provider_principal_id: node_provider_id.to_vec(),
        dc_id: "dc1".to_string(),
        node_allowance: 10,
        rewardable_nodes: [("type1".to_string(), 5), ("type2".to_string(), 3)]
            .into_iter()
            .collect(),
        max_rewardable_nodes: [("type1".to_string(), 8), ("type2".to_string(), 4)]
            .into_iter()
            .collect(),
        ..Default::default()
    };

    let new_record = NodeOperatorRecord {
        node_operator_principal_id: new_operator_id.to_vec(),
        node_provider_principal_id: node_provider_id.to_vec(),
        dc_id: "dc1".to_string(),
        node_allowance: 7,
        rewardable_nodes: [("type1".to_string(), 2)].into_iter().collect(),
        max_rewardable_nodes: [("type1".to_string(), 3)].into_iter().collect(),
        ..Default::default()
    };

    let (mutations, node_ids) = setup_node_operator_mutations(
        &[
            (old_operator_id, old_record.clone()),
            (new_operator_id, new_record.clone()),
        ],
        &[(old_operator_id, 3), (new_operator_id, 2)],
    );

    let old_operator_node_ids: Vec<NodeId> = node_ids
        .iter()
        .find(|(op, _)| *op == old_operator_id)
        .unwrap()
        .1
        .clone();

    let new_operator_node_ids: Vec<NodeId> = node_ids
        .iter()
        .find(|(op, _)| *op == new_operator_id)
        .unwrap()
        .1
        .clone();

    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    });
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;

    // Advance time past the rate limit
    pocket_ic
        .advance_time(Duration::from_secs(13 * 60 * 60))
        .await;

    let response = migrate_node_operator_directly(
        &pocket_ic,
        MigrateNodeOperatorPayload {
            new_node_operator_id: Some(new_operator_id),
            old_node_operator_id: Some(old_operator_id),
        },
        node_provider_id,
    )
    .await;

    assert!(response.is_ok(), "Expected ok but got {response:?}");

    // Verify: new operator record exists with merged data
    let merged_record: NodeOperatorRecord = decode_get_value_response(
        get_value(
            &pocket_ic,
            make_node_operator_record_key(new_operator_id),
            None,
        )
        .await
        .unwrap(),
    );

    assert_eq!(
        merged_record.node_provider_principal_id,
        node_provider_id.to_vec()
    );
    assert_eq!(merged_record.dc_id, "dc1");
    // node_allowance should be summed: 10 + 7 = 17
    assert_eq!(merged_record.node_allowance, 17);
    // rewardable_nodes type1 should be summed: 5 + 2 = 7
    assert_eq!(merged_record.rewardable_nodes.get("type1"), Some(&7));
    // rewardable_nodes type2 should be carried over from old: 3
    assert_eq!(merged_record.rewardable_nodes.get("type2"), Some(&3));
    // max_rewardable_nodes type1 should be summed: 8 + 3 = 11
    assert_eq!(merged_record.max_rewardable_nodes.get("type1"), Some(&11));
    // max_rewardable_nodes type2 should be carried over from old: 4
    assert_eq!(merged_record.max_rewardable_nodes.get("type2"), Some(&4));

    // Verify: old operator record is deleted
    assert!(
        !key_exists_in_registry(&pocket_ic, &make_node_operator_record_key(old_operator_id)).await,
        "Old node operator record should have been deleted"
    );

    // Verify: old operator's nodes now point to the new operator
    for node_id in &old_operator_node_ids {
        let node_record: NodeRecord = decode_get_value_response(
            get_value(&pocket_ic, make_node_record_key(*node_id), None)
                .await
                .unwrap(),
        );

        assert_eq!(
            node_record.node_operator_id,
            new_operator_id.to_vec(),
            "Old operator node {:?} should now point to new operator",
            node_id
        );
    }

    // Verify: new operator's existing nodes still point to the new operator (unchanged)
    for node_id in &new_operator_node_ids {
        let node_record: NodeRecord = decode_get_value_response(
            get_value(&pocket_ic, make_node_record_key(*node_id), None)
                .await
                .unwrap(),
        );

        assert_eq!(
            node_record.node_operator_id,
            new_operator_id.to_vec(),
            "New operator node {:?} should still point to new operator",
            node_id
        );
    }
}
