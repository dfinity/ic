use super::*;
use crate::common::test_helpers::{
    add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
    prepare_registry_with_nodes,
};
use ic_base_types::PrincipalId;
use ic_test_utilities_types::ids::subnet_test_id;
use lazy_static::lazy_static;
use maplit::btreemap;
use pretty_assertions::assert_eq;

lazy_static! {
    static ref SUBNET_ID: SubnetId = subnet_test_id(1000);

    static ref _FIXTURE: (Registry, NodeId, NodeRecord, SubnetRecord) = {
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // start_mutation_id
            1, // nodes
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let (node_id, dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID");
        let node_id = *node_id;

        // Add a subnet.
        let mut subnet_list_record = registry.get_subnet_list_record();
        let subnet_record = get_invariant_compliant_subnet_record(vec![node_id]);
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            *SUBNET_ID,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(node_id => dkg_pk.clone()),
        ));

        // Make sure our test data is good. In particular, the original records
        // do not already look like what they will be changed to later.
        let original_node_record = registry.get_node_or_panic(node_id);
        let original_subnet_record = registry.get_subnet_or_panic(*SUBNET_ID);
        assert_eq!(
            original_node_record.ssh_node_state_write_access,
            Vec::<String>::new()
        );
        assert_eq!(original_subnet_record.is_halted, false);
        assert_eq!(
            original_subnet_record.ssh_readonly_access,
            Vec::<String>::new()
        );

        (registry, node_id, original_node_record, original_subnet_record)
    };

    // Has 1 node and one subnet, whose IDs are also lazy_static pseudo-
    // constants.
    static ref REGISTRY: Registry = _FIXTURE.0.clone();
    static ref NODE_ID: NodeId = _FIXTURE.1;
    static ref ORIGINAL_NODE_RECORD: NodeRecord = _FIXTURE.2.clone();
    static ref ORIGINAL_SUBNET_RECORD: SubnetRecord = _FIXTURE.3.clone();
}

#[test]
fn test_set_subnet_operational_level() {
    // Step 1: Prepare the world. I.e. populate Registry in a way that lets us
    // meaningfully exercise set_subnet_operational_level.

    let mut registry = REGISTRY.clone();

    // Step 2A: Call code under test for starting subnet recovery.
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(*SUBNET_ID),
        operational_level: Some(operational_level::DOWN_FOR_REPAIRS),
        ssh_readonly_access: Some(vec!["fake read-only public key".to_string()]),
        ssh_node_state_write_access: Some(vec![NodeSshAccess {
            node_id: Some(*NODE_ID),
            public_keys: Some(vec!["fake node state write public key".to_string()]),
        }]),
        recalled_replica_version_ids: None,
    });

    // Step 3A: Verify results.

    // Step 3A.1: Verify SubnetRecord.
    let new_subnet_record = registry.get_subnet_or_panic(*SUBNET_ID);
    assert_eq!(
        new_subnet_record,
        SubnetRecord {
            is_halted: true,
            ssh_readonly_access: vec!["fake read-only public key".to_string()],
            ..ORIGINAL_SUBNET_RECORD.clone()
        }
    );

    // Step 3A.2: Verify NodeRecord.
    let new_node_record = registry.get_node_or_panic(*NODE_ID);
    assert_eq!(
        new_node_record,
        NodeRecord {
            ssh_node_state_write_access: vec!["fake node state write public key".to_string()],
            ..ORIGINAL_NODE_RECORD.clone()
        }
    );

    // Step 2B: Call code under test for ending subnet recovery.
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(*SUBNET_ID),
        operational_level: Some(operational_level::NORMAL),
        ssh_readonly_access: Some(vec![]),
        ssh_node_state_write_access: Some(vec![NodeSshAccess {
            node_id: Some(*NODE_ID),
            public_keys: Some(vec![]),
        }]),
        recalled_replica_version_ids: None,
    });

    // Step 3B: Verify results. In particular, everything is now back to the way it was.
    assert_eq!(
        registry.get_subnet_or_panic(*SUBNET_ID),
        ORIGINAL_SUBNET_RECORD.clone(),
    );
    assert_eq!(
        registry.get_node_or_panic(*NODE_ID),
        ORIGINAL_NODE_RECORD.clone()
    );
}

#[test]
fn test_validate_operational_level_ok() {
    validate_operational_level(None).unwrap();

    validate_operational_level(Some(operational_level::NORMAL)).unwrap();
    validate_operational_level(Some(operational_level::DOWN_FOR_REPAIRS)).unwrap();

    for code in operational_level::ALL_VALID_CODES {
        validate_operational_level(Some(code)).unwrap();
    }
}

#[test]
fn test_validate_operational_level_zero() {
    let result = validate_operational_level(Some(0));

    match result {
        Ok(()) => panic!("Err not returned"),
        Err(err) => assert!(err.contains("operational_level")),
    }
}

#[test]
fn test_validate_operational_level_garbage() {
    let garbage = 6;
    assert!(!operational_level::ALL_VALID_CODES.contains(&garbage));
    let result = validate_operational_level(Some(garbage));

    match result {
        Ok(()) => panic!("Err not returned"),
        Err(err) => assert!(err.contains("not one of the allowed values")),
    }
}

lazy_static! {
    static ref GENERAL_SSH_NODE_STATE_WRITE_ACCESS: Vec<NodeSshAccess> = vec![
        NodeSshAccess {
            node_id: Some(NodeId::from(PrincipalId::new_user_test_id(42))),
            public_keys: Some(vec!["hello, world!".to_string()]),
        },
        NodeSshAccess {
            node_id: Some(NodeId::from(PrincipalId::new_user_test_id(43))),
            public_keys: Some(vec![
                "Daniel Wong".to_string(),
                "deserves a phat raise.".to_string(),
            ]),
        },
    ];
}

#[test]
fn test_validate_ssh_node_state_write_access_ok() {
    validate_ssh_node_state_write_access(&None).unwrap();
    validate_ssh_node_state_write_access(&Some(vec![])).unwrap();
    validate_ssh_node_state_write_access(&Some(GENERAL_SSH_NODE_STATE_WRITE_ACCESS.clone()))
        .unwrap();
}

#[test]
fn test_validate_ssh_node_state_write_access_not_unique() {
    let mut ssh_node_state_write_access = GENERAL_SSH_NODE_STATE_WRITE_ACCESS.clone();
    ssh_node_state_write_access.push(ssh_node_state_write_access.first().unwrap().clone());
    let result = validate_ssh_node_state_write_access(&Some(ssh_node_state_write_access));

    match result {
        Ok(()) => panic!("Err not returned"),
        Err(err) => assert!(err.contains("unique")),
    }
}

#[test]
fn test_validate_ssh_node_state_write_access_missing_node_id() {
    let mut ssh_node_state_write_access = GENERAL_SSH_NODE_STATE_WRITE_ACCESS.clone();
    ssh_node_state_write_access.get_mut(0).unwrap().node_id = None;
    let result = validate_ssh_node_state_write_access(&Some(ssh_node_state_write_access));

    match result {
        Ok(()) => panic!("Err not returned"),
        Err(err) => assert!(err.contains("node_id")),
    }
}

#[test]
fn test_validate_ssh_node_state_write_access_missing_public_keys() {
    let mut ssh_node_state_write_access = GENERAL_SSH_NODE_STATE_WRITE_ACCESS.clone();
    ssh_node_state_write_access.get_mut(0).unwrap().public_keys = None;
    let result = validate_ssh_node_state_write_access(&Some(ssh_node_state_write_access));

    match result {
        Ok(()) => panic!("Err not returned"),
        Err(err) => assert!(err.contains("public_keys")),
    }
}

lazy_static! {
    static ref GENERAL_PAYLOAD: SetSubnetOperationalLevelPayload =
        SetSubnetOperationalLevelPayload {
            subnet_id: Some(SubnetId::from(PrincipalId::new_user_test_id(777))),
            operational_level: Some(operational_level::NORMAL),
            ssh_readonly_access: Some(vec!["hello".to_string(), "world".to_string()]),
            ssh_node_state_write_access: Some(GENERAL_SSH_NODE_STATE_WRITE_ACCESS.clone()),
            recalled_replica_version_ids: None,
        };
}

#[test]
fn test_validate_payload_no_subnet_ok() {
    // Step 1: Prepare the world.
    let mut registry = REGISTRY.clone();

    // Step 2: Run code under test.

    // This just changes the NodeRecord, not the SubnetRecord.
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: None,
        operational_level: None,
        ssh_readonly_access: None,

        ssh_node_state_write_access: Some(vec![NodeSshAccess {
            node_id: Some(*NODE_ID),
            public_keys: Some(vec!["fake node state write public key".to_string()]),
        }]),
        recalled_replica_version_ids: None,
    });

    // Step 3: Verify results.

    // Step 3A.1: Verify SubnetRecord.
    let new_subnet_record = registry.get_subnet_or_panic(*SUBNET_ID);
    assert_eq!(new_subnet_record, ORIGINAL_SUBNET_RECORD.clone(),);

    // Step 3A.2: Verify NodeRecord.
    let new_node_record = registry.get_node_or_panic(*NODE_ID);
    assert_eq!(
        new_node_record,
        NodeRecord {
            ssh_node_state_write_access: vec!["fake node state write public key".to_string()],
            ..ORIGINAL_NODE_RECORD.clone()
        }
    );
}

#[test]
fn test_validate_payload_no_node_ok() {
    // Step 1: Prepare the world.
    let mut registry = REGISTRY.clone();

    // Step 2: Run code under test.

    // This just changes the NodeRecord, not the SubnetRecord.
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(*SUBNET_ID),
        operational_level: Some(operational_level::DOWN_FOR_REPAIRS),
        ssh_readonly_access: Some(vec!["fake read-only public key".to_string()]),

        ssh_node_state_write_access: None,
        recalled_replica_version_ids: None,
    });

    // Step 3: Verify results.

    // Step 3A.1: Verify SubnetRecord.
    let new_subnet_record = registry.get_subnet_or_panic(*SUBNET_ID);
    assert_eq!(
        new_subnet_record,
        SubnetRecord {
            is_halted: true,
            ssh_readonly_access: vec!["fake read-only public key".to_string()],
            ..ORIGINAL_SUBNET_RECORD.clone()
        }
    );

    // Step 3A.2: Verify NodeRecord.
    let new_node_record = registry.get_node_or_panic(*NODE_ID);
    assert_eq!(new_node_record, ORIGINAL_NODE_RECORD.clone(),);
}

#[test]
#[should_panic(expected = "no changes")]
fn test_validate_payload_empty() {
    // Step 1: Prepare the world.
    let mut registry = REGISTRY.clone();

    // Step 2: Run code under test.

    // This just changes the NodeRecord, not the SubnetRecord.
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: None,
        operational_level: None,
        ssh_readonly_access: None,

        ssh_node_state_write_access: None,
        recalled_replica_version_ids: None,
    });

    // Step 3: Verify results.
    // Actually, this is done by should_panic, at the top.
}

#[test]
fn test_validate_payload_no_subnet_but_operational_level() {
    let result =
        REGISTRY.validate_set_subnet_operational_level(&SetSubnetOperationalLevelPayload {
            subnet_id: None,
            operational_level: Some(operational_level::NORMAL),
            ssh_readonly_access: None,

            ssh_node_state_write_access: Some(vec![NodeSshAccess {
                node_id: Some(*NODE_ID),
                public_keys: Some(vec!["fake node state write public key".to_string()]),
            }]),
            recalled_replica_version_ids: None,
        });

    // Step 3: Verify results.
    match result {
        Ok(()) => panic!("Err not returned"),
        Err(err) => assert!(err.contains("operational_level")),
    }
}

#[test]
fn test_validate_payload_no_subnet_but_ssh_readonly_access() {
    let result =
        REGISTRY.validate_set_subnet_operational_level(&SetSubnetOperationalLevelPayload {
            subnet_id: None,
            operational_level: None,
            ssh_readonly_access: Some(vec!["hello".to_string()]),

            ssh_node_state_write_access: Some(vec![NodeSshAccess {
                node_id: Some(*NODE_ID),
                public_keys: Some(vec!["fake node state write public key".to_string()]),
            }]),
            recalled_replica_version_ids: None,
        });

    match result {
        Ok(()) => panic!("Err not returned"),
        Err(err) => assert!(err.contains("ssh_readonly_access")),
    }
}

#[test]
fn test_recall_replica_versions() {
    let (mut registry, _node_id, _node_record, _subnet_record) = _FIXTURE.clone();

    let version_id_1 = "test-version-1".to_string();
    let version_id_2 = "test-version-2".to_string();
    let version_id_3 = "test-version-3".to_string();

    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(*SUBNET_ID),
        operational_level: None,
        ssh_readonly_access: None,
        ssh_node_state_write_access: None,
        recalled_replica_version_ids: Some(vec![version_id_1.clone()]),
    });

    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(*SUBNET_ID),
        operational_level: None,
        ssh_readonly_access: None,
        ssh_node_state_write_access: None,
        recalled_replica_version_ids: Some(vec![version_id_2.clone(), version_id_3.clone()]),
    });

    // version_id_1 again - should be ignored
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(*SUBNET_ID),
        operational_level: Some(operational_level::DOWN_FOR_REPAIRS),
        ssh_readonly_access: None,
        ssh_node_state_write_access: None,
        recalled_replica_version_ids: Some(vec![version_id_1.clone()]),
    });

    let subnet_record = registry.get_subnet_or_panic(*SUBNET_ID);
    assert_eq!(
        subnet_record.recalled_replica_version_ids,
        vec![version_id_1, version_id_2, version_id_3]
    );
}

#[test]
fn test_validate_recalled_replica_version_ids_without_subnet_id() {
    let result =
        REGISTRY.validate_set_subnet_operational_level(&SetSubnetOperationalLevelPayload {
            subnet_id: None,
            operational_level: None,
            ssh_readonly_access: None,
            ssh_node_state_write_access: None,
            recalled_replica_version_ids: Some(vec!["test-version".to_string()]),
        });

    assert!(
        result
            .expect_err("Err not returned")
            .contains("recalled_replica_version_ids specified, but not subnet_id")
    );

    let subnet_record = registry.get_subnet_or_panic(*SUBNET_ID);
    assert_eq!(subnet_record.recalled_replica_version_ids, vec![]);
}

#[test]
fn test_validate_recalled_replica_version_ids_empty() {
    let result =
        REGISTRY.validate_set_subnet_operational_level(&SetSubnetOperationalLevelPayload {
            subnet_id: Some(*SUBNET_ID),
            operational_level: None,
            ssh_readonly_access: None,
            ssh_node_state_write_access: None,
            recalled_replica_version_ids: Some(vec!["".to_string()]),
        });

    assert!(
        result
            .expect_err("Err not returned")
            .contains("recalled_replica_version_ids cannot contain empty strings")
    );

    let subnet_record = registry.get_subnet_or_panic(*SUBNET_ID);
    assert_eq!(subnet_record.recalled_replica_version_ids, vec![]);
}
