use super::*;
use crate::common::test_helpers::{
    add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
    prepare_registry_with_nodes,
};
use ic_test_utilities_types::ids::subnet_test_id;
use maplit::btreemap;
use pretty_assertions::assert_eq;

#[test]
fn test_set_subnet_operational_level() {
    // Step 1: Prepare the world. I.e. populate Registry in a way that lets us
    // meaningfully exercise set_subnet_operational_level.

    // Step 1.1: Registry with 1 node.
    let mut registry = invariant_compliant_registry(0);
    let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
        1, // start_mutation_id
        1, // nodes
    );
    registry.maybe_apply_mutation_internal(mutate_request.mutations);

    // Step 1.2: Add a subnet.
    let mut subnet_list_record = registry.get_subnet_list_record();
    let (node_id, dkg_pk) = node_ids_and_dkg_pks
        .iter()
        .next()
        .expect("should contain at least one node ID");
    let node_id = *node_id;
    let subnet_record = get_invariant_compliant_subnet_record(vec![node_id]);
    let subnet_id = subnet_test_id(1000);
    registry.maybe_apply_mutation_internal(add_fake_subnet(
        subnet_id,
        &mut subnet_list_record,
        subnet_record,
        &btreemap!(node_id => dkg_pk.clone()),
    ));

    let original_node_record = registry.get_node_or_panic(node_id);
    let original_subnet_record = registry.get_subnet_or_panic(subnet_id);
    // Make sure our test data is good. More precisely, that the original
    // records do not already look like what they will look like at the end.
    assert_eq!(
        original_node_record.ssh_node_state_write_access,
        Vec::<String>::new()
    );
    assert_eq!(original_subnet_record.is_halted, false);
    assert_eq!(
        original_subnet_record.ssh_readonly_access,
        Vec::<String>::new()
    );

    // Step 2A: Call code under test for starting subnet recovery.
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(subnet_id),
        operational_level: Some(operational_level::DOWN_FOR_REPAIRS),
        ssh_readonly_access: Some(vec!["fake read-only public key".to_string()]),
        ssh_node_state_write_access: Some(vec![NodeSshAccess {
            node_id: Some(node_id),
            public_keys: Some(vec!["fake node state write public key".to_string()]),
        }]),
    });

    // Step 3A: Verify results.

    // Step 3A.1: Verify SubnetRecord.
    let new_subnet_record = registry.get_subnet_or_panic(subnet_id);
    assert_eq!(
        new_subnet_record,
        SubnetRecord {
            is_halted: true,
            ssh_readonly_access: vec!["fake read-only public key".to_string()],
            ..original_subnet_record.clone()
        }
    );

    // Step 3A.2: Verify NodeRecord.
    let new_node_record = registry.get_node_or_panic(node_id);
    assert_eq!(
        new_node_record,
        NodeRecord {
            ssh_node_state_write_access: vec!["fake node state write public key".to_string()],
            ..original_node_record.clone()
        }
    );

    // Step 2B: Call code under test for ending subnet recovery.
    registry.do_set_subnet_operational_level(SetSubnetOperationalLevelPayload {
        subnet_id: Some(subnet_id),
        operational_level: Some(operational_level::NORMAL),
        ssh_readonly_access: Some(vec![]),
        ssh_node_state_write_access: Some(vec![NodeSshAccess {
            node_id: Some(node_id),
            public_keys: Some(vec![]),
        }]),
    });

    // Step 3B: Verify results. In particular, everything is now back to the way it was.
    assert_eq!(
        registry.get_subnet_or_panic(subnet_id),
        original_subnet_record,
    );
    assert_eq!(registry.get_node_or_panic(node_id), original_node_record,);
}
