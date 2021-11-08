use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
};

use crate::invariants::common::{
    get_subnet_ids_from_snapshot, InvariantCheckError, RegistrySnapshot,
};

use ic_base_types::{NodeId, PrincipalId};
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
use ic_registry_keys::{make_node_record_key, make_subnet_record_key, SUBNET_RECORD_KEY_PREFIX};

const MAX_NUM_SSH_KEYS: usize = 50;

/// Subnet invariants hold iff:
///    * Each SSH key access list does not contain more than 50 keys
///    * Subnet membership contains no repetition
///    * Each node belongs to at most one subnet
///    * Each subnet contains at least one node
///    * There is at least one system subnet
///    * Each subnet in the registry occurs in the subnet list and vice versa
pub(crate) fn check_subnet_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let mut accumulated_nodes_in_subnets: HashSet<NodeId> = HashSet::new();
    let mut system_subnet_count = 0;
    let mut subnet_records_map = get_subnet_records_map(snapshot);
    let subnet_id_list = get_subnet_ids_from_snapshot(snapshot);
    for subnet_id in subnet_id_list {
        // Subnets in the subnet list have a subnet record
        let subnet_record = subnet_records_map
            .remove(&make_subnet_record_key(subnet_id).into_bytes())
            .unwrap_or_else(|| {
                panic!(
                    "Subnet {:} is in subnet list but no record exists",
                    subnet_id
                )
            });

        if subnet_record.ssh_readonly_access.len() > MAX_NUM_SSH_KEYS
            || subnet_record.ssh_backup_access.len() > MAX_NUM_SSH_KEYS
        {
            return Err(InvariantCheckError {
                msg: format!(
                    "Mutation would have resulted in an SSH key access list that is too long, \
                    the maximum allowable length is {}, and the `readonly` and `backup` lists had \
                    {} and {} keys, respectively",
                    MAX_NUM_SSH_KEYS,
                    subnet_record.ssh_readonly_access.len(),
                    subnet_record.ssh_backup_access.len()
                ),
                source: None,
            });
        }

        let num_nodes = subnet_record.membership.len();
        let mut subnet_members: HashSet<NodeId> = subnet_record
            .membership
            .iter()
            .map(|v| NodeId::from(PrincipalId::try_from(v).unwrap()))
            .collect();

        // Subnet membership must contain registered nodes only
        subnet_members.retain(|&k| {
            let node_key = make_node_record_key(k);
            let node_exists = snapshot.contains_key(node_key.as_bytes());
            if !node_exists {
                panic!("Node {} does not exist in Subnet {}", k, subnet_id);
            }
            node_exists
        });

        // Each node appears at most once in a subnet membership
        if num_nodes > subnet_members.len() {
            panic!("Repeated nodes in subnet {:}", subnet_id);
        }
        // Each subnet contains at least one node
        if subnet_members.is_empty() {
            panic!("No node in subnet {:}", subnet_id);
        }
        let intersection = accumulated_nodes_in_subnets
            .intersection(&subnet_members)
            .collect::<HashSet<_>>();
        // Each node appears at most once in at most one subnet membership
        if !intersection.is_empty() {
            return Err(InvariantCheckError {
                msg: format!(
                    "Nodes in subnet {:} also belong to other subnets",
                    subnet_id
                ),
                source: None,
            });
        }
        accumulated_nodes_in_subnets.extend(&subnet_members);
        // Count occurrence of system subnets
        if subnet_record.subnet_type == i32::from(SubnetType::System) {
            system_subnet_count += 1;
        }
        assert!(
            subnet_record.max_instructions_per_message <= subnet_record.max_instructions_per_round,
            "The message instruction limit should not exceed \
                the round instruction limit."
        );
    }
    // There is at least one system subnet
    if system_subnet_count < 1 {
        return Err(InvariantCheckError {
            msg: "no system subnet".to_string(),
            source: None,
        });
    }
    // TODO (OR1-22): uncomment the following when NNS disaster recovery
    // has fully been implemented which guarantees that no unnecessary
    // subnet records are in the registry.
    // All subnet records have been listed
    // if !subnet_records_map.is_empty() {
    //    panic!(
    //        "Subnets {:?} has not been listed in the snapshot",
    //       subnet_records_map.keys()
    //    );
    //}

    Ok(())
}

// Return all subnet records in the snapshot
fn get_subnet_records_map(snapshot: &RegistrySnapshot) -> BTreeMap<Vec<u8>, SubnetRecord> {
    let mut subnets: BTreeMap<Vec<u8>, SubnetRecord> = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(SUBNET_RECORD_KEY_PREFIX.as_bytes()) {
            let record = decode_or_panic::<SubnetRecord>(v.clone());
            subnets.insert((*k).clone(), record);
        }
    }
    subnets
}
