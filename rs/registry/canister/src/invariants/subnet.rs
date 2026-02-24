use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
};

use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, get_node_record_from_snapshot,
    get_subnet_ids_from_snapshot,
};

use ic_base_types::{NodeId, PrincipalId};
use ic_nns_common::registry::MAX_NUM_SSH_KEYS;
use ic_protobuf::registry::subnet::v1::{CanisterCyclesCostSchedule, SubnetRecord, SubnetType};
use ic_registry_keys::{SUBNET_RECORD_KEY_PREFIX, make_node_record_key, make_subnet_record_key};
use prost::Message;

/// Subnet invariants hold iff:
///    * Each SSH key access list does not contain more than 50 keys
///    * Subnet membership contains no repetition
///    * Each node belongs to at most one subnet
///    * Each subnet contains at least one node
///    * There is at least one system subnet
///    * Each subnet in the registry occurs in the subnet list and vice versa
///    * Only application subnets can be rented and therefore have a "free" cycles cost schedule
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
                panic!("Subnet {subnet_id:} is in subnet list but no record exists")
            });

        // Each SSH key access list does not contain more than 50 keys
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

        let subnet_members: HashSet<NodeId> = subnet_record
            .membership
            .iter()
            .map(|v| NodeId::from(PrincipalId::try_from(v).unwrap()))
            .collect();

        // Subnet membership must contain registered nodes only
        for &node_id in &subnet_members {
            let node_key = make_node_record_key(node_id);
            if !snapshot.contains_key(node_key.as_bytes()) {
                panic!("Node {node_id} does not exist in Subnet {subnet_id}");
            }
        }

        // Each node appears at most once in a subnet membership
        let num_nodes = subnet_record.membership.len();
        if num_nodes > subnet_members.len() {
            panic!("Repeated nodes in subnet {subnet_id:}");
        }

        // Each subnet contains at least one node
        if subnet_members.is_empty() {
            panic!("No node in subnet {subnet_id:}");
        }

        // Each node appears at most once in at most one subnet membership
        let intersection = accumulated_nodes_in_subnets
            .intersection(&subnet_members)
            .collect::<HashSet<_>>();
        if !intersection.is_empty() {
            return Err(InvariantCheckError {
                msg: format!("Nodes in subnet {subnet_id:} also belong to other subnets"),
                source: None,
            });
        }
        accumulated_nodes_in_subnets.extend(&subnet_members);

        // Count occurrence of system subnets
        if subnet_record.subnet_type == i32::from(SubnetType::System) {
            system_subnet_count += 1;
        }

        // Only application subnets can be rented and have a "free" cycles cost schedule.
        if subnet_record.subnet_type != i32::from(SubnetType::Application)
            && subnet_record.canister_cycles_cost_schedule
                == i32::from(CanisterCyclesCostSchedule::Free)
        {
            return Err(InvariantCheckError {
                msg: format!(
                    "Subnet {subnet_id:} is not an application subnet but has a free cycles cost schedule"
                ),
                source: None,
            });
        }

        // SEV-enabled subnets consist of SEV-enabled nodes only (i.e. nodes with a chip ID in the node record)
        if let Some(features) = subnet_record.features.as_ref() {
            if features.sev_enabled == Some(true) {
                for &node_id in &subnet_members {
                    // handle missing node record
                    let node_record = get_node_record_from_snapshot(node_id, snapshot)?
                        .ok_or_else(|| InvariantCheckError {
                            msg: format!("Subnet {subnet_id} has node {node_id} in its membership but the node record does not exist"),
                            source: None,
                    })?;

                    // handle missing chip_id
                    node_record.chip_id.as_ref().ok_or_else(|| InvariantCheckError {
                        msg: format!("Subnet {subnet_id} is SEV-enabled but at least one of its nodes is not: {node_id} does not have a chip ID in its node record"),
                        source: None,
                    })?;
                }
            }
        }
    }

    // There is at least one system subnet. Note that we disable this invariant for benchmarks, as
    // the code to set up "invariants compliant" registry mostly depends on "test-only" code, and
    // it's very difficult to conform canbench benchmarks to test-only code. It's also risky to move
    // those "test-only" code towards "non-test-only" code.
    if system_subnet_count < 1 && !cfg!(feature = "canbench-rs") {
        return Err(InvariantCheckError {
            msg: "no system subnet".to_string(),
            source: None,
        });
    }
    // TODO (OR1-22): uncomment the following when NNS subnet recovery
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
pub(crate) fn get_subnet_records_map(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<Vec<u8>, SubnetRecord> {
    let mut subnets: BTreeMap<Vec<u8>, SubnetRecord> = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(SUBNET_RECORD_KEY_PREFIX.as_bytes()) {
            let record = SubnetRecord::decode(v.as_slice()).unwrap();
            subnets.insert((*k).clone(), record);
        }
    }
    subnets
}

#[cfg(test)]
mod tests;
