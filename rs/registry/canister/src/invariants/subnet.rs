use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
};

use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, get_node_record_from_snapshot,
    get_subnet_ids_from_snapshot,
};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nns_common::registry::MAX_NUM_SSH_KEYS;
use ic_protobuf::registry::{
    node::v1::{NodeRecord, NodeRewardType},
    subnet::v1::{CanisterCyclesCostSchedule, SubnetRecord, SubnetType},
};
use ic_registry_keys::{SUBNET_RECORD_KEY_PREFIX, make_subnet_record_key};
use prost::Message;

/// Subnet invariants hold iff:
///    * Each SSH key access list does not contain more than 50 keys
///    * Subnet membership contains no repetition
///    * Each node belongs to at most one subnet
///    * Each subnet contains at least one node
///    * There is at least one system subnet
///    * Each subnet in the registry occurs in the subnet list and vice versa
///    * Only application subnets (when rented) and cloud engines can have a "free" cycles cost schedule
///    * Cloud engines must:
///         * have a "free" cycles cost schedule
///         * consist of nodes with reward type 4
///    * Conversely, only cloud engines can have nodes with reward type 4
///    * SEV-enabled subnets consist of SEV-enabled nodes only (i.e. nodes with a chip ID in the node record)
///    * Only rented subnets can have subnet admins set to a non-empty list
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
        let node_records = subnet_members
            .iter()
            .map(|&node_id| {
                get_node_record_from_snapshot(node_id, snapshot).and_then(|opt| {
                    opt.ok_or_else(|| InvariantCheckError {
                        msg: format!("Node {node_id} does not exist in the registry"),
                        source: None,
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

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

        // Only Application subnets and cloud engines are allowed to be free (of cost).
        let ok = subnet_record.canister_cycles_cost_schedule != i32::from(CanisterCyclesCostSchedule::Free)
          // If free, then the subnet must be of type Application (this implies that it is
          // rented), or CloudEngine.
          || [
              i32::from(SubnetType::Application),
              i32::from(SubnetType::CloudEngine),
          ].contains(&subnet_record.subnet_type);
        if !ok {
            return Err(InvariantCheckError {
                msg: format!(
                    "Subnet {subnet_id:} is not an application subnet or CloudEngine but has a free cycles cost schedule"
                ),
                source: None,
            });
        }

        if subnet_record.subnet_type == i32::from(SubnetType::CloudEngine)
            && subnet_record.canister_cycles_cost_schedule
                != i32::from(CanisterCyclesCostSchedule::Free)
        {
            return Err(InvariantCheckError {
                msg: format!(
                    "Subnet {subnet_id:} is a cloud engine subnet but its cycles cost schedule \
                    is not free"
                ),
                source: None,
            });
        }

        check_node_type4_iff_cloud_engine(subnet_id, &subnet_record, &node_records)?;

        // SEV-enabled subnets invariants
        if let Some(features) = subnet_record.features.as_ref()
            && features.sev_enabled == Some(true)
        {
            check_sev_subnet_invariants(subnet_id, subnet_members, snapshot)?;
        }

        check_subnet_admins_invariant(&subnet_record, subnet_id)?;
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

// Checks that only rented subnets or cloud engine subnets can have admins.
fn check_subnet_admins_invariant(
    subnet_record: &SubnetRecord,
    subnet_id: SubnetId,
) -> Result<(), InvariantCheckError> {
    // Here, it is taken that rented subnets are of type application and on a
    // free schedule. This is not very reliable and could be improved in the
    // future (e.g. by adding a new subnet type).
    let is_application_subnet = subnet_record.subnet_type == i32::from(SubnetType::Application);
    let is_on_free_cost_schedule =
        subnet_record.canister_cycles_cost_schedule == i32::from(CanisterCyclesCostSchedule::Free);
    let is_rented = is_on_free_cost_schedule && is_application_subnet;

    let is_cloud_engine_subnet =
        subnet_record.subnet_type == i32::from(SubnetType::CloudEngine) && is_on_free_cost_schedule;

    let can_have_admins =
        subnet_record.subnet_admins.is_empty() || is_rented || is_cloud_engine_subnet;
    if !can_have_admins {
        return Err(InvariantCheckError {
            msg: format!(
                "Subnet {subnet_id:} is not a rented or cloud engine subnet but has a non-empty subnet admins list"
            ),
            source: None,
        });
    }
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

/// All nodes of a subnet must support SEV in order for SEV to be enabled on the subnet.
fn check_sev_subnet_invariants(
    subnet_id: SubnetId, // only used for error messages, so we can report which subnet is non-compliant
    subnet_members: HashSet<NodeId>,
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    // SEV-enabled subnets consist of SEV-enabled nodes only (i.e. nodes with a chip ID in the node record)
    let nodes_missing_chip_id: Vec<NodeId> = subnet_members
        .iter()
        .filter_map(|&node_id| {
            let node_record = get_node_record_from_snapshot(node_id, snapshot)
                .ok()
                .flatten();

            let Some(node_record) = node_record else {
                // Missing nodes are ok, because that is checked earlier.
                // (What we really care about here is that all (existing)
                // nodes support SEV.)
                return None;
            };
            if node_record.chip_id.is_some() {
                // This node is SEV-enabled as it has a chip ID;
                // no need to report it as non-compliant.
                return None;
            }
            // We have found a non-compliant node! Report it (to the caller)!
            Some(node_id)
        })
        .collect();

    if !nodes_missing_chip_id.is_empty() {
        return Err(InvariantCheckError {
            msg: format!(
                "Subnet {subnet_id} is SEV-enabled, but the following nodes are missing a chip ID: {:?}",
                nodes_missing_chip_id
            ),
            source: None,
        });
    }

    Ok(())
}

fn check_node_type4_iff_cloud_engine(
    subnet_id: SubnetId, // only used for error messages, so we can report which subnet is non-compliant
    subnet_record: &SubnetRecord,
    node_records: &[NodeRecord],
) -> Result<(), InvariantCheckError> {
    let is_cloud_engine = subnet_record.subnet_type == i32::from(SubnetType::CloudEngine);
    let is_cloud_engine_node = |node: &NodeRecord| match node.node_reward_type() {
        NodeRewardType::Unspecified
        | NodeRewardType::Type0
        | NodeRewardType::Type1
        | NodeRewardType::Type2
        | NodeRewardType::Type3
        | NodeRewardType::Type3dot1
        | NodeRewardType::Type1dot1 => false,
        NodeRewardType::Type4
        | NodeRewardType::Type4dot1
        | NodeRewardType::Type4dot2
        | NodeRewardType::Type4dot3
        | NodeRewardType::Type4dot4
        | NodeRewardType::Type4dot5 => true,
    };
    let is_node_ok = |node: &NodeRecord| is_cloud_engine == is_cloud_engine_node(node);

    let ok = node_records.iter().all(is_node_ok);
    if !ok {
        let msg = if is_cloud_engine {
            "is a cloud engine subnet but some nodes do not have reward type 4"
        } else {
            "is not a cloud engine subnet but some nodes have reward type 4"
        };
        return Err(InvariantCheckError {
            msg: format!("Subnet {subnet_id:} {msg}"),
            source: None,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests;
