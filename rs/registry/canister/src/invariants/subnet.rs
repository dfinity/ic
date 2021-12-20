use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
};

use crate::invariants::common::{
    get_subnet_ids_from_snapshot, InvariantCheckError, RegistrySnapshot,
};

use ic_base_types::SubnetId;
use ic_base_types::{NodeId, PrincipalId};
use ic_nns_common::registry::{decode_or_panic, MAX_NUM_SSH_KEYS};
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType};
use ic_registry_keys::{make_node_record_key, make_subnet_record_key, SUBNET_RECORD_KEY_PREFIX};

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

        check_gossip_config_invariants(subnet_id, subnet_record);
    }
    // There is at least one system subnet
    if system_subnet_count < 1 {
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

/// Gossip config invariants hold iff:
///    * number of chunks requested in parallel > 0
///    * timeout for chunk > 200 ms
///    * number of times a chunk is requested from peers in parallel > 0
///    * 0 < size of receive_check_cache < 2 * priority function interval
///    * 50ms < priority function interval < 6 * consensus unit delay
///    * registry poll period > 3000 milliseconds
///    * 10s < retranmission request interval < 2min
fn check_gossip_config_invariants(subnet_id: SubnetId, subnet_record: SubnetRecord) {
    match subnet_record.gossip_config {
        Some(gossip_config) => {
            if gossip_config.max_artifact_streams_per_peer < 1 {
                panic!(
                    "Gossip config value for max_artifact_streams_per_peer for subnet {:} is \
                    currently {:} but it must be at least one.",
                    subnet_id, gossip_config.max_artifact_streams_per_peer
                )
            }
            if gossip_config.max_chunk_wait_ms < 200 {
                panic!(
                    "Gossip config value for max_chunk_wait_ms for subnet {:} is currently {:} \
                    but it must be at least 200ms to take the network delay into account.",
                    subnet_id, gossip_config.max_chunk_wait_ms
                )
            }
            if gossip_config.max_duplicity < 1 {
                panic!(
                    "Gossip config value for max_duplicity for subnet {:} is currently {:} but it \
                     must be at least 1.",
                    subnet_id, gossip_config.max_duplicity
                )
            }
            if gossip_config.receive_check_cache_size < 1
                || gossip_config.receive_check_cache_size
                    > 6 * gossip_config.pfn_evaluation_period_ms
            {
                panic!(
                    "Gossip config value for receive_check_cache_size for subnet {:} is \
                    currently {:} but it must be between 1 and  6 * pfn_evaluation_period_ms which is {:} \
                    (no honest peer sends more than 6000 adverts per second per Gossip client, \
                    larger cache does not help).",
                    subnet_id, gossip_config.receive_check_cache_size,
                    6 * gossip_config.pfn_evaluation_period_ms
                )
            }
            if gossip_config.pfn_evaluation_period_ms < 50
                || gossip_config.pfn_evaluation_period_ms as u64
                    > 6 * subnet_record.unit_delay_millis
            {
                panic!(
                    "Gossip config value for pfn_evaluation_period_ms for subnet {:} is currently \
                    {:} but it must be between 50 and 6 * unit_delay_millis which is {:}, to update the \
                    priority function at roughly the same rate as consensus progresses.",
                    subnet_id, gossip_config.pfn_evaluation_period_ms,
                    6 * subnet_record.unit_delay_millis,
                )
            }
            if gossip_config.registry_poll_period_ms < 2000 {
                panic!(
                    "Gossip config value for registry_poll_period_ms for subnet {:} is currently \
                    {:} but it must be at least 2000, aligned with the NNS block interval.",
                    subnet_id, gossip_config.registry_poll_period_ms
                )
            }
            if gossip_config.retransmission_request_ms < 10_000
                || gossip_config.retransmission_request_ms > 120_000
            {
                panic!(
                    "Gossip config value for retransmission_request_ms for subnet {:} is currently\
                     {:} but it must be between 10_000 and 120_000. This ensures a subnet with \
                     healthy nodes which have not received all adverts have the opportunity to \
                     catch up in the order of 10 seconds to two minutes.",
                    subnet_id, gossip_config.retransmission_request_ms
                )
            }
        }
        None => panic!("No gossip config defined in subnet record {:}.", subnet_id),
    }
}
