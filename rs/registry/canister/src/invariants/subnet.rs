use std::{
    collections::{BTreeMap, HashSet},
    convert::TryFrom,
};

use crate::invariants::common::{
    get_subnet_ids_from_snapshot, InvariantCheckError, RegistrySnapshot,
};

use ic_base_types::{NodeId, PrincipalId};
use ic_nns_common::registry::{decode_or_panic, MAX_NUM_SSH_KEYS};
use ic_protobuf::registry::subnet::v1::{ChainKeyConfig, SubnetRecord, SubnetType};
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

// TODO[NNS1-2986]: Remove this function after the migration has been performed.
pub fn subnet_record_mutations_from_ecdsa_configs_to_chain_key_configs(
    snapshot: &RegistrySnapshot,
) -> Vec<ic_registry_transport::pb::v1::RegistryMutation> {
    #[cfg(target_arch = "wasm32")]
    use dfn_core::println;

    let mut subnet_records_map = get_subnet_records_map(snapshot);
    let subnet_id_list = get_subnet_ids_from_snapshot(snapshot);
    let mut mutations = vec![];

    for subnet_id in subnet_id_list {
        let mut subnet_record = subnet_records_map
            .remove(&make_subnet_record_key(subnet_id).into_bytes())
            .unwrap_or_else(|| {
                panic!(
                    "Subnet {:} is in subnet list but no record exists",
                    subnet_id
                );
            });

        let chain_key_config = match (
            subnet_record.ecdsa_config.as_ref(),
            subnet_record.chain_key_config.as_ref(),
        ) {
            (None, None) => {
                println!(
                    "Neither ecdsa_config nor chain_key_config are specified in subnet record \
                     of subnet ID {:?}. Skipping this subnet record.",
                    subnet_id,
                );
                continue;
            }
            (None, Some(chain_key_config)) => {
                // This code should not be reachable, as all operations that set `ecdsa_config`
                // in subnet records should also set `chain_key_config` to an equavalent value.
                panic!(
                    "ecdsa_config not specified, but chain_key_config is specified in subnet \
                     record of subnet ID {:?}. chain_key_config = {:?}. There must be a bug. \
                     Aborting Registry upgrade ...",
                    subnet_id, chain_key_config,
                );
            }
            (Some(ecdsa_config), None) => {
                // The normal case: We need to retrofit data into `chain_key_config`.
                let chain_key_config = ChainKeyConfig::from(ecdsa_config.clone());
                println!(
                    "Retrofitting data from ecdsa_config to initialize chain_key_config \
                     in subnet record of subnet ID {:?}. \
                     ecdsa_config = {:?}. chain_key_config = {:?}.",
                    subnet_id, ecdsa_config, chain_key_config,
                );
                chain_key_config
            }
            (Some(ecdsa_config), Some(chain_key_config)) => {
                // This might happen only if someone invoked a Registry operation that set or
                // changed the value of the `subnet_record.ecdsa_config` field, thereby setting
                // a value also for `subnet_record.chain_key_config`.
                // Comparing debug string representations to circumvent the fact that these types
                // do not implement `PartialEq`.
                assert_eq!(
                    format!("{:?}", chain_key_config),
                    format!("{:?}", ChainKeyConfig::from(ecdsa_config.clone())),
                    "Inconsistency detected between already-present chain_key_config and data \
                     from ecdsa_config. There must be a bug. Aborting Registry upgrade ..."
                );
                println!(
                    "Both ecdsa_config and chain_key_config are specified in subnet record \
                     of subnet ID {:?}. chain_key_config = f(ecdsa_config) = {:?}. \
                     Skipping this subnet record.",
                    subnet_id, chain_key_config,
                );
                continue;
            }
        };

        subnet_record.chain_key_config = Some(chain_key_config);

        let subnet_record_mutation = ic_registry_transport::upsert(
            make_subnet_record_key(subnet_id).into_bytes(),
            crate::mutations::common::encode_or_panic(&subnet_record),
        );

        mutations.push(subnet_record_mutation);
    }

    mutations
}

// Return all subnet records in the snapshot
pub(crate) fn get_subnet_records_map(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<Vec<u8>, SubnetRecord> {
    let mut subnets: BTreeMap<Vec<u8>, SubnetRecord> = BTreeMap::new();
    for (k, v) in snapshot {
        if k.starts_with(SUBNET_RECORD_KEY_PREFIX.as_bytes()) {
            let record = decode_or_panic::<SubnetRecord>(v.clone());
            subnets.insert((*k).clone(), record);
        }
    }
    subnets
}
