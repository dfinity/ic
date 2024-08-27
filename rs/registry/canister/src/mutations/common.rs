use crate::registry::Registry;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::{
    replica_version::v1::BlessedReplicaVersions, subnet::v1::SubnetListRecord,
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_keys::{
    make_api_boundary_node_record_key, make_blessed_replica_versions_key, make_node_record_key,
    make_unassigned_nodes_config_record_key,
};
use prost::Message;
use std::{cmp::Eq, collections::HashSet, convert::TryFrom, hash::Hash};

pub fn get_subnet_ids_from_subnet_list(subnet_list: SubnetListRecord) -> Vec<SubnetId> {
    subnet_list
        .subnets
        .iter()
        .map(|subnet_id_vec| SubnetId::new(PrincipalId::try_from(subnet_id_vec).unwrap()))
        .collect()
}

fn blessed_versions_to_string(blessed: &BlessedReplicaVersions) -> String {
    format!("[{}]", blessed.blessed_version_ids.join(", "))
}

pub(crate) fn check_api_boundary_nodes_exist(registry: &Registry, node_ids: &[NodeId]) {
    let version = registry.latest_version();

    node_ids.iter().copied().for_each(|node_id| {
        let key = make_api_boundary_node_record_key(node_id);

        let record = registry.get(key.as_bytes(), version);
        if record.is_none() {
            panic!("record not found");
        }
    });
}

pub(crate) fn get_blessed_replica_versions(
    registry: &Registry,
) -> Result<BlessedReplicaVersions, String> {
    let blessed_replica_key = make_blessed_replica_versions_key();
    registry
        .get(blessed_replica_key.as_bytes(), registry.latest_version())
        .map_or(
            Err("Failed to retrieve the blessed replica versions.".to_string()),
            |result| {
                let decoded = BlessedReplicaVersions::decode(result.value.as_slice()).unwrap();
                Ok(decoded)
            },
        )
}

pub(crate) fn check_replica_version_is_blessed(registry: &Registry, replica_version_id: &str) {
    match get_blessed_replica_versions(registry) {
        Ok(blessed_list) => {
            // Verify that the new one is blessed
            let replica_version_id = replica_version_id.to_string();
            assert!(
                blessed_list
                    .blessed_version_ids
                    .contains(&replica_version_id),
                "Attempt to check if the replica version to '{}' is blessed was rejected, \
                because that version is NOT blessed. The list of blessed replica versions is: {}.",
                replica_version_id,
                blessed_versions_to_string(&blessed_list)
            );
        }
        Err(_) => {
            panic!(
                "Error while fetching the list of blessed replica versions record: {}",
                replica_version_id
            )
        }
    }
}

pub(crate) fn node_exists_or_panic(registry: &Registry, node_id: NodeId) {
    let version = registry.latest_version();
    let node_key = make_node_record_key(node_id);
    let record = registry.get(node_key.as_bytes(), version);
    if record.is_none() {
        panic!("record not found");
    }
}

/// Check for the ipv6 field in node operator, checks that the string consists in 8 hexadecimal
/// numbers in the range 0-65535 (2**16).
pub fn check_ipv6_format(ipv6_string: &str) -> bool {
    let mut count = 0;
    for hex_str in ipv6_string.split(':') {
        count += 1;
        let hex = i32::from_str_radix(hex_str, 16);
        if !(hex.is_ok() && hex.unwrap() < 65536) {
            return false;
        }
    }
    count == 8
}

pub fn get_unassigned_nodes_record(
    registry: &Registry,
) -> Result<UnassignedNodesConfigRecord, String> {
    let unassigned_nodes_key = make_unassigned_nodes_config_record_key();
    registry
        .get(unassigned_nodes_key.as_bytes(), registry.latest_version())
        .map_or(
            Err("No unassigned nodes record found in the registry.".to_string()),
            |result| {
                let decoded = UnassignedNodesConfigRecord::decode(result.value.as_slice()).unwrap();
                Ok(decoded)
            },
        )
}

/// Returns whether a list has duplicate elements.
pub fn has_duplicates<T>(v: &Vec<T>) -> bool
where
    T: Hash + Eq,
{
    let s: HashSet<_> = HashSet::from_iter(v);
    s.len() < v.len()
}

#[cfg(test)]
pub(crate) mod test {
    use crate::mutations::common::check_ipv6_format;

    pub(crate) const TEST_NODE_ID: &str = "2vxsx-fae";

    #[test]
    fn test_check_ipv6_format() {
        // Invalid IPv6
        assert!(!check_ipv6_format("0:0:0:0:0:0"));
        assert!(!check_ipv6_format("0-0-0-0-0-0-0"));
        assert!(!check_ipv6_format("This ipv6"));
        assert!(!check_ipv6_format("0:0:0:0:0:1234567:0:0"));
        assert!(!check_ipv6_format("0"));
        assert!(!check_ipv6_format(""));

        // Valid IPv6
        assert!(check_ipv6_format("0:0:0:0:0:0:0:0"));
        assert!(check_ipv6_format("123:221:4567:323:4123:2111:7:7"));
    }
}
