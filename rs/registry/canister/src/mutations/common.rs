use std::convert::TryFrom;

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::{
    replica_version::v1::BlessedReplicaVersions, subnet::v1::SubnetListRecord,
};
use ic_registry_keys::{make_api_boundary_node_record_key, make_blessed_replica_versions_key};
use ic_registry_transport::pb::v1::RegistryValue;
use prost::Message;

use crate::registry::Registry;

/// Wraps around Message::encode and panics on error.
pub(crate) fn encode_or_panic<T: Message>(msg: &T) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    msg.encode(&mut buf).unwrap();
    buf
}

pub fn decode_registry_value<T: Message + Default>(registry_value: Vec<u8>) -> T {
    T::decode(registry_value.as_slice()).unwrap()
}

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

pub(crate) fn check_replica_version_is_blessed(registry: &Registry, replica_version_id: &str) {
    let blessed_replica_key = make_blessed_replica_versions_key();
    // Get the current list of blessed replica versions
    if let Some(RegistryValue {
        value: blessed_list_vec,
        version,
        deletion_marker: _,
    }) = registry.get(blessed_replica_key.as_bytes(), registry.latest_version())
    {
        let blessed_list =
            decode_registry_value::<BlessedReplicaVersions>(blessed_list_vec.clone());
        // Verify that the new one is blessed
        assert!(
            blessed_list
                .blessed_version_ids
                .iter()
                .any(|v| v == replica_version_id),
            "Attempt to change the replica version to '{}' is rejected, \
            because that version is NOT blessed. The list of blessed replica versions, at \
            registry version {}, is: {}.",
            replica_version_id,
            version,
            blessed_versions_to_string(&blessed_list)
        );
    } else {
        panic!(
            "Error while fetching the list of blessed replica versions record: {}",
            replica_version_id
        )
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

// Perform a basic domain validation for a string
// Note that this is not meant to be an exhaustive check
pub fn is_valid_domain(domain: &str) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() < 2 {
        return false; // Domain should have at least one subdomain and a TLD
    }

    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false; // Each part should not be empty and should not exceed 63 characters
        }

        if part.starts_with('-') || part.ends_with('-') {
            return false; // Parts should not start or end with a hyphen
        }

        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false; // Parts should consist only of ASCII alphanumeric characters and hyphens
        }
    }

    true
}

#[cfg(test)]
pub(crate) mod test {
    use crate::mutations::common::{check_ipv6_format, is_valid_domain};

    pub(crate) const TEST_NODE_ID: &str = "2vxsx-fae";

    #[test]
    fn test_check_ipv6_format() {
        // Invalid ipv6
        assert!(!check_ipv6_format("0:0:0:0:0:0"));
        assert!(!check_ipv6_format("0-0-0-0-0-0-0"));
        assert!(!check_ipv6_format("This ipv6"));
        assert!(!check_ipv6_format("0:0:0:0:0:1234567:0:0"));
        assert!(!check_ipv6_format("0"));
        assert!(!check_ipv6_format(""));

        // Valid Ipv6
        assert!(check_ipv6_format("0:0:0:0:0:0:0:0"));
        assert!(check_ipv6_format("123:221:4567:323:4123:2111:7:7"));
    }

    #[test]
    fn test_is_valid_domain() {
        // Invalid cases
        for d in ["", "com", ".com", "-a.com", "a-.com"] {
            assert!(!is_valid_domain(d), "expected {d} to be an invalid domain");
        }

        // Valid cases
        for d in [
            "example.com",
            "a.example.com",
            "a.b.example.com",
            "example--a.com",
            "example-a.com",
        ] {
            assert!(is_valid_domain(d), "expected {d} to be a valid domain");
        }
    }
}
