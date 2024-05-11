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
use std::{
    cmp::Eq, collections::HashSet, convert::TryFrom, fmt, hash::Hash, net::Ipv4Addr, str::FromStr,
};

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

pub(crate) fn get_blessed_replica_versions(
    registry: &Registry,
) -> Result<BlessedReplicaVersions, String> {
    let blessed_replica_key = make_blessed_replica_versions_key();
    registry
        .get(blessed_replica_key.as_bytes(), registry.latest_version())
        .map_or(
            Err("Failed to retrieve the blessed replica versions.".to_string()),
            |result| {
                let decoded =
                    decode_registry_value::<BlessedReplicaVersions>(result.value.to_vec());
                Ok(decoded)
            },
        )
}

pub(crate) fn check_replica_version_is_blessed(registry: &Registry, replica_version_id: &str) {
    match get_blessed_replica_versions(registry) {
        Ok(blessed_list) => {
            // Verify that the new one is blessed
            assert!(
                blessed_list
                    .blessed_version_ids
                    .iter()
                    .any(|v| v == replica_version_id),
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
                let decoded =
                    decode_registry_value::<UnassignedNodesConfigRecord>(result.value.to_vec());
                Ok(decoded)
            },
        )
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

// Check that the given string is indeed a valid IPv4 address
pub fn is_valid_ipv4_address(ipv4_address: &str) -> bool {
    Ipv4Addr::from_str(ipv4_address).is_ok()
}

pub fn is_global_ipv4_address(ipv4_address: &str) -> bool {
    let ip_address = Ipv4Addr::from_str(ipv4_address).unwrap();

    // IETF RFC 2544
    let is_benchmarking = u32::from_be_bytes(ip_address.octets()) & (!0 << 17)
        == u32::from_be_bytes(Ipv4Addr::new(198, 18, 0, 0).octets());
    // IETF RFC 1112
    let is_reserved = u32::from_be_bytes(ip_address.octets()) & (!0 << 28)
        == u32::from_be_bytes(Ipv4Addr::new(240, 0, 0, 0).octets());
    // IETF RFC 6598
    let is_shared = u32::from_be_bytes(ip_address.octets()) & (!0 << 22)
        == u32::from_be_bytes(Ipv4Addr::new(100, 64, 0, 0).octets());

    !is_benchmarking
        && !ip_address.is_broadcast()
        && !ip_address.is_documentation()
        && !ip_address.is_link_local()
        && !ip_address.is_private()
        && !ip_address.is_loopback()
        && !is_reserved
        && !is_shared
        && !ip_address.is_unspecified()
}

pub fn is_valid_ipv4_prefix_length(prefix_length: u32) -> bool {
    prefix_length <= 32
}

// Check that the given IPv4 addresses are all in the same subnet with respect to the subnet mask
pub fn are_in_the_same_subnet(ipv4_addresses: Vec<String>, prefix_length: u32) -> bool {
    let bitmask: u32 = !0 << (32 - prefix_length);
    let bitmask: [u8; 4] = bitmask.to_be_bytes();
    let subnet_mask = Ipv4Addr::new(bitmask[0], bitmask[1], bitmask[2], bitmask[3]);

    let subnet_prefixes: HashSet<Vec<u8>> = ipv4_addresses
        .iter()
        .map(|x| extract_subnet_bytes(x.as_str(), subnet_mask))
        .collect();
    // all IP addresses are in the same subnet, if they share the same subnet bytes
    subnet_prefixes.len() == 1
}

// Helper function to extract the subnet bytes of the given IP address
fn extract_subnet_bytes(ipv4_address: &str, subnet_mask: Ipv4Addr) -> Vec<u8> {
    Ipv4Addr::from_str(ipv4_address)
        .unwrap_or_else(|_| panic!("Failed to parse IP address: {}", ipv4_address))
        .octets()
        .iter()
        .zip(subnet_mask.octets().iter())
        .map(|(&a, &b)| a & b)
        .collect::<Vec<u8>>()
}

#[derive(Debug)]
pub enum IPv4ConfigError {
    InvalidIPv4Address,
    InvalidGatewayAddress,
    InvalidPrefixLength,
    NotInSameSubnet,
    NotGlobalIPv4Address,
}

impl fmt::Display for IPv4ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IPv4ConfigError::InvalidIPv4Address => {
                write!(f, "Invalid IPv4 address")
            }
            IPv4ConfigError::InvalidGatewayAddress => {
                write!(f, "Invalid gateway IPv4 address")
            }
            IPv4ConfigError::InvalidPrefixLength => {
                write!(f, "Invalid prefix length")
            }
            IPv4ConfigError::NotInSameSubnet => {
                write!(f, "IP addresses are not in the same subnet")
            }
            IPv4ConfigError::NotGlobalIPv4Address => {
                write!(f, "IPv4 address is not a global address")
            }
        }
    }
}

// Check that a given IPv4 config is valid
pub fn check_ipv4_config(
    ip_addr: String,
    gateway_ip_addrs: Vec<String>,
    prefix_length: u32,
) -> Result<(), IPv4ConfigError> {
    // Ensure all are valid IPv4 addresses
    if !is_valid_ipv4_address(&ip_addr) {
        return Err(IPv4ConfigError::InvalidIPv4Address);
    }

    for gateway_ip_addr in &gateway_ip_addrs {
        if !is_valid_ipv4_address(gateway_ip_addr) {
            return Err(IPv4ConfigError::InvalidGatewayAddress);
        }
    }

    // Ensure the prefix length is valid
    if !is_valid_ipv4_prefix_length(prefix_length) {
        return Err(IPv4ConfigError::InvalidPrefixLength);
    }

    // Ensure all IPv4 addresses are in the same subnet
    let mut all_ip_addrs = gateway_ip_addrs.clone();
    all_ip_addrs.push(ip_addr.clone());
    if !are_in_the_same_subnet(all_ip_addrs, prefix_length) {
        return Err(IPv4ConfigError::NotInSameSubnet);
    }

    // Ensure the IPv4 address is a routable address
    if !is_global_ipv4_address(&ip_addr) {
        return Err(IPv4ConfigError::NotGlobalIPv4Address);
    }

    Ok(())
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
    use crate::mutations::common::{
        are_in_the_same_subnet, check_ipv6_format, is_global_ipv4_address, is_valid_domain,
        is_valid_ipv4_address,
    };

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

    #[test]
    fn test_is_valid_ipv4_address() {
        // Valid IPv4 addresses
        assert!(is_valid_ipv4_address("192.168.1.1"));
        assert!(is_valid_ipv4_address("0.0.0.0"));
        assert!(is_valid_ipv4_address("255.255.255.255"));
        assert!(is_valid_ipv4_address("10.0.0.1"));
        assert!(is_valid_ipv4_address("172.16.0.1"));
        assert!(is_valid_ipv4_address("8.8.8.8"));
        assert!(is_valid_ipv4_address("255.255.224.0"));

        // Invalid IPv4 addresses
        assert!(!is_valid_ipv4_address("256.256.256.256")); // Values exceed 255
        assert!(!is_valid_ipv4_address("192.168.1.")); // Incomplete address
        assert!(!is_valid_ipv4_address("192.168.1.1.1")); // Too many segments
        assert!(!is_valid_ipv4_address("192.168.1.-1")); // Negative value
        assert!(!is_valid_ipv4_address("abc.def.ghi.jkl")); // Non-numeric characters
        assert!(!is_valid_ipv4_address("")); // Empty string
    }

    #[test]
    fn test_are_in_the_same_subnet() {
        // Test case 1: All IPv4 addresses are in the same subnet
        let ip_addresses1 = vec![
            "192.168.1.1".to_string(),
            "192.168.1.2".to_string(),
            "192.168.1.3".to_string(),
        ];
        assert!(are_in_the_same_subnet(ip_addresses1, 24));

        // Test case 2: All IPv4 addresses are in different subnets
        let ip_addresses2 = vec![
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
            "172.16.0.1".to_string(),
        ];
        assert!(!are_in_the_same_subnet(ip_addresses2, 24));

        // Test case 3: One IP address is in a different subnet
        let ip_addresses3 = vec![
            "192.168.1.1".to_string(),
            "192.168.1.2".to_string(),
            "10.0.0.1".to_string(),
        ];
        assert!(!are_in_the_same_subnet(ip_addresses3, 24));
    }

    #[test]
    fn test_is_global_ipv4_address() {
        // Valid IPv4 addresses
        assert!(is_global_ipv4_address("8.8.1.1"));
        assert!(is_global_ipv4_address("212.71.124.187"));
        assert!(is_global_ipv4_address("193.118.59.140"));

        // Invalid IPv4 addresses
        assert!(!is_global_ipv4_address("198.19.32.89")); // benchmarking
        assert!(!is_global_ipv4_address("255.255.255.255")); // broadcast
        assert!(!is_global_ipv4_address("192.0.2.55")); // documentation
        assert!(!is_global_ipv4_address("198.51.100.0")); // documentation
        assert!(!is_global_ipv4_address("203.0.113.13")); // documentation
        assert!(!is_global_ipv4_address("169.254.11.12")); // link local
        assert!(!is_global_ipv4_address("127.0.0.1")); // loopback
        assert!(!is_global_ipv4_address("10.0.0.1")); // private
        assert!(!is_global_ipv4_address("172.16.255.12")); // private
        assert!(!is_global_ipv4_address("192.168.1.1")); // private
        assert!(!is_global_ipv4_address("100.96.12.34")); // shared
        assert!(!is_global_ipv4_address("240.255.249.11")); // reserved
        assert!(!is_global_ipv4_address("0.0.0.0")); // unspecified
    }
}
