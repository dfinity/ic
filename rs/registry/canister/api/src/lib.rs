use candid::{CandidType, Deserialize};
use ic_base_types::NodeId;
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IPv4ConfigError {
    #[error("Invalid IPv4 address")]
    InvalidIPv4Address,
    #[error("Invalid gateway IPv4 address")]
    InvalidGatewayAddress,
    #[error("Invalid prefix length")]
    InvalidPrefixLength,
    #[error("IP addresses are not in the same subnet")]
    NotInSameSubnet,
    #[error("IPv4 address is not a global address")]
    NotGlobalIPv4Address,
}

fn is_valid_ipv4_prefix_length(prefix_length: u32) -> bool {
    prefix_length <= 32
}

fn is_global_ipv4_address(ipv4_address: &str) -> bool {
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

// Check that the given IPv4 addresses are all in the same subnet with respect to the IPv4 subnet mask
fn are_in_the_same_subnet(ipv4_addresses: Vec<String>, prefix_length: u32) -> bool {
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

// Helper function to extract the IPv4 subnet bytes of the given IP address
fn extract_subnet_bytes(ipv4_address: &str, subnet_mask: Ipv4Addr) -> Vec<u8> {
    Ipv4Addr::from_str(ipv4_address)
        .unwrap_or_else(|_| panic!("Failed to parse IP address: {}", ipv4_address))
        .octets()
        .iter()
        .zip(subnet_mask.octets().iter())
        .map(|(&a, &b)| a & b)
        .collect::<Vec<u8>>()
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Deserialize, Serialize)]
pub struct IPv4Config {
    ip_addr: String,
    gateway_ip_addr: String,
    prefix_length: u32,
}

impl IPv4Config {
    // TODO: it is not ideal to have this constructor if we try to always construct a valid IPv4Config.
    pub fn maybe_invalid_new(ip_addr: String, gateway_ip_addr: String, prefix_length: u32) -> Self {
        Self {
            ip_addr,
            gateway_ip_addr,
            prefix_length,
        }
    }

    pub fn try_new(
        ip_addr: String,
        gateway_ip_addr: String,
        prefix_length: u32,
    ) -> Result<Self, IPv4ConfigError> {
        // Ensure all are valid IPv4 addresses
        if Ipv4Addr::from_str(&ip_addr).is_err() {
            return Err(IPv4ConfigError::InvalidIPv4Address);
        }

        if Ipv4Addr::from_str(&gateway_ip_addr).is_err() {
            return Err(IPv4ConfigError::InvalidGatewayAddress);
        }

        // Ensure the prefix length is valid
        if !is_valid_ipv4_prefix_length(prefix_length) {
            return Err(IPv4ConfigError::InvalidPrefixLength);
        }

        // Ensure all IPv4 addresses are in the same subnet
        let all_ip_addrs = vec![gateway_ip_addr.clone(), ip_addr.clone()];
        if !are_in_the_same_subnet(all_ip_addrs, prefix_length) {
            return Err(IPv4ConfigError::NotInSameSubnet);
        }

        // Ensure the IPv4 address is a routable address
        if !is_global_ipv4_address(&ip_addr) {
            return Err(IPv4ConfigError::NotGlobalIPv4Address);
        }

        Ok(Self {
            ip_addr,
            gateway_ip_addr,
            prefix_length,
        })
    }

    pub fn panic_on_invalid(&self) {
        IPv4Config::try_new(
            self.ip_addr.clone(),
            self.gateway_ip_addr.clone(),
            self.prefix_length,
        )
        .unwrap();
    }

    // TODO: either remove this method or return std::net::IpAddr to signal that the ip addr is valid
    pub fn ip_addr(&self) -> &str {
        &self.ip_addr
    }

    // TODO: either remove this method or return std::net::IpAddr to signal that the ip addr is valid
    pub fn gateway_ip_addr(&self) -> &str {
        &self.gateway_ip_addr
    }

    // TODO: consider adding a type for the prefix
    pub fn prefix_length(&self) -> u32 {
        self.prefix_length
    }
}

impl fmt::Display for IPv4Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4Config: {:?}/{:?} with gateway {:?}",
            self.ip_addr, self.prefix_length, self.gateway_ip_addr
        )
    }
}

/// The payload of an update request to add a new node.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct AddNodePayload {
    // Raw bytes of the protobuf, but these should be PublicKey
    pub node_signing_pk: Vec<u8>,
    pub committee_signing_pk: Vec<u8>,
    pub ni_dkg_dealing_encryption_pk: Vec<u8>,
    // Raw bytes of the protobuf, but these should be X509PublicKeyCert
    pub transport_tls_cert: Vec<u8>,
    // Raw bytes of the protobuf, but these should be PublicKey
    pub idkg_dealing_encryption_pk: Option<Vec<u8>>,

    pub xnet_endpoint: String,
    pub http_endpoint: String,

    pub chip_id: Option<Vec<u8>>,

    pub public_ipv4_config: Option<IPv4Config>,
    pub domain: Option<String>,

    // TODO(NNS1-2444): The fields below are deprecated and they are not read anywhere.
    pub p2p_flow_endpoints: Vec<String>,
    pub prometheus_metrics_endpoint: String,
}

/// The payload of a request to update keys of the existing node.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct UpdateNodeDirectlyPayload {
    pub idkg_dealing_encryption_pk: Option<Vec<u8>>,
}

// The payload of a request to update the IPv4 configuration of an existing node
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateNodeIPv4ConfigDirectlyPayload {
    pub node_id: NodeId,
    pub ipv4_config: Option<IPv4Config>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn succeeds_if_ipv4_config_is_valid() {
        assert!(
            IPv4Config::try_new("204.153.51.58".to_string(), "204.153.51.1".to_string(), 24,)
                .is_ok()
        );
    }

    #[test]
    fn fails_if_ipv4_config_is_invalid() {
        assert!(
            IPv4Config::try_new("204.153.51.58".to_string(), "204.153.49.1".to_string(), 24,)
                .is_err()
        );
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
