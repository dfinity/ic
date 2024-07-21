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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IPv4Config {
    ip_addr: String,
    gateway_ip_addr: String,
    prefix_length: u32,
}

impl IPv4Config {
    pub fn new(
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
            self.ip_addr, self.prefix_length, self.prefix_length
        )
    }
}

/// The payload of an update request to add a new node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
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

/// The payload of an request to update keys of the existing node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateNodeDirectlyPayload {
    pub idkg_dealing_encryption_pk: Option<Vec<u8>>,
}

// The payload of a request to update the IPv4 configuration of an existing node
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateNodeIPv4ConfigDirectlyPayload {
    pub node_id: NodeId,
    pub ipv4_config: Option<IPv4Config>,
}
