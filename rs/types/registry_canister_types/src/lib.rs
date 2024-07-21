use candid::{CandidType, Deserialize};
use ic_base_types::NodeId;
use serde::Serialize;
use std::fmt;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IPv4Config {
    pub ip_addr: String,
    pub gateway_ip_addr: String,
    pub prefix_length: u32,
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
