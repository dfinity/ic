/// A connection endpoint.
#[derive(serde::Serialize, serde::Deserialize, Eq, PartialOrd, Ord)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConnectionEndpoint {
    /// The IP address. Senders SHOULD use dotted-quad notation for IPv4 addresses
    /// and RFC5952 representation for IPv6 addresses (which means that IPv6
    /// addresses are *not* enclosed in `[` and `]`, as they are not written
    /// with the port in the same field).
    ///
    /// Clients MUST be prepared to accept IPv6 addresses in the forms shown in
    /// RFC4291.
    #[prost(string, tag = "1")]
    pub ip_addr: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub port: u32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowEndpoint {
    /// The IP/port for this flow.
    #[prost(message, optional, tag = "2")]
    pub endpoint: ::core::option::Option<ConnectionEndpoint>,
}
/// A node: one machine running a replica instance.
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRecord {
    /// The endpoint where this node receives xnet messages.
    #[prost(message, optional, tag = "5")]
    pub xnet: ::core::option::Option<ConnectionEndpoint>,
    /// The endpoint where this node receives http requests.
    #[prost(message, optional, tag = "6")]
    pub http: ::core::option::Option<ConnectionEndpoint>,
    /// The P2P flow end points.
    #[prost(message, repeated, tag = "8")]
    pub p2p_flow_endpoints: ::prost::alloc::vec::Vec<FlowEndpoint>,
    /// The id of the node operator that added this node.
    #[prost(bytes = "vec", tag = "15")]
    pub node_operator_id: ::prost::alloc::vec::Vec<u8>,
    /// The SEV-SNP chip_identifier for this node.
    #[prost(bytes = "vec", tag = "16")]
    pub chip_id: ::prost::alloc::vec::Vec<u8>,
    /// ID of the HostOS version to run.
    #[prost(string, optional, tag = "17")]
    pub hostos_version_id: ::core::option::Option<::prost::alloc::string::String>,
}
