/// A connection endpoint.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConnectionEndpoint {
    /// The IP address. Senders SHOULD use dotted-quad notation for IPv4 addresses
    /// and RFC5952 representation for IPv6 addresses (which means that IPv6
    /// addresses are *not* enclosed in `[` and `]`, as they are not written
    /// with the port in the same field).
    ///
    /// Clients MUST be prepared to accept IPv6 addresses in the forms shown in
    /// RFC4291.
    #[prost(string, tag="1")]
    pub ip_addr: ::prost::alloc::string::String,
    #[prost(uint32, tag="2")]
    pub port: u32,
    /// Protocol that is used on this endpoint. If PROTOCOL_UNSPECIFIED then
    /// code should default to PROTOCOL_HTTP1 for backwards compatability.
    #[prost(enumeration="connection_endpoint::Protocol", tag="4")]
    pub protocol: i32,
}
/// Nested message and enum types in `ConnectionEndpoint`.
pub mod connection_endpoint {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Protocol {
        Unspecified = 0,
        Http1 = 1,
        Http1Tls13 = 2,
        P2p1Tls13 = 3,
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowEndpoint {
    /// The flow identifier (tag). This has to be unique per NodeRecord.
    #[prost(uint32, tag="1")]
    pub flow_tag: u32,
    /// The IP/port for this flow.
    #[prost(message, optional, tag="2")]
    pub endpoint: ::core::option::Option<ConnectionEndpoint>,
}
/// A node: one machine running a replica instance.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRecord {
    /// The endpoint where this node receives xnet messages.
    #[prost(message, optional, tag="5")]
    pub xnet: ::core::option::Option<ConnectionEndpoint>,
    /// The endpoint where this node receives http requests.
    #[prost(message, optional, tag="6")]
    pub http: ::core::option::Option<ConnectionEndpoint>,
    /// The P2P flow end points.
    #[prost(message, repeated, tag="8")]
    pub p2p_flow_endpoints: ::prost::alloc::vec::Vec<FlowEndpoint>,
    /// Endpoint where the node provides Prometheus format metrics over HTTP
    #[prost(message, optional, tag="10")]
    pub prometheus_metrics_http: ::core::option::Option<ConnectionEndpoint>,
    /// Endpoints on which the public API is served.
    #[prost(message, repeated, tag="11")]
    pub public_api: ::prost::alloc::vec::Vec<ConnectionEndpoint>,
    /// Endpoints on which private APIs are served.
    #[prost(message, repeated, tag="12")]
    pub private_api: ::prost::alloc::vec::Vec<ConnectionEndpoint>,
    /// Endpoints on which metrics compatible with the Prometheus export
    /// format are served.
    #[prost(message, repeated, tag="13")]
    pub prometheus_metrics: ::prost::alloc::vec::Vec<ConnectionEndpoint>,
    /// Endpoints on which the XNet API is served
    #[prost(message, repeated, tag="14")]
    pub xnet_api: ::prost::alloc::vec::Vec<ConnectionEndpoint>,
    /// The id of the node operator that added this node.
    #[prost(bytes="vec", tag="15")]
    pub node_operator_id: ::prost::alloc::vec::Vec<u8>,
}
