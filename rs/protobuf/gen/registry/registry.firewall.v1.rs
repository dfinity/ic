/// Firewall configuration
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FirewallConfig {
    /// The firewall configuration content
    #[prost(string, tag="1")]
    pub firewall_config: ::prost::alloc::string::String,
    /// List of allowed IPv4 prefixes
    #[prost(string, repeated, tag="2")]
    pub ipv4_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// List of allowed IPv6 prefixes
    #[prost(string, repeated, tag="3")]
    pub ipv6_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
