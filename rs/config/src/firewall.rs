use ic_protobuf::registry::firewall::v1::FirewallRule;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;

// This path is not used in practice. The code should panic if it is.
pub const FIREWALL_FILE_DEFAULT_PATH: &str = "/This/must/not/be/a/real/path";

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ReplicaConfig {
    /// Path to use for storing state on the file system
    #[cfg_attr(test, proptest(strategy = "any::<String>().prop_map(PathBuf::from)"))]
    pub config_file: PathBuf,
    pub file_template: String,
    pub ipv4_tcp_rule_template: String,
    pub ipv6_tcp_rule_template: String,
    pub ipv4_udp_rule_template: String,
    pub ipv6_udp_rule_template: String,
    pub ipv4_user_output_rule_template: String,
    pub ipv6_user_output_rule_template: String,
    #[cfg_attr(test, proptest(strategy = "any::<String>().prop_map(|_x| vec![])"))]
    pub default_rules: Vec<FirewallRule>,
    /// A map from protocol, UDP or TCP, to a list of ports that the node will use to whitelist for other nodes in the subnet.
    pub tcp_ports_for_node_whitelist: Vec<u32>,
    pub udp_ports_for_node_whitelist: Vec<u32>,
    pub ports_for_http_adapter_blacklist: Vec<u32>,
    /// We allow a maximum of `max_simultaneous_connections_per_ip_address` persistent connections to any ip address.
    /// Any ip address with `max_simultaneous_connections_per_ip_address` connections will be dropped if a new connection is attempted.
    pub max_simultaneous_connections_per_ip_address: u32,
}

impl Default for ReplicaConfig {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from(FIREWALL_FILE_DEFAULT_PATH),
            file_template: "".to_string(),
            ipv4_tcp_rule_template: "".to_string(),
            ipv6_tcp_rule_template: "".to_string(),
            ipv4_udp_rule_template: "".to_string(),
            ipv6_udp_rule_template: "".to_string(),
            ipv4_user_output_rule_template: "".to_string(),
            ipv6_user_output_rule_template: "".to_string(),
            default_rules: vec![],
            tcp_ports_for_node_whitelist: vec![],
            udp_ports_for_node_whitelist: vec![],
            ports_for_http_adapter_blacklist: vec![],
            max_simultaneous_connections_per_ip_address: 0,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct BoundaryNodeConfig {
    /// Path to use for storing state on the file system
    #[cfg_attr(test, proptest(strategy = "any::<String>().prop_map(PathBuf::from)"))]
    pub config_file: PathBuf,
    pub file_template: String,
    pub ipv4_tcp_rule_template: String,
    pub ipv6_tcp_rule_template: String,
    pub ipv4_udp_rule_template: String,
    pub ipv6_udp_rule_template: String,
    #[cfg_attr(test, proptest(strategy = "any::<String>().prop_map(|_x| vec![])"))]
    pub default_rules: Vec<FirewallRule>,
    /// We allow a maximum of `max_simultaneous_connections_per_ip_address` persistent connections to any ip address.
    /// Any ip address with `max_simultaneous_connections_per_ip_address` connections will be dropped if a new connection is attempted.
    pub max_simultaneous_connections_per_ip_address: u32,
}

impl Default for BoundaryNodeConfig {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from(FIREWALL_FILE_DEFAULT_PATH),
            file_template: String::default(),
            ipv4_tcp_rule_template: String::default(),
            ipv6_tcp_rule_template: String::default(),
            ipv4_udp_rule_template: String::default(),
            ipv6_udp_rule_template: String::default(),
            default_rules: Vec::default(),
            max_simultaneous_connections_per_ip_address: 0,
        }
    }
}
