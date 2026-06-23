use ic_protobuf::registry::firewall::v1::FirewallRule;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(test)]
use proptest::prelude::{Strategy, any};
#[cfg(test)]
use proptest_derive::Arbitrary;

/// The sets of ports that an assigned node (a replica or a cloud engine) opens
/// or blocks for the other nodes in the network when compiling its firewall
/// rules.
///
/// This is embedded into both [`ReplicaConfig`] and [`CloudEngineConfig`] with
/// `#[serde(flatten)]`, so on disk these fields appear directly inside the
/// surrounding firewall config.
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct AssignedNodePortLists {
    /// Ports opened to whitelisted nodes in the network.
    /// "whitelisted" here refers to the logic found in
    /// `rs/orchestrator/src/firewall.rs:is_whitelisted()`
    pub whitelisted_nodes_tcp_ports_whitelist: Vec<u32>,
    pub whitelisted_nodes_udp_ports_whitelist: Vec<u32>,
    /// Ports opened to all nodes in the network (including non-whitelisted).
    pub all_nodes_tcp_ports_whitelist: Vec<u32>,
    pub all_nodes_udp_ports_whitelist: Vec<u32>,
    pub ports_for_http_adapter_blacklist: Vec<u32>,
}

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
    /// Ports opened/blocked for the other nodes in the network.
    #[serde(flatten)]
    pub assigned_node_port_lists: AssignedNodePortLists,
    /// We allow a maximum of `max_simultaneous_connections_per_ip_address` persistent connections to any ip address.
    /// Any ip address with `max_simultaneous_connections_per_ip_address` connections will be dropped if a new connection is attempted.
    pub max_simultaneous_connections_per_ip_address: u32,
}

impl ReplicaConfig {
    /// Create a ReplicaConfig from a given path to the config file.
    pub fn new(config_file: PathBuf) -> Self {
        Self {
            config_file,
            file_template: "".to_string(),
            ipv4_tcp_rule_template: "".to_string(),
            ipv6_tcp_rule_template: "".to_string(),
            ipv4_udp_rule_template: "".to_string(),
            ipv6_udp_rule_template: "".to_string(),
            ipv4_user_output_rule_template: "".to_string(),
            ipv6_user_output_rule_template: "".to_string(),
            default_rules: vec![],
            assigned_node_port_lists: AssignedNodePortLists::default(),
            max_simultaneous_connections_per_ip_address: 0,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct CloudEngineConfig {
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
    /// Ports opened/blocked for the other nodes in the network.
    #[serde(flatten)]
    pub assigned_node_port_lists: AssignedNodePortLists,
    /// We allow a maximum of `max_simultaneous_connections_per_ip_address` persistent connections to any ip address.
    /// Any ip address with `max_simultaneous_connections_per_ip_address` connections will be dropped if a new connection is attempted.
    pub max_simultaneous_connections_per_ip_address: u32,
}

impl CloudEngineConfig {
    /// Create a CloudEngineConfig from a given path to the config file.
    pub fn new(config_file: PathBuf) -> Self {
        Self {
            config_file,
            file_template: "".to_string(),
            ipv4_tcp_rule_template: "".to_string(),
            ipv6_tcp_rule_template: "".to_string(),
            ipv4_udp_rule_template: "".to_string(),
            ipv6_udp_rule_template: "".to_string(),
            ipv4_user_output_rule_template: "".to_string(),
            ipv6_user_output_rule_template: "".to_string(),
            default_rules: vec![],
            assigned_node_port_lists: AssignedNodePortLists::default(),
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

impl BoundaryNodeConfig {
    /// Create a BoundaryNodeConfig from a given path to the config file.
    pub fn new(config_file: PathBuf) -> Self {
        Self {
            config_file,
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
