#![allow(clippy::redundant_closure)]

use ic_protobuf::registry::firewall::v1::FirewallRule;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;

// This path is not used in practice. The code should panic if it is.
pub const FIREWALL_FILE_DEFAULT_PATH: &str = "/This/must/not/be/a/real/path";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct Config {
    /// Path to use for storing state on the file system
    #[cfg_attr(
        test,
        proptest(strategy = "any::<String>().prop_map(|x| PathBuf::from(x))")
    )]
    pub config_file: PathBuf,

    // The following fields are obsolete and are to be removed when IC-1026 is staged
    pub firewall_config: String,
    pub ipv4_prefixes: Vec<String>,
    pub ipv6_prefixes: Vec<String>,

    pub file_template: String,
    pub ipv4_rule_template: String,
    pub ipv6_rule_template: String,
    #[cfg_attr(test, proptest(strategy = "any::<String>().prop_map(|_x| vec![])"))]
    pub default_rules: Vec<FirewallRule>,
    pub ports_for_node_whitelist: Vec<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from(FIREWALL_FILE_DEFAULT_PATH),
            firewall_config: "".to_string(),
            ipv4_prefixes: vec![],
            ipv6_prefixes: vec![],
            file_template: "".to_string(),
            ipv4_rule_template: "".to_string(),
            ipv6_rule_template: "".to_string(),
            default_rules: vec![],
            ports_for_node_whitelist: vec![],
        }
    }
}
