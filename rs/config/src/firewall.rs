#![allow(clippy::redundant_closure)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(test)]
use proptest::prelude::{any, Strategy};
#[cfg(test)]
use proptest_derive::Arbitrary;

// This path is not used in practice. The code should panic if it is.
pub const FIREWALL_FILE_DEFAULT_PATH: &str = "/This/must/not/be/a/real/path";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(Arbitrary))]
pub struct Config {
    /// Path to use for storing state on the file system
    #[cfg_attr(
        test,
        proptest(strategy = "any::<String>().prop_map(|x| PathBuf::from(x))")
    )]
    pub config_file: PathBuf,
    pub firewall_config: String,
    pub ipv4_prefixes: Vec<String>,
    pub ipv6_prefixes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_file: PathBuf::from(FIREWALL_FILE_DEFAULT_PATH),
            firewall_config: "".to_string(),
            ipv4_prefixes: vec![],
            ipv6_prefixes: vec![],
        }
    }
}
