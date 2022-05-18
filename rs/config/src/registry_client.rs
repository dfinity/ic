use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

/// Eventually, the replica will only read registry data from the local store
/// and the orchestrator will both read from and write to the registry local
/// store.
///
/// I.e. all data provider variants except for the variant `LocalStore` are
/// considered deprecated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub data_provider: Option<DataProviderConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataProviderConfig {
    /// DEPRECATED
    /// Comma separated list of base Urls of a node on the NNS subnetwork that
    /// hosts the registry canister. The registry canister will be queried
    /// for update frequently for registry updates using canister queries.
    RegistryCanisterUrl(Vec<Url>),
    /// A path to a directory that containing the locally persisted registry.
    LocalStore(PathBuf),
}

impl DataProviderConfig {
    pub fn get_registry_urls(&self) -> Vec<Url> {
        match self {
            Self::LocalStore(_) => vec![],
            Self::RegistryCanisterUrl(u) => u.clone(),
        }
    }
}
