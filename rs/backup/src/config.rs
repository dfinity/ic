use ic_config::{ConfigSource, ConfigValidate};
use ic_types::{ReplicaVersion, SubnetId};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use std::path::PathBuf;
use url::Url;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubnetConfig {
    pub subnet_id: SubnetId,
    #[serde(deserialize_with = "replica_from_string")]
    pub replica_version: ReplicaVersion,
    pub sync_period_secs: u64,
    pub replay_period_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct Config {
    pub root_dir: PathBuf,
    pub nns_url: String,
    pub ssh_credentials: PathBuf,
    pub subnets: Vec<SubnetConfig>,
}

fn replica_from_string<'de, D>(deserializer: D) -> Result<ReplicaVersion, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    ReplicaVersion::try_from(s).map_err(D::Error::custom)
}

impl ConfigValidate for Config {
    fn validate(self) -> Result<Self, String> {
        Url::parse(&self.nns_url).map_err(|e| format!("Unable to parse NNS Url {:?}", e))?;
        if !self.ssh_credentials.exists() {
            return Err(format!(
                "Missing ssh credentials file: {:?}",
                self.ssh_credentials
            ));
        }
        if self.subnets.is_empty() {
            return Err("No subnet configured for backup!".to_string());
        }
        Ok(self)
    }
}

impl Config {
    pub fn load_config(config_path: PathBuf) -> Result<Config, String> {
        let config: Config = ConfigSource::File(config_path)
            .load()
            .map_err(|e| e.to_string())?;
        Ok(config)
    }
}
