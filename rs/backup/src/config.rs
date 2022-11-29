use ic_config::{ConfigSource, ConfigValidate};
use ic_types::{ReplicaVersion, SubnetId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubnetConfig {
    pub subnet_id: SubnetId,
    #[serde(
        deserialize_with = "crate::util::replica_from_string",
        serialize_with = "crate::util::replica_to_string"
    )]
    pub initial_replica_version: ReplicaVersion,
    pub nodes_syncing: u32,
    pub sync_period_secs: u64,
    pub replay_period_secs: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub backup_instance: String,
    pub nns_url: Option<Url>,
    pub nns_pem: PathBuf,
    pub root_dir: PathBuf,
    pub excluded_dirs: Vec<String>,
    pub ssh_private_key: PathBuf,
    pub disk_threshold_warn: u32,
    pub slack_token: String,
    pub subnets: Vec<SubnetConfig>,
}

impl ConfigValidate for Config {
    fn validate(self) -> Result<Self, String> {
        if self.nns_url.is_none() {
            return Err("NNS Url is required!".to_string());
        }
        if !self.ssh_private_key.exists() {
            return Err(format!(
                "Missing ssh credentials file: {:?}",
                self.ssh_private_key
            ));
        }
        if self.disk_threshold_warn > 100 {
            return Err("Disk threshhold warning value is > 100".to_string());
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
