use ic_config::{ConfigSource, ConfigValidate};
use ic_types::{ReplicaVersion, SubnetId};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write, net::IpAddr, path::PathBuf};
use url::Url;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct SubnetConfig {
    pub subnet_id: SubnetId,
    #[serde(
        deserialize_with = "crate::util::replica_from_string",
        serialize_with = "crate::util::replica_to_string"
    )]
    pub initial_replica_version: ReplicaVersion,
    pub nodes_syncing: usize,
    pub sync_period_secs: u64,
    pub replay_period_secs: u64,
    pub thread_id: u32,
    pub disable_cold_storage: bool,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct ColdStorage {
    pub cold_storage_dir: PathBuf,
    pub versions_hot: usize,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    pub push_metrics: bool,
    pub metrics_urls: Vec<Url>,
    pub network_name: String,
    pub backup_instance: String,
    pub nns_url: Option<Url>,
    pub nns_pem: PathBuf,
    pub root_dir: PathBuf,
    pub excluded_dirs: Vec<String>,
    pub ssh_private_key: PathBuf,
    pub hot_disk_resource_threshold_percentage: u32,
    pub cold_disk_resource_threshold_percentage: u32,
    pub slack_token: String,
    pub cold_storage: Option<ColdStorage>,
    pub blacklisted_nodes: Option<Vec<IpAddr>>,
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
        if self.hot_disk_resource_threshold_percentage >= 100 {
            return Err("Hot disk threshold warning should be below 100%".to_string());
        }
        if self.cold_disk_resource_threshold_percentage >= 100 {
            return Err("Cold disk threshold warning should be below 100%".to_string());
        }
        // we accept no subnets in the config at the initial stage only
        if self.subnets.is_empty() && self.slack_token != "<INSERT SLACK TOKEN>" {
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
    pub fn save_config(&self, config_path: PathBuf) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|err| format!("Error serializing config: {err:?}"))?;
        let mut file = File::create(config_path)
            .map_err(|err| format!("Error creating config file: {err:?}"))?;
        file.write_all(json.as_bytes())
            .map_err(|err| format!("Error writing config: {err:?}"))
    }
}
