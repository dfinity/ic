use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use config_types::DeploymentEnvironment;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use url::Url;

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct DeploymentSettings {
    pub deployment: Deployment,
    pub nns: Nns,
    pub vm_resources: VmResources,
}

#[serde_as]
#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Deployment {
    /// The deployment environment is either "mainnet" or "testnet"
    #[serde_as(as = "DisplayFromStr")]
    pub deployment_environment: DeploymentEnvironment,
    /// Optional management MAC address for network configuration, used for nested environments
    pub mgmt_mac: Option<String>,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Nns {
    pub urls: Vec<Url>,
}

#[serde_as]
#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct VmResources {
    #[serde_as(as = "DisplayFromStr")]
    pub memory: u32,
    /// CPU virtualization type: "kvm" or "qemu".
    pub cpu: String,
    /// Maximum number of virtual CPUs allocated for the GuestOS,
    /// which must be between 1 and the maximum supported by the hypervisor.
    pub nr_of_vcpus: u32,
}

pub fn get_deployment_settings(deployment_json: &Path) -> Result<DeploymentSettings> {
    let file = File::open(deployment_json).context("failed to open deployment config file")?;
    serde_json::from_reader(&file).context("Invalid json content")
}

#[cfg(test)]
mod test {
    use super::*;
    use once_cell::sync::Lazy;
    use serde_json::{json, Value};

    static DEPLOYMENT_VALUE: Lazy<Value> = Lazy::new(|| {
        json!({
              "deployment": {
                "deployment_environment": "mainnet",
                "mgmt_mac": null
              },
              "nns": {
                "urls": ["https://icp-api.io", "https://icp0.io", "https://ic0.app"]
              },
              "vm_resources": {
                "memory": "490",
                "cpu": "kvm",
                "nr_of_vcpus": 64
              }
            }
        )
    });

    const DEPLOYMENT_STR: &str = r#"{
  "deployment": {
    "deployment_environment": "mainnet",
    "mgmt_mac": null
  },
  "nns": {
    "urls": ["https://icp-api.io", "https://icp0.io", "https://ic0.app"]
  },
  "vm_resources": {
    "memory": "490",
    "cpu": "kvm",
    "nr_of_vcpus": 64
  }
}"#;

    static DEPLOYMENT_STRUCT: Lazy<DeploymentSettings> = Lazy::new(|| DeploymentSettings {
        deployment: Deployment {
            deployment_environment: DeploymentEnvironment::Mainnet,
            mgmt_mac: None,
        },
        nns: Nns {
            urls: vec![
                Url::parse("https://icp-api.io").unwrap(),
                Url::parse("https://icp0.io").unwrap(),
                Url::parse("https://ic0.app").unwrap(),
            ],
        },
        vm_resources: VmResources {
            memory: 490,
            cpu: "kvm".to_string(),
            nr_of_vcpus: 64,
        },
    });

    #[test]
    fn deserialize_deployment() {
        let parsed_deployment = { serde_json::from_str(DEPLOYMENT_STR).unwrap() };

        assert_eq!(*DEPLOYMENT_STRUCT, parsed_deployment);

        // Exercise DeserializeOwned using serde_json::from_value.
        // DeserializeOwned is used by serde_json::from_reader, which is the
        // main entrypoint of this code, in practice.
        let parsed_deployment = { serde_json::from_value(DEPLOYMENT_VALUE.clone()).unwrap() };

        assert_eq!(*DEPLOYMENT_STRUCT, parsed_deployment);
    }
}
