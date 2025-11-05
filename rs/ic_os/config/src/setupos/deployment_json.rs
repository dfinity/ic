use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use config_types::DeploymentEnvironment;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use url::Url;

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct DeploymentSettings {
    pub deployment: Deployment,
    #[serde(default)]
    pub logging: Logging,
    pub nns: Nns,
    pub dev_vm_resources: VmResources,
}

// NOTE #7037: We should always use DeploymentSettings directly, but we need to
// be compatible with old naming for some tests.
#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct CompatDeploymentSettings {
    pub deployment: Deployment,
    #[serde(default)]
    pub logging: Logging,
    pub nns: Nns,
    pub vm_resources: Option<VmResources>,
    pub dev_vm_resources: Option<VmResources>,
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

// NODE-1762: Remove default once default attribute on mainnet nodes
#[derive(PartialEq, Debug, Deserialize, Serialize, Default)]
pub struct Logging {}

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

impl Default for VmResources {
    /// These currently match the defaults for nested tests on Farm:
    /// (`HOSTOS_VCPUS_PER_VM / 2`, `HOSTOS_MEMORY_KIB_PER_VM / 2`)
    fn default() -> Self {
        VmResources {
            memory: 16,
            cpu: "kvm".to_string(),
            nr_of_vcpus: 16,
        }
    }
}

pub fn get_deployment_settings(deployment_json: &Path) -> Result<DeploymentSettings> {
    let file = File::open(deployment_json).context("failed to open deployment config file")?;
    serde_json::from_reader(&file).context("Invalid json content")
}

#[cfg(test)]
mod test {
    use super::*;
    use config_types::HostOSDevSettings;
    use once_cell::sync::Lazy;
    use serde_json::{Value, json};

    static DEPLOYMENT_VALUE: Lazy<Value> = Lazy::new(|| {
        json!({
              "deployment": {
                "deployment_environment": "mainnet",
                "mgmt_mac": null
              },
              "nns": {
                "urls": ["https://icp-api.io", "https://icp0.io", "https://ic0.app"]
              },
              "dev_vm_resources": {
                "memory": "16",
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
  "dev_vm_resources": {
    "memory": "16",
    "cpu": "kvm",
    "nr_of_vcpus": 64
  }
}"#;

    static DEPLOYMENT_STRUCT: Lazy<DeploymentSettings> = Lazy::new(|| DeploymentSettings {
        deployment: Deployment {
            deployment_environment: DeploymentEnvironment::Mainnet,
            mgmt_mac: None,
        },
        logging: Logging {},
        nns: Nns {
            urls: vec![
                Url::parse("https://icp-api.io").unwrap(),
                Url::parse("https://icp0.io").unwrap(),
                Url::parse("https://ic0.app").unwrap(),
            ],
        },
        dev_vm_resources: VmResources {
            memory: 16,
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

    #[test]
    /// Confirm that the defaults for HostOsDevSettings (the config type) and
    /// VmResources (the type from deployment.json) are in line.
    fn defaults_aligned() {
        let dev_settings = HostOSDevSettings::default();
        let vm_resources = VmResources::default();

        assert_eq!(dev_settings.vm_memory, vm_resources.memory);
        assert_eq!(dev_settings.vm_cpu, vm_resources.cpu);
        assert_eq!(dev_settings.vm_nr_of_vcpus, vm_resources.nr_of_vcpus);
    }
}
