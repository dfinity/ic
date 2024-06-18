use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use url::Url;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct DeploymentJson {
    pub deployment: Deployment,
    pub logging: Logging,
    pub nns: Nns,
    pub resources: Resources,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Deployment {
    pub name: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Logging {
    pub hosts: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Nns {
    pub url: Url,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Resources {
    #[serde_as(as = "DisplayFromStr")]
    pub memory: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
}

pub fn read_deployment_file(deployment_json: &Path) -> Result<DeploymentJson> {
    let file = File::open(deployment_json).context("failed to open deployment config file")?;
    serde_json::from_reader(&file).context("Invalid json content")
}

#[cfg(test)]
mod test {
    use super::*;
    use once_cell::sync::Lazy;

    const DEPLOYMENT_STR: &str = r#"{
  "deployment": {
    "name": "mainnet"
  },
  "logging": {
    "hosts": "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443"
  },
  "nns": {
    "url": "https://dfinity.org/"
  },
  "resources": {
    "memory": "490"
  }
}"#;

    static DEPLOYMENT_STRUCT: Lazy<DeploymentJson> = Lazy::new(|| {
        DeploymentJson {
            deployment: Deployment { name: "mainnet".to_string() },
            logging: Logging { hosts: "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443".to_string() },
            nns: Nns { url: Url::parse("https://dfinity.org").unwrap() },
            resources: Resources { memory: 490, cpu: None },
        }
    });

    const CPU_DEPLOYMENT_STR: &str = r#"{
  "deployment": {
    "name": "mainnet"
  },
  "logging": {
    "hosts": "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443"
  },
  "nns": {
    "url": "https://dfinity.org/"
  },
  "resources": {
    "memory": "490",
    "cpu": "qemu"
  }
}"#;

    static CPU_DEPLOYMENT_STRUCT: Lazy<DeploymentJson> = Lazy::new(|| {
        DeploymentJson {
            deployment: Deployment { name: "mainnet".to_string() },
            logging: Logging { hosts: "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443".to_string() },
            nns: Nns { url: Url::parse("https://dfinity.org").unwrap() },
            resources: Resources { memory: 490, cpu: Some("qemu".to_string()) },
        }
    });

    #[test]
    fn read_deployment() {
        let parsed_deployment: DeploymentJson = { serde_json::from_str(DEPLOYMENT_STR).unwrap() };

        assert_eq!(*DEPLOYMENT_STRUCT, parsed_deployment);

        let parsed_cpu_deployment: DeploymentJson =
            { serde_json::from_str(CPU_DEPLOYMENT_STR).unwrap() };

        assert_eq!(*CPU_DEPLOYMENT_STRUCT, parsed_cpu_deployment);
    }

    #[test]
    fn write_deployment() {
        let written_deployment =
            serde_json::to_string_pretty::<DeploymentJson>(&DEPLOYMENT_STRUCT).unwrap();

        assert_eq!(DEPLOYMENT_STR, written_deployment);

        let written_cpu_deployment =
            serde_json::to_string_pretty::<DeploymentJson>(&CPU_DEPLOYMENT_STRUCT).unwrap();

        assert_eq!(CPU_DEPLOYMENT_STR, written_cpu_deployment);
    }
}
