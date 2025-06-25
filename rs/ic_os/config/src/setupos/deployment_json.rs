use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use url::Url;

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct DeploymentSettings {
    pub deployment: Deployment,
    pub logging: Logging,
    pub nns: Nns,
    pub resources: Resources,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Deployment {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mgmt_mac: Option<String>,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Logging {
    pub hosts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Nns {
    #[serde(with = "comma_urls")]
    pub url: Vec<Url>,
}

#[serde_as]
#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Resources {
    #[serde_as(as = "DisplayFromStr")]
    pub memory: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Can be "kvm" or "qemu". If None, is treated as "kvm".
    pub cpu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Maximum number of virtual CPUs allocated for the GuestOS,
    /// which must be between 1 and the maximum supported by the hypervisor.
    /// If None, defaults to 64.
    pub nr_of_vcpus: Option<u32>,
}

pub fn get_deployment_settings(deployment_json: &Path) -> Result<DeploymentSettings> {
    let file = File::open(deployment_json).context("failed to open deployment config file")?;
    serde_json::from_reader(&file).context("Invalid json content")
}

mod comma_urls {
    use serde::{de, Deserialize, Deserializer, Serializer};
    use url::Url;

    pub(crate) fn serialize<S>(urls: &[Url], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(
            &urls
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    pub(crate) fn deserialize<'de, D>(d: D) -> Result<Vec<Url>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(d)?;

        s.split(',')
            .map(|v| v.parse::<Url>().map_err(de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use once_cell::sync::Lazy;
    use serde_json::{json, Value};

    static DEPLOYMENT_VALUE: Lazy<Value> = Lazy::new(|| {
        json!({
              "deployment": {
                "name": "mainnet",
                "mgmt_mac": null
              },
              "logging": {
                "hosts": "elasticsearch.ch1-obsdev1.dfinity.network:443"
              },
              "nns": {
                "url": "https://icp-api.io,https://icp0.io,https://ic0.app"
              },
              "resources": {
                "memory": "490",
                "cpu": "kvm",
                "nr_of_vcpus": null
              }
            }
        )
    });

    const DEPLOYMENT_STR: &str = r#"{
  "deployment": {
    "name": "mainnet",
    "mgmt_mac": null
  },
  "logging": {
    "hosts": "elasticsearch.ch1-obsdev1.dfinity.network:443"
  },
  "nns": {
    "url": "https://icp-api.io,https://icp0.io,https://ic0.app"
  },
  "resources": {
    "memory": "490",
    "cpu": "kvm",
    "nr_of_vcpus": null
  }
}"#;

    static DEPLOYMENT_STRUCT: Lazy<DeploymentSettings> = Lazy::new(|| {
        let hosts = ["elasticsearch.ch1-obsdev1.dfinity.network:443"].join(" ");
        DeploymentSettings {
            deployment: Deployment {
                name: "mainnet".to_string(),
                mgmt_mac: None,
            },
            logging: Logging { hosts, tags: None },
            nns: Nns {
                url: vec![
                    Url::parse("https://icp-api.io").unwrap(),
                    Url::parse("https://icp0.io").unwrap(),
                    Url::parse("https://ic0.app").unwrap(),
                ],
            },
            resources: Resources {
                memory: 490,
                cpu: Some("kvm".to_string()),
                nr_of_vcpus: None,
            },
        }
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
