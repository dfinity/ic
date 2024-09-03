use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use url::Url;

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct DeploymentJson {
    pub deployment: Deployment,
    pub logging: Logging,
    pub nns: Nns,
    pub resources: Resources,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Deployment {
    pub name: String,
}

#[derive(PartialEq, Debug, Deserialize, Serialize)]
pub struct Logging {
    pub hosts: String,
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
    pub cpu: Option<String>,
}

pub fn read_deployment_file(deployment_json: &Path) -> Result<DeploymentJson> {
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

    static DEPLOYMENT_VALUE: Lazy<Value> = Lazy::new(|| {
        json!({
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
            }
        )
    });

    static DEPLOYMENT_STRUCT: Lazy<DeploymentJson> = Lazy::new(|| {
        DeploymentJson {
            deployment: Deployment { name: "mainnet".to_string() },
            logging: Logging { hosts: "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443".to_string() },
            nns: Nns { url: vec![Url::parse("https://dfinity.org").unwrap()] },
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
            nns: Nns { url: vec![Url::parse("https://dfinity.org").unwrap()] },
            resources: Resources { memory: 490, cpu: Some("qemu".to_string()) },
        }
    });

    const MULTI_URL_STR: &str = r#"{
  "deployment": {
    "name": "mainnet"
  },
  "logging": {
    "hosts": "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443"
  },
  "nns": {
    "url": "http://[2001:920:401a:1710:5000:6aff:fee4:19cd]:8080/,http://[2600:3006:1400:1500:5000:19ff:fe38:c418]:8080/,http://[2600:2c01:21:0:5000:27ff:fe23:4839]:8080/"
  },
  "resources": {
    "memory": "490"
  }
}"#;

    const MULTI_URL_SANS_SLASH_STR: &str = r#"{
  "deployment": {
    "name": "mainnet"
  },
  "logging": {
    "hosts": "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443"
  },
  "nns": {
    "url": "http://[2001:920:401a:1710:5000:6aff:fee4:19cd]:8080,http://[2600:3006:1400:1500:5000:19ff:fe38:c418]:8080,http://[2600:2c01:21:0:5000:27ff:fe23:4839]:8080"
  },
  "resources": {
    "memory": "490"
  }
}"#;

    static MULTI_URL_STRUCT: Lazy<DeploymentJson> = Lazy::new(|| {
        DeploymentJson {
            deployment: Deployment { name: "mainnet".to_string() },
            logging: Logging { hosts: "elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443".to_string() },
            nns: Nns { url: vec![Url::parse("http://[2001:920:401a:1710:5000:6aff:fee4:19cd]:8080").unwrap(), Url::parse("http://[2600:3006:1400:1500:5000:19ff:fe38:c418]:8080").unwrap(), Url::parse("http://[2600:2c01:21:0:5000:27ff:fe23:4839]:8080").unwrap()] },
            resources: Resources { memory: 490, cpu: None },
        }
    });

    #[test]
    fn read_deployment() {
        let parsed_deployment: DeploymentJson = { serde_json::from_str(DEPLOYMENT_STR).unwrap() };

        assert_eq!(*DEPLOYMENT_STRUCT, parsed_deployment);

        let parsed_cpu_deployment: DeploymentJson =
            { serde_json::from_str(CPU_DEPLOYMENT_STR).unwrap() };

        assert_eq!(*CPU_DEPLOYMENT_STRUCT, parsed_cpu_deployment);

        let parsed_multi_url_deployment: DeploymentJson =
            { serde_json::from_str(MULTI_URL_STR).unwrap() };

        assert_eq!(*MULTI_URL_STRUCT, parsed_multi_url_deployment);

        // NOTE: Canonically, url thinks these addresses should have a trailing
        // slash, so the above case parses with a slash for the sake of the
        // writeback test below. In practice, we have used addresses without
        // this slash, so here we verify that this parses to the same value.
        let parsed_multi_url_sans_slash_deployment: DeploymentJson =
            { serde_json::from_str(MULTI_URL_SANS_SLASH_STR).unwrap() };

        assert_eq!(*MULTI_URL_STRUCT, parsed_multi_url_sans_slash_deployment);

        // Exercise DeserializeOwned using serde_json::from_value.
        // DeserializeOwned is used by serde_json::from_reader, which is the
        // main entrypoint of this code, in practice.
        let parsed_deployment: DeploymentJson =
            { serde_json::from_value(DEPLOYMENT_VALUE.clone()).unwrap() };

        assert_eq!(*DEPLOYMENT_STRUCT, parsed_deployment);
    }

    #[test]
    fn write_deployment() {
        let written_deployment =
            serde_json::to_string_pretty::<DeploymentJson>(&DEPLOYMENT_STRUCT).unwrap();

        assert_eq!(DEPLOYMENT_STR, written_deployment);

        let written_cpu_deployment =
            serde_json::to_string_pretty::<DeploymentJson>(&CPU_DEPLOYMENT_STRUCT).unwrap();

        assert_eq!(CPU_DEPLOYMENT_STR, written_cpu_deployment);

        let written_multi_url_deployment =
            serde_json::to_string_pretty::<DeploymentJson>(&MULTI_URL_STRUCT).unwrap();

        assert_eq!(MULTI_URL_STR, written_multi_url_deployment);
    }
}
