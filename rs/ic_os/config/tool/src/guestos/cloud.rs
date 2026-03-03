use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Error, Result, anyhow, bail};
use config_types::GuestOSConfig;

use reqwest::header::{HeaderMap, HeaderValue};

use ::reqwest::Method;
use serde_json::Value;

/// URL of the metadata server
const METADATA_URL: &str = "http://169.254.169.254";

/// Type of the cloud that we provision from
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudType {
    Aws,
    Gcp,
    Azure,
}

impl CloudType {
    /// Discovers the cloud type by making a request to the metadata server
    pub fn discover() -> Result<Self, Error> {
        let mut retries = 30;

        let resp = loop {
            match reqwest::blocking::get(METADATA_URL) {
                Ok(v) => break v,
                Err(e) => {
                    retries -= 1;
                    if retries == 0 {
                        return Err(anyhow!("unable to discover cloud type: retries exhausted"));
                    }

                    println!("Unable to contact metadata server (retries left {retries}): {e:#}");
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        };

        discover_cloud_type(resp.headers())
    }

    /// Tries to fetch the GuestOS config from the cloud's metadata service
    pub fn obtain_config(&self) -> Result<GuestOSConfig, Error> {
        let json = match self {
            Self::Aws => reqwest::blocking::get(format!("{METADATA_URL}/latest/user-data"))
                .context("unable to execute request")?
                .bytes()
                .context("unable to fetch config JSON")?
                .to_vec(),

            Self::Gcp => {
                let mut req = reqwest::blocking::Request::new(
                    Method::GET,
                    format!("{METADATA_URL}/computeMetadata/v1/instance/attributes/config_json")
                        .parse()
                        .unwrap(),
                );
                req.headers_mut()
                    .insert("Metadata-Flavor", "Google".try_into().unwrap());

                reqwest::blocking::Client::new()
                    .execute(req)
                    .context("unable to execute request")?
                    .bytes()
                    .context("unable to fetch config JSON")?
                    .to_vec()
            }

            Self::Azure => {
                let mut req = reqwest::blocking::Request::new(Method::GET, format!("{METADATA_URL}/metadata/instance/compute/userData?api-version=2025-04-07&format=text").parse().unwrap());
                req.headers_mut()
                    .insert("Metadata", "true".try_into().unwrap());

                // Azure user data is base64-encoded
                let b64 = reqwest::blocking::Client::new()
                    .execute(req)
                    .context("unable to execute request")?
                    .bytes()
                    .context("unable to fetch config JSON")?;

                base64::decode(&b64)
                    .context("unable to decode from Base64")?
                    .to_vec()
            }
        };

        let config: GuestOSConfig =
            serde_json::from_slice(&json).context("unable to deserialize config to JSON")?;

        Ok(config)
    }

    /// Tries to obtain external IPv4/IPv6 addresses from the Cloud's metadata service
    pub fn obtain_public_ip(&self) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), Error> {
        match self {
            Self::Azure => {
                let mut req = reqwest::blocking::Request::new(
                    Method::GET,
                    format!("{METADATA_URL}/metadata/loadbalancer?api-version=2025-04-07")
                        .parse()
                        .unwrap(),
                );
                req.headers_mut()
                    .insert("Metadata", "true".try_into().unwrap());

                let json: Value = reqwest::blocking::Client::new()
                    .execute(req)
                    .context("unable to execute request")?
                    .json()
                    .context("unable to parse response as JSON")?;

                Ok(azure_get_public_ips(json))
            }

            _ => bail!("unimplemented"),
        }
    }
}

/// Tries to discover the type of the cloud we're running in by examining the response headers
fn discover_cloud_type(hdr: &HeaderMap) -> Result<CloudType, Error> {
    if hdr.get("Server") == Some(&HeaderValue::from_static("EC2ws")) {
        return Ok(CloudType::Aws);
    }

    if hdr.get("Metadata-Flavor") == Some(&HeaderValue::from_static("Google")) {
        return Ok(CloudType::Gcp);
    }

    if let Some(v) = hdr.get("Server")
        && v.to_str().unwrap_or_default().starts_with("Microsoft")
    {
        return Ok(CloudType::Azure);
    }

    Err(anyhow!("Unsupported cloud type detected"))
}

/// Figures out the external IP addresses from the JSON response
fn azure_get_public_ips(v: Value) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    // There's no indication which address is IPv4/IPv6, so we brute force it
    let ip1 = v
        .pointer("/loadbalancer/publicIpAddresses/0/frontendIpAddress")
        .and_then(|x| x.as_str());
    let ip2 = v
        .pointer("/loadbalancer/publicIpAddresses/1/frontendIpAddress")
        .and_then(|x| x.as_str());

    let ipv4 = ip1
        .and_then(|x| Ipv4Addr::from_str(x).ok())
        .or_else(|| ip2.and_then(|x| Ipv4Addr::from_str(x).ok()));
    let ipv6 = ip1
        .and_then(|x| Ipv6Addr::from_str(x.trim_matches(['[', ']'])).ok())
        .or_else(|| ip2.and_then(|x| Ipv6Addr::from_str(x.trim_matches(['[', ']'])).ok()));

    (ipv4, ipv6)
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_discover_cloud_type() {
        let mut hdr = HeaderMap::new();
        hdr.insert("Server", HeaderValue::from_static("EC2ws"));
        assert_eq!(discover_cloud_type(&hdr).unwrap(), CloudType::Aws);

        let mut hdr = HeaderMap::new();
        hdr.insert("Metadata-Flavor", HeaderValue::from_static("Google"));
        assert_eq!(discover_cloud_type(&hdr).unwrap(), CloudType::Gcp);

        let mut hdr = HeaderMap::new();
        hdr.insert("Server", HeaderValue::from_static("Microsoft-IIS/10.0"));
        assert_eq!(discover_cloud_type(&hdr).unwrap(), CloudType::Azure);

        let hdr = HeaderMap::new();
        assert!(discover_cloud_type(&hdr).is_err());
    }

    #[test]
    fn test_azure_get_public_ips() {
        // Both v4 v6
        let js = json!({
          "loadbalancer": {
            "publicIpAddresses": [
              {
                "frontendIpAddress": "172.191.104.213",
                "privateIpAddress": "172.16.0.4"
              },
              {
                "frontendIpAddress": "[2a01:111:f100:2001::a83e:2843]",
                "privateIpAddress": "[fd00:a1b:8b8c::4]"
              }
            ],
            "inboundRules": [],
            "outboundRules": []
          }
        });

        assert_eq!(
            azure_get_public_ips(js),
            (
                Some(Ipv4Addr::from_str("172.191.104.213").unwrap()),
                Some(Ipv6Addr::from_str("2a01:111:f100:2001::a83e:2843").unwrap())
            )
        );

        // Reversed
        let js = json!({
          "loadbalancer": {
            "publicIpAddresses": [
              {
                "frontendIpAddress": "[2a01:111:f100:2001::a83e:2843]",
                "privateIpAddress": "[fd00:a1b:8b8c::4]"
              },
              {
                "frontendIpAddress": "172.191.104.213",
                "privateIpAddress": "172.16.0.4"
              }
            ],
            "inboundRules": [],
            "outboundRules": []
          }
        });

        assert_eq!(
            azure_get_public_ips(js),
            (
                Some(Ipv4Addr::from_str("172.191.104.213").unwrap()),
                Some(Ipv6Addr::from_str("2a01:111:f100:2001::a83e:2843").unwrap())
            )
        );

        // Only v4 valid, bad v6
        let js = json!({
          "loadbalancer": {
            "publicIpAddresses": [
              {
                "frontendIpAddress": "foo::bar",
                "privateIpAddress": "[fd00:a1b:8b8c::4]"
              },
              {
                "frontendIpAddress": "172.191.104.213",
                "privateIpAddress": "172.16.0.4"
              }
            ],
            "inboundRules": [],
            "outboundRules": []
          }
        });

        assert_eq!(
            azure_get_public_ips(js),
            (Some(Ipv4Addr::from_str("172.191.104.213").unwrap()), None,)
        );

        // Only v6 valid, bad v4
        let js = json!({
          "loadbalancer": {
            "publicIpAddresses": [
              {
                "frontendIpAddress": "2a01:111:f100:2001::a83e:2843",
                "privateIpAddress": "[fd00:a1b:8b8c::4]"
              },
              {
                "frontendIpAddress": "1.2.3",
                "privateIpAddress": "172.16.0.4"
              }
            ],
            "inboundRules": [],
            "outboundRules": []
          }
        });

        assert_eq!(
            azure_get_public_ips(js),
            (
                None,
                Some(Ipv6Addr::from_str("2a01:111:f100:2001::a83e:2843").unwrap())
            )
        );

        // Only v6
        let js = json!({
          "loadbalancer": {
            "publicIpAddresses": [
              {
                "frontendIpAddress": "2a01:111:f100:2001::a83e:2843",
                "privateIpAddress": "[fd00:a1b:8b8c::4]"
              }
            ],
            "inboundRules": [],
            "outboundRules": []
          }
        });

        assert_eq!(
            azure_get_public_ips(js),
            (
                None,
                Some(Ipv6Addr::from_str("2a01:111:f100:2001::a83e:2843").unwrap())
            )
        );

        // Only v4
        let js = json!({
          "loadbalancer": {
            "publicIpAddresses": [
              {
                "frontendIpAddress": "172.191.104.213",
                "privateIpAddress": "172.16.0.4"
              }
            ],
            "inboundRules": [],
            "outboundRules": []
          }
        });

        assert_eq!(
            azure_get_public_ips(js),
            (Some(Ipv4Addr::from_str("172.191.104.213").unwrap()), None,)
        );
    }
}
