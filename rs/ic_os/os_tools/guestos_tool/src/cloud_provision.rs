use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use ::reqwest::Method;
use anyhow::{Context, Error, Result, anyhow, bail};
use config_types::GuestOSConfig;
use nix::{sys::signal::Signal::SIGTERM, unistd::Pid};

use reqwest::header::{HeaderMap, HeaderValue};

use crate::generate_network_config::get_interface_name;

/// URL of the metadata server
const METADATA_URL: &str = "http://169.254.169.254";

/// Type of the cloud that we provision from
#[derive(Debug, Clone, PartialEq, Eq)]
enum CloudType {
    Aws,
    Gcp,
    Azure,
}

impl CloudType {
    /// Discovers the cloud type by making a request to the metadata server
    fn discover() -> Result<Self, Error> {
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
    fn obtain_config(&self) -> Result<GuestOSConfig, Error> {
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
}

/// Assigns IPv4 DHCP address to the interface and unassigns it when dropped
#[derive(Debug)]
struct DHCPConfig {
    config_path: PathBuf,
    process: Child,
}

impl DHCPConfig {
    /// Installs a temporary systemd-networkd config to obtain a DHCP lease
    fn new(interface: String, systemd_network_dir: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&systemd_network_dir)
            .context("unable to create the systemd-networkd dir")?;

        let intf_config = indoc::formatdoc!(
            r#"
                [Match]
                Name={interface}
                Virtualization=!container

                [Network]
                DHCP=ipv4
            "#,
        );

        // Write the config
        let config_path = systemd_network_dir.join(format!("10-{interface}.network"));
        std::fs::write(&config_path, intf_config)
            .context("unable to write systemd network config")?;

        // Fire up systemd-networkd
        let process = Command::new("/usr/lib/systemd/systemd-networkd")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("unable to execute systemd-networkd")?;

        Ok(Self {
            config_path,
            process,
        })
    }
}

impl Drop for DHCPConfig {
    fn drop(&mut self) {
        // Tell systemd-networkd to shutdown & wait for it to happen
        let _ = nix::sys::signal::kill(Pid::from_raw(self.process.id() as i32), SIGTERM);
        let _ = self.process.wait();

        // Remove the config
        let _ = std::fs::remove_file(&self.config_path);
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

/// Tries to obtain the GuestOS config from the cloud's metadata service
pub fn obtain_guestos_config(systemd_network_dir: PathBuf) -> Result<GuestOSConfig, Error> {
    // Find the network interface to work on, it might not be initialized yet so give it a few tries
    let mut retries = 10;

    let intf = loop {
        match get_interface_name() {
            Ok(v) => break v,
            Err(e) => {
                println!("unable to choose interface: {e:#}");
                retries -= 1;
                if retries == 0 {
                    bail!("unable to choose interface: retries exhausted");
                }

                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };

    // Configure it with a DHCP
    let _dhcp = DHCPConfig::new(intf.clone(), systemd_network_dir)
        .context("unable to configure IPv4 DHCP")?;
    println!("DHCP on the interace {intf} configured");

    // Discover the cloud we're running in.
    let cloud_type = CloudType::discover().context("unable to discover cloud type")?;
    println!("Cloud type detected: {cloud_type:?}");

    // Get the config from the MDS
    let config = cloud_type
        .obtain_config()
        .context("unable to obtain GuestOS config")?;

    Ok(config)
}

#[cfg(test)]
mod test {
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
}
