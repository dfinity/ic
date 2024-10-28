pub mod config_ini;
pub mod deployment_json;
pub mod generate_testnet_config;
pub mod types;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

pub static DEFAULT_SETUPOS_CONFIG_OBJECT_PATH: &str = "/var/ic/config/config.json";
pub static DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH: &str = "/config/config.ini";
pub static DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH: &str = "/data/deployment.json";

pub static DEFAULT_SETUPOS_HOSTOS_CONFIG_OBJECT_PATH: &str = "/var/ic/config/config-hostos.json";

pub static DEFAULT_HOSTOS_CONFIG_INI_FILE_PATH: &str = "/boot/config/config.ini";
pub static DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH: &str = "/boot/config/deployment.json";

pub fn serialize_and_write_config<T: Serialize>(path: &Path, config: &T) -> Result<()> {
    let serialized_config =
        serde_json::to_string_pretty(config).expect("Failed to serialize configuration");

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(path)?;
    file.write_all(serialized_config.as_bytes())?;
    Ok(())
}

pub fn deserialize_config<T: for<'de> Deserialize<'de>, P: AsRef<Path>>(file_path: P) -> Result<T> {
    let file =
        File::open(&file_path).context(format!("Failed to open file: {:?}", file_path.as_ref()))?;
    serde_json::from_reader(file).context(format!(
        "Failed to deserialize JSON from file: {:?}",
        file_path.as_ref()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mac_address::mac_address::FormattedMacAddress;
    use types::*;

    #[test]
    fn test_serialize_and_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let ipv6_config = Ipv6Config::Deterministic(DeterministicIpv6Config {
            prefix: "2a00:fb01:400:200".to_string(),
            prefix_length: 64_u8,
            gateway: "2a00:fb01:400:200::1".parse().unwrap(),
        });
        let network_settings = NetworkSettings {
            ipv6_config,
            ipv4_config: None,
        };
        let logging = Logging {
            elasticsearch_hosts: [
                "elasticsearch-node-0.mercury.dfinity.systems:443",
                "elasticsearch-node-1.mercury.dfinity.systems:443",
                "elasticsearch-node-2.mercury.dfinity.systems:443",
                "elasticsearch-node-3.mercury.dfinity.systems:443",
            ]
            .join(" "),
            elasticsearch_tags: None,
        };
        let icos_dev_settings = ICOSDevSettings::default();
        let icos_settings = ICOSSettings {
            mgmt_mac: FormattedMacAddress::try_from("ec:2a:72:31:a2:0c")?,
            deployment_environment: "Mainnet".to_string(),
            logging,
            nns_public_key_exists: true,
            nns_urls: vec!["http://localhost".parse().unwrap()],
            node_operator_private_key_exists: true,
            use_ssh_authorized_keys: false,
            icos_dev_settings,
        };
        let setupos_settings = SetupOSSettings;
        let hostos_settings = HostOSSettings {
            vm_memory: 490,
            vm_cpu: "kvm".to_string(),
            verbose: false,
        };
        let guestos_settings = GuestOSSettings {
            inject_ic_crypto: false,
            inject_ic_state: false,
            inject_ic_registry_local_store: false,
            guestos_dev_settings: GuestOSDevSettings::default(),
        };

        let setupos_config_struct = SetupOSConfig {
            network_settings: network_settings.clone(),
            icos_settings: icos_settings.clone(),
            setupos_settings: setupos_settings.clone(),
            hostos_settings: hostos_settings.clone(),
            guestos_settings: guestos_settings.clone(),
        };
        let hostos_config_struct = HostOSConfig {
            network_settings: network_settings.clone(),
            icos_settings: icos_settings.clone(),
            hostos_settings: hostos_settings.clone(),
            guestos_settings: guestos_settings.clone(),
        };
        let guestos_config_struct = GuestOSConfig {
            network_settings: network_settings.clone(),
            icos_settings: icos_settings.clone(),
            guestos_settings: guestos_settings.clone(),
        };

        fn serialize_and_deserialize<T>(config: &T)
        where
            T: serde::Serialize
                + serde::de::DeserializeOwned
                + std::cmp::PartialEq
                + std::fmt::Debug,
        {
            // Test serialization
            let buffer = serde_json::to_vec_pretty(config).expect("Failed to serialize config");
            assert!(!buffer.is_empty());

            // Test deserialization
            let deserialized_config: T =
                serde_json::from_slice(&buffer).expect("Failed to deserialize config");
            assert_eq!(*config, deserialized_config);
        }

        serialize_and_deserialize(&setupos_config_struct);
        serialize_and_deserialize(&hostos_config_struct);
        serialize_and_deserialize(&guestos_config_struct);

        Ok(())
    }
}
