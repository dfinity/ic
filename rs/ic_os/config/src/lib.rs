pub mod config_ini;
pub mod deployment_json;
pub mod types;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

pub static DEFAULT_SETUPOS_CONFIG_OBJECT_PATH: &str = "/var/ic/config/config.json";
pub static DEFAULT_SETUPOS_CONFIG_INI_FILE_PATH: &str = "/config/config.ini";
pub static DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH: &str = "/data/deployment.json";
pub static DEFAULT_SETUPOS_NNS_PUBLIC_KEY_PATH: &str = "/data/nns_public_key.pem";
pub static DEFAULT_SETUPOS_SSH_AUTHORIZED_KEYS_PATH: &str = "/config/ssh_authorized_keys";
pub static DEFAULT_SETUPOS_NODE_OPERATOR_PRIVATE_KEY_PATH: &str =
    "/config/node_operator_private_key.pem";

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

pub fn deserialize_config<T: for<'de> Deserialize<'de>>(file_path: &str) -> Result<T> {
    let file = File::open(file_path).context(format!("Failed to open file: {}", file_path))?;
    serde_json::from_reader(file).context(format!(
        "Failed to deserialize JSON from file: {}",
        file_path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use types::{
        GuestOSConfig, GuestOSSettings, GuestosDevConfig, HostOSConfig, HostOSSettings,
        ICOSSettings, Logging, NetworkSettings, SetupOSConfig, SetupOSSettings,
    };

    #[test]
    fn test_serialize_and_deserialize() {
        let network_settings = NetworkSettings {
            ipv6_prefix: None,
            ipv6_address: None,
            ipv6_prefix_length: 64_u8,
            ipv6_gateway: "2001:db8::1".parse().unwrap(),
            ipv4_address: None,
            ipv4_gateway: None,
            ipv4_prefix_length: None,
            domain: None,
            mgmt_mac: None,
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
        let icos_settings = ICOSSettings {
            logging,
            nns_public_key_path: PathBuf::from("/path/to/key"),
            nns_urls: vec!["http://localhost".parse().unwrap()],
            hostname: "mainnet".to_string(),
            node_operator_private_key_path: None,
            ssh_authorized_keys_path: None,
        };
        let setupos_settings = SetupOSSettings;
        let hostos_settings = HostOSSettings {
            vm_memory: 490,
            vm_cpu: "kvm".to_string(),
            verbose: false,
        };
        let guestos_settings = GuestOSSettings {
            ic_crypto_path: None,
            ic_state_path: None,
            ic_registry_local_store_path: None,
            guestos_dev: GuestosDevConfig::default(),
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
    }
}
