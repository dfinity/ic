pub mod generate_testnet_config;
pub mod hostos;
pub mod setupos;

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
pub static DEFAULT_HOSTOS_CONFIG_OBJECT_PATH: &str = "/boot/config/config.json";
pub static DEFAULT_HOSTOS_GUESTOS_CONFIG_OBJECT_PATH: &str = "/boot/config/config-guestos.json";
pub static DEFAULT_GUESTOS_CONFIG_OBJECT_PATH: &str = "/boot/config/config.json";

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
    use config_types::*;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    #[test]
    fn test_serialize_and_deserialize() {
        let ipv6_config = Ipv6Config::Deterministic(DeterministicIpv6Config {
            prefix: "2a00:fb01:400:200".to_string(),
            prefix_length: 64_u8,
            gateway: "2a00:fb01:400:200::1".parse().unwrap(),
        });
        let network_settings = NetworkSettings {
            ipv6_config,
            ipv4_config: None,
            domain_name: None,
        };
        let icos_dev_settings = ICOSDevSettings::default();
        let icos_settings = ICOSSettings {
            node_reward_type: Some("type3.1".to_string()),
            mgmt_mac: "ec:2a:72:31:a2:0c".parse().unwrap(),
            deployment_environment: DeploymentEnvironment::Mainnet,
            use_nns_public_key: true,
            nns_urls: vec!["http://localhost".parse().unwrap()],
            use_node_operator_private_key: true,
            enable_trusted_execution_environment: true,
            use_ssh_authorized_keys: false,
            icos_dev_settings,
        };
        let setupos_settings = SetupOSSettings;
        let hostos_settings = HostOSSettings {
            vm_memory: 490,
            vm_cpu: "kvm".to_string(),
            vm_nr_of_vcpus: 64,
            verbose: false,
        };
        let guestos_settings = GuestOSSettings {
            inject_ic_crypto: false,
            inject_ic_state: false,
            inject_ic_registry_local_store: false,
            guestos_dev_settings: GuestOSDevSettings::default(),
        };

        let setupos_config_struct = SetupOSConfig {
            config_version: CONFIG_VERSION.to_string(),
            network_settings: network_settings.clone(),
            icos_settings: icos_settings.clone(),
            setupos_settings: setupos_settings.clone(),
            hostos_settings: hostos_settings.clone(),
            guestos_settings: guestos_settings.clone(),
        };
        let hostos_config_struct = HostOSConfig {
            config_version: CONFIG_VERSION.to_string(),
            network_settings: network_settings.clone(),
            icos_settings: icos_settings.clone(),
            hostos_settings: hostos_settings.clone(),
            guestos_settings: guestos_settings.clone(),
        };
        let guestos_config_struct = GuestOSConfig {
            config_version: CONFIG_VERSION.to_string(),
            network_settings: network_settings.clone(),
            icos_settings: icos_settings.clone(),
            guestos_settings: guestos_settings.clone(),
            guest_vm_type: GuestVMType::Default,
            upgrade_config: GuestOSUpgradeConfig {
                peer_guest_vm_address: Some(Ipv6Addr::from_str("2001:db8::1").unwrap()),
            },
            trusted_execution_environment_config: None,
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

    // Test config version 1.0.0
    const HOSTOS_CONFIG_JSON_V1_0_0: &str = r#"
    {
        "config_version": "1.0.0",
        "network_settings": {
            "ipv6_config": {
                "Deterministic": {
                    "prefix": "2a00:fb01:400:200",
                    "prefix_length": 64,
                    "gateway": "2a00:fb01:400:200::1"
                }
            },
            "ipv4_config": {
                "address": "192.168.0.2",
                "gateway": "192.168.0.1",
                "prefix_length": 24
            },
            "domain_name": "example.com"
        },
        "icos_settings": {
            "node_reward_type": "type3.1",
            "mgmt_mac": "EC:2A:72:31:A2:0C",
            "deployment_environment": "Mainnet",
            "use_nns_public_key": true,
            "nns_urls": [
                "http://localhost"
            ],
            "use_node_operator_private_key": true,
            "use_ssh_authorized_keys": false,
            "icos_dev_settings": {}
        },
        "hostos_settings": {
            "vm_memory": 490,
            "vm_cpu": "kvm",
            "vm_nr_of_vcpus": 64,
            "verbose": false
        },
        "guestos_settings": {
            "inject_ic_crypto": false,
            "inject_ic_state": false,
            "inject_ic_registry_local_store": false,
            "guestos_dev_settings": {
                "backup_spool": {
                    "backup_retention_time_seconds": 3600,
                    "backup_purging_interval_seconds": 600
                },
                "malicious_behavior": null,
                "query_stats_epoch_length": 1000,
                "bitcoind_addr": "127.0.0.1:8333",
                "jaeger_addr": "127.0.0.1:6831",
                "socks_proxy": "127.0.0.1:1080",
                "hostname": "my-node",
                "generate_ic_boundary_tls_cert": "domain"
            }
        }
    }
    "#;

    const GUESTOS_CONFIG_JSON_V1_0_0: &str = r#"
    {
        "config_version": "1.0.0",
        "network_settings": {
            "ipv6_config": {
                "Deterministic": {
                    "prefix": "2a00:fb01:400:200",
                    "prefix_length": 64,
                    "gateway": "2a00:fb01:400:200::1"
                }
            },
            "ipv4_config": {
                "address": "192.168.0.2",
                "gateway": "192.168.0.1",
                "prefix_length": 24
            },
            "domain_name": "example.com"
        },
        "icos_settings": {
            "node_reward_type": "type3.1",
            "mgmt_mac": "EC:2A:72:31:A2:0C",
            "deployment_environment": "Mainnet",
            "use_nns_public_key": true,
            "nns_urls": [
                "http://localhost"
            ],
            "use_node_operator_private_key": true,
            "use_ssh_authorized_keys": false,
            "icos_dev_settings": {}
        },
        "guestos_settings": {
            "inject_ic_crypto": false,
            "inject_ic_state": false,
            "inject_ic_registry_local_store": false,
            "guestos_dev_settings": {
                "backup_spool": {
                    "backup_retention_time_seconds": 3600,
                    "backup_purging_interval_seconds": 600
                },
                "malicious_behavior": null,
                "query_stats_epoch_length": 1000,
                "bitcoind_addr": "127.0.0.1:8333",
                "jaeger_addr": "127.0.0.1:6831",
                "socks_proxy": "127.0.0.1:1080",
                "hostname": "my-node",
                "generate_ic_boundary_tls_cert": "domain"
            }
        }
    }
    "#;

    #[test]
    fn test_deserialize_hostos_config_v1_0_0() {
        let config: HostOSConfig = serde_json::from_str(HOSTOS_CONFIG_JSON_V1_0_0).unwrap();
        assert_eq!(config.config_version, "1.0.0");
        assert_eq!(config.hostos_settings.vm_cpu, "kvm");
        assert_eq!(config.hostos_settings.vm_nr_of_vcpus, 64);
    }

    #[test]
    fn test_deserialize_guestos_config_v1_0_0() {
        let config: GuestOSConfig = serde_json::from_str(GUESTOS_CONFIG_JSON_V1_0_0).unwrap();
        assert_eq!(config.config_version, "1.0.0");
        assert_eq!(
            config.icos_settings.mgmt_mac.to_string(),
            "EC:2A:72:31:A2:0C"
        );
    }
}
