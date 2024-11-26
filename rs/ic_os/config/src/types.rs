//! # Configuration Update Protocol
//!
//! When updating the IC-OS configuration, it's crucial to maintain backwards compatibility.
//! Please adhere to the following guidelines when making changes to the configuration structures:
//!
//! - **Backwards Compatibility**: Configuration persists across reboots, so all config updates should be backwards compatible to ensure that older configuration files are still deserializable across GuestOS and HostOS upgrades.
//!
//! - **Updating `CONFIG_VERSION`**: Always update the `CONFIG_VERSION` constant (increment the minor version) whenever you modify the configuration.
//!
//! - **Unit Tests**: Add a unit test in `lib.rs` that tests deserialization of your new configuration version.
//!
//! - **Adding New Fields**: If adding a new field to a configuration struct, make sure it is optional or has a default value by implementing `Default` or via `#[serde(default)]`.
//!
//! - **Removing Fields**: To prevent backwards-compatibility deserialization errors, required fields must not be removed directly: In a first step, they have to be made optional and code that reads the value must be removed/handle missing values. In a second step, after the first step has rolled out to all OSes and there is no risk of a rollback, the field can be removed. Additionally, to avoid reintroducing a previously removed field, add your removed field to the RESERVED_FIELD_NAMES list.
//!
//! - **Renaming Fields**: Avoid renaming fields unless absolutely necessary. If you must rename a field, use `#[serde(rename = "old_name")]`.
use ic_types::malicious_behaviour::MaliciousBehaviour;
use mac_address::mac_address::FormattedMacAddress;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

pub const CONFIG_VERSION: &str = "1.0.0";

/// List of field names that have been removed and should not be reused.
pub static RESERVED_FIELD_NAMES: &[&str] = &["DUMMY_RESERVED_VALUE"];

/// SetupOS configuration. User-facing configuration files
/// (e.g., `config.ini`, `deployment.json`) are transformed into `SetupOSConfig`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct SetupOSConfig {
    /// Tracks the config version, set to CONFIG_VERSION at runtime.
    pub config_version: String,
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub setupos_settings: SetupOSSettings,
    pub hostos_settings: HostOSSettings,
    pub guestos_settings: GuestOSSettings,
}

/// HostOS configuration. In production, this struct inherits settings from `SetupOSConfig`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct HostOSConfig {
    /// Tracks the config version, set to CONFIG_VERSION at runtime.
    pub config_version: String,
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub hostos_settings: HostOSSettings,
    pub guestos_settings: GuestOSSettings,
}

/// GuestOS configuration. In production, this struct inherits settings from `HostOSConfig`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct GuestOSConfig {
    /// Tracks the config version, set to CONFIG_VERSION at runtime.
    pub config_version: String,
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub guestos_settings: GuestOSSettings,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ICOSSettings {
    /// The node reward type determines node rewards
    pub node_reward_type: Option<String>,
    /// In nested testing, mgmt_mac is set in deployment.json.template,
    /// else found dynamically in call to config tool CreateSetuposConfig
    pub mgmt_mac: FormattedMacAddress,
    /// "mainnet" or "testnet"
    pub deployment_environment: String,
    pub logging: Logging,
    pub use_nns_public_key: bool,
    /// The URL (HTTP) of the NNS node(s).
    pub nns_urls: Vec<Url>,
    pub use_node_operator_private_key: bool,
    /// This ssh keys directory contains individual files named `admin`, `backup`, `readonly`.
    /// The contents of these files serve as `authorized_keys` for their respective role account.
    /// This means that, for example, `accounts_ssh_authorized_keys/admin`
    /// is transferred to `~admin/.ssh/authorized_keys` on the target system.
    /// backup and readonly can only be modified via an NNS proposal
    /// and are in place for subnet recovery or issue debugging purposes.
    /// use_ssh_authorized_keys triggers the use of the ssh keys directory
    pub use_ssh_authorized_keys: bool,
    pub icos_dev_settings: ICOSDevSettings,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct ICOSDevSettings {}

/// Placeholder for SetupOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct SetupOSSettings;

/// HostOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct HostOSSettings {
    pub vm_memory: u32,
    pub vm_cpu: String,
    pub verbose: bool,
}

/// GuestOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default, Clone)]
pub struct GuestOSSettings {
    /// Externally generated cryptographic keys.
    /// Must be a directory with contents matching the internal representation of the ic_crypto directory.
    /// When given, this provides the private keys of the node.
    /// If not given, the node will generate its own private/public key pair.
    pub inject_ic_crypto: bool,
    pub inject_ic_state: bool,
    /// Initial registry state.
    /// Must be a directory with contents matching the internal representation of the ic_registry_local_store.
    /// When given, this provides the initial state of the registry.
    /// If not given, the node will fetch (initial) registry state from the NNS.
    pub inject_ic_registry_local_store: bool,
    pub guestos_dev_settings: GuestOSDevSettings,
}

/// GuestOS development configuration. These settings are strictly used for development images.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default, Clone)]
pub struct GuestOSDevSettings {
    pub backup_spool: Option<BackupSpoolSettings>,
    pub malicious_behavior: Option<MaliciousBehaviour>,
    pub query_stats_epoch_length: Option<u64>,
    pub bitcoind_addr: Option<String>,
    pub jaeger_addr: Option<String>,
    pub socks_proxy: Option<String>,
    // An optional hostname to override the deterministically generated hostname
    pub hostname: Option<String>,
    // Generate and inject a self-signed TLS certificate and key for ic-boundary
    // for the given domain name. To be used in system tests only.
    pub generate_ic_boundary_tls_cert: Option<String>,
}

/// Configures the usage of the backup spool directory.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct BackupSpoolSettings {
    /// The maximum age of any file or directory kept in the backup spool.
    pub backup_retention_time_seconds: Option<u64>,
    /// The interval at which the backup spool directory will be scanned for files to delete.
    pub backup_purging_interval_seconds: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Logging {
    /// Space-separated lists of hosts to ship logs to.
    pub elasticsearch_hosts: String,
    /// Space-separated list of tags to apply to exported log records.
    pub elasticsearch_tags: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct NetworkSettings {
    pub ipv6_config: Ipv6Config,
    pub ipv4_config: Option<Ipv4Config>,
    pub domain_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Ipv4Config {
    pub address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub prefix_length: u8,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Ipv6Config {
    Deterministic(DeterministicIpv6Config),
    Fixed(FixedIpv6Config),
    RouterAdvertisement,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DeterministicIpv6Config {
    pub prefix: String,
    pub prefix_length: u8,
    pub gateway: Ipv6Addr,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct FixedIpv6Config {
    // Fixed ipv6 address includes subnet mask /64
    pub address: String,
    pub gateway: Ipv6Addr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashSet;

    #[test]
    fn test_no_reserved_field_names_used() -> Result<(), Box<dyn std::error::Error>> {
        let reserved_field_names: HashSet<&str> = RESERVED_FIELD_NAMES.iter().cloned().collect();

        let setupos_config = SetupOSConfig {
            config_version: CONFIG_VERSION.to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::RouterAdvertisement,
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: Some(String::new()),
                mgmt_mac: FormattedMacAddress::try_from("00:00:00:00:00:00")?,
                deployment_environment: String::new(),
                logging: Logging {
                    elasticsearch_hosts: String::new(),
                    elasticsearch_tags: None,
                },
                use_nns_public_key: false,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                use_ssh_authorized_keys: false,
                icos_dev_settings: ICOSDevSettings::default(),
            },
            setupos_settings: SetupOSSettings,
            hostos_settings: HostOSSettings {
                vm_memory: 0,
                vm_cpu: String::new(),
                verbose: false,
            },
            guestos_settings: GuestOSSettings::default(),
        };

        fn get_all_field_names(value: &Value, field_names: &mut HashSet<String>) {
            match value {
                Value::Object(map) => {
                    for (key, val) in map {
                        field_names.insert(key.clone());
                        get_all_field_names(val, field_names);
                    }
                }
                Value::Array(arr) => {
                    for val in arr {
                        get_all_field_names(val, field_names);
                    }
                }
                _ => {}
            }
        }

        let setupos_config = serde_json::to_value(&setupos_config)?;

        let mut field_names = HashSet::new();
        get_all_field_names(&setupos_config, &mut field_names);
        for field in field_names {
            assert!(
                !reserved_field_names.contains(field.as_str()),
                "Field name '{}' is reserved and should not be used.",
                field
            );
        }

        Ok(())
    }
}
