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
//! - **Adding Enum Variants (Forward Compatibility)**: When adding new variants to an enum, ensure older versions can handle unknown variants gracefully by using `#[serde(other)]` on a fallback variant.
//!
//! - **Removing Fields**: To prevent backwards compatibility deserialization errors, required fields must not be removed directly: In a first step, they have to be given a default attribute and all IC-OS references to them have to be removed. In a second step, after the first step has rolled out to all OSes (HostOS and GuestOS) and there is no risk of a rollback, the field can be removed. Additionally, to avoid reintroducing a previously removed field, add your removed field to the RESERVED_FIELD_PATHS list.
//!
//! - **Renaming Fields**: Avoid renaming fields unless absolutely necessary. If you must rename a field, use `#[serde(rename = "old_name")]`.
//!
//! ## Logging safety
//!
//! All configuration objects defined in this file are safe to log. They do not contain any secret material.
use ic_types::malicious_behavior::MaliciousBehavior;
use macaddr::MacAddr6;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use strum::EnumString;
use url::Url;

pub const CONFIG_VERSION: &str = "1.11.0";

/// List of field paths that have been removed and should not be reused.
pub static RESERVED_FIELD_PATHS: &[&str] =
    &["icos_settings.logging", "icos_settings.use_nns_public_key"];

pub type ConfigMap = HashMap<String, String>;

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

/// The type of the virtual machine running the GuestOS.
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug, EnumString, Default)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum GuestVMType {
    /// This is what runs most of the time, executing the replica, serving requests, etc.
    #[default]
    Default,
    /// The Guest VM brought up temporarily during the GuestOS upgrade process.
    Upgrade,
    /// Unknown variant fallback for forward compatibility with future version
    /// (used in case a newer HostOS sends a value that an older GuestOS does not understand)
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct TrustedExecutionEnvironmentConfig {
    /// AMD SEV-SNP certificate chain in PEM format.
    pub sev_cert_chain_pem: String,
}

/// GuestOS configuration. In production, this struct inherits settings from `HostOSConfig`.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct GuestOSConfig {
    /// Tracks the config version, set to CONFIG_VERSION at runtime.
    pub config_version: String,
    pub network_settings: NetworkSettings,
    pub icos_settings: ICOSSettings,
    pub guestos_settings: GuestOSSettings,
    #[serde(default)]
    pub guest_vm_type: GuestVMType,
    #[serde(default)]
    pub upgrade_config: GuestOSUpgradeConfig,
    /// This is only filled in when running on SEV-SNP capable hardware and trusted execution
    /// environment is enabled in icos_settings.enable_trusted_execution_environment
    #[serde(default)]
    pub trusted_execution_environment_config: Option<TrustedExecutionEnvironmentConfig>,
    /// The hash of the recovery artifacts to be used in the event of a manual recovery.
    pub recovery_config: Option<RecoveryConfig>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ICOSSettings {
    /// The node reward type determines node rewards
    pub node_reward_type: Option<String>,
    #[serde_as(as = "DisplayFromStr")]
    /// In nested testing, mgmt_mac is set in deployment.json.template,
    /// else found dynamically in call to config tool CreateSetuposConfig
    pub mgmt_mac: MacAddr6,
    #[serde_as(as = "DisplayFromStr")]
    pub deployment_environment: DeploymentEnvironment,
    /// The URL (HTTP) of the NNS node(s).
    pub nns_urls: Vec<Url>,
    pub use_node_operator_private_key: bool,
    /// Whether SEV-SNP should be enabled. This is configured when the machine is deployed.
    /// If the value is enabled, we check during deployment that SEV-SNP is supported
    /// by the hardware. Once deployment is successful, we rely on the hardware supporting
    /// SEV-SNP.
    ///
    /// IMPORTANT: This field only controls whether TEE is enabled in config.
    /// In GuestOS code, check the $SEV_ACTIVE environment variable or use the `is_sev_active()`
    /// wrapper from the `ic_sev` crate, as this cannot be faked by a malicious HostOS.
    #[serde(default)]
    pub enable_trusted_execution_environment: bool,
    /// This ssh keys directory contains individual files named `admin`, `backup`, `readonly`.
    /// The contents of these files serve as `authorized_keys` for their respective role account.
    /// This means that, for example, `accounts_ssh_authorized_keys/admin`
    /// is transferred to `~admin/.ssh/authorized_keys` on the target system.
    /// backup and readonly can only be modified via an NNS proposal
    /// and are in place for subnet recovery or issue debugging purposes.
    /// use_ssh_authorized_keys triggers the use of the ssh keys directory
    pub use_ssh_authorized_keys: bool,
    pub icos_dev_settings: ICOSDevSettings,

    /// This flag enables the beta features for onboarding the nodes using the new mechanism
    /// without the need for the node operator private key.
    pub enable_beta_registration_feature: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct ICOSDevSettings {}

/// Placeholder for SetupOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct SetupOSSettings;

/// HostOS-specific settings.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct HostOSSettings {
    #[serde(default)]
    pub hostos_dev_settings: HostOSDevSettings,
    #[deprecated(note = "Please use hostos_dev_settings")]
    pub vm_memory: u32,
    #[deprecated(note = "Please use hostos_dev_settings")]
    pub vm_cpu: String,
    #[deprecated(note = "Please use hostos_dev_settings")]
    #[serde(default = "default_vm_nr_of_vcpus")]
    pub vm_nr_of_vcpus: u32,
    pub verbose: bool,
}

impl Default for HostOSSettings {
    fn default() -> Self {
        #[allow(deprecated)]
        HostOSSettings {
            vm_memory: Default::default(),
            vm_cpu: Default::default(),
            vm_nr_of_vcpus: default_vm_nr_of_vcpus(),
            verbose: Default::default(),
            hostos_dev_settings: Default::default(),
        }
    }
}

const fn default_vm_nr_of_vcpus() -> u32 {
    64
}

/// HostOS development configuration. These settings are strictly used for development images.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct HostOSDevSettings {
    pub vm_memory: u32,
    pub vm_cpu: String,
    pub vm_nr_of_vcpus: u32,
}

impl Default for HostOSDevSettings {
    /// These currently match the defaults for nested tests on Farm:
    /// (`HOSTOS_VCPUS_PER_VM / 2`, `HOSTOS_MEMORY_KIB_PER_VM / 2`)
    fn default() -> Self {
        HostOSDevSettings {
            vm_memory: 16,
            vm_cpu: "kvm".to_string(),
            vm_nr_of_vcpus: 16,
        }
    }
}

/// Config specific to the GuestOS upgrade process.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default, Clone)]
pub struct GuestOSUpgradeConfig {
    /// IPv6 address of the peer Guest virtual machine.
    /// Inside the Default VM, it's the address of the Upgrade VM.
    /// Inside the Upgrade VM, it's the address of the Default VM.
    #[serde(default)]
    pub peer_guest_vm_address: Option<Ipv6Addr>,
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
    pub malicious_behavior: Option<MaliciousBehavior>,
    pub query_stats_epoch_length: Option<u64>,
    pub bitcoind_addr: Option<String>,
    pub dogecoind_addr: Option<String>,
    pub jaeger_addr: Option<String>,
    pub socks_proxy: Option<String>,
    // An optional hostname to override the deterministically generated hostname
    pub hostname: Option<String>,
    // Generate and inject a self-signed TLS certificate and key for ic-boundary
    // for the given domain name. To be used in system tests only.
    pub generate_ic_boundary_tls_cert: Option<String>,
}

/// GuestOS recovery configuration used in the event of a manual recovery.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct RecoveryConfig {
    /// The hash of the recovery artifacts to be used in the event of a manual recovery.
    pub recovery_hash: String,
}

/// Configures the usage of the backup spool directory.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct BackupSpoolSettings {
    /// The maximum age of any file or directory kept in the backup spool.
    pub backup_retention_time_seconds: Option<u64>,
    /// The interval at which the backup spool directory will be scanned for files to delete.
    pub backup_purging_interval_seconds: Option<u64>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum DeploymentEnvironment {
    Mainnet,
    Testnet,
}

impl fmt::Display for DeploymentEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeploymentEnvironment::Mainnet => write!(f, "mainnet"),
            DeploymentEnvironment::Testnet => write!(f, "testnet"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentParseError {
    #[error("invalid deployment variant")]
    InvalidVariant,
}

impl FromStr for DeploymentEnvironment {
    type Err = DeploymentParseError;
    fn from_str(s: &str) -> Result<DeploymentEnvironment, DeploymentParseError> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(DeploymentEnvironment::Mainnet),
            "testnet" => Ok(DeploymentEnvironment::Testnet),
            _ => Err(DeploymentParseError::InvalidVariant),
        }
    }
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
    /// Unknown variant for forward compatibility with future versions
    /// (used in case a newer HostOS sends a value that an older GuestOS does not understand)
    #[serde(other)]
    Unknown,
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
    fn test_vm_nr_of_vcpus_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        #[allow(deprecated)]
        {
            // Test with vm_nr_of_vcpus specified
            let json = r#"{
                "vm_memory": 16,
                "vm_cpu": "host",
                "vm_nr_of_vcpus": 4,
                "verbose": true
            }"#;
            let settings: HostOSSettings = serde_json::from_str(json)?;
            assert_eq!(settings.vm_nr_of_vcpus, 4);

            // Test without vm_nr_of_vcpus (should use default)
            let json = r#"{
                "vm_memory": 16,
                "vm_cpu": "host",
                "verbose": true
            }"#;
            let settings: HostOSSettings = serde_json::from_str(json)?;
            assert_eq!(settings.vm_nr_of_vcpus, 64);
        }

        Ok(())
    }

    #[test]
    fn test_guest_vm_type_forward_compatibility() -> Result<(), Box<dyn std::error::Error>> {
        // Test that unknown enum variants deserialize to Unknown
        // Create a minimal GuestOSConfig with the unknown variant
        let config_json = serde_json::json!({
            "config_version": CONFIG_VERSION,
            "network_settings": {
                "ipv6_config": "RouterAdvertisement"
            },
            "icos_settings": {
                "mgmt_mac": "00:00:00:00:00:00",
                "deployment_environment": "testnet",
                "nns_urls": [],
                "use_node_operator_private_key": false,
                "use_ssh_authorized_keys": false,
                "icos_dev_settings": {}
            },
            "guestos_settings": {
                "inject_ic_crypto": false,
                "inject_ic_state": false,
                "inject_ic_registry_local_store": false,
                "recovery_hash": None::<String>,
                "guestos_dev_settings": {}
            },
            "guest_vm_type": "unknown_future_variant"
        });

        // This should not fail and should deserialize guest_vm_type to Unknown
        let config: GuestOSConfig = serde_json::from_value(config_json)?;
        assert_eq!(config.guest_vm_type, GuestVMType::Unknown);

        Ok(())
    }

    #[test]
    fn test_no_reserved_field_paths_used() -> Result<(), Box<dyn std::error::Error>> {
        let reserved_field_paths: HashSet<&str> = RESERVED_FIELD_PATHS.iter().cloned().collect();

        let setupos_config = SetupOSConfig {
            config_version: CONFIG_VERSION.to_string(),
            network_settings: NetworkSettings {
                ipv6_config: Ipv6Config::RouterAdvertisement,
                ipv4_config: None,
                domain_name: None,
            },
            icos_settings: ICOSSettings {
                node_reward_type: None,
                mgmt_mac: "00:00:00:00:00:00".parse()?,
                deployment_environment: DeploymentEnvironment::Testnet,
                nns_urls: vec![],
                use_node_operator_private_key: false,
                enable_trusted_execution_environment: false,
                use_ssh_authorized_keys: false,
                icos_dev_settings: ICOSDevSettings::default(),
                enable_beta_registration_feature: None,
            },
            setupos_settings: SetupOSSettings,
            hostos_settings: HostOSSettings::default(),
            guestos_settings: GuestOSSettings::default(),
        };

        fn get_all_field_paths(prefix: &str, value: &Value, field_paths: &mut HashSet<String>) {
            match value {
                Value::Object(map) => {
                    for (key, val) in map {
                        field_paths.insert(format!("{prefix}{key}"));
                        get_all_field_paths(&format!("{prefix}{key}."), val, field_paths);
                    }
                }
                Value::Array(arr) => {
                    for val in arr {
                        get_all_field_paths(&format!("{prefix}[]."), val, field_paths);
                    }
                }
                _ => {}
            }
        }

        let setupos_config = serde_json::to_value(&setupos_config)?;

        let mut field_paths = HashSet::new();
        get_all_field_paths("", &setupos_config, &mut field_paths);
        for field in field_paths {
            assert!(
                !reserved_field_paths.contains(field.as_str()),
                "Field path '{field}' is reserved and should not be used."
            );
        }

        Ok(())
    }
}
