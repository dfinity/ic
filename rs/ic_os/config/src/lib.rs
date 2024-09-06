use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::read_to_string;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::bail;
use anyhow::{Context, Result};

pub mod types;
use crate::types::NetworkSettings;

pub type ConfigMap = HashMap<String, String>;

pub static DEFAULT_SETUPOS_CONFIG_OBJECT_PATH: &str = "/var/ic/config/config.json";
pub static DEFAULT_SETUPOS_CONFIG_FILE_PATH: &str = "/config/config.ini";
pub static DEFAULT_SETUPOS_DEPLOYMENT_JSON_PATH: &str = "/data/deployment.json";
pub static DEFAULT_SETUPOS_NNS_PUBLIC_KEY_PATH: &str = "/data/nns_public_key.pem";
pub static DEFAULT_SETUPOS_SSH_AUTHORIZED_KEYS_PATH: &str = "/config/ssh_authorized_keys";
pub static DEFAULT_SETUPOS_NODE_OPERATOR_PRIVATE_KEY_PATH: &str =
    "/config/node_operator_private_key.pem";

pub static DEFAULT_HOSTOS_CONFIG_FILE_PATH: &str = "/boot/config/config.ini";
pub static DEFAULT_HOSTOS_DEPLOYMENT_JSON_PATH: &str = "/boot/config/deployment.json";

fn parse_config_line(line: &str) -> Option<(String, String)> {
    // Skip blank lines and comments
    if line.is_empty() || line.trim().starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() == 2 {
        Some((parts[0].trim().into(), parts[1].trim().into()))
    } else {
        eprintln!("Warning: skipping config line due to unrecognized format: \"{line}\"");
        eprintln!("Expected format: \"<key>=<value>\"");
        None
    }
}

pub fn config_map_from_path(config_file_path: &Path) -> Result<ConfigMap> {
    let file_contents = read_to_string(config_file_path)
        .with_context(|| format!("Error reading file: {}", config_file_path.display()))?;

    let normalized_file_contents = file_contents.replace("\r\n", "\n").replace("\r", "\n");

    Ok(normalized_file_contents
        .lines()
        .filter_map(parse_config_line)
        .collect())
}

fn is_valid_ipv6_prefix(ipv6_prefix: &str) -> bool {
    ipv6_prefix.len() <= 19 && format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok()
}

pub fn get_config_ini_settings(config_file_path: &Path) -> Result<(NetworkSettings, bool)> {
    let config_map: ConfigMap = config_map_from_path(config_file_path)?;

    let ipv6_prefix = config_map
        .get("ipv6_prefix")
        .map(|prefix| {
            // Prefix should have a max length of 19 ("1234:6789:1234:6789")
            // It could have fewer characters though. Parsing as an ip address with trailing '::' should work.
            if !is_valid_ipv6_prefix(prefix) {
                bail!("Invalid IPv6 prefix: {}", prefix);
            }
            format!("{}::", prefix)
                .parse::<Ipv6Addr>()
                .context(format!("Failed to parse IPv6 prefix: {}", prefix))
        })
        .transpose()?;

    // Per PFOPS - ipv6_subnet will never not be 64
    let ipv6_subnet = 64_u8;
    // Optional ipv6_address - for testing. Takes precedence over ipv6_prefix.
    let ipv6_address = config_map
        .get("ipv6_address")
        .map(|address| {
            // ipv6_address might be formatted with the trailing suffix. Remove it.
            address
                .strip_suffix(&format!("/{}", ipv6_subnet))
                .unwrap_or(address)
                .parse::<Ipv6Addr>()
                .context(format!("Invalid IPv6 address: {}", address))
        })
        .transpose()?;

    if ipv6_address.is_none() && ipv6_prefix.is_none() {
        bail!("Missing config parameter: need at least one of ipv6_prefix or ipv6_address");
    }

    let ipv6_gateway = config_map
        .get("ipv6_gateway")
        .context("Missing config parameter: ipv6_gateway")?
        .parse::<Ipv6Addr>()
        .context("Invalid IPv6 gateway address")?;

    let ipv4_address = config_map
        .get("ipv4_address")
        .map(|address| {
            address
                .parse::<Ipv4Addr>()
                .context(format!("Invalid IPv4 address: {}", address))
        })
        .transpose()?;

    let ipv4_gateway = config_map
        .get("ipv4_gateway")
        .map(|address| {
            address
                .parse::<Ipv4Addr>()
                .context(format!("Invalid IPv4 gateway: {}", address))
        })
        .transpose()?;

    let ipv4_prefix_length = config_map
        .get("ipv4_prefix_length")
        .map(|prefix| {
            let prefix = prefix
                .parse::<u8>()
                .context(format!("Invalid IPv4 prefix length: {}", prefix))?;
            if prefix > 32 {
                bail!(
                    "IPv4 prefix length must be between 0 and 32, got {}",
                    prefix
                );
            }
            Ok(prefix)
        })
        .transpose()?;

    let domain = config_map.get("domain").cloned();

    let networking = crate::types::NetworkSettings {
        ipv6_prefix,
        ipv6_address,
        ipv6_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        domain,
    };

    let verbose = config_map
        .get("verbose")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    Ok((networking, verbose))
}

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
    use tempfile::{tempdir, NamedTempFile};
    use types::{
        GuestOSConfig, GuestOSSettings, GuestosDevConfig, HostOSConfig, HostOSSettings,
        ICOSSettings, SetupOSConfig, SetupOSSettings,
    };

    #[test]
    fn test_serialize_and_deserialize() {
        let network_settings = NetworkSettings {
            ipv6_prefix: None,
            ipv6_address: None,
            ipv6_gateway: "2001:db8::1".parse().unwrap(),
            ipv4_address: None,
            ipv4_gateway: None,
            ipv4_prefix_length: None,
            domain: None,
        };
        let icos_settings = ICOSSettings {
            nns_public_key_path: PathBuf::from("/path/to/key"),
            nns_urls: vec!["http://localhost".parse().unwrap()],
            elasticsearch_hosts: [
                "elasticsearch-node-0.mercury.dfinity.systems:443",
                "elasticsearch-node-1.mercury.dfinity.systems:443",
                "elasticsearch-node-2.mercury.dfinity.systems:443",
                "elasticsearch-node-3.mercury.dfinity.systems:443",
            ]
            .join(" "),
            elasticsearch_tags: None,
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

        let temp_dir = tempdir().expect("Failed to create temp directory");
        let json_setupos_file = temp_dir.path().join("test_setupos_config.json");
        let json_hostos_file = temp_dir.path().join("test_hostos_config.json");
        let json_guestos_file = temp_dir.path().join("test_guestos_config.json");

        assert!(serialize_and_write_config(&json_setupos_file, &setupos_config_struct).is_ok());
        assert!(serialize_and_write_config(&json_hostos_file, &hostos_config_struct).is_ok());
        assert!(serialize_and_write_config(&json_guestos_file, &guestos_config_struct).is_ok());

        let deserialized_setupos_config: SetupOSConfig =
            deserialize_config(json_setupos_file.to_str().unwrap())
                .expect("Failed to deserialize setupos config");
        let deserialized_hostos_config: HostOSConfig =
            deserialize_config(json_hostos_file.to_str().unwrap())
                .expect("Failed to deserialize hostos config");
        let deserialized_guestos_config: GuestOSConfig =
            deserialize_config(json_guestos_file.to_str().unwrap())
                .expect("Failed to deserialize guestos config");

        assert_eq!(setupos_config_struct, deserialized_setupos_config);
        assert_eq!(hostos_config_struct, deserialized_hostos_config);
        assert_eq!(guestos_config_struct, deserialized_guestos_config);
    }

    #[test]
    fn test_is_valid_ipv6_prefix() {
        assert!(is_valid_ipv6_prefix("2a00:1111:1111:1111"));
        assert!(is_valid_ipv6_prefix("2a00:111:11:11"));
        assert!(is_valid_ipv6_prefix("2602:fb2b:100:10"));
    }

    #[test]
    fn test_parse_config_line() {
        assert_eq!(
            parse_config_line("key=value"),
            Some(("key".to_string(), "value".to_string()))
        );
        assert_eq!(
            parse_config_line("   key   =   value   "),
            Some(("key".to_string(), "value".to_string()))
        );
        assert_eq!(parse_config_line(""), None);
        assert_eq!(parse_config_line("# this is a comment"), None);
        assert_eq!(parse_config_line("keywithoutvalue"), None);
        assert_eq!(
            parse_config_line("key=value=extra"),
            Some(("key".to_string(), "value=extra".to_string()))
        );
    }

    #[test]
    fn test_config_map_from_path() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        let file_path = temp_file.path().to_path_buf();

        writeln!(temp_file, "key1=value1")?;
        writeln!(temp_file, "key2=value2")?;
        writeln!(temp_file, "# This is a comment")?;
        writeln!(temp_file, "key3=value3")?;
        writeln!(temp_file, "")?;

        let config_map = config_map_from_path(&file_path)?;

        assert_eq!(config_map.get("key1"), Some(&"value1".to_string()));
        assert_eq!(config_map.get("key2"), Some(&"value2".to_string()));
        assert_eq!(config_map.get("key3"), Some(&"value3".to_string()));
        assert_eq!(config_map.get("bad_key"), None);

        // CRLF test
        let mut temp_file_crlf = NamedTempFile::new()?;
        let file_path_crlf = temp_file_crlf.path().to_path_buf();

        writeln!(temp_file_crlf, "key4=value4\r\nkey5=value5\r\n")?;

        let config_map_crlf = config_map_from_path(&file_path_crlf)?;

        assert_eq!(config_map_crlf.get("key4"), Some(&"value4".to_string()));
        assert_eq!(config_map_crlf.get("key5"), Some(&"value5".to_string()));
        assert_eq!(config_map.get("bad_key"), None);

        std::fs::remove_file(&file_path)?;
        std::fs::remove_file(&file_path_crlf)?;

        Ok(())
    }
}
