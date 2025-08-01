use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use config_types::ConfigMap;

use anyhow::{anyhow, bail};
use anyhow::{Context, Result};
use ini::Ini;

pub struct ConfigIniSettings {
    pub ipv6_prefix: String,
    pub ipv6_prefix_length: u8,
    pub ipv6_gateway: Ipv6Addr,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain_name: Option<String>,
    pub verbose: bool,
    pub node_reward_type: Option<String>,
    pub enable_trusted_execution_environment: bool,
}

// Prefix should have a max length of 19 ("1234:6789:1234:6789")
// It could have fewer characters though. Parsing as an ip address with trailing '::' should work.
fn is_valid_ipv6_prefix(ipv6_prefix: &str) -> bool {
    ipv6_prefix.len() <= 19 && format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok()
}

/// Read a boolean value from the config map.
///
/// Returns Err() if the value is not "true" or "false".
/// Returns Ok(None) if the value cannot be found in the config map.
fn read_boolean(config_map: &ConfigMap, key: &str) -> Result<Option<bool>> {
    config_map
        .get(key)
        .map(|value| {
            value.parse().map_err(|_| {
                anyhow!(
                    "Error reading bool value: {key}. Only true and false are valid values but \
                    got: '{value}'."
                )
            })
        })
        .transpose()
}

pub fn get_config_ini_settings(config_file_path: &Path) -> Result<ConfigIniSettings> {
    let config_map: ConfigMap = config_map_from_path(config_file_path)?;

    let ipv6_prefix = config_map
        .get("ipv6_prefix")
        .context("Missing config parameter: ipv6_prefix")
        .and_then(|prefix| {
            if is_valid_ipv6_prefix(prefix) {
                Ok(prefix.clone())
            } else {
                bail!("Invalid ipv6 prefix: {}", prefix)
            }
        })?;

    // Per PFOPS - ipv6_prefix_length will always be 64
    let ipv6_prefix_length = 64_u8;

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

    let domain_name = config_map.get("domain").cloned();

    let verbose = read_boolean(&config_map, "verbose")?.unwrap_or(false);

    let node_reward_type = config_map
        .get("node_reward_type")
        .filter(|s| !s.is_empty())
        .cloned();

    let enable_trusted_execution_environment =
        read_boolean(&config_map, "enable_trusted_execution_environment")?.unwrap_or(false);

    Ok(ConfigIniSettings {
        ipv6_prefix,
        ipv6_prefix_length,
        ipv6_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        domain_name,
        verbose,
        node_reward_type,
        enable_trusted_execution_environment,
    })
}

fn config_map_from_path(config_file_path: &Path) -> Result<ConfigMap> {
    let parsed_ini = Ini::load_from_file(config_file_path).context("Failed to parse INI file")?;

    // Flatten all sections into a single HashMap
    let config_map: ConfigMap = parsed_ini
        .into_iter()
        .flat_map(|(_, properties)| properties.into_iter())
        .map(|(key, value)| (key.to_lowercase(), value))
        .collect();

    Ok(config_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_is_valid_ipv6_prefix() {
        // Valid prefixes
        assert!(is_valid_ipv6_prefix("2a00:1111:1111:1111"));
        assert!(is_valid_ipv6_prefix("2a00:111:11:11"));
        assert!(is_valid_ipv6_prefix("2602:fb2b:100:10"));

        // Invalid prefixes
        assert!(!is_valid_ipv6_prefix("2a00:1111:1111:1111:")); // Trailing colon
        assert!(!is_valid_ipv6_prefix("2a00:1111:1111:1111:1111:1111")); // Too long
        assert!(!is_valid_ipv6_prefix("abcd::1234:5678")); // Contains "::"
    }

    #[test]
    fn test_config_map_from_path() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        let file_path = temp_file.path().to_path_buf();

        writeln!(temp_file, "key1=value1")?;
        writeln!(temp_file, "key2=value2")?;
        writeln!(temp_file, "# This is a comment")?;
        writeln!(temp_file, "key3=value3")?;
        writeln!(temp_file)?;

        let config_map = config_map_from_path(&file_path)?;

        assert_eq!(config_map.get("key1"), Some(&"value1".to_string()));
        assert_eq!(config_map.get("key2"), Some(&"value2".to_string()));
        assert_eq!(config_map.get("key3"), Some(&"value3".to_string()));
        assert_eq!(config_map.get("bad_key"), None);

        Ok(())
    }

    #[test]
    fn test_config_map_from_path_crlf() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        let file_path = temp_file.path().to_path_buf();

        writeln!(temp_file, "key4=value4\r\nkey5=value5\r\n")?;

        let config_map = config_map_from_path(&file_path)?;

        assert_eq!(config_map.get("key4"), Some(&"value4".to_string()));
        assert_eq!(config_map.get("key5"), Some(&"value5".to_string()));
        assert_eq!(config_map.get("bad_key"), None);

        Ok(())
    }

    #[test]
    fn test_get_config_ini_settings() -> Result<()> {
        // Test valid config.ini
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "\n\t\r")?;
        writeln!(temp_file, "# COMMENT          ")?;
        writeln!(temp_file, "\n\n\n\n")?;
        writeln!(temp_file, "ipv6_prefix=2a00:fb01:400:200")?;
        writeln!(temp_file, "ipv6_gateway=2a00:fb01:400:200::1")?;
        writeln!(temp_file, "ipv4_address=212.71.124.178")?;
        writeln!(temp_file, "ipv4_gateway=212.71.124.177")?;
        writeln!(temp_file, "ipv4_prefix_length=28")?;
        writeln!(temp_file, "domain=example.com")?;
        writeln!(temp_file, "verbose=false")?;

        let config_ini_settings = get_config_ini_settings(temp_file.path())?;

        assert_eq!(
            config_ini_settings.ipv6_prefix,
            "2a00:fb01:400:200".to_string()
        );
        assert_eq!(
            config_ini_settings.ipv6_gateway,
            "2a00:fb01:400:200::1".parse::<Ipv6Addr>()?
        );
        assert_eq!(config_ini_settings.ipv6_prefix_length, 64);
        assert_eq!(
            config_ini_settings.ipv4_address.unwrap(),
            "212.71.124.178".parse::<Ipv4Addr>()?
        );
        assert_eq!(
            config_ini_settings.ipv4_gateway.unwrap(),
            "212.71.124.177".parse::<Ipv4Addr>()?
        );
        assert_eq!(config_ini_settings.ipv4_prefix_length.unwrap(), 28);
        assert_eq!(
            config_ini_settings.domain_name,
            Some("example.com".to_string())
        );
        assert!(!config_ini_settings.verbose);

        // Test missing ipv6
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "ipv4_address=212.71.124.178")?;
        writeln!(temp_file, "ipv4_gateway=212.71.124.177")?;
        writeln!(temp_file, "ipv4_prefix_length=28")?;

        let result = get_config_ini_settings(temp_file.path());
        assert!(result.is_err());

        // Test invalid IPv6 prefix
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "ipv6_prefix=invalid_ipv6_prefix")?;
        writeln!(temp_file, "ipv6_gateway=2001:db8:85a3:0000::1")?;
        writeln!(temp_file, "ipv4_address=192.168.1.1")?;
        writeln!(temp_file, "ipv4_gateway=192.168.1.254")?;
        writeln!(temp_file, "ipv4_prefix_length=24")?;

        let result = get_config_ini_settings(temp_file.path());
        assert!(result.is_err());

        // Test missing prefix
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "ipv6_gateway=2001:db8:85a3:0000::1")?;
        let result = get_config_ini_settings(temp_file.path());
        assert!(result.is_err());

        Ok(())
    }
}
