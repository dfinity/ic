use regex::Regex;
use std::collections::HashMap;
use std::fs::read_to_string;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::bail;
use anyhow::{Context, Result};

pub type ConfigMap = HashMap<String, String>;
pub struct ConfigIniSettings {
    pub ipv6_prefix: Option<String>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub ipv6_prefix_length: u8,
    pub ipv6_gateway: Ipv6Addr,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain: Option<String>,
    pub verbose: bool,
}

// Prefix should have a max length of 19 ("1234:6789:1234:6789")
// It could have fewer characters though. Parsing as an ip address with trailing '::' should work.
fn is_valid_ipv6_prefix(ipv6_prefix: &str) -> bool {
    ipv6_prefix.len() <= 19 && format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok()
}

pub fn get_config_ini_settings(config_file_path: &Path) -> Result<ConfigIniSettings> {
    let config_map: ConfigMap = config_map_from_path(config_file_path)?;

    let ipv6_prefix = config_map
        .get("ipv6_prefix")
        .map(|prefix| {
            if !is_valid_ipv6_prefix(prefix) {
                bail!("Invalid ipv6 prefix: {}", prefix);
            }
            Ok(prefix.clone())
        })
        .transpose()?;

    // Per PFOPS - ipv6_prefix_length will always be 64
    let ipv6_prefix_length = 64_u8;

    // Optional ipv6_address - for testing. Takes precedence over ipv6_prefix.
    let ipv6_address = config_map
        .get("ipv6_address")
        .map(|address| {
            // ipv6_address might be formatted with the trailing suffix. Remove it.
            address
                .strip_suffix(&format!("/{}", ipv6_prefix_length))
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

    let verbose = config_map
        .get("verbose")
        .is_some_and(|s| s.eq_ignore_ascii_case("true"));

    Ok(ConfigIniSettings {
        ipv6_prefix,
        ipv6_address,
        ipv6_prefix_length,
        ipv6_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        domain,
        verbose,
    })
}

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

    let normalized_file_contents = normalize_contents(&file_contents);

    Ok(normalized_file_contents
        .lines()
        .filter_map(parse_config_line)
        .collect())
}

fn normalize_contents(contents: &str) -> String {
    let mut normalized_contents = contents.replace("\r\n", "\n").replace("\r", "\n");

    let comment_regex = Regex::new(r"#.*$").unwrap();
    normalized_contents = comment_regex
        .replace_all(&normalized_contents, "")
        .to_string();

    normalized_contents = normalized_contents.replace("\"", "").replace("'", "");

    normalized_contents = normalized_contents.to_lowercase();

    let empty_line_regex = Regex::new(r"^\s*$\n?").unwrap();
    normalized_contents = empty_line_regex
        .replace_all(&normalized_contents, "")
        .to_string();

    if !normalized_contents.ends_with('\n') {
        normalized_contents.push('\n');
    }

    normalized_contents
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
        writeln!(temp_file, "BAD INPUT          ")?;
        writeln!(temp_file, "\n\n\n\n")?;
        writeln!(temp_file, "ipv6_prefix=2a00:fb01:400:200")?;
        writeln!(temp_file, "ipv6_address=2a00:fb01:400:200::/64")?;
        writeln!(temp_file, "ipv6_gateway=2a00:fb01:400:200::1")?;
        writeln!(temp_file, "ipv4_address=212.71.124.178")?;
        writeln!(temp_file, "ipv4_gateway=212.71.124.177")?;
        writeln!(temp_file, "ipv4_prefix_length=28")?;
        writeln!(temp_file, "domain=example.com")?;
        writeln!(temp_file, "verbose=false")?;

        let temp_file_path = temp_file.path();

        let config_ini_settings = get_config_ini_settings(temp_file_path)?;

        assert_eq!(
            config_ini_settings.ipv6_prefix.unwrap(),
            "2a00:fb01:400:200".to_string()
        );
        assert_eq!(
            config_ini_settings.ipv6_address.unwrap(),
            "2a00:fb01:400:200::".parse::<Ipv6Addr>()?
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
        assert_eq!(config_ini_settings.domain, Some("example.com".to_string()));
        assert!(!config_ini_settings.verbose);

        // Test ipv6_address without ipv6_prefix_length length
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "ipv6_address=2a00:fb01:400:200::")?;
        let config_ini_settings = get_config_ini_settings(temp_file_path)?;
        assert_eq!(
            config_ini_settings.ipv6_address.unwrap(),
            "2a00:fb01:400:200::".parse::<Ipv6Addr>()?
        );
        assert_eq!(config_ini_settings.ipv6_prefix_length, 64);

        // Test missing ipv6
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "ipv4_address=212.71.124.178")?;
        writeln!(temp_file, "ipv4_gateway=212.71.124.177")?;
        writeln!(temp_file, "ipv4_prefix_length=28")?;

        let temp_file_path = temp_file.path();
        let result = get_config_ini_settings(temp_file_path);
        assert!(result.is_err());

        // Test invalid IPv6 address
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "ipv6_prefix=invalid_ipv6_prefix")?;
        writeln!(temp_file, "ipv6_gateway=2001:db8:85a3:0000::1")?;
        writeln!(temp_file, "ipv4_address=192.168.1.1")?;
        writeln!(temp_file, "ipv4_gateway=192.168.1.254")?;
        writeln!(temp_file, "ipv4_prefix_length=24")?;

        let temp_file_path = temp_file.path();
        let result = get_config_ini_settings(temp_file_path);
        assert!(result.is_err());

        // Test missing prefix and address
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "ipv6_gateway=2001:db8:85a3:0000::1")?;
        let result = get_config_ini_settings(temp_file_path);
        assert!(result.is_err());

        Ok(())
    }
}
