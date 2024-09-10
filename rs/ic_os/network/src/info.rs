use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};

use config::ConfigMap;

#[derive(Debug)]
pub struct NetworkInfo {
    // Config files can specify ipv6 prefix, address and prefix, or just address.
    // ipv6_address takes precedence. Some tests provide only the address.
    // Should be kept as a string until parsing later.
    pub ipv6_prefix: Option<Ipv6Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub ipv6_subnet: u8,
    pub ipv6_gateway: Ipv6Addr,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv4_prefix_length: Option<u8>,
    pub domain: Option<String>,
    pub mgmt_mac: Option<String>,
}

fn is_valid_prefix(ipv6_prefix: &str) -> bool {
    ipv6_prefix.len() <= 19 && format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok()
}

impl NetworkInfo {
    pub fn from_config_map(config_map: &ConfigMap) -> Result<NetworkInfo> {
        // Per PFOPS - this will never not be 64
        let ipv6_subnet = 64_u8;

        let ipv6_prefix = config_map
        .get("ipv6_prefix")
        .map(|prefix| {
            // Prefix should have a max length of 19 ("1234:6789:1234:6789")
            // It could have fewer characters though. Parsing as an ip address with trailing '::' should work.
            if !is_valid_prefix(prefix) {
                bail!("Invalid IPv6 prefix: {}", prefix);
            }
            format!("{}::", prefix)
                .parse::<Ipv6Addr>()
                .context(format!("Failed to parse IPv6 prefix: {}", prefix))
        })
        .transpose()?;

        // Optional ipv6_address - for testing. Takes precedence over ipv6_prefix.
        let ipv6_address = match config_map.get("ipv6_address") {
            Some(address) => {
                // ipv6_address might be formatted with the trailing suffix. Remove it.
                let ipv6_subnet = format!("/{}", ipv6_subnet);
                let address = address.strip_suffix(&ipv6_subnet).unwrap_or(address);
                let address = address
                    .parse::<Ipv6Addr>()
                    .context(format!("Invalid ipv6 address: {}", address))?;
                Some(address)
            }
            None => None,
        };

        if ipv6_address.is_none() && ipv6_prefix.is_none() {
            bail!("Missing config parameter: need at least one of ipv6_prefix or ipv6_address");
        }

        let ipv6_gateway = config_map
            .get("ipv6_gateway")
            .context("Missing config parameter: ipv6_gateway")?;
        let ipv6_gateway = ipv6_gateway
            .parse::<Ipv6Addr>()
            .context(format!("Invalid ipv6 address: {}", ipv6_gateway))?;

        Ok(NetworkInfo {
            ipv6_prefix,
            ipv6_subnet,
            ipv6_gateway,
            ipv6_address,
            ipv4_gateway: None,
            ipv4_prefix_length: None,
            domain: None,
            mgmt_mac: None,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use super::*;
    #[test]
    fn test_is_valid_prefix() {
        assert!(is_valid_prefix("2a00:1111:1111:1111"));
        assert!(is_valid_prefix("2a00:111:11:11"));
        assert!(is_valid_prefix("2602:fb2b:100:10"));
    }

    #[test]
    fn test_from_config_map() {
        // Example config.ini
        let config_map = HashMap::from([
            ("ipv6_prefix".to_string(), "2a00:fb01:400:100".to_string()),
            (
                "ipv6_gateway".to_string(),
                "2a00:fb01:400:100::1".to_string(),
            ),
        ]);
        assert!(NetworkInfo::from_config_map(&config_map).is_ok());

        // With ipv6_address and ipv6_prefix
        let config_map = HashMap::from([
            ("ipv6_prefix".to_string(), "2a00:fb01:400:100".to_string()),
            (
                "ipv6_gateway".to_string(),
                "2a00:fb01:400:100::1".to_string(),
            ),
            (
                "ipv6_address".to_string(),
                "2a00:fb01:400:100::3".to_string(),
            ),
        ]);
        assert!(NetworkInfo::from_config_map(&config_map).is_ok());

        // No subnet
        let config_map = HashMap::from([
            ("ipv6_prefix".to_string(), "2a00:fb01:400:100".to_string()),
            (
                "ipv6_gateway".to_string(),
                "2a00:fb01:400:100::1".to_string(),
            ),
        ]);
        assert!(NetworkInfo::from_config_map(&config_map).is_ok());

        // Need address or prefix
        let config_map = HashMap::from([
            (
                "ipv6_address".to_string(),
                "2a00:fb01:400:100::1".to_string(),
            ),
            (
                "ipv6_gateway".to_string(),
                "2a00:fb01:400:100::1".to_string(),
            ),
        ]);
        assert!(NetworkInfo::from_config_map(&config_map).is_ok());

        // Need prefix or address, gateway
        let config_map = HashMap::from([(
            "ipv6_gateway".to_string(),
            "2a00:fb01:400:100::1".to_string(),
        )]);
        assert!(NetworkInfo::from_config_map(&config_map).is_err());
        let config_map =
            HashMap::from([("ipv6_prefix".to_string(), "2a00:fb01:400:100".to_string())]);
        assert!(NetworkInfo::from_config_map(&config_map).is_err());

        // With ipv6_address with subnet len
        let config_map = HashMap::from([
            (
                "ipv6_gateway".to_string(),
                "2a00:fb01:400:100::1".to_string(),
            ),
            ("ipv6_address".to_string(), "fd00:2:1:1::11/64".to_string()),
        ]);
        assert!(NetworkInfo::from_config_map(&config_map).is_ok());
    }
}
