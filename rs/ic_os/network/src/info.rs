use std::net::Ipv6Addr;

use anyhow::{bail, Context, Result};

use config_types::ConfigMap;

#[derive(Debug)]
pub struct NetworkInfo {
    pub ipv6_prefix: String,
    pub ipv6_subnet: u8,
    pub ipv6_gateway: Ipv6Addr,
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
            .context("Missing config parameter: ipv6_prefix")
            .and_then(|prefix| {
                if is_valid_prefix(prefix) {
                    Ok(prefix.clone())
                } else {
                    bail!("Invalid IPv6 prefix: {}", prefix)
                }
            })?;

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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

        // No subnet
        let config_map = HashMap::from([
            ("ipv6_prefix".to_string(), "2a00:fb01:400:100".to_string()),
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
    }
}
