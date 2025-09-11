use std::net::Ipv6Addr;

use anyhow::{Result, anyhow};
use config_types::DeploymentEnvironment;
use ic_crypto_sha2::Sha256;
use macaddr::MacAddr6;

pub mod node_type;
use node_type::NodeType;

pub trait MacAddr6Ext {
    fn calculate_slaac(&self, prefix: &str) -> Result<Ipv6Addr>;
}

impl MacAddr6Ext for MacAddr6 {
    /// Generates the SLAAC IPv6 address for the given prefix.
    fn calculate_slaac(&self, prefix: &str) -> Result<Ipv6Addr> {
        let mac_octets = self.into_array();

        // Create the EUI-64 interface identifier
        let mut interface_id = [0u8; 8];

        // Flip the Universal/Local bit in the first octet
        interface_id[0] = mac_octets[0] ^ 0x02;
        interface_id[1] = mac_octets[1];
        interface_id[2] = mac_octets[2];
        interface_id[3] = 0xff;
        interface_id[4] = 0xfe;
        interface_id[5] = mac_octets[3];
        interface_id[6] = mac_octets[4];
        interface_id[7] = mac_octets[5];

        let prefix_octets = prefix_octets(prefix)?;

        // Combine the prefix with the interface identifier
        let mut addr_octets = [0; 16];
        addr_octets[..8].copy_from_slice(&prefix_octets);
        addr_octets[8..].copy_from_slice(&interface_id);

        // Construct the full IPv6 address
        Ok(Ipv6Addr::from(addr_octets))
    }
}

// parse the octets by going through Ipv6Addr
fn prefix_octets(prefix: &str) -> Result<[u8; 8]> {
    // Prepare the prefix by appending '::' if necessary
    let full_prefix = if prefix.contains("::") {
        prefix.to_string()
    } else {
        format!("{prefix}::")
    };

    // Parse the prefix into an Ipv6Addr
    let prefix_addr = full_prefix
        .parse::<Ipv6Addr>()
        .map_err(|_| anyhow!("Invalid IPv6 prefix: {}", prefix))?;

    // Extract the network prefix (first 64 bits)
    Ok(prefix_addr.octets()[..8].try_into()?)
}

#[derive(Copy, Clone)]
pub enum IpVariant {
    V4,
    V6,
}

pub fn calculate_deterministic_mac(
    mgmt_mac: &MacAddr6,
    deployment_environment: DeploymentEnvironment,
    // TODO(NODE-1609): consider removing IpVariant as it's always set to V6 in prod.
    ip_version: IpVariant,
    node_type: NodeType,
) -> MacAddr6 {
    let index = node_type.to_index();

    // NOTE: In order to be backwards compatible with existing scripts, this
    // **MUST** have a newline.
    let seed = format!(
        "{}{}\n",
        mgmt_mac.to_string().to_lowercase(),
        deployment_environment
    );

    let hash = Sha256::hash(seed.as_bytes());

    let version = match ip_version {
        IpVariant::V4 => 0x4a,
        IpVariant::V6 => 0x6a,
    };

    [version, index, hash[0], hash[1], hash[2], hash[3]].into()
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn mac() {
        let mgmt_mac: MacAddr6 = "70:B5:E8:E8:25:DE".parse().unwrap();
        let expected_mac: MacAddr6 = "4a:00:f8:87:a4:8a".parse().unwrap();
        let mac = calculate_deterministic_mac(
            &mgmt_mac,
            DeploymentEnvironment::Testnet,
            IpVariant::V4,
            NodeType::HostOS,
        );
        assert_eq!(mac, expected_mac);
    }

    #[test]
    fn test_calculate_slaac() {
        let mac = "6a01e5962d49".parse::<MacAddr6>().unwrap();
        let prefix = "2a04:9dc0:0:108";

        let expected_ip = "2a04:9dc0:0:108:6801:e5ff:fe96:2d49"
            .parse::<Ipv6Addr>()
            .unwrap();

        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }

    #[test]
    fn mac_to_slaac() {
        let mgmt_mac = "b0:7b:25:c8:f6:c0".parse::<MacAddr6>().unwrap();
        let prefix = "2602:FFE4:801:17";
        let expected_ip = "2602:ffe4:801:17:6801:ff:feec:bd51"
            .parse::<Ipv6Addr>()
            .unwrap();
        let mac = calculate_deterministic_mac(
            &mgmt_mac,
            DeploymentEnvironment::Mainnet,
            IpVariant::V6,
            NodeType::GuestOS,
        );
        let slaac = mac.calculate_slaac(prefix).unwrap();
        assert_eq!(slaac, expected_ip);
    }

    #[test]
    fn test_prefix_without_suffix() {
        let mac = "6a:01:e5:96:2d:49".parse::<MacAddr6>().unwrap();
        let prefix = "2001:db8";

        let expected_ip = "2001:db8::6801:e5ff:fe96:2d49".parse::<Ipv6Addr>().unwrap();

        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }

    #[test]
    fn test_prefix_with_double_colon() {
        let mac = "6a:01:e5:96:2d:49".parse::<MacAddr6>().unwrap();
        let prefix = "2a04:9dc0:0:108::";

        let expected_ip = "2a04:9dc0:0:108:6801:e5ff:fe96:2d49"
            .parse::<Ipv6Addr>()
            .unwrap();

        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }

    #[test]
    fn test_invalid_prefix() {
        let mac = "6a:01:e5:96:2d:49".parse::<MacAddr6>().unwrap();
        let invalid_prefixes = vec![
            "invalid_prefix",
            "gggg::",
            "2a04:9dc0:0:108:zzzz",
            "1234:::",
        ];

        for prefix in invalid_prefixes {
            let result = mac.calculate_slaac(prefix);
            assert!(result.is_err(), "Prefix '{prefix}' should be invalid");
        }
    }

    #[test]
    fn test_all_zero_mac() {
        let mac = "00:00:00:00:00:00".parse::<MacAddr6>().unwrap();
        let prefix = "2001:db8::";

        let expected_ip = "2001:db8::0200:ff:fe00:0".parse::<Ipv6Addr>().unwrap();

        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }

    #[test]
    fn test_all_one_mac() {
        let mac = "ff:ff:ff:ff:ff:ff".parse::<MacAddr6>().unwrap();
        let prefix = "2001:db8::";

        let expected_ip = "2001:db8::fdff:ffff:feff:ffff".parse::<Ipv6Addr>().unwrap();

        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }
}
