use std::net::Ipv6Addr;

use anyhow::{anyhow, Context, Result};

use mac_address::mac_address::UnformattedMacAddress;
use utils::intersperse;

/// Generate a deterministic ipv6 address
pub fn generate_ipv6_address(
    ipv6_prefix: &str,
    generated_mac: &UnformattedMacAddress,
) -> Result<Ipv6Addr> {
    let mac_first6: String = generated_mac.get().chars().take(6).collect();
    // Succinct as possible... Reverse, take 6, then reverse those to get the original order.
    // TODO - Might be better as slicing operator?
    let mac_last6: String = generated_mac
        .get()
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let output = format!("{}fffe{}", mac_first6, mac_last6);
    let prefix: String = output.chars().take(2).collect();
    let prefix_as_i64 = i64::from_str_radix(prefix.as_str(), 16)? ^ 2;
    let tail: String = output.chars().skip(2).collect();
    let ipv6_suffix = format!("{:02x}{}", prefix_as_i64, tail);
    let ipv6_suffix = intersperse(ipv6_suffix.as_str(), ':', 4);
    let address = format!("{}:{}", ipv6_prefix, ipv6_suffix);
    let address = address
        .parse::<Ipv6Addr>()
        .context(anyhow!("Couldn't parse {}", address))?;
    Ok(address)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_generate_ipv6_address() {
        assert_eq!(
            generate_ipv6_address(
                "2a00:1111:1111:1111",
                &UnformattedMacAddress::try_from("4a0ff7e0c684").unwrap()
            )
            .unwrap(),
            "2a00:1111:1111:1111:480f:f7ff:fee0:c684"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            generate_ipv6_address(
                "1111:1111:1111:1111",
                &UnformattedMacAddress::try_from("111111111111").unwrap()
            )
            .unwrap(),
            "1111:1111:1111:1111:1311:11ff:fe11:1111"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            generate_ipv6_address(
                "2a00:fb01:400:100",
                &UnformattedMacAddress::try_from("a1b2c3d4e5f6").unwrap()
            )
            .unwrap(),
            "2a00:fb01:400:100:a3b2:c3ff:fed4:e5f6"
                .parse::<Ipv6Addr>()
                .unwrap()
        );

        // Use actual generated mac address - GuestOS, version '6', "de:ad:de:ad:de:ad"
        assert_eq!(
            generate_ipv6_address(
                "2a00:fb01:400:100",
                &UnformattedMacAddress::try_from("6a01f7e0c684").unwrap()
            )
            .unwrap(),
            "2a00:fb01:400:100:6801:f7ff:fee0:c684"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
    }
}
