use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use getifs::IfNet;
use network::interfaces::{get_interface_name, get_interface_paths};

/// Picks the best interface from the list
fn pick_best_interface(mut interfaces: Vec<String>) -> Option<String> {
    interfaces.sort();

    // Try to pick eth* interface first, then others.
    // On Azure both eth* and en* are created, but we should use eth* one.
    // In other environments we have only en* interfaces.
    interfaces
        .iter()
        .find(|x| x.starts_with("eth"))
        .or_else(|| interfaces.iter().find(|x| x.starts_with("en")))
        .cloned()
}

/// Returns the name of the best matching interface
pub fn get_best_interface_name() -> Result<String> {
    // Get a list of all network interfaces in the system
    let interfaces = get_interface_paths()
        .into_iter()
        .map(|x| get_interface_name(&x))
        .collect::<Result<Vec<_>>>()
        .context("unable to extract interface name")?;

    let valid_interface =
        pick_best_interface(interfaces).context("no valid network interfaces found")?;

    Ok(valid_interface)
}

/// Gets the most appropriate IPv4/IPv6 addresses from the provided interface
pub fn get_interface_addresses(interface: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    // Get the interface
    let interface = getifs::interfaces()
        .context("failed to get network interfaces")?
        .into_iter()
        .find(|x| x.name() == interface)
        .with_context(|| format!("interface {interface} not found"))?;

    // Get all of its addresses
    let addrs = interface
        .addrs()
        .context("unable to get interface addresses")?;

    let addrs_v4 = addrs
        .iter()
        .filter_map(|x| {
            if let IfNet::V4(v) = x {
                Some(v.addr())
            } else {
                None
            }
        })
        .collect();

    let addrs_v6 = addrs
        .iter()
        .filter_map(|x| {
            if let IfNet::V6(v) = x {
                Some(v.addr())
            } else {
                None
            }
        })
        .collect();

    Ok((
        pick_best_ipv4_address(addrs_v4),
        pick_best_ipv6_address(addrs_v6),
    ))
}

/// Picks the most appropriate IPv4 address from a list.
/// Prefers global over local/private/loopback/etc.
fn pick_best_ipv4_address(mut addrs: Vec<Ipv4Addr>) -> Option<Ipv4Addr> {
    // Sort addresses by locality (non-local first)
    addrs.sort_by_key(|x| {
        x.is_link_local()
            || x.is_loopback()
            || x.is_private()
            || x.is_documentation()
            || x.is_multicast()
    });

    // Pick first address
    addrs.into_iter().next()
}

/// Picks the most appropriate IPv6 address from a list.
/// Prefers global over local/multicast/etc.
fn pick_best_ipv6_address(mut addrs: Vec<Ipv6Addr>) -> Option<Ipv6Addr> {
    // Sort addresses by locality (non-local first)
    addrs.sort_by_key(|x| x.is_unicast_link_local() || x.is_unique_local() || x.is_multicast());

    // Pick first address
    addrs.into_iter().next()
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_pick_best_interface() {
        let interfaces = vec!["lo", "ens0", "eth1", "ens1", "eth0"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("eth0".to_string()));

        let interfaces = vec!["lo", "eth0", "eth1", "ens0", "ens1"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("eth0".to_string()));

        let interfaces = vec!["lo", "ens0"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("ens0".to_string()));

        let interfaces = vec!["lo", "enp0"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("enp0".to_string()));

        let interfaces = vec!["lo"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert!(pick_best_interface(interfaces).is_none());
    }

    #[test]
    fn test_pick_best_ipv4_address() {
        // Pick 1st global addr over local ones
        let addrs = vec![
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            Ipv4Addr::from_str("192.168.0.1").unwrap(),
            Ipv4Addr::from_str("169.254.169.254").unwrap(),
            Ipv4Addr::from_str("224.0.0.1").unwrap(),
            Ipv4Addr::from_str("1.1.1.1").unwrap(),
            Ipv4Addr::from_str("1.1.2.2").unwrap(),
        ];
        assert_eq!(
            pick_best_ipv4_address(addrs),
            Some(Ipv4Addr::from_str("1.1.1.1").unwrap())
        );

        // Pick just 1st local addr
        let addrs = vec![
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            Ipv4Addr::from_str("192.168.0.1").unwrap(),
            Ipv4Addr::from_str("169.254.169.254").unwrap(),
            Ipv4Addr::from_str("224.0.0.1").unwrap(),
        ];
        assert_eq!(
            pick_best_ipv4_address(addrs),
            Some(Ipv4Addr::from_str("127.0.0.1").unwrap())
        );
    }

    #[test]
    fn test_pick_best_ipv6_address() {
        // Pick 1st global addr over local ones
        let addrs = vec![
            Ipv6Addr::from_str("fe80::1").unwrap(),
            Ipv6Addr::from_str("fc00::1").unwrap(),
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("2a00:1450:400a:1009::65").unwrap(),
            Ipv6Addr::from_str("2a00:1450:400a:1009::66").unwrap(),
        ];
        assert_eq!(
            pick_best_ipv6_address(addrs),
            Some(Ipv6Addr::from_str("2a00:1450:400a:1009::65").unwrap())
        );

        // Pick just 1st local addr
        let addrs = vec![
            Ipv6Addr::from_str("fe80::1").unwrap(),
            Ipv6Addr::from_str("fc00::1").unwrap(),
            Ipv6Addr::from_str("fd00::1").unwrap(),
        ];
        assert_eq!(
            pick_best_ipv6_address(addrs),
            Some(Ipv6Addr::from_str("fe80::1").unwrap())
        );
    }
}
