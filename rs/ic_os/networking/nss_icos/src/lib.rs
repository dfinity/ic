// `libnss_host_hooks!` expands to a `lazy_static!` invocation, so the macro must be in scope here.
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::LazyLock;

struct ICOSHosts;
libnss_host_hooks!(icos, ICOSHosts);

/// Why no local IPv6 address could be determined.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalIpError {
    /// Enumerating the network interfaces failed.
    Interfaces(nix::Error),
    /// No interface has a suitable (non-loopback, non-link-local) IPv6 address.
    NotFound,
}

impl fmt::Display for LocalIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalIpError::Interfaces(e) => write!(f, "failed to list network interfaces: {e}"),
            LocalIpError::NotFound => write!(f, "no local IPv6 address found"),
        }
    }
}

impl std::error::Error for LocalIpError {}

/// Returns the first IPv6 address of a non-loopback interface that is neither a loopback nor a
/// link-local address, i.e. the first address with global scope in the order reported by
/// `getifaddrs(3)`.
///
/// This function is invoked strictly once under `LazyLock` below. This avoids having to re-query
/// network interfaces on every host name resolution. The disadvantage is that long-running
/// programs will not be able to detect runtime changes of IPv6 addresses on the host.
fn get_local_ipv6() -> Result<Ipv6Addr, LocalIpError> {
    let ifaddrs = getifaddrs().map_err(LocalIpError::Interfaces)?;
    ifaddrs
        .filter(|ifaddr| !ifaddr.flags.contains(InterfaceFlags::IFF_LOOPBACK))
        .filter_map(|ifaddr| ifaddr.address?.as_sockaddr_in6().map(|v6| v6.ip()))
        .find(|addr| !addr.is_loopback() && !addr.is_unicast_link_local())
        .ok_or(LocalIpError::NotFound)
}

fn ipv6_to_hostos_ipv6(addr: Ipv6Addr) -> Ipv6Addr {
    // By convention, the first two bytes of the host-part of the HostOS' IP
    // address are 0x6800.
    let s = addr.segments();
    Ipv6Addr::new(s[0], s[1], s[2], s[3], 0x6800, s[5], s[6], s[7])
}

fn ipv6_to_guestos_ipv6(addr: Ipv6Addr) -> Ipv6Addr {
    // By convention, the first two bytes of the host-part of the GuestOS' IP
    // address are 0x6801.
    let s = addr.segments();
    Ipv6Addr::new(s[0], s[1], s[2], s[3], 0x6801, s[5], s[6], s[7])
}

/// Whether `addr` belongs to a GuestOS in a multi-VM (type4.x) slot, whose MAC
/// is `[0x7a, node_index, slot, ..]` rather than `[0x6a, node_index, hash0, ..]`.
fn is_multi_vm_guest(addr: Ipv6Addr) -> bool {
    addr.segments()[4] >> 8 == 0x78
}

/// Resolves `name` against the local address, or `None` if it cannot be answered.
///
/// Multi-VM guests get `None` because `slot` displaces the `hash0` byte the
/// HostOS address is built from, making that address underivable: two nodes with
/// different HostOS addresses can share one slot address. Only lookups from
/// inside a guest can be guarded this way — a HostOS address is the same whether
/// or not it hosts many VMs, so `guestos` still resolves to the single-VM address
/// there, and nothing listens on it.
fn resolve(name: &str, local_ipv6: Ipv6Addr) -> Option<Ipv6Addr> {
    if is_multi_vm_guest(local_ipv6) {
        return None;
    }
    match name {
        "guestos" => Some(ipv6_to_guestos_ipv6(local_ipv6)),
        "hostos" => Some(ipv6_to_hostos_ipv6(local_ipv6)),
        _ => None,
    }
}

const KNOWN_NAMES: [&str; 2] = ["hostos", "guestos"];

static PUBLIC_IPV6: LazyLock<Result<Ipv6Addr, LocalIpError>> = LazyLock::new(get_local_ipv6);

impl HostHooks for ICOSHosts {
    fn get_all_entries() -> Response<Vec<Host>> {
        match PUBLIC_IPV6.clone() {
            Ok(local_ipv6) => Response::Success(
                KNOWN_NAMES
                    .into_iter()
                    .filter_map(|name| {
                        resolve(name, local_ipv6).map(|addr| Host {
                            name: name.to_string(),
                            addresses: Addresses::V6(vec![addr]),
                            aliases: vec![],
                        })
                    })
                    .collect(),
            ),
            Err(_) => Response::Success(vec![]),
        }
    }

    fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
        match addr {
            IpAddr::V6(addr) => match PUBLIC_IPV6.clone() {
                Ok(local_ipv6) => KNOWN_NAMES
                    .into_iter()
                    .find(|name| resolve(name, local_ipv6) == Some(addr))
                    .map_or(Response::NotFound, |name| {
                        Response::Success(Host {
                            name: name.to_string(),
                            addresses: Addresses::V6(vec![addr]),
                            aliases: vec![],
                        })
                    }),
                _ => Response::NotFound,
            },
            _ => Response::NotFound,
        }
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {
        match family {
            AddressFamily::IPv6 => match PUBLIC_IPV6.clone() {
                Ok(local_ipv6) => match resolve(name, local_ipv6) {
                    Some(addr) => Response::Success(Host {
                        name: name.to_string(),
                        addresses: Addresses::V6(vec![addr]),
                        aliases: vec![],
                    }),
                    None => Response::NotFound,
                },
                Err(_) => Response::NotFound,
            },
            _ => Response::NotFound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deterministic_ips::node_type::NodeType;
    use deterministic_ips::{
        DeploymentEnvironment, MacAddr6Ext, VmSlot, calculate_deterministic_mac,
    };
    use macaddr::MacAddr6;

    const MGMT_MAC: &str = "b0:7b:25:c8:f6:c0";
    const PREFIX: &str = "2602:FFE4:801:17";

    /// The address such a node actually receives via SLAAC.
    fn real_address(node_type: NodeType, slot: VmSlot) -> Ipv6Addr {
        let mgmt_mac = MGMT_MAC.parse::<MacAddr6>().unwrap();
        calculate_deterministic_mac(&mgmt_mac, DeploymentEnvironment::Mainnet, node_type, slot)
            .calculate_slaac(PREFIX)
            .unwrap()
    }

    /// HostOS always runs in the plain slot, even when it hosts many guests.
    fn real_hostos_address() -> Ipv6Addr {
        real_address(NodeType::HostOS, VmSlot::Plain)
    }

    #[test]
    fn single_vm_node_resolves_both_names() {
        let host = real_hostos_address();
        let guest = real_address(NodeType::GuestOS, VmSlot::Plain);

        assert_eq!(resolve("guestos", host), Some(guest));
        assert_eq!(resolve("hostos", guest), Some(host));
        assert_eq!(resolve("hostos", host), Some(host));
        assert_eq!(resolve("guestos", guest), Some(guest));
    }

    #[test]
    fn multi_vm_guest_refuses_to_resolve() {
        for slot in 1..=4_u8 {
            let guest = real_address(NodeType::GuestOS, VmSlot::new(slot));
            assert!(is_multi_vm_guest(guest), "slot {slot}: {guest}");
            assert_eq!(resolve("hostos", guest), None, "slot {slot}");
            assert_eq!(resolve("guestos", guest), None, "slot {slot}");
        }
    }

    /// The guard must not catch ordinary nodes, or it would break every one.
    #[test]
    fn single_vm_addresses_are_not_flagged_as_multi_vm() {
        for node_type in [NodeType::HostOS, NodeType::GuestOS] {
            let addr = real_address(node_type, VmSlot::Plain);
            assert!(!is_multi_vm_guest(addr), "{node_type} {addr}");
        }
    }

    #[test]
    fn unknown_names_do_not_resolve() {
        assert_eq!(resolve("nowhere", real_hostos_address()), None);
    }

    struct Vector {
        node_type: NodeType,
        slot: u8,
        address: &'static str,
        hostos: Option<&'static str>,
        guestos: Option<&'static str>,
    }

    /// Known-answer vectors for the whole chain: mgmt MAC -> deterministic MAC ->
    /// SLAAC address -> what a node holding it resolves. This addressing is baked
    /// into deployed nodes, so moving any of these has to be deliberate.
    #[test]
    fn golden_vectors() {
        const SINGLE_VM_HOST: Option<&str> = Some("2602:ffe4:801:17:6800:ff:feec:bd51");
        const SINGLE_VM_GUEST: Option<&str> = Some("2602:ffe4:801:17:6801:ff:feec:bd51");

        let vectors = [
            Vector {
                node_type: NodeType::HostOS,
                slot: 0,
                address: "2602:ffe4:801:17:6800:ff:feec:bd51",
                hostos: SINGLE_VM_HOST,
                guestos: SINGLE_VM_GUEST,
            },
            Vector {
                node_type: NodeType::GuestOS,
                slot: 0,
                address: "2602:ffe4:801:17:6801:ff:feec:bd51",
                hostos: SINGLE_VM_HOST,
                guestos: SINGLE_VM_GUEST,
            },
            // The upgrade VM shares the plain slot, so it resolves too.
            Vector {
                node_type: NodeType::UpgradeGuestOS,
                slot: 0,
                address: "2602:ffe4:801:17:6802:ff:feec:bd51",
                hostos: SINGLE_VM_HOST,
                guestos: SINGLE_VM_GUEST,
            },
            // Multi-VM slots: type4.1 runs 60 guests on one host.
            Vector {
                node_type: NodeType::GuestOS,
                slot: 1,
                address: "2602:ffe4:801:17:7801:1ff:feec:bd51",
                hostos: None,
                guestos: None,
            },
            Vector {
                node_type: NodeType::GuestOS,
                slot: 60,
                address: "2602:ffe4:801:17:7801:3cff:feec:bd51",
                hostos: None,
                guestos: None,
            },
            Vector {
                node_type: NodeType::GuestOS,
                slot: 255,
                address: "2602:ffe4:801:17:7801:ffff:feec:bd51",
                hostos: None,
                guestos: None,
            },
            Vector {
                node_type: NodeType::UpgradeGuestOS,
                slot: 1,
                address: "2602:ffe4:801:17:7802:1ff:feec:bd51",
                hostos: None,
                guestos: None,
            },
        ];

        let parse = |a: Option<&str>| a.map(|a| a.parse::<Ipv6Addr>().unwrap());

        for v in vectors {
            let expected: Ipv6Addr = v.address.parse().unwrap();
            let (node_type, slot) = (v.node_type, v.slot);
            assert_eq!(
                real_address(node_type, VmSlot::new(slot)),
                expected,
                "{node_type} slot {slot}: SLAAC address moved"
            );
            assert_eq!(
                resolve("hostos", expected),
                parse(v.hostos),
                "{node_type} slot {slot}: `hostos` resolution moved"
            );
            assert_eq!(
                resolve("guestos", expected),
                parse(v.guestos),
                "{node_type} slot {slot}: `guestos` resolution moved"
            );
        }
    }
}
