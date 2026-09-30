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

static PUBLIC_IPV6: LazyLock<Result<Ipv6Addr, LocalIpError>> = LazyLock::new(get_local_ipv6);

impl HostHooks for ICOSHosts {
    fn get_all_entries() -> Response<Vec<Host>> {
        match PUBLIC_IPV6.clone() {
            Ok(local_ipv6) => Response::Success(vec![
                Host {
                    name: "hostos".to_string(),
                    addresses: Addresses::V6(vec![ipv6_to_hostos_ipv6(local_ipv6)]),
                    aliases: vec![],
                },
                Host {
                    name: "guestos".to_string(),
                    addresses: Addresses::V6(vec![ipv6_to_guestos_ipv6(local_ipv6)]),
                    aliases: vec![],
                },
            ]),
            Err(_) => Response::Success(vec![]),
        }
    }

    fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
        match addr {
            IpAddr::V6(addr) => match PUBLIC_IPV6.clone() {
                Ok(local_ipv6) => {
                    if addr == ipv6_to_guestos_ipv6(local_ipv6) {
                        Response::Success(Host {
                            name: "guestos".to_string(),
                            addresses: Addresses::V6(vec![addr]),
                            aliases: vec![],
                        })
                    } else if addr == ipv6_to_hostos_ipv6(local_ipv6) {
                        Response::Success(Host {
                            name: "hostos".to_string(),
                            addresses: Addresses::V6(vec![addr]),
                            aliases: vec![],
                        })
                    } else {
                        Response::NotFound
                    }
                }
                _ => Response::NotFound,
            },
            _ => Response::NotFound,
        }
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {
        match family {
            AddressFamily::IPv6 => match name {
                "guestos" => match PUBLIC_IPV6.clone() {
                    Ok(local_ipv6) => Response::Success(Host {
                        name: name.to_string(),
                        addresses: Addresses::V6(vec![ipv6_to_guestos_ipv6(local_ipv6)]),
                        aliases: vec![],
                    }),
                    Err(_) => Response::NotFound,
                },
                "hostos" => match PUBLIC_IPV6.clone() {
                    Ok(local_ipv6) => Response::Success(Host {
                        name: name.to_string(),
                        addresses: Addresses::V6(vec![ipv6_to_hostos_ipv6(local_ipv6)]),
                        aliases: vec![],
                    }),
                    Err(_) => Response::NotFound,
                },
                _ => Response::NotFound,
            },
            _ => Response::NotFound,
        }
    }
}
