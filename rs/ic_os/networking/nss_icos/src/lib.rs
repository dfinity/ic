extern crate libc;
// Required by the libnss_host_hooks! macro, which expands to a lazy_static!.
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;
use local_ip_address::local_ipv6;

use std::net::{IpAddr, Ipv6Addr};
use std::sync::OnceLock;

struct ICOSHosts;
libnss_host_hooks!(icos, ICOSHosts);

static PUBLIC_IPV6: OnceLock<Ipv6Addr> = OnceLock::new();

// Only successful lookups are memoized. This avoids having to re-query
// network interfaces on every host name resolution, while never poisoning the
// process for the rest of its lifetime. A program that resolves a name before
// the machine has a global IPv6 address, for instance a service that starts
// before the first router advertisement arrives, would otherwise fail to
// resolve it for the rest of its lifetime.
fn memoize(
    cache: &OnceLock<Ipv6Addr>,
    query: impl FnOnce() -> Option<Ipv6Addr>,
) -> Option<Ipv6Addr> {
    if let Some(addr) = cache.get() {
        return Some(*addr);
    }
    let addr = query()?;
    Some(*cache.get_or_init(|| addr))
}

fn get_local_ipv6() -> Option<Ipv6Addr> {
    memoize(&PUBLIC_IPV6, || match local_ipv6() {
        Ok(IpAddr::V6(v6addr)) => Some(v6addr),
        _ => None,
    })
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

impl HostHooks for ICOSHosts {
    fn get_all_entries() -> Response<Vec<Host>> {
        match get_local_ipv6() {
            Some(local_ipv6) => Response::Success(vec![
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
            None => Response::Success(vec![]),
        }
    }

    fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
        match addr {
            IpAddr::V6(addr) => match get_local_ipv6() {
                Some(local_ipv6) => {
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
                "guestos" => match get_local_ipv6() {
                    Some(local_ipv6) => Response::Success(Host {
                        name: name.to_string(),
                        addresses: Addresses::V6(vec![ipv6_to_guestos_ipv6(local_ipv6)]),
                        aliases: vec![],
                    }),
                    None => Response::NotFound,
                },
                "hostos" => match get_local_ipv6() {
                    Some(local_ipv6) => Response::Success(Host {
                        name: name.to_string(),
                        addresses: Addresses::V6(vec![ipv6_to_hostos_ipv6(local_ipv6)]),
                        aliases: vec![],
                    }),
                    None => Response::NotFound,
                },
                _ => Response::NotFound,
            },
            _ => Response::NotFound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 0x6802, 3, 4, 5);
    const HOSTOS: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 0x6800, 3, 4, 5);
    const GUESTOS: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 0x6801, 3, 4, 5);

    #[test]
    fn derives_the_peer_addresses() {
        assert_eq!(ipv6_to_hostos_ipv6(LOCAL), HOSTOS);
        assert_eq!(ipv6_to_guestos_ipv6(LOCAL), GUESTOS);
        // The derivation overwrites the word it keys on, so it also works
        // starting from either peer's address.
        assert_eq!(ipv6_to_hostos_ipv6(GUESTOS), HOSTOS);
        assert_eq!(ipv6_to_guestos_ipv6(HOSTOS), GUESTOS);
    }

    // A lookup that fails because the machine has no global IPv6 address yet
    // must not poison the lookups that follow it.
    #[test]
    fn only_successful_lookups_are_memoized() {
        let cache = OnceLock::new();
        assert_eq!(memoize(&cache, || None), None);
        assert_eq!(memoize(&cache, || Some(LOCAL)), Some(LOCAL));
        assert_eq!(memoize(&cache, || None), Some(LOCAL));
    }
}
