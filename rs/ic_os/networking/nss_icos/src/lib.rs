extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;
use local_ip_address::{Error, list_afinet_netifas, local_ipv6};

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

struct ICOSHosts;
libnss_host_hooks!(icos, ICOSHosts);

// This function is invoked strictly once under lazy_static
// below.  This avoids having to re-query network interfaces
// on every host name resolution.  The disadvantage is that
// long-running programs will not be able to detect runtime
// changes of IPv6 addresses on the host.
//
// Why do we use an Arc<Error> for the error leg of the return?
// Because the Error we are returning does not implement the
// Copy trait, so we can't unpack it as-is — we must wrap it
// into an atomic reference-counted value so that we may then
// clone it for use.
fn get_local_ipv6() -> Result<Ipv6Addr, Arc<Error>> {
    // Preferred strategy: ask the kernel which source address it would use to
    // reach an off-link destination.  On a normally-configured HostOS/GuestOS
    // (which has a default IPv6 route) this yields the canonical outbound
    // address.
    if let Ok(IpAddr::V6(v6addr)) = local_ipv6() {
        return Ok(v6addr);
    }

    // Fallback for hosts without a default IPv6 route.  The route-based lookup
    // above fails with ENETUNREACH when no route to the probe destination
    // exists (e.g. the local system-test backend advertises an on-link SLAAC
    // prefix with a router lifetime of 0, so guests configure a global address
    // but install no default route).  In that case we enumerate the configured
    // interface addresses and pick the first global-scope unicast IPv6 address.
    let interfaces = list_afinet_netifas().map_err(Arc::new)?;
    first_global_unicast_ipv6(&interfaces).ok_or_else(|| Arc::new(Error::LocalIpAddressNotFound))
}

// Returns the first global-scope unicast IPv6 address from a list of
// `(interface_name, address)` pairs, or `None` if there is none.
fn first_global_unicast_ipv6(interfaces: &[(String, IpAddr)]) -> Option<Ipv6Addr> {
    interfaces.iter().find_map(|(_, addr)| match addr {
        IpAddr::V6(v6addr) if is_global_unicast_ipv6(*v6addr) => Some(*v6addr),
        _ => None,
    })
}

// Returns true if `addr` is a unicast address usable as the basis for deriving
// the HostOS/GuestOS addresses.  Loopback, unspecified, multicast and
// link-local (`fe80::/10`) addresses are rejected.  Unique-local addresses
// (`fd00::/8`) are deliberately accepted because the local system-test backend
// addresses guests out of the ULA range.
fn is_global_unicast_ipv6(addr: Ipv6Addr) -> bool {
    let is_link_local = (addr.segments()[0] & 0xffc0) == 0xfe80;
    !addr.is_loopback() && !addr.is_unspecified() && !addr.is_multicast() && !is_link_local
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

lazy_static! {
    static ref PUBLIC_IPV6: Result<Ipv6Addr, Arc<Error>> = get_local_ipv6();
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn is_global_unicast_ipv6_accepts_global_and_ula() {
        assert!(is_global_unicast_ipv6(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        ));
        // Unique-local (fd00::/8) is accepted: the local system-test backend
        // addresses guests out of this range.
        assert!(is_global_unicast_ipv6(
            "fd00:2201:1010::6801:abcd".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn is_global_unicast_ipv6_rejects_special_scopes() {
        // Loopback.
        assert!(!is_global_unicast_ipv6("::1".parse::<Ipv6Addr>().unwrap()));
        // Unspecified.
        assert!(!is_global_unicast_ipv6("::".parse::<Ipv6Addr>().unwrap()));
        // Link-local (fe80::/10).
        assert!(!is_global_unicast_ipv6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        ));
        // Upper edge of the fe80::/10 block is still link-local.
        assert!(!is_global_unicast_ipv6(
            "febf::1".parse::<Ipv6Addr>().unwrap()
        ));
        // Multicast.
        assert!(!is_global_unicast_ipv6(
            "ff02::1".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn first_global_unicast_ipv6_skips_loopback_and_link_local() {
        let interfaces = vec![
            ("lo".to_string(), v6("::1")),
            ("eth0".to_string(), v6("fe80::1")),
            ("eth0".to_string(), v6("fd00:2201:1010::6801:abcd")),
            ("eth0".to_string(), v6("2001:db8::2")),
        ];
        assert_eq!(
            first_global_unicast_ipv6(&interfaces),
            Some("fd00:2201:1010::6801:abcd".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn first_global_unicast_ipv6_ignores_ipv4() {
        let interfaces = vec![
            ("eth0".to_string(), "192.0.2.1".parse::<IpAddr>().unwrap()),
            ("eth0".to_string(), v6("2001:db8::5")),
        ];
        assert_eq!(
            first_global_unicast_ipv6(&interfaces),
            Some("2001:db8::5".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn first_global_unicast_ipv6_returns_none_without_usable_address() {
        let interfaces = vec![
            ("lo".to_string(), v6("::1")),
            ("eth0".to_string(), v6("fe80::1")),
        ];
        assert_eq!(first_global_unicast_ipv6(&interfaces), None);
    }

    #[test]
    fn ipv6_to_hostos_ipv6_sets_host_part() {
        let base = "fd00:2201:1010:0:5054:ffff:fe12:3456"
            .parse::<Ipv6Addr>()
            .unwrap();
        let hostos = ipv6_to_hostos_ipv6(base);
        let s = hostos.segments();
        assert_eq!(s[4], 0x6800);
        // All other segments are preserved.
        let b = base.segments();
        assert_eq!([s[0], s[1], s[2], s[3]], [b[0], b[1], b[2], b[3]]);
        assert_eq!([s[5], s[6], s[7]], [b[5], b[6], b[7]]);
    }

    #[test]
    fn ipv6_to_guestos_ipv6_sets_host_part() {
        let base = "fd00:2201:1010:0:5054:ffff:fe12:3456"
            .parse::<Ipv6Addr>()
            .unwrap();
        let guestos = ipv6_to_guestos_ipv6(base);
        let s = guestos.segments();
        assert_eq!(s[4], 0x6801);
        // All other segments are preserved.
        let b = base.segments();
        assert_eq!([s[0], s[1], s[2], s[3]], [b[0], b[1], b[2], b[3]]);
        assert_eq!([s[5], s[6], s[7]], [b[5], b[6], b[7]]);
    }
}
