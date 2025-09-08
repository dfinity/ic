extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;
use local_ip_address::{Error, local_ipv6};

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
    match local_ipv6() {
        Ok(addr) => match addr {
            IpAddr::V6(v6addr) => Ok(v6addr),
            _ => Err(Arc::new(Error::LocalIpAddressNotFound)),
        },
        Err(e) => Err(Arc::new(e)),
    }
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
