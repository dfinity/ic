// `libnss_host_hooks!` expands to a `lazy_static!` invocation, so the macro must be in scope here.
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use config_types::{GuestOSConfig, HostOSConfig, ICOSSettings};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{DeploymentEnvironment, MacAddr6Ext, VmSlot, calculate_deterministic_mac};
use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;
use macaddr::MacAddr6;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

use std::fs::File;
use std::net::{IpAddr, Ipv6Addr};

struct ICOSHosts;
libnss_host_hooks!(icos, ICOSHosts);

const GUESTOS_CONFIG_PATH: &str = "/run/config/config.json";
const HOSTOS_CONFIG_PATH: &str = "/boot/config/config.json";

lazy_static! {
    static ref PUBLIC_IPV6: Option<Ipv6Addr> = local_ipv6_address();
    static ref HOSTOS_IPV6: Option<Ipv6Addr> = compute_hostos_address();
}

fn local_ipv6_address() -> Option<Ipv6Addr> {
    let ifaddrs = getifaddrs().ok()?;
    ifaddrs
        .filter(|ifaddr| !ifaddr.flags.contains(InterfaceFlags::IFF_LOOPBACK))
        .filter_map(|ifaddr| ifaddr.address?.as_sockaddr_in6().map(|v6| v6.ip()))
        .find(|addr| !addr.is_loopback() && !addr.is_unicast_link_local())
}

fn read_icos_settings() -> Option<(MacAddr6, DeploymentEnvironment)> {
    let (mgmt_mac, deployment_environment) = [GUESTOS_CONFIG_PATH, HOSTOS_CONFIG_PATH]
        .into_iter()
        .find_map(|path| {
            File::open(path).ok().and_then(|file| {
                serde_json::from_reader::<_, GuestOSConfig>(&file)
                    .ok()
                    .map(|config| {
                        let GuestOSConfig {
                            icos_settings:
                                ICOSSettings {
                                    mgmt_mac,
                                    deployment_environment,
                                    ..
                                },
                            ..
                        } = config;

                        (mgmt_mac, deployment_environment)
                    })
                    .or_else(|| {
                        serde_json::from_reader::<_, HostOSConfig>(&file)
                            .ok()
                            .map(|config| {
                                let HostOSConfig {
                                    icos_settings:
                                        ICOSSettings {
                                            mgmt_mac,
                                            deployment_environment,
                                            ..
                                        },
                                    ..
                                } = config;

                                (mgmt_mac, deployment_environment)
                            })
                    })
            })
        })?;

    Some((mgmt_mac, deployment_environment))
}

fn ipv6_prefix_of(addr: Ipv6Addr) -> String {
    let s = addr.segments();
    format!("{:x}:{:x}:{:x}:{:x}::", s[0], s[1], s[2], s[3])
}

fn compute_hostos_address() -> Option<Ipv6Addr> {
    let prefix = ipv6_prefix_of((*PUBLIC_IPV6)?);
    let (mgmt_mac, deployment_environment) = read_icos_settings()?;

    calculate_deterministic_mac(
        &mgmt_mac,
        deployment_environment,
        NodeType::HostOS,
        VmSlot::Plain,
    )
    .calculate_slaac(&prefix)
    .ok()
}

fn ipv6_to_guestos_ipv6(addr: Ipv6Addr) -> Ipv6Addr {
    let s = addr.segments();
    Ipv6Addr::new(s[0], s[1], s[2], s[3], 0x6801, s[5], s[6], s[7])
}

fn guestos_address() -> Option<Ipv6Addr> {
    Some(ipv6_to_guestos_ipv6((*PUBLIC_IPV6)?))
}

fn host_entry(name: &str, address: Ipv6Addr) -> Host {
    Host {
        name: name.to_string(),
        addresses: Addresses::V6(vec![address]),
        aliases: vec![],
    }
}

impl HostHooks for ICOSHosts {
    fn get_all_entries() -> Response<Vec<Host>> {
        let entries = [("hostos", *HOSTOS_IPV6), ("guestos", guestos_address())]
            .into_iter()
            .filter_map(|(name, address)| address.map(|address| host_entry(name, address)))
            .collect();

        Response::Success(entries)
    }

    fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
        let IpAddr::V6(addr) = addr else {
            return Response::NotFound;
        };

        if Some(addr) == *HOSTOS_IPV6 {
            Response::Success(host_entry("hostos", addr))
        } else if Some(addr) == guestos_address() {
            Response::Success(host_entry("guestos", addr))
        } else {
            Response::NotFound
        }
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {
        match family {
            AddressFamily::IPv6 => {
                let address = match name {
                    "hostos" => *HOSTOS_IPV6,
                    "guestos" => guestos_address(),
                    _ => return Response::NotFound,
                };
                match address {
                    Some(address) => Response::Success(host_entry(name, address)),
                    None => Response::NotFound,
                }
            }
            _ => Response::NotFound,
        }
    }
}
