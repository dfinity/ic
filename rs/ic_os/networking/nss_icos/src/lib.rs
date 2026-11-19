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

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU8;
use std::sync::LazyLock;

struct ICOSHosts;
libnss_host_hooks!(icos, ICOSHosts);

const GUESTOS_CONFIG_PATH: &str = "/run/config/config.json";
const HOSTOS_CONFIG_PATH: &str = "/boot/config/config.json";

static PUBLIC_IPV6: LazyLock<Option<Ipv6Addr>> = LazyLock::new(get_local_ipv6_address);
static ICOS_CONFIG: LazyLock<Option<Config>> = LazyLock::new(read_icos_config);

struct Config {
    mgmt_mac: MacAddr6,
    deployment_environment: DeploymentEnvironment,
    multi_vm: bool,
}

fn get_local_ipv6_address() -> Option<Ipv6Addr> {
    getifaddrs()
        .ok()?
        .filter(|ifaddr| !ifaddr.flags.contains(InterfaceFlags::IFF_LOOPBACK))
        .filter_map(|ifaddr| ifaddr.address?.as_sockaddr_in6().map(|v6| v6.ip()))
        .find(|addr| !addr.is_loopback() && !addr.is_unicast_link_local())
}

fn compute_hostos_address() -> Option<Ipv6Addr> {
    let prefix = ipv6_prefix((*PUBLIC_IPV6)?);
    let &Config {
        ref mgmt_mac,
        deployment_environment,
        ..
    } = ICOS_CONFIG.as_ref()?;

    calculate_deterministic_mac(
        mgmt_mac,
        deployment_environment,
        NodeType::HostOS,
        VmSlot::Plain,
    )
    .calculate_slaac(&prefix)
    .ok()
}

fn compute_guestos_address() -> Option<Ipv6Addr> {
    let prefix = ipv6_prefix((*PUBLIC_IPV6)?);
    let &Config {
        ref mgmt_mac,
        deployment_environment,
        multi_vm,
    } = ICOS_CONFIG.as_ref()?;

    if multi_vm {
        // TODO: For now we always choose the first VM in multi-VM hosts.
        calculate_deterministic_mac(
            mgmt_mac,
            deployment_environment,
            NodeType::GuestOS,
            VmSlot::Multi(NonZeroU8::new(1).unwrap()),
        )
        .calculate_slaac(&prefix)
        .ok()
    } else {
        calculate_deterministic_mac(
            mgmt_mac,
            deployment_environment,
            NodeType::GuestOS,
            VmSlot::Plain,
        )
        .calculate_slaac(&prefix)
        .ok()
    }
}

fn ipv6_prefix(addr: Ipv6Addr) -> String {
    let s = addr.segments();
    format!("{:x}:{:x}:{:x}:{:x}::", s[0], s[1], s[2], s[3])
}

fn read_icos_config() -> Option<Config> {
    // Only one of these will ever exist at a time.
    if let Ok(contents) = std::fs::read_to_string(GUESTOS_CONFIG_PATH) {
        let GuestOSConfig {
            icos_settings:
                ICOSSettings {
                    node_reward_type,
                    mgmt_mac,
                    deployment_environment,
                    ..
                },
            ..
        } = serde_json::from_str::<GuestOSConfig>(&contents).ok()?;

        return Some(Config {
            mgmt_mac,
            deployment_environment,
            multi_vm: node_reward_type.is_some_and(|v| v.starts_with("type4")),
        });
    }

    if let Ok(contents) = std::fs::read_to_string(HOSTOS_CONFIG_PATH) {
        let HostOSConfig {
            icos_settings:
                ICOSSettings {
                    node_reward_type,
                    mgmt_mac,
                    deployment_environment,
                    ..
                },
            ..
        } = serde_json::from_str::<HostOSConfig>(&contents).ok()?;

        return Some(Config {
            mgmt_mac,
            deployment_environment,
            multi_vm: node_reward_type.is_some_and(|v| v.starts_with("type4")),
        });
    }

    None
}

fn make_host_entry(name: &str, address: Ipv6Addr) -> Host {
    Host {
        name: name.to_string(),
        addresses: Addresses::V6(vec![address]),
        aliases: vec![],
    }
}

impl HostHooks for ICOSHosts {
    fn get_all_entries() -> Response<Vec<Host>> {
        let entries = [
            ("hostos", compute_hostos_address()),
            ("guestos", compute_guestos_address()),
        ]
        .into_iter()
        .filter_map(|(name, address)| address.map(|address| make_host_entry(name, address)))
        .collect();

        Response::Success(entries)
    }

    fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
        let IpAddr::V6(addr) = addr else {
            return Response::NotFound;
        };

        if Some(addr) == compute_hostos_address() {
            Response::Success(make_host_entry("hostos", addr))
        } else if Some(addr) == compute_guestos_address() {
            Response::Success(make_host_entry("guestos", addr))
        } else {
            Response::NotFound
        }
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {
        match family {
            AddressFamily::IPv6 => {
                let address = match name {
                    "hostos" => compute_hostos_address(),
                    "guestos" => compute_guestos_address(),
                    _ => return Response::NotFound,
                };
                match address {
                    Some(address) => Response::Success(make_host_entry(name, address)),
                    None => Response::NotFound,
                }
            }
            _ => Response::NotFound,
        }
    }
}
