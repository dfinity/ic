use std::fs::{create_dir_all, write};
use std::net::Ipv6Addr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::info::NetworkInfo;
use crate::interfaces::{get_interfaces, has_ipv6_connectivity, Interface};
use crate::mac_address::FormattedMacAddress;

pub static DEFAULT_SYSTEMD_NETWORK_DIR: &str = "/run/systemd/network";

pub const IPV6_NAME_SERVER_NETWORKD_CONTENTS: &str = r#"
DNS=2606:4700:4700::1111
DNS=2606:4700:4700::1001
DNS=2001:4860:4860::8888
DNS=2001:4860:4860::8844
"#;

fn generate_network_interface_content(interface_name: &str) -> String {
    format!(
        "
[Match]
Name={interface_name}

[Link]
RequiredForOnline=no
MTUBytes=1500

[Network]
LLDP=true
EmitLLDP=true
Bond=bond6
"
    )
}

// `mac_line` - Must be in format: "MACAddress=ff:ff:ff:ff:ff:ff". Potentially unnecessary.
fn generate_bond6_netdev_content(mac_line: &str) -> String {
    format!(
        "
[NetDev]
Name=bond6
Kind=bond
{mac_line}

[Bond]
Mode=active-backup
MIIMonitorSec=5
UpDelaySec=10
DownDelaySec=10"
    )
}

static BOND6_NETWORK_CONTENT: &str = "
[Match]
Name=bond6

[Network]
Bridge=br6";

static BRIDGE6_NETDEV_CONTENT: &str = "
[NetDev]
Name=br6
Kind=bridge

[Bridge]
ForwardDelaySec=0
STP=false";

fn generate_bridge6_network_content(
    ipv6_address: &str,
    ipv6_gateway: &str,
    nameserver_content: &str,
) -> String {
    format!(
        "
[Match]
Name=br6

[Network]
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=ipv6
Address={ipv6_address}
Gateway={ipv6_gateway}
{nameserver_content}
"
    )
}

pub fn restart_systemd_networkd() {
    let _ = Command::new("timeout")
        .args(["3", "systemctl", "restart", "systemd-networkd"])
        .status();
    // Explicitly don't care about return code status...
}

fn generate_and_write_systemd_files(
    output_directory: &Path,
    interface: &Interface,
    generated_mac: Option<&FormattedMacAddress>,
    ipv6_address: &str,
    ipv6_gateway: &str,
) -> Result<()> {
    eprintln!("Creating directory: {}", output_directory.to_string_lossy());
    create_dir_all(output_directory)?;

    let interface_filename = format!("20-{}.network", interface.name);
    let interface_path = output_directory.join(interface_filename);
    let interface_content = generate_network_interface_content(&interface.name);
    eprintln!("Writing {}", interface_path.to_string_lossy());
    write(interface_path, interface_content)?;

    let bond6_filename = "20-bond6.network";
    let bond6_path = output_directory.join(bond6_filename);
    eprintln!("Writing {}", bond6_path.to_string_lossy());
    write(bond6_path, BOND6_NETWORK_CONTENT)?;

    let bond6_netdev_filename = "20-bond6.netdev";
    let bond6_netdev_path = output_directory.join(bond6_netdev_filename);
    let mac_line = match generated_mac {
        Some(mac) => format!("MACAddress={}", mac.get()),
        None => String::new(),
    };
    let bond6_netdev_content = generate_bond6_netdev_content(&mac_line);
    eprintln!("Writing {}", bond6_netdev_path.to_string_lossy());
    write(bond6_netdev_path, bond6_netdev_content)?;

    let bridge6_netdev_filename = "20-br6.netdev";
    let bridge6_netdev_path = output_directory.join(bridge6_netdev_filename);
    eprintln!("Writing {}", bridge6_netdev_path.to_string_lossy());
    write(bridge6_netdev_path, BRIDGE6_NETDEV_CONTENT)?;

    let bridge6_filename = "20-br6.network";
    let bridge6_path = output_directory.join(bridge6_filename);

    let bridge6_content = generate_bridge6_network_content(
        ipv6_address,
        ipv6_gateway,
        IPV6_NAME_SERVER_NETWORKD_CONTENTS,
    );
    eprintln!("Writing {}", bridge6_path.to_string_lossy());
    write(bridge6_path, bridge6_content)?;

    Ok(())
}

pub fn generate_systemd_config_files(
    output_directory: &Path,
    network_info: &NetworkInfo,
    generated_mac: Option<&FormattedMacAddress>,
    ipv6_address: &Ipv6Addr,
) -> Result<()> {
    let mut interfaces = get_interfaces()?;
    interfaces.sort_by(|a, b| a.speed_mbps.cmp(&b.speed_mbps));
    eprintln!("Interfaces sorted by speed: {:?}", interfaces);

    let ping_target = network_info.ipv6_gateway.to_string();
    // old nodes are still configured with a local IPv4 interface connection
    // local IPv4 interfaces must be filtered out
    let ipv6_interfaces: Vec<&Interface> = interfaces
        .iter()
        .filter(|i| {
            match has_ipv6_connectivity(i, ipv6_address, network_info.ipv6_subnet, &ping_target) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Error testing connectivity on {}: {}", &i.name, e);
                    false
                }
            }
        })
        .collect();

    // For now only assign the fastest interface to ipv6.
    // TODO - probe to make sure the interfaces are on the same network before doing active-backup bonding.
    // TODO - Ensure ipv6 connectivity exists
    let fastest_interface = ipv6_interfaces
        .first()
        .context("Could not find any network interfaces")?;

    eprintln!("Using fastest interface: {:?}", fastest_interface);

    // Format the ip address to include the subnet length. See `man systemd.network`.
    let ipv6_address = format!("{}/{}", &ipv6_address.to_string(), network_info.ipv6_subnet);
    generate_and_write_systemd_files(
        output_directory,
        fastest_interface,
        generated_mac,
        &ipv6_address,
        &network_info.ipv6_gateway.to_string(),
    )?;

    print!("Restarting systemd networkd");
    restart_systemd_networkd();

    Ok(())
}
