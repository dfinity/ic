use std::cmp::Reverse;
use std::fs::{create_dir_all, write};
use std::net::Ipv6Addr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::interfaces::{Interface, get_interfaces, has_ipv6_connectivity};
use config_types::DeterministicIpv6Config;
use macaddr::MacAddr6;

pub static DEFAULT_SYSTEMD_NETWORK_DIR: &str = "/run/systemd/network";

pub const IPV6_NAME_SERVER_NETWORKD_CONTENTS: &str = r#"
DNS=2606:4700:4700::1111
DNS=2606:4700:4700::1001
DNS=2001:4860:4860::8888
DNS=2001:4860:4860::8844
"#;

fn generate_network_interface_content(interface_name: &str, mac_line: &str) -> String {
    format!(
        "
[Match]
Name={interface_name}

[Link]
RequiredForOnline=no
MTUBytes=1500
{mac_line}

[Network]
LLDP=true
EmitLLDP=true
Bridge=br6
"
    )
}

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

pub fn generate_systemd_config_files(
    output_directory: &Path,
    ipv6_config: &DeterministicIpv6Config,
    generated_mac: Option<&MacAddr6>,
    ipv6_address: &Ipv6Addr,
) -> Result<()> {
    let mut interfaces = get_interfaces()?;
    interfaces.sort_by_key(|v| Reverse(v.speed_mbps));
    eprintln!("Interfaces sorted decending by speed: {interfaces:?}");

    let ping_target = ipv6_config.gateway.to_string();

    let fastest_interface = interfaces
        .iter()
        .find(|i| {
            match has_ipv6_connectivity(i, ipv6_address, ipv6_config.prefix_length, &ping_target) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("Error testing connectivity on {}: {}", &i.name, e);
                    false
                }
            }
        })
        .context("Could not find any network interfaces")?;

    eprintln!("Using fastest interface: {fastest_interface:?}");

    // Format the IP address to include the subnet length. See `man systemd.network`.
    let ipv6_address = format!(
        "{}/{}",
        &ipv6_address.to_string(),
        ipv6_config.prefix_length
    );
    generate_and_write_systemd_files(
        output_directory,
        fastest_interface,
        generated_mac,
        &ipv6_address,
        &ipv6_config.gateway.to_string(),
    )?;

    println!("Restarting systemd networkd");
    restart_systemd_networkd();

    Ok(())
}

fn generate_and_write_systemd_files(
    output_directory: &Path,
    interface: &Interface,
    generated_mac: Option<&MacAddr6>,
    ipv6_address: &str,
    ipv6_gateway: &str,
) -> Result<()> {
    eprintln!("Creating directory: {}", output_directory.to_string_lossy());
    create_dir_all(output_directory)?;

    let mac_line = match generated_mac {
        Some(mac) => format!("MACAddress={mac}"),
        None => String::new(),
    };

    let interface_filename = format!("20-{}.network", interface.name);
    let interface_path = output_directory.join(interface_filename);
    let interface_content = generate_network_interface_content(&interface.name, &mac_line);
    eprintln!("Writing {}", interface_path.to_string_lossy());
    write(interface_path, interface_content)?;

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
