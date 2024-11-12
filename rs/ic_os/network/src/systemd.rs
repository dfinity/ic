use std::fs::{create_dir_all, write};
use std::net::Ipv6Addr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::info::NetworkInfo;
use crate::interfaces::{get_interfaces, has_ipv6_connectivity, Interface};

pub static DEFAULT_SYSTEMD_NETWORK_DIR: &str = "/run/systemd/network";

pub const IPV6_NAME_SERVER_NETWORKD_CONTENTS: &str = r#"
DNS=2606:4700:4700::1111
DNS=2606:4700:4700::1001
DNS=2001:4860:4860::8888
DNS=2001:4860:4860::8844
"#;

fn generate_network_interface_content(
    interface_name: &str,
    ipv6_address: &str,
    ipv6_gateway: &str,
    nameserver_content: &str,
) -> String {
    format!(
        "
[Match]
Name={interface_name}

[Network]
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=ipv6
Address={ipv6_address}
Gateway={ipv6_gateway}
{nameserver_content}
LLDP=true
EmitLLDP=true

[Link]
RequiredForOnline=no
MTUBytes=1500
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
    ipv6_address: &str,
    ipv6_gateway: &str,
) -> Result<()> {
    eprintln!("Creating directory: {}", output_directory.to_string_lossy());
    create_dir_all(output_directory)?;

    let interface_filename = format!("20-{}.network", interface.name);
    let interface_path = output_directory.join(interface_filename);

    let interface_content = generate_network_interface_content(
        &interface.name,
        ipv6_address,
        ipv6_gateway,
        IPV6_NAME_SERVER_NETWORKD_CONTENTS,
    );
    eprintln!("Writing {}", interface_path.to_string_lossy());
    write(interface_path, interface_content)?;

    Ok(())
}

pub fn generate_systemd_config_files(
    output_directory: &Path,
    network_info: &NetworkInfo,
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
        &ipv6_address,
        &network_info.ipv6_gateway.to_string(),
    )?;

    print!("Restarting systemd networkd");
    restart_systemd_networkd();

    Ok(())
}
