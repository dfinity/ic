use clap::Parser;
use config_types::DeploymentEnvironment;
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{IpVariant, MacAddr6Ext, calculate_deterministic_mac};
use macaddr::MacAddr6;
use std::net::Ipv6Addr;

/// A small tool to generate the deterministic IP addresses used by IC-OS.
#[derive(Parser)]
struct Args {
    #[arg(long)]
    /// MAC address of the onboard IPMI.
    mac: MacAddr6,

    #[arg(long)]
    /// IPv6 prefix for this DC.
    prefix: String,

    #[arg(long, default_value_t = DeploymentEnvironment::Mainnet)]
    /// Deployment type for this node.
    deployment_environment: DeploymentEnvironment,

    #[arg(short, long)]
    /// Node type used for MAC generation. If not specified, display IPs for GuestOS and HostOS.
    node_type: Option<NodeType>,
}

fn calculate_ip(
    mac: MacAddr6,
    prefix: &str,
    deployment_environment: DeploymentEnvironment,
    node_type: NodeType,
) -> anyhow::Result<Ipv6Addr> {
    // For now, this tool only outputs IPv6
    let mac = calculate_deterministic_mac(&mac, deployment_environment, IpVariant::V6, node_type);
    let ip = mac.calculate_slaac(prefix)?;

    Ok(ip)
}

fn main() -> anyhow::Result<()> {
    let Args {
        mac,
        prefix,
        deployment_environment,
        node_type,
    } = Args::parse();

    // When given, only calculate one index
    if let Some(node_type) = node_type {
        let ip = calculate_ip(mac, &prefix, deployment_environment, node_type)?;

        println!("IP: {ip}");
    } else {
        // Otherwise, calculate and display for Guest and Host
        let guest_ip = calculate_ip(mac, &prefix, deployment_environment, NodeType::GuestOS)?;
        let host_ip = calculate_ip(mac, &prefix, deployment_environment, NodeType::HostOS)?;

        println!("GuestOS IP: {guest_ip}");
        println!("HostOS IP:  {host_ip}");
    }

    Ok(())
}
