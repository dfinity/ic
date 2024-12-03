use clap::{
    builder::{EnumValueParser, TypedValueParser},
    Parser, ValueEnum,
};
use deterministic_ips::{calculate_deterministic_mac, Deployment, HwAddr, IpVariant};
use std::net::Ipv6Addr;

/// Map `Deployment` from `DeploymentArg` to avoid a dependency on `clap` in
/// the lib.
#[derive(Copy, Clone, ValueEnum)]
enum DeploymentArg {
    Mainnet,
    Testnet,
}

impl From<DeploymentArg> for Deployment {
    fn from(item: DeploymentArg) -> Self {
        match item {
            DeploymentArg::Mainnet => Deployment::Mainnet,
            DeploymentArg::Testnet => Deployment::Testnet,
        }
    }
}

#[derive(Parser)]
/// A small tool to generate the deterministic IP addresses used by IC-OS.
struct Args {
    #[arg(long)]
    /// MAC address of the onboard IPMI.
    mac: HwAddr,
    #[arg(long)]
    /// IPv6 prefix for this DC.
    prefix: String,
    #[arg(long, default_value_t = Deployment::Mainnet)]
    #[arg(value_parser = EnumValueParser::new().map(|v: DeploymentArg| Deployment::from(v)))]
    /// Deployment type for this node.
    deployment: Deployment,
    #[arg(long)]
    /// Index to use for MAC generation. If not specified, display IPs for HostOS and GuestOS.
    index: Option<u8>,
}

fn calculate_ip(
    mac: HwAddr,
    prefix: &str,
    deployment: Deployment,
    index: u8,
) -> anyhow::Result<Ipv6Addr> {
    // For now, this tool only outputs IPv6
    let mac = calculate_deterministic_mac(mac, deployment, IpVariant::V6, index)?;
    let ip = mac.calculate_slaac(prefix)?;

    Ok(ip)
}

fn main() -> anyhow::Result<()> {
    let Args {
        mac,
        prefix,
        deployment,
        index,
    } = Args::parse();

    // When given, only calculate one index
    if let Some(index) = index {
        let ip = calculate_ip(mac, &prefix, deployment, index)?;

        println!("IP: {}", ip);
    } else {
        // Otherwise, calculate and display for Guest and Host
        let guest_ip = calculate_ip(mac, &prefix, deployment, 1)?;
        let host_ip = calculate_ip(mac, &prefix, deployment, 0)?;

        println!("GuestOS IP: {}", guest_ip);
        println!("HostOS IP:  {}", host_ip);
    }

    Ok(())
}
