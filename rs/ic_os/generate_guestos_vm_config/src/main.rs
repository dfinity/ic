use anyhow::{bail, Context, Result};
use askama::Template;
use bootstrap_config::{build_bootstrap_config_image, BootstrapOptions};
use clap::Parser;
use config::guestos_config::generate_guestos_config;
use config::{
    serialize_and_write_config, DEFAULT_HOSTOS_CONFIG_OBJECT_PATH,
    DEFAULT_HOSTOS_GUESTOS_CONFIG_OBJECT_PATH,
};
use config_types::{GuestOSConfig, HostOSConfig, Ipv6Config};
use deterministic_ips::node_type::NodeType;
use deterministic_ips::{calculate_deterministic_mac, IpVariant};
use ic_metrics_tool::{Metric, MetricsWriter};
use macaddr::MacAddr6;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Generate the GuestOS configuration
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Specify the config media image file
    #[arg(short, long, default_value = "/run/ic-node/config.img")]
    media: PathBuf,

    /// Specify the output configuration file
    #[arg(short, long, default_value = "/var/lib/libvirt/guestos.xml")]
    output: PathBuf,

    /// Path to the HostOS config file
    #[arg(short, long, default_value = DEFAULT_HOSTOS_CONFIG_OBJECT_PATH)]
    config: PathBuf,
}

/// Get the IPv6 gateway from the configuration
fn get_ipv6_gateway(config: &HostOSConfig) -> Result<String> {
    match &config.network_settings.ipv6_config {
        Ipv6Config::Deterministic(config) => Ok(config.gateway.to_string()),
        Ipv6Config::Fixed(config) => Ok(config.gateway.to_string()),
        Ipv6Config::RouterAdvertisement => {
            bail!("RouterAdvertisement IPv6 configuration does not have a gateway")
        }
    }
}

/// Assemble the configuration media
fn assemble_config_media(hostos_config: &HostOSConfig, media_path: &Path) -> Result<()> {
    let guestos_config = generate_guestos_config(hostos_config)?;
    serialize_and_write_config(
        Path::new(DEFAULT_HOSTOS_GUESTOS_CONFIG_OBJECT_PATH),
        &guestos_config,
    )?;
    println!("GuestOSConfig has been written to {DEFAULT_HOSTOS_GUESTOS_CONFIG_OBJECT_PATH}");

    let bootstrap_options = make_bootstrap_options(&hostos_config, guestos_config)?;

    build_bootstrap_config_image(media_path, &bootstrap_options)?;

    println!(
        "Assembling config media for GuestOS: {}",
        media_path.display()
    );

    Ok(())
}

fn make_bootstrap_options(
    hostos_config: &HostOSConfig,
    guestos_config: GuestOSConfig,
) -> Result<BootstrapOptions> {
    let mut bootstrap_options = BootstrapOptions {
        guestos_config: Some(PathBuf::from(DEFAULT_HOSTOS_GUESTOS_CONFIG_OBJECT_PATH)),
        ..Default::default()
    };

    // Set SSH authorized keys (only in dev builds)
    #[cfg(feature = "dev")]
    if hostos_config.icos_settings.use_ssh_authorized_keys {
        bootstrap_options.accounts_ssh_authorized_keys =
            Some(PathBuf::from("/boot/config/ssh_authorized_keys"));
    }

    if hostos_config.icos_settings.use_nns_public_key {
        bootstrap_options.nns_public_key = Some(PathBuf::from("/boot/config/nns_public_key.pem"));
    }

    if hostos_config.icos_settings.use_node_operator_private_key {
        bootstrap_options.node_operator_private_key =
            Some(PathBuf::from("/boot/config/node_operator_private_key.pem"));
    }

    let guestos_address = match guestos_config.network_settings.ipv6_config {
        Ipv6Config::Fixed(ip_config) => ip_config.address,
        _ => bail!(
            "Expected GuestOS IPv6 address to be fixed but was {:?}",
            guestos_config.network_settings.ipv6_config
        ),
    };
    bootstrap_options.ipv6_address = Some(guestos_address);
    bootstrap_options.ipv6_gateway = Some(get_ipv6_gateway(hostos_config)?);

    if let Some(ipv4_config) = &hostos_config.network_settings.ipv4_config {
        bootstrap_options.ipv4_address = Some(format!(
            "{}/{}",
            ipv4_config.address, ipv4_config.prefix_length
        ));
        bootstrap_options.ipv4_gateway = Some(ipv4_config.gateway.to_string());
    }

    if let Some(domain) = &hostos_config.network_settings.domain_name {
        bootstrap_options.domain = Some(domain.clone());
    }

    if let Some(node_reward_type) = &hostos_config.icos_settings.node_reward_type {
        bootstrap_options.node_reward_type = Some(node_reward_type.clone());
    }

    let hostname = format!(
        "guest-{}",
        hostos_config
            .icos_settings
            .mgmt_mac
            .to_string()
            .replace(":", "")
    );
    bootstrap_options.hostname = Some(hostname);

    bootstrap_options.nns_urls = hostos_config
        .icos_settings
        .nns_urls
        .iter()
        .map(|url| url.to_string())
        .collect();

    Ok(bootstrap_options)
}

fn generate_vm_config(config: &HostOSConfig, media_path: &Path) -> Result<String> {
    // If you get a compile error pointing at #[derive(Template)], there is likely a syntax error in
    // the template.
    #[derive(Template)]
    #[template(path = "guestos_vm_template.xml")]
    pub struct GuestOSTemplateProps<'a> {
        pub cpu_domain: &'a str,
        pub vm_memory: u32,
        pub nr_of_vcpus: u32,
        pub mac_address: MacAddr6,
        pub config_media: &'a str,
    }

    let mac_address = calculate_deterministic_mac(
        &config.icos_settings.mgmt_mac,
        config.icos_settings.deployment_environment,
        IpVariant::V6,
        NodeType::GuestOS,
    );

    let cpu_domain = if config.hostos_settings.vm_cpu == "qemu" {
        "qemu"
    } else {
        "kvm"
    };

    GuestOSTemplateProps {
        cpu_domain,
        vm_memory: config.hostos_settings.vm_memory,
        nr_of_vcpus: config.hostos_settings.vm_nr_of_vcpus,
        mac_address,
        config_media: &media_path.display().to_string(),
    }
    .render()
    .context("Failed to render GuestOS template")
}

fn main() -> Result<()> {
    let args = Args::parse();

    let metrics_writer = MetricsWriter::new(
        "/run/node_exporter/collector_textfile/hostos_generate_guestos_config.prom",
    );

    let hostos_config: HostOSConfig =
        serde_json::from_reader(File::open(&args.config).context("Failed to open config file")?)
            .context("Failed to parse config file")?;

    assemble_config_media(&hostos_config, &args.media)
        .context("Failed to assemble config media")?;

    if args.output.exists() {
        metrics_writer.write_metrics(&[Metric::with_annotation(
            "hostos_generate_guestos_config",
            0.0,
            "HostOS generate GuestOS config",
        )])?;

        bail!(
            "GuestOS configuration file already exists: {}",
            args.output.display()
        );
    }

    let output_path = &args.output;

    // Create parent directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    File::create(output_path)
        .context("Failed to create output file")?
        .write_all(generate_vm_config(&hostos_config, &args.media)?.as_bytes())
        .context("Failed to write output file")?;

    // Restore SELinux security context
    if let Some(parent) = output_path.parent() {
        if !Command::new("restorecon")
            .arg("-R")
            .arg(parent)
            .status()?
            .success()
        {
            bail!("Failed to run restorecon");
        }
    }

    println!(
        "Generating GuestOS configuration file: {}",
        output_path.display(),
    );

    metrics_writer.write_metrics(&[Metric::with_annotation(
        "hostos_generate_guestos_config",
        1.0,
        "HostOS generate GuestOS config",
    )])?;

    Ok(())
}
