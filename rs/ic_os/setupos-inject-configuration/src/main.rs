use std::os::unix::fs::PermissionsExt;
use std::{
    assert,
    fs::{self, File, Permissions},
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Error};
use clap::{Args, Parser};
use tempfile::NamedTempFile;
use url::Url;

use partition_tools::{ext::ExtPartition, fat::FatPartition, Partition};
use utils::deployment::DeploymentJson;

const SERVICE_NAME: &str = "setupos-inject-configuration";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    image_path: PathBuf,

    #[command(flatten)]
    config_ini: ConfigIni,

    #[arg(long)]
    private_key_path: Option<PathBuf>,

    #[arg(long, value_delimiter = ',')]
    public_keys: Option<Vec<String>>,

    #[command(flatten)]
    deployment: DeploymentConfig,
}

#[derive(Args)]
struct ConfigIni {
    #[arg(long)]
    ipv6_prefix: Option<String>,

    #[arg(long)]
    ipv6_gateway: Option<Ipv6Addr>,

    #[arg(long)]
    ipv4_address: Option<Ipv4Addr>,

    #[arg(long)]
    ipv4_gateway: Option<Ipv4Addr>,

    #[arg(long)]
    ipv4_prefix_length: Option<u8>,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long)]
    verbose: Option<String>,
}

#[derive(Args)]
struct DeploymentConfig {
    #[arg(long)]
    nns_url: Option<Url>,

    #[arg(long, allow_hyphen_values = true)]
    nns_public_key: Option<String>,

    #[arg(long)]
    memory_gb: Option<u32>,

    /// Can be "kvm" or "qemu". If None, is treated as "kvm".
    #[arg(long)]
    cpu: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Open config partition
    let mut config = FatPartition::open(cli.image_path.clone(), Some(3)).await?;

    // Print previous config.ini
    println!("Previous config.ini:\n---");
    let previous_config = config
        .read_file(Path::new("/config.ini"))
        .await
        .context("failed to print previous config")?;
    println!("{previous_config}");

    // Update config.ini
    let config_ini = NamedTempFile::new()?;
    write_config(config_ini.path(), &cli.config_ini)
        .await
        .context("failed to write config file")?;
    config
        .write_file(config_ini.path(), Path::new("/config.ini"))
        .await
        .context("failed to copy config file")?;

    // Update node-provider private-key
    if let Some(private_key_path) = cli.private_key_path {
        config
            .write_file(
                &private_key_path,
                Path::new("/node_operator_private_key.pem"),
            )
            .await
            .context("failed to copy private-key")?;
    }

    // Print previous public keys
    println!("Previous ssh_authorized_keys/admin:\n---");
    let previous_admin_keys = config
        .read_file(Path::new("ssh_authorized_keys/admin"))
        .await
        .context("failed to print previous config")?;
    println!("{previous_admin_keys}");

    // Update SSH keys
    if let Some(ks) = cli.public_keys {
        let public_keys = NamedTempFile::new()?;
        write_public_keys(public_keys.path(), ks)
            .await
            .context("failed to write public keys")?;

        config
            .write_file(public_keys.path(), Path::new("/ssh_authorized_keys/admin"))
            .await
            .context("failed to copy public keys")?;
    }

    // Close config partition
    config.close().await?;

    // Open data partition
    let mut data = ExtPartition::open(cli.image_path.clone(), Some(4)).await?;

    // Print previous deployment.json
    println!("Previous deployment.json:\n---");
    let previous_deployment = data
        .read_file(Path::new("/deployment.json"))
        .await
        .context("failed to print previous deployment config")?;
    println!("{previous_deployment}");

    // Update deployment.json
    let mut deployment_json = NamedTempFile::new()?;
    deployment_json.write_all(previous_deployment.as_bytes())?;
    fs::set_permissions(deployment_json.path(), Permissions::from_mode(0o644))?;
    update_deployment(deployment_json.path(), &cli.deployment)
        .await
        .context("failed to write deployment config file")?;
    data.write_file(deployment_json.path(), Path::new("/deployment.json"))
        .await
        .context("failed to copy deployment config file")?;

    // Update NNS key
    if let Some(public_key) = cli.deployment.nns_public_key {
        let mut nns_key = NamedTempFile::new()?;
        write!(&mut nns_key, "{public_key}")?;
        fs::set_permissions(nns_key.path(), Permissions::from_mode(0o644))?;

        data.write_file(nns_key.path(), Path::new("/nns_public_key.pem"))
            .await
            .context("failed to copy nns key file")?;
    }

    // Close data partition
    data.close().await?;

    Ok(())
}

async fn write_config(path: &Path, cfg: &ConfigIni) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create config file")?;

    let ConfigIni {
        ipv6_prefix,
        ipv6_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        domain,
        verbose,
    } = cfg;

    if let (Some(ipv6_prefix), Some(ipv6_gateway)) = (ipv6_prefix, ipv6_gateway) {
        // Always write 4 segments, even if our prefix is less.
        assert!(format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok());
        writeln!(&mut f, "ipv6_prefix={}", ipv6_prefix)?;
        writeln!(&mut f, "ipv6_gateway={}", ipv6_gateway)?;
    }

    if let (Some(ipv4_address), Some(ipv4_gateway), Some(ipv4_prefix_length), Some(domain)) =
        (ipv4_address, ipv4_gateway, ipv4_prefix_length, domain)
    {
        writeln!(&mut f, "ipv4_address={}", ipv4_address)?;
        writeln!(&mut f, "ipv4_gateway={}", ipv4_gateway)?;
        writeln!(&mut f, "ipv4_prefix_length={}", ipv4_prefix_length)?;
        writeln!(&mut f, "domain={}", domain)?;
    }

    if let Some(verbose) = verbose {
        writeln!(&mut f, "verbose={}", verbose)?;
    }

    Ok(())
}

async fn write_public_keys(path: &Path, ks: Vec<String>) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create public keys file")?;

    for k in ks {
        writeln!(&mut f, "{k}")?;
    }

    Ok(())
}

async fn update_deployment(path: &Path, cfg: &DeploymentConfig) -> Result<(), Error> {
    let mut deployment_json = {
        let f = File::open(path).context("failed to open deployment config file")?;
        let deployment_json: DeploymentJson = serde_json::from_reader(f)?;

        deployment_json
    };

    if let Some(nns_url) = &cfg.nns_url {
        deployment_json.nns.url = vec![nns_url.clone()];
    }

    if let Some(memory) = cfg.memory_gb {
        deployment_json.resources.memory = memory;
    }

    if let Some(cpu) = &cfg.cpu {
        deployment_json.resources.cpu = Some(cpu.to_owned());
    }

    let mut f = File::create(path).context("failed to open deployment config file")?;
    let output = serde_json::to_string_pretty(&deployment_json)?;
    write!(&mut f, "{output}")?;

    Ok(())
}
