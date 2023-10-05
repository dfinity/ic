use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error};
use clap::{Args, Parser};
use ipnet::Ipv6Net;
use loopdev::{create_loop_device, detach_loop_device};
use sysmount::{mount, umount};
use tempfile::tempdir;
use tokio::fs;
use url::Url;

mod deployment;
use deployment::DeploymentJson;
mod loopdev;
mod sysmount;

const SERVICE_NAME: &str = "setupos-inject-configuration";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    image_path: PathBuf,

    #[command(flatten)]
    network: NetworkConfig,

    #[arg(long)]
    private_key_path: Option<PathBuf>,

    #[arg(long, value_delimiter = ',')]
    public_keys: Option<Vec<String>>,

    #[command(flatten)]
    deployment: DeploymentConfig,
}

#[derive(Args)]
struct NetworkConfig {
    #[arg(long)]
    ipv6_prefix: Option<Ipv6Net>,

    #[arg(long)]
    ipv6_gateway: Option<Ipv6Net>,

    #[arg(long)]
    mgmt_mac: Option<String>,
}

#[derive(Args)]
struct DeploymentConfig {
    #[arg(long)]
    nns_url: Option<Url>,

    #[arg(long, allow_hyphen_values = true)]
    nns_public_key: Option<String>,

    #[arg(long)]
    memory_gb: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Create a loop device
    let device_path = create_loop_device(&cli.image_path)
        .await
        .context("failed to create loop device")?;

    let config_partition_path = format!("{device_path}p3");

    // Mount config partition
    let target_dir = tempdir().context("failed to create temporary dir")?;

    mount(
        &config_partition_path,               // source
        &target_dir.path().to_string_lossy(), // target
    )
    .await
    .context("failed to mount partition")?;

    // Print previous config.ini
    println!("Previous config.ini:\n---");
    print_file_contents(&target_dir.path().join("config.ini"))
        .await
        .context("failed to print previous config")?;

    // Update config.ini
    write_config(&target_dir.path().join("config.ini"), &cli.network)
        .await
        .context("failed to write config file")?;

    // Update node-provider private-key
    if let Some(private_key_path) = cli.private_key_path {
        fs::copy(
            private_key_path,
            &target_dir.path().join("node_operator_private_key.pem"),
        )
        .await
        .context("failed to copy private-key")?;
    }

    // Print previous public keys
    println!("Previous ssh_authorized_keys/admin:\n---");
    print_file_contents(&target_dir.path().join("ssh_authorized_keys/admin"))
        .await
        .context("failed to print previous config")?;

    // Update SSH keys
    if let Some(ks) = cli.public_keys {
        write_public_keys(&target_dir.path().join("ssh_authorized_keys/admin"), ks)
            .await
            .context("failed to write public keys")?;
    }

    // Unmount partition
    umount(&target_dir.path().to_string_lossy())
        .await
        .context("failed to unmount partition")?;

    let data_partition_path = format!("{device_path}p4");

    // Mount data partition
    let target_dir = tempdir().context("failed to create temporary dir")?;

    mount(
        &data_partition_path,                 // source
        &target_dir.path().to_string_lossy(), // target
    )
    .await
    .context("failed to mount partition")?;

    // Print previous deployment.json
    println!("Previous deployment.json:\n---");
    print_file_contents(&target_dir.path().join("deployment.json"))
        .await
        .context("failed to print previous deployment config")?;

    // Update deployment.json
    update_deployment(&target_dir.path().join("deployment.json"), &cli.deployment)
        .await
        .context("failed to write deployment config file")?;

    // Update NNS key
    if let Some(public_key) = cli.deployment.nns_public_key {
        let mut f = File::create(target_dir.path().join("nns_public_key.pem"))
            .context("failed to create nns key file")?;
        write!(&mut f, "{public_key}")?;
    }

    // Unmount partition
    umount(&target_dir.path().to_string_lossy())
        .await
        .context("failed to unmount partition")?;

    // Detach loop device
    detach_loop_device(&device_path)
        .await
        .context("failed to detach loop device")?;

    Ok(())
}

async fn print_file_contents(path: &Path) -> Result<(), Error> {
    let s = fs::read_to_string(path).await;

    if let Ok(s) = s {
        println!("{s}");
    }

    Ok(())
}

async fn write_config(path: &Path, cfg: &NetworkConfig) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create config file")?;

    let NetworkConfig {
        ipv6_prefix,
        ipv6_gateway,
        mgmt_mac,
    } = cfg;

    if let (Some(ipv6_prefix), Some(ipv6_gateway)) = (ipv6_prefix, ipv6_gateway) {
        writeln!(
            &mut f,
            "ipv6_prefix={}",
            ipv6_prefix.addr().to_string().trim_end_matches("::")
        )?;

        writeln!(&mut f, "ipv6_subnet=/{}", ipv6_prefix.prefix_len())?;
        writeln!(&mut f, "ipv6_gateway={}", ipv6_gateway.addr())?;
    }

    if let Some(mgmt_mac) = mgmt_mac {
        writeln!(&mut f, "mgmt_mac={}", mgmt_mac)?;
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
        deployment_json.nns.url = nns_url.clone();
    }

    if let Some(memory) = cfg.memory_gb {
        deployment_json.resources.memory = memory;
    }

    let mut f = File::create(path).context("failed to open deployment config file")?;
    let output = serde_json::to_string_pretty(&deployment_json)?;
    write!(&mut f, "{output}")?;

    Ok(())
}
