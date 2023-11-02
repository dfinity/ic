use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error};
use clap::Parser;
use ipnet::Ipv6Net;
use loopdev::{create_loop_device, detach_loop_device};
use sysmount::{mount, umount};
use tempfile::tempdir;
use tokio::fs;

mod loopdev;
mod sysmount;

const SERVICE_NAME: &str = "setupos-inject-configuration";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    image_path: PathBuf,

    #[arg(long)]
    ipv6_prefix: Ipv6Net,

    #[arg(long)]
    ipv6_gateway: Ipv6Net,

    #[arg(long)]
    private_key_path: Option<PathBuf>,

    #[arg(long, value_delimiter = ',')]
    public_keys: Option<Vec<String>>,
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
    write_config(
        &target_dir.path().join("config.ini"),
        &Config {
            ipv6_prefix: cli.ipv6_prefix,
            ipv6_gateway: cli.ipv6_gateway,
        },
    )
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

    // Detach loop device
    detach_loop_device(&device_path)
        .await
        .context("failed to detach loop device")?;

    Ok(())
}

struct Config {
    ipv6_prefix: Ipv6Net,
    ipv6_gateway: Ipv6Net,
}

async fn print_file_contents(path: &Path) -> Result<(), Error> {
    let s = fs::read_to_string(path).await;

    if let Ok(s) = s {
        println!("{s}");
    }

    Ok(())
}

async fn write_config(path: &Path, cfg: &Config) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create config file")?;

    writeln!(
        &mut f,
        "ipv6_prefix={}",
        cfg.ipv6_prefix.addr().to_string().trim_end_matches("::")
    )?;

    writeln!(&mut f, "ipv6_subnet=/{}", cfg.ipv6_prefix.prefix_len())?;
    writeln!(&mut f, "ipv6_gateway={}", cfg.ipv6_gateway.addr())?;

    Ok(())
}

async fn write_public_keys(path: &Path, ks: Vec<String>) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create public keys file")?;

    for k in ks {
        writeln!(&mut f, "{k}",)?;
    }

    Ok(())
}
