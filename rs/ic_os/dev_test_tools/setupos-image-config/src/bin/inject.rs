use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{self, Permissions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error};
use clap::Parser;
use tempfile::NamedTempFile;

use partition_tools::{ext::ExtPartition, fat::FatPartition, Partition};
use setupos_image_config::{
    update_deployment, write_config, write_public_keys, ConfigIni, DeploymentConfig,
};

#[derive(Parser)]
#[command(name = "setupos-inject-config")]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    image_path: PathBuf,

    #[command(flatten)]
    config_ini: ConfigIni,

    #[arg(long)]
    node_operator_private_key: Option<PathBuf>,

    #[arg(long, value_delimiter = ',')]
    public_keys: Option<Vec<String>>,

    #[command(flatten)]
    deployment: DeploymentConfig,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Open config partition
    let mut config = FatPartition::open(cli.image_path.clone(), Some(3)).await?;

    // Print previous config.ini
    println!("Previous config.ini:\n---");
    let previous_config = String::from_utf8(
        config
            .read_file(Path::new("/config.ini"))
            .await
            .context("failed to print previous config")?,
    )?;
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

    // Print updated config.ini
    println!("Updated config.ini:\n---");
    let updated_config = String::from_utf8(
        config
            .read_file(Path::new("/config.ini"))
            .await
            .context("failed to read updated config")?,
    )?;
    println!("{updated_config}");

    // Update node_operator_private_key.pem
    if let Some(key_path) = cli.node_operator_private_key {
        config
            .write_file(&key_path, Path::new("/node_operator_private_key.pem"))
            .await
            .context("failed to write node_operator_private_key.pem")?;

        // Print updated node_operator_private_key.pem
        println!("Updated node_operator_private_key.pem:\n---");
        let updated_key = String::from_utf8(
            config
                .read_file(Path::new("/node_operator_private_key.pem"))
                .await
                .context("failed to read updated node operator private key")?,
        )?;
        println!("{updated_key}");
    }

    // Print previous public keys
    println!("Previous ssh_authorized_keys/admin:\n---");
    let previous_admin_keys = String::from_utf8(
        config
            .read_file(Path::new("ssh_authorized_keys/admin"))
            .await
            .context("failed to print previous config")?,
    )?;
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

        // Print updated SSH keys
        println!("Updated ssh_authorized_keys/admin:\n---");
        let updated_admin_keys = String::from_utf8(
            config
                .read_file(Path::new("/ssh_authorized_keys/admin"))
                .await
                .context("failed to read updated admin keys")?,
        )?;
        println!("{updated_admin_keys}");
    }

    // Close config partition
    config.close().await?;

    // Open data partition
    let mut data = ExtPartition::open(cli.image_path.clone(), Some(4)).await?;

    // Print previous deployment.json
    println!("Previous deployment.json:\n---");
    let previous_deployment = String::from_utf8(
        data.read_file(Path::new("/deployment.json"))
            .await
            .context("failed to print previous deployment config")?,
    )?;
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

    // Print updated deployment.json
    println!("Updated deployment.json:\n---");
    let updated_deployment = String::from_utf8(
        data.read_file(Path::new("/deployment.json"))
            .await
            .context("failed to read updated deployment config")?,
    )?;
    println!("{updated_deployment}");

    // Update NNS key
    if let Some(public_key) = cli.deployment.nns_public_key_override {
        let mut nns_key = NamedTempFile::new()?;
        write!(&mut nns_key, "{public_key}")?;
        fs::set_permissions(nns_key.path(), Permissions::from_mode(0o644))?;

        data.write_file(nns_key.path(), Path::new("/nns_public_key_override.pem"))
            .await
            .context("failed to copy nns key file")?;

        // Print updated NNS key
        println!("Updated nns_public_key_override.pem:\n---");
        let updated_nns_key = String::from_utf8(
            data.read_file(Path::new("/nns_public_key_override.pem"))
                .await
                .context("failed to read updated nns key")?,
        )?;
        println!("{updated_nns_key}");
    }

    // Close data partition
    data.close().await?;

    Ok(())
}
