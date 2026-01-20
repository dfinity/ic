use std::os::unix::fs::PermissionsExt;
use std::{
    fs::{self, File, Permissions},
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Error};
use clap::{Args, Parser};
use config::setupos::config_ini::ConfigIniSettings;
use tempfile::NamedTempFile;
use url::Url;

use config::setupos::deployment_json::DeploymentSettings;
use config_types::DeploymentEnvironment;
use partition_tools::{Partition, ext::ExtPartition, fat::FatPartition};
use setupos_image_config::write_config;

#[derive(Parser)]
#[command(name = "setupos-inject-config")]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    image_path: PathBuf,

    #[command(flatten)]
    config_ini: ConfigIni,

    #[arg(long)]
    node_operator_private_key: Option<PathBuf>,

    #[arg(long)]
    nns_public_key_override: Option<PathBuf>,

    #[arg(long, value_delimiter = ',')]
    public_keys: Option<Vec<String>>,

    #[command(flatten)]
    deployment: DeploymentConfig,
}

#[derive(Args)]
struct ConfigIni {
    #[arg(long)]
    node_reward_type: Option<String>,

    #[arg(long)]
    ipv6_prefix: String,

    #[arg(long)]
    ipv6_prefix_length: u8,

    #[arg(long)]
    ipv6_gateway: Ipv6Addr,

    #[arg(long)]
    ipv4_address: Option<Ipv4Addr>,

    #[arg(long)]
    ipv4_gateway: Option<Ipv4Addr>,

    #[arg(long)]
    ipv4_prefix_length: Option<u8>,

    #[arg(long)]
    domain_name: Option<String>,

    #[arg(long)]
    enable_trusted_execution_environment: bool,

    #[arg(long)]
    verbose: bool,
}

#[derive(Args)]
struct DeploymentConfig {
    #[arg(long)]
    nns_urls: Option<Url>,

    #[arg(long)]
    memory_gb: Option<u32>,

    /// Can be "kvm" or "qemu". If None, is treated as "kvm".
    #[arg(long)]
    cpu: Option<String>,

    /// If None, is treated as 64.
    #[arg(long)]
    nr_of_vcpus: Option<u32>,

    #[arg(long)]
    mgmt_mac: Option<String>,

    #[arg(long)]
    deployment_environment: Option<DeploymentEnvironment>,
}

fn write_public_keys(path: &Path, ks: Vec<String>) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create public keys file")?;

    for k in ks {
        writeln!(&mut f, "{k}")?;
    }

    Ok(())
}

fn update_deployment(path: &Path, cfg: &DeploymentConfig) -> Result<(), Error> {
    let mut deployment_json = {
        let f = File::open(path).context("failed to open deployment config file")?;
        let deployment_json: DeploymentSettings = serde_json::from_reader(f)?;

        deployment_json
    };

    if let Some(mgmt_mac) = &cfg.mgmt_mac {
        deployment_json.deployment.mgmt_mac = Some(mgmt_mac.to_owned());
    }

    if let Some(nns_urls) = &cfg.nns_urls {
        deployment_json.nns.urls = vec![nns_urls.clone()];
    }

    if let Some(memory) = cfg.memory_gb {
        deployment_json.dev_vm_resources.memory = memory;
    }

    if let Some(cpu) = &cfg.cpu {
        deployment_json.dev_vm_resources.cpu = cpu.to_owned();
    }

    if let Some(nr_of_vcpus) = &cfg.nr_of_vcpus {
        deployment_json.dev_vm_resources.nr_of_vcpus = nr_of_vcpus.to_owned();
    }

    if let Some(deployment_environment) = &cfg.deployment_environment {
        deployment_json.deployment.deployment_environment = deployment_environment.to_owned();
    }

    let mut f = File::create(path).context("failed to open deployment config file")?;
    let output = serde_json::to_string_pretty(&deployment_json)?;
    write!(&mut f, "{output}")?;

    Ok(())
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Open config partition
    let mut config = FatPartition::open(cli.image_path.clone(), Some(3))?;

    // Print previous config.ini
    println!("Previous config.ini:\n---");
    let previous_config = String::from_utf8(
        config
            .read_file(Path::new("/config.ini"))
            .context("failed to print previous config")?,
    )?;
    println!("{previous_config}");

    // Update config.ini
    let config_ini = NamedTempFile::with_prefix("config.ini")?;
    let settings = {
        let ConfigIni {
            node_reward_type,
            ipv6_prefix,
            ipv6_prefix_length,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            ipv4_prefix_length,
            domain_name,
            enable_trusted_execution_environment,
            verbose,
        } = cli.config_ini;

        ConfigIniSettings {
            ipv6_prefix,
            ipv6_prefix_length,
            ipv6_gateway,
            ipv4_address,
            ipv4_gateway,
            ipv4_prefix_length,
            domain_name,
            verbose,
            node_reward_type,
            enable_trusted_execution_environment,
        }
    };
    write_config(config_ini.path(), &settings).context("failed to write config file")?;
    config
        .write_file(config_ini.path(), Path::new("/config.ini"))
        .context("failed to copy config file")?;

    // Print updated config.ini
    println!("Updated config.ini:\n---");
    let updated_config = String::from_utf8(
        config
            .read_file(Path::new("/config.ini"))
            .context("failed to read updated config")?,
    )?;
    println!("{updated_config}");

    // Update node_operator_private_key.pem
    if let Some(key_path) = cli.node_operator_private_key {
        config
            .write_file(&key_path, Path::new("/node_operator_private_key.pem"))
            .context("failed to write node_operator_private_key.pem")?;

        // Print updated node_operator_private_key.pem
        println!("Updated node_operator_private_key.pem:\n---");
        let updated_key = String::from_utf8(
            config
                .read_file(Path::new("/node_operator_private_key.pem"))
                .context("failed to read updated node operator private key")?,
        )?;
        println!("{updated_key}");
    }

    // Print previous public keys
    println!("Previous ssh_authorized_keys/admin:\n---");
    let previous_admin_keys = String::from_utf8(
        config
            .read_file(Path::new("ssh_authorized_keys/admin"))
            .context("failed to print previous config")?,
    )?;
    println!("{previous_admin_keys}");

    // Update SSH keys
    if let Some(ks) = cli.public_keys {
        let public_keys = NamedTempFile::with_prefix("public_keys")?;
        write_public_keys(public_keys.path(), ks).context("failed to write public keys")?;

        config
            .write_file(public_keys.path(), Path::new("/ssh_authorized_keys/admin"))
            .context("failed to copy public keys")?;

        // Print updated SSH keys
        println!("Updated ssh_authorized_keys/admin:\n---");
        let updated_admin_keys = String::from_utf8(
            config
                .read_file(Path::new("/ssh_authorized_keys/admin"))
                .context("failed to read updated admin keys")?,
        )?;
        println!("{updated_admin_keys}");
    }

    // Close config partition
    config.close()?;

    // Open data partition
    let mut data = ExtPartition::open(cli.image_path.clone(), Some(4))?;

    // Print previous deployment.json
    println!("Previous deployment.json:\n---");
    let previous_deployment = String::from_utf8(
        data.read_file(Path::new("/deployment.json"))
            .context("failed to print previous deployment config")?,
    )?;
    println!("{previous_deployment}");

    // Update deployment.json
    let mut deployment_json = NamedTempFile::with_prefix("deployment.json")?;
    deployment_json.write_all(previous_deployment.as_bytes())?;
    fs::set_permissions(deployment_json.path(), Permissions::from_mode(0o644))?;
    update_deployment(deployment_json.path(), &cli.deployment)
        .context("failed to write deployment config file")?;
    data.write_file(deployment_json.path(), Path::new("/deployment.json"))
        .context("failed to copy deployment config file")?;

    // Print updated deployment.json
    println!("Updated deployment.json:\n---");
    let updated_deployment = String::from_utf8(
        data.read_file(Path::new("/deployment.json"))
            .context("failed to read updated deployment config")?,
    )?;
    println!("{updated_deployment}");

    // Update NNS key
    if let Some(path) = cli.nns_public_key_override {
        let public_key = std::fs::read_to_string(path)?;
        let mut nns_key = NamedTempFile::with_prefix("nns_key")?;
        write!(&mut nns_key, "{public_key}")?;
        fs::set_permissions(nns_key.path(), Permissions::from_mode(0o644))?;

        data.write_file(nns_key.path(), Path::new("/nns_public_key_override.pem"))
            .context("failed to copy nns key file")?;

        // Print updated NNS key
        println!("Updated nns_public_key_override.pem:\n---");
        let updated_nns_key = String::from_utf8(
            data.read_file(Path::new("/nns_public_key_override.pem"))
                .context("failed to read updated nns key")?,
        )?;
        println!("{updated_nns_key}");
    }

    // Close data partition
    data.close()?;

    Ok(())
}
