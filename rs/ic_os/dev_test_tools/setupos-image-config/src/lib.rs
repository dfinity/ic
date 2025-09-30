use anyhow::{Context, Error, bail};
use clap::Args;
use std::{
    assert,
    fs::{self, File},
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
use url::Url;

use config::setupos::config_ini::ConfigIniSettings;
use config::setupos::deployment_json::DeploymentSettings;
use config_types::DeploymentEnvironment;

#[derive(Args)]
pub struct ConfigIni {
    #[arg(long)]
    pub node_reward_type: Option<String>,

    #[arg(long)]
    pub ipv6_prefix: String,

    #[arg(long)]
    pub ipv6_prefix_length: u8,

    #[arg(long)]
    pub ipv6_gateway: Ipv6Addr,

    #[arg(long)]
    pub ipv4_address: Option<Ipv4Addr>,

    #[arg(long)]
    pub ipv4_gateway: Option<Ipv4Addr>,

    #[arg(long)]
    pub ipv4_prefix_length: Option<u8>,

    #[arg(long)]
    pub domain_name: Option<String>,

    #[arg(long)]
    pub enable_trusted_execution_environment: bool,

    #[arg(long)]
    pub verbose: bool,
}

#[derive(Args)]
pub struct DeploymentConfig {
    #[arg(long)]
    pub nns_urls: Option<Url>,

    #[arg(long, allow_hyphen_values = true)]
    pub nns_public_key_override: Option<String>,

    #[arg(long)]
    pub memory_gb: Option<u32>,

    /// Can be "kvm" or "qemu". If None, is treated as "kvm".
    #[arg(long)]
    pub cpu: Option<String>,

    /// If None, is treated as 64.
    #[arg(long)]
    pub nr_of_vcpus: Option<u32>,

    #[arg(long)]
    pub mgmt_mac: Option<String>,

    #[arg(long)]
    pub deployment_environment: Option<DeploymentEnvironment>,
}

pub fn create_setupos_config(
    config_dir: &Path,
    data_dir: &Path,
    config_ini: ConfigIniSettings,
    node_operator_private_key: Option<&Path>,
    nns_public_key: Option<&Path>,
    admin_keys: Option<&Path>,
    deployment_settings: DeploymentSettings,
) -> Result<(), Error> {
    // Check that config and data dirs are valid
    if !config_dir.is_dir() {
        bail!("config dir is not valid")
    }
    if !data_dir.is_dir() {
        bail!("data dir is not valid")
    }

    // Write config.ini
    let config_ini_path = config_dir.join("config.ini");
    write_config(&config_ini_path, &config_ini).context("failed to write config file")?;

    // Write node_operator_private_key.pem
    if let Some(key_path) = node_operator_private_key {
        fs::copy(key_path, config_dir.join("node_operator_private_key.pem"))
            .context("failed to write node_operator_private_key.pem")?;
    }

    // Write SSH keys
    if let Some(admin_keys) = admin_keys {
        let public_keys_dir = config_dir.join("ssh_authorized_keys");
        fs::create_dir_all(&public_keys_dir)?;
        fs::copy(admin_keys, public_keys_dir.join("admin"))
            .context("failed to write admin keys")?;
    }

    // Write deployment.json
    let output = serde_json::to_string_pretty(&deployment_settings)?;
    let mut deployment_json = fs::File::create(data_dir.join("deployment.json"))?;
    deployment_json.write_all(output.as_bytes())?;

    // Write NNS key
    if let Some(path) = nns_public_key {
        let nns_public_key_override = std::fs::read_to_string(path)?;
        let mut nns_key = fs::File::create(data_dir.join("nns_public_key_override.pem"))?;
        nns_key.write_all(nns_public_key_override.as_bytes())?;
        // NODE-1653: Remove once rolled out to all nodes. Exists to pass "latest_release" nested tests.
        let mut nns_key = fs::File::create(data_dir.join("nns_public_key.pem"))?;
        nns_key.write_all(nns_public_key_override.as_bytes())?;
    }

    Ok(())
}

pub fn write_config(path: &Path, cfg: &ConfigIniSettings) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create config file")?;

    let ConfigIniSettings {
        node_reward_type,
        ipv6_prefix,
        ipv6_prefix_length: _,
        ipv6_gateway,
        ipv4_address,
        ipv4_gateway,
        ipv4_prefix_length,
        enable_trusted_execution_environment,
        domain_name,
        verbose,
    } = cfg;

    if let Some(node_reward_type) = node_reward_type {
        writeln!(&mut f, "node_reward_type={node_reward_type}")?;
    }

    // Always write 4 segments, even if our prefix is less.
    assert!(format!("{ipv6_prefix}::").parse::<Ipv6Addr>().is_ok());
    writeln!(&mut f, "ipv6_prefix={ipv6_prefix}")?;
    writeln!(&mut f, "ipv6_gateway={ipv6_gateway}")?;

    if let (Some(ipv4_address), Some(ipv4_gateway), Some(ipv4_prefix_length), Some(domain)) =
        (ipv4_address, ipv4_gateway, ipv4_prefix_length, domain_name)
    {
        writeln!(&mut f, "ipv4_address={ipv4_address}")?;
        writeln!(&mut f, "ipv4_gateway={ipv4_gateway}")?;
        writeln!(&mut f, "ipv4_prefix_length={ipv4_prefix_length}")?;
        writeln!(&mut f, "domain={domain}")?;
    }

    writeln!(
        &mut f,
        "enable_trusted_execution_environment={enable_trusted_execution_environment}"
    )?;

    writeln!(&mut f, "verbose={verbose}")?;

    Ok(())
}

pub fn write_public_keys(path: &Path, ks: Vec<String>) -> Result<(), Error> {
    let mut f = File::create(path).context("failed to create public keys file")?;

    for k in ks {
        writeln!(&mut f, "{k}")?;
    }

    Ok(())
}

pub fn update_deployment(path: &Path, cfg: &DeploymentConfig) -> Result<(), Error> {
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
        deployment_json.vm_resources.memory = memory;
    }

    if let Some(cpu) = &cfg.cpu {
        deployment_json.vm_resources.cpu = cpu.to_owned();
    }

    if let Some(nr_of_vcpus) = &cfg.nr_of_vcpus {
        deployment_json.vm_resources.nr_of_vcpus = nr_of_vcpus.to_owned();
    }

    if let Some(deployment_environment) = &cfg.deployment_environment {
        deployment_json.deployment.deployment_environment = deployment_environment.to_owned();
    }

    let mut f = File::create(path).context("failed to open deployment config file")?;
    let output = serde_json::to_string_pretty(&deployment_json)?;
    write!(&mut f, "{output}")?;

    Ok(())
}
