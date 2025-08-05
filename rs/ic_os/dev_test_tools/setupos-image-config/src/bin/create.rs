use std::{
    fs::{self},
    io::Write,
    path::PathBuf,
};

use anyhow::{bail, Context, Error};
use clap::Parser;

use config::setupos::deployment_json::{Deployment, DeploymentSettings, Logging, Nns, VmResources};
use config_types::DeploymentEnvironment;
use setupos_image_config::{write_config, ConfigIni, DeploymentConfig};

#[derive(Parser)]
#[command(name = "setupos-create-config")]
struct Cli {
    #[arg(long)]
    config_dir: PathBuf,

    #[arg(long)]
    data_dir: PathBuf,

    #[command(flatten)]
    config_ini: ConfigIni,

    #[arg(long)]
    node_operator_private_key: Option<PathBuf>,

    #[arg(long)]
    admin_keys: Option<PathBuf>,

    #[command(flatten)]
    deployment: DeploymentConfig,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Check that config and data dirs are valid
    let config_dir = cli.config_dir;
    if !config_dir.is_dir() {
        bail!("config dir is not valid")
    }
    let data_dir = cli.data_dir;
    if !data_dir.is_dir() {
        bail!("data dir is not valid")
    }

    // Write config.ini
    let config_ini = config_dir.join("config.ini");
    write_config(&config_ini, &cli.config_ini)
        .await
        .context("failed to write config file")?;

    // Write node_operator_private_key.pem
    if let Some(key_path) = cli.node_operator_private_key {
        fs::copy(key_path, config_dir.join("node_operator_private_key.pem"))
            .context("failed to write node_operator_private_key.pem")?;
    }

    // Write SSH keys
    if let Some(admin_keys) = cli.admin_keys {
        let public_keys_dir = config_dir.join("ssh_authorized_keys");
        fs::create_dir_all(&public_keys_dir)?;
        fs::copy(admin_keys, public_keys_dir.join("admin"))
            .context("failed to write admin keys")?;
    }

    // Write deployment.json
    let deployment_settings = DeploymentSettings {
        deployment: Deployment {
            mgmt_mac: cli.deployment.mgmt_mac,
            deployment_environment: cli
                .deployment
                .deployment_environment
                .unwrap_or(DeploymentEnvironment::Mainnet),
        },
        nns: Nns {
            urls: cli.deployment.nns_urls.into_iter().collect(),
        },
        vm_resources: VmResources {
            memory: cli.deployment.memory_gb.unwrap_or(490),
            cpu: cli.deployment.cpu.unwrap_or("kvm".to_string()),
            nr_of_vcpus: cli.deployment.nr_of_vcpus.unwrap_or(64),
        },
    };

    let output = serde_json::to_string_pretty(&deployment_settings)?;
    let mut deployment_json = fs::File::create(data_dir.join("deployment.json"))?;
    deployment_json.write_all(output.as_bytes())?;

    // Write NNS key
    if let Some(public_key) = cli.deployment.nns_public_key {
        let mut nns_key = fs::File::create(data_dir.join("nns_public_key.pem"))?;

        nns_key.write_all(public_key.as_bytes())?;
    }

    Ok(())
}
