use anyhow::{Context, Error, bail};
use candid::Principal;
use clap::Parser;
use ic_agent::{Agent, identity::Secp256k1Identity};
use k256::elliptic_curve::SecretKey;
use rate_limiting_canister_client::{check_config, submit_config};
use std::{path::PathBuf, str};
use tracing::info;
use tracing_subscriber::EnvFilter;

const SERVICE_NAME: &str = "rate-limiting-canister-client";

#[derive(Parser, Debug)]
#[command(name = SERVICE_NAME)]
struct Cli {
    /// ID of the rate-limiting canister
    #[arg(long)]
    canister_id: Option<Principal>,

    /// Path to the file containing all the rules
    #[arg(long)]
    config_file: PathBuf,

    /// Identity key
    #[arg(long)]
    identity_key: Option<String>,

    /// IC domain URL
    #[arg(long, default_value = "https://icp-api.io")]
    ic_domain: String,

    /// Only check the config file
    #[arg(long)]
    check: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // parse command-line arguments
    let cli = Cli::parse();

    // initialize tracing subscriber with corresponding log level
    let log_level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .init();

    if cli.check {
        check_config(cli.config_file).context("Failed to parse the config")?;
        info!("Config file is correctly formatted");
    } else {
        if cli.identity_key.is_none() || cli.canister_id.is_none() {
            bail!(
                "Canister ID and identity key are required to submit the configuration to the canister!"
            );
        }
        let identity_key = cli.identity_key.unwrap();
        let canister_id = cli.canister_id.unwrap();

        // create the agent
        let identity = Secp256k1Identity::from_private_key(
            SecretKey::from_sec1_pem(&identity_key).context("failed to parse the identity key")?,
        );
        let agent = Agent::builder()
            .with_url(cli.ic_domain)
            .with_identity(identity)
            .build()
            .context("failed to build the agent")?;

        submit_config(cli.config_file, canister_id, agent)
            .await
            .context("failed to submit the config to the canister")?;
    }
    Ok(())
}
