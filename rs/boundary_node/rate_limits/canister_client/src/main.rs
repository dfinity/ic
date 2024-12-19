use candid::Principal;
use clap::Parser;
use ic_agent::{identity::Secp256k1Identity, Agent};
use k256::elliptic_curve::SecretKey;
use rate_limiting_canister_client::submit_config;
use std::{path::PathBuf, str};

const SERVICE_NAME: &str = "rate-limiting-canister-client";

#[derive(Parser, Debug)]
#[command(name = SERVICE_NAME)]
struct Cli {
    /// ID of the rate-limiting canister
    #[arg(long)]
    canister_id: Principal,

    /// Path to the file containing all the rules
    #[arg(long)]
    config_file: PathBuf,

    /// Identity key
    #[arg(long)]
    identity_key: String,

    /// IC domain URL
    #[arg(long, default_value = "https://icp-api.io")]
    ic_domain: String,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() {
    // parse command-line arguments
    let cli = Cli::parse();

    // create the agent
    let identity = Secp256k1Identity::from_private_key(
        SecretKey::from_sec1_pem(&cli.identity_key).expect("failed to parse the identity key"),
    );
    let agent = Agent::builder()
        .with_url(cli.ic_domain)
        .with_identity(identity)
        .build()
        .expect("failed to build the agent");

    submit_config(cli.config_file, cli.canister_id, agent, cli.debug)
        .await
        .expect("failed to submit the config to the canister");
}
