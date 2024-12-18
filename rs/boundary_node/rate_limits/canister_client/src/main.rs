use candid::{Decode, Encode, Principal};
use clap::Parser;
use ic_agent::{identity::Secp256k1Identity, Agent, Identity};
use k256::elliptic_curve::SecretKey;
use rate_limits_api::{
    v1::RateLimitRule, AddConfigError, AddConfigResponse, IncidentId, InputConfig, InputRule,
};
use serde::Deserialize;
use std::{fs, path::PathBuf, str};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

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

    // initialize tracing subscriber with corresponding log level
    let log_level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .init();

    // read the rules
    let (schema_version, rules) = read_yaml_file(&cli.config_file);

    // information
    info!(
        "{} rules with schema version {} read from {}",
        rules.len(),
        schema_version,
        cli.config_file.display()
    );

    for rule in &rules {
        debug!(
            "Rule: {} - Description: {} - Incident ID: {}",
            str::from_utf8(&rule.rule_raw).expect("failed to turn raw rule into a string"),
            rule.description,
            rule.incident_id
        );
    }

    // create the agent
    let agent = create_agent(
        Secp256k1Identity::from_private_key(
            SecretKey::from_sec1_pem(&cli.identity_key).expect("failed to parse the identity key"),
        ),
        cli.ic_domain,
    );

    // submit the rules
    let args = Encode!(&InputConfig {
        schema_version,
        rules
    })
    .unwrap();

    let result = agent
        .update(&cli.canister_id, "add_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("failed to submit the rules to the canister");

    let response = Decode!(&result, AddConfigResponse)
        .expect("failed to parse the response from the canister");

    match response {
        Ok(()) => info!("successfully updated the rules"),
        Err(AddConfigError::Unauthorized) => info!("identity not authorized to modify rules"),
        Err(AddConfigError::InvalidInputConfig(x)) => {
            info!("rules file is malformed: {}", x.to_string())
        }
        Err(AddConfigError::PolicyViolation(x)) => {
            info!("rules violate a policy: {}", x.to_string())
        }
        Err(AddConfigError::Internal(x)) => info!("unexpected error: {}", x.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct YamlConfig {
    schema_version: u64,
    rules: Vec<YamlRule>,
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    #[serde(flatten)]
    rate_limit_rule: RateLimitRule,
    incident_id: IncidentId,
    description: String,
}

fn read_yaml_file(file_path: &PathBuf) -> (u64, Vec<InputRule>) {
    let yaml_str = fs::read_to_string(file_path).expect("Unable to read file");

    // Deserialize directly into `YamlConfig`
    let yaml_config: YamlConfig = serde_yaml::from_str(&yaml_str).expect("Failed to parse YAML");

    // Get the api version
    let schema_version = yaml_config.schema_version;

    // Transform `YamlRule` into `InputRule`
    let yaml_rules = yaml_config.rules;
    let input_rules = yaml_rules
        .into_iter()
        .map(|entry| InputRule {
            incident_id: Uuid::parse_str(&entry.incident_id)
                .expect("Invalid UUID")
                .to_string(),
            rule_raw: entry
                .rate_limit_rule
                .to_bytes_json()
                .expect("Unable to serialize rate-limiting rule"),
            description: entry.description,
        })
        .collect();

    (schema_version, input_rules)
}

fn create_agent<I: Identity + 'static>(identity: I, ic_domain: String) -> Agent {
    Agent::builder()
        .with_url(ic_domain)
        .with_identity(identity)
        .build()
        .expect("failed to build the agent")
}
