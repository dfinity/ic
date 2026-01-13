use anyhow::{Context, Error, Result, bail};
use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use rate_limits_api::{
    AddConfigError, AddConfigResponse, IncidentId, InputConfig, InputRule,
    v1::{RateLimitRule, SCHEMA_VERSION},
};
use serde::Deserialize;
use std::{fs, path::PathBuf, str};
use tracing::{debug, info};
use uuid::Uuid;

pub async fn submit_config(
    config_file: PathBuf,
    canister_id: Principal,
    agent: Agent,
) -> Result<(), Error> {
    // read the rules
    let rules = read_yaml_file(&config_file)?;

    // information
    info!(
        "{} rules with schema version {} read from {}",
        rules.len(),
        SCHEMA_VERSION,
        config_file.display()
    );

    for rule in &rules {
        debug!(
            "Rule: {} - Description: {} - Incident ID: {}",
            str::from_utf8(&rule.rule_raw).context("failed to turn raw rule into a string")?,
            rule.description,
            rule.incident_id
        );
    }

    // submit the rules
    let args = Encode!(&InputConfig {
        schema_version: SCHEMA_VERSION,
        rules
    })
    .context("failed to encode the payload")?;

    let result = agent
        .update(&canister_id, "add_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .context("failed to submit the rules to the canister")?;

    let response = Decode!(&result, AddConfigResponse)
        .context("failed to parse the response from the canister")?;

    if let Err(err) = response {
        match err {
            AddConfigError::Unauthorized => {
                bail!("identity not authorized to modify rules");
            }

            AddConfigError::InvalidInputConfig(x) => {
                bail!("rules file is malformed: {x}");
            }

            AddConfigError::PolicyViolation(x) => {
                bail!("rules violate a policy: {x}");
            }

            AddConfigError::Internal(x) => {
                bail!("unexpected error: {x}");
            }
        }
    }

    Ok(())
}

pub fn check_config(config_file: PathBuf) -> Result<(), Error> {
    let _ = read_yaml_file(&config_file)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    #[serde(flatten)]
    rate_limit_rule: RateLimitRule,
    incident_id: IncidentId,
    description: String,
}

fn read_yaml_file(file_path: &PathBuf) -> Result<Vec<InputRule>, Error> {
    let yaml_str = fs::read_to_string(file_path).context("Unable to read file")?;

    // Deserialize directly into `YamlRule` and transform `InputRule`
    let yaml_rules: Vec<YamlRule> = serde_yaml::from_str(&yaml_str)?;
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

    Ok(input_rules)
}
