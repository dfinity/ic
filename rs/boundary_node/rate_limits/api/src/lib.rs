use candid::CandidType;
use candid::Principal;
use schema_versions::v1::RateLimitRule;
use serde::{Deserialize, Serialize};
mod schema_versions;
pub use schema_versions::v1;

pub type Version = u64;
pub type Timestamp = u64;
pub type RuleId = String;
pub type IncidentId = String;
pub type SchemaVersion = u64;

pub type GetConfigResponse = Result<ConfigResponse, GetConfigError>;
pub type AddConfigResponse = Result<(), AddConfigError>;
pub type GetRuleByIdResponse = Result<OutputRuleMetadata, GetRuleByIdError>;
pub type DiscloseRulesResponse = Result<(), DiscloseRulesError>;
pub type GetRulesByIncidentIdResponse = Result<Vec<OutputRuleMetadata>, GetRulesByIncidentIdError>;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum DiscloseRulesArg {
    RuleIds(Vec<RuleId>),
    IncidentIds(Vec<IncidentId>),
}

#[derive(CandidType, Debug, Deserialize)]
pub enum GetConfigError {
    /// Indicates that a config with the specified version does not exist
    NotFound,
    /// Indicates that no configs exist, hence nothing could be returned
    NoExistingConfigsFound,
    /// Captures all unexpected internal errors
    Internal(String),
}

#[derive(CandidType, Debug, Deserialize)]
pub enum GetRuleByIdError {
    /// Indicates that a rule with the specified ID does not exist
    NotFound,
    // Indicates that the provided ID is not a valid UUID
    InvalidUuidFormat,
    /// Captures all unexpected internal errors
    Internal(String),
}

#[derive(CandidType, Debug, Deserialize)]
pub enum GetRulesByIncidentIdError {
    /// Indicates that an incident with the specified ID does not exist
    NotFound,
    /// Indicates that the provided ID is not a valid UUID
    InvalidUuidFormat,
    /// Captures all unexpected internal errors
    Internal(String),
}

#[derive(CandidType, Debug, Deserialize)]
pub enum AddConfigError {
    /// Indicates an unauthorized attempt to add a new config
    Unauthorized,
    /// Signifies that the provided input config is malformed
    InvalidInputConfig(String),
    /// Signifies that a new configuration cannot be added due to some policy infringement
    PolicyViolation(String),
    /// Captures all unexpected internal errors during the disclosure process
    Internal(String),
}

#[derive(CandidType, Debug, Deserialize)]
pub enum DiscloseRulesError {
    /// Indicates an unauthorized attempt to disclose rules
    Unauthorized,
    /// Signifies that an input ID provided for disclosure is not a valid UUID
    InvalidUuidFormat(String),
    /// Signifies that a specified incident ID could not be found
    IncidentIdNotFound(String),
    /// Signifies that a specified rule ID could not be found
    RuleIdNotFound(String),
    /// Captures all unexpected internal errors during the disclosure process
    Internal(String),
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct ConfigResponse {
    pub version: Version,
    pub active_since: Timestamp,
    pub config: OutputConfig,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct OutputConfig {
    pub schema_version: SchemaVersion,
    pub is_redacted: bool,
    pub rules: Vec<OutputRule>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct InputConfig {
    pub schema_version: SchemaVersion,
    pub rules: Vec<InputRule>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct InputRule {
    pub incident_id: IncidentId,
    pub rule_raw: Vec<u8>,
    pub description: String,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct OutputRule {
    pub rule_id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
}

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub struct OutputRuleMetadata {
    pub rule_id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
    pub added_in_version: Version,
    pub removed_in_version: Option<Version>,
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct InitArg {
    pub registry_polling_period_secs: u64,
    pub authorized_principal: Option<Principal>,
}

#[derive(CandidType, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct GetApiBoundaryNodeIdsRequest {}

#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct ApiBoundaryNodeIdRecord {
    pub id: Option<Principal>,
}

const INDENT: &str = "  ";
const DOUBLE_INDENT: &str = "    ";

impl std::fmt::Display for ConfigResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "\nConfiguration details:")?;
        writeln!(f, "{INDENT}Version: {}", self.version)?;
        writeln!(f, "{INDENT}Active Since: {}", self.active_since)?;
        writeln!(f, "{INDENT}{}", self.config)?;
        Ok(())
    }
}

impl std::fmt::Display for OutputConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Schema version: {}", self.schema_version)?;
        writeln!(f, "{INDENT}Is redacted: {}", self.is_redacted)?;
        for (i, rule) in self.rules.iter().enumerate() {
            writeln!(f, "{DOUBLE_INDENT}Rule {}:", i + 1)?;
            writeln!(f, "{DOUBLE_INDENT}ID: {}", rule.rule_id)?;
            writeln!(f, "{DOUBLE_INDENT}Incident ID: {}", rule.incident_id)?;
            if let Some(ref description) = rule.description {
                writeln!(f, "{DOUBLE_INDENT}Description: {description}")?;
            }
            if let Some(ref rule_raw) = rule.rule_raw {
                let decoded_rule = RateLimitRule::from_bytes_json(rule_raw.as_slice()).unwrap();
                writeln!(f, "{DOUBLE_INDENT}Rate-limit rule:\n{decoded_rule}")?;
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for OutputRuleMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\nOutputRuleMetadata")?;
        writeln!(f, "{INDENT}ID: {}", self.rule_id)?;
        writeln!(
            f,
            "{INDENT}Disclosed at: {}",
            self.disclosed_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "None".to_string())
        )?;
        writeln!(f, "{INDENT}Added in version: {}", self.added_in_version)?;
        writeln!(
            f,
            "{INDENT}Removed in version: {}",
            self.removed_in_version
                .map(|v| v.to_string())
                .unwrap_or_else(|| "None".to_string())
        )?;
        if let Some(ref description) = self.description {
            writeln!(f, "{INDENT}Description: {description}")?;
        }
        if let Some(ref rule_raw) = self.rule_raw {
            let decoded_rule = RateLimitRule::from_bytes_json(rule_raw.as_slice()).unwrap();
            writeln!(f, "{INDENT}Rate-limit rule:\n{decoded_rule}")?;
        }
        Ok(())
    }
}
