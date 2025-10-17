use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::AsRefStr;
use thiserror::Error;
use uuid::Uuid;

pub type Version = u64;
pub type Timestamp = u64;
pub type SchemaVersion = u64;

use rate_limits_api as api;

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub struct RuleId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub struct IncidentId(pub Uuid);

#[derive(Debug)]
pub enum DiscloseRulesArg {
    RuleIds(Vec<RuleId>),
    IncidentIds(Vec<IncidentId>),
}

#[derive(Debug)]
pub struct ConfigResponse {
    pub version: Version,
    pub active_since: Timestamp,
    pub config: OutputConfig,
}

#[derive(Clone, Debug)]
pub struct OutputConfig {
    pub schema_version: SchemaVersion,
    pub is_redacted: bool,
    pub rules: Vec<OutputRule>,
}

#[derive(Debug)]
pub struct InputConfig {
    pub schema_version: SchemaVersion,
    pub rules: Vec<InputRule>,
}

#[derive(Debug)]
pub struct InputRule {
    pub incident_id: IncidentId,
    pub rule_raw: Vec<u8>,
    pub description: String,
}

impl InputRule {
    fn rule_as_json(&self) -> Option<Value> {
        serde_json::from_slice(&self.rule_raw).ok()
    }
}

// Rules are compared based on incident_id, description, and rule_raw (deserialized as serde::Value for JSON comparison, as raw blobs are not reliably comparable).
impl PartialEq for InputRule {
    fn eq(&self, other: &Self) -> bool {
        self.incident_id == other.incident_id
            && self.description == other.description
            && self.rule_as_json().as_ref() == other.rule_as_json().as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct OutputRule {
    pub id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
}

impl From<OutputRule> for api::OutputRule {
    fn from(value: OutputRule) -> Self {
        api::OutputRule {
            description: value.description,
            rule_id: value.id.to_string(),
            incident_id: value.incident_id.to_string(),
            rule_raw: value.rule_raw,
        }
    }
}

#[derive(Debug, Error)]
pub enum GetConfigError {
    #[error("Config for version={0} not found")]
    NotFound(Version),
    #[error("No existing configs found")]
    NoExistingConfigsFound,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<GetConfigError> for api::GetConfigError {
    fn from(value: GetConfigError) -> Self {
        match value {
            GetConfigError::NotFound(_) => api::GetConfigError::NotFound,
            GetConfigError::NoExistingConfigsFound => api::GetConfigError::NoExistingConfigsFound,
            GetConfigError::Internal(error) => api::GetConfigError::Internal(error.to_string()),
        }
    }
}

#[derive(Debug, Error)]
pub enum GetEntityError {
    #[error("The provided id={0} not found")]
    NotFound(String),
    #[error("The provided id={0} is not a valid UUID")]
    InvalidUuidFormat(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<GetEntityError> for api::GetRuleByIdError {
    fn from(value: GetEntityError) -> Self {
        match value {
            GetEntityError::NotFound(_) => api::GetRuleByIdError::NotFound,
            GetEntityError::InvalidUuidFormat(_) => api::GetRuleByIdError::InvalidUuidFormat,
            GetEntityError::Internal(error) => api::GetRuleByIdError::Internal(error.to_string()),
        }
    }
}

impl From<GetEntityError> for api::GetRulesByIncidentIdError {
    fn from(value: GetEntityError) -> Self {
        match value {
            GetEntityError::NotFound(_) => api::GetRulesByIncidentIdError::NotFound,
            GetEntityError::InvalidUuidFormat(_) => {
                api::GetRulesByIncidentIdError::InvalidUuidFormat
            }
            GetEntityError::Internal(error) => {
                api::GetRulesByIncidentIdError::Internal(error.to_string())
            }
        }
    }
}

#[derive(Debug, Error, AsRefStr)]
pub enum AddConfigError {
    /// Indicates an unauthorized attempt to add a new config
    #[error("Unauthorized operation")]
    #[strum(serialize = "unauthorized_error")]
    Unauthorized,
    /// Signifies that the provided input config is malformed
    #[error("Invalid input configuration: {0}")]
    #[strum(serialize = "invalid_input_error")]
    InvalidInputConfig(#[from] InputConfigError),
    /// Signifies policy infringement, a newly added rule refers to an incident which was already disclosed
    #[strum(serialize = "policy_violation_error")]
    #[error("Rule at index={index} is linked to an already disclosed incident_id={incident_id}")]
    LinkingRuleToDisclosedIncident {
        index: usize,
        incident_id: IncidentId,
    },
    /// Captures all unexpected internal errors during process
    #[error("An unexpected internal error occurred: {0}")]
    #[strum(serialize = "internal_error")]
    Internal(#[from] anyhow::Error),
}

impl From<AddConfigError> for api::AddConfigError {
    fn from(value: AddConfigError) -> Self {
        match value {
            AddConfigError::Unauthorized => api::AddConfigError::Unauthorized,
            AddConfigError::InvalidInputConfig(err) => {
                api::AddConfigError::InvalidInputConfig(err.to_string())
            }
            AddConfigError::LinkingRuleToDisclosedIncident { index, incident_id } => {
                api::AddConfigError::PolicyViolation(format!(
                    "Rule at index={index} is linked to an already disclosed incident_id={incident_id}"
                ))
            }
            AddConfigError::Internal(error) => api::AddConfigError::Internal(error.to_string()),
        }
    }
}

#[derive(Debug, Error, AsRefStr)]
pub enum DiscloseRulesError {
    /// Indicates an unauthorized attempt to disclose rules
    #[error("Unauthorized operation")]
    #[strum(serialize = "unauthorized_error")]
    Unauthorized,
    /// Signifies that an input ID provided for disclosure is not a valid UUID
    #[error("Invalid UUID at index={0}")]
    InvalidUuidFormat(usize),
    /// Signifies that a specified incident ID could not be found
    #[error("Incident with ID={0} not found")]
    #[strum(serialize = "incident_id_not_found_error")]
    IncidentIdNotFound(IncidentId),
    /// Signifies that a specified rule ID could not be found
    #[error("Rule with ID={0} not found")]
    #[strum(serialize = "rule_id_not_found_error")]
    RuleIdNotFound(RuleId),
    /// Captures unexpected internal errors during the disclosure process
    #[error("An unexpected internal error occurred: {0}")]
    #[strum(serialize = "internal_error")]
    Internal(#[from] anyhow::Error),
}

impl From<DiscloseRulesError> for api::DiscloseRulesError {
    fn from(value: DiscloseRulesError) -> Self {
        match value {
            DiscloseRulesError::Unauthorized => api::DiscloseRulesError::Unauthorized,
            DiscloseRulesError::InvalidUuidFormat(idx) => {
                api::DiscloseRulesError::InvalidUuidFormat(format!("Invalid UUID at index={idx}"))
            }
            DiscloseRulesError::IncidentIdNotFound(incident_id) => {
                api::DiscloseRulesError::IncidentIdNotFound(format!(
                    "Incident with ID={} not found",
                    incident_id.0
                ))
            }
            DiscloseRulesError::RuleIdNotFound(rule_id) => api::DiscloseRulesError::RuleIdNotFound(
                format!("Rule with ID={0} not found", rule_id.0),
            ),
            DiscloseRulesError::Internal(error) => {
                api::DiscloseRulesError::Internal(error.to_string())
            }
        }
    }
}

#[derive(Debug, Error, Clone)]
pub enum InputConfigError {
    #[error("Invalid JSON encoding of rule_raw for rule at index={0}")]
    InvalidRuleJsonEncoding(usize),
    #[error("Invalid UUID format of incident_id for rule at index={0}")]
    InvalidIncidentUuidFormat(usize),
    #[error("Duplicate rules detected at indices {0} and {1}")]
    DuplicateRules(usize, usize),
}

impl TryFrom<api::InputConfig> for InputConfig {
    type Error = InputConfigError;

    fn try_from(value: api::InputConfig) -> Result<Self, Self::Error> {
        let mut rules = Vec::with_capacity(value.rules.len());

        for (idx, rule) in value.rules.into_iter().enumerate() {
            // Validate that rule_raw blob encodes a valid JSON object
            serde_json::from_slice::<Value>(rule.rule_raw.as_slice())
                .map_err(|_| InputConfigError::InvalidRuleJsonEncoding(idx))?;

            let rule = InputRule {
                incident_id: IncidentId::try_from(rule.incident_id)
                    .map_err(|_| InputConfigError::InvalidIncidentUuidFormat(idx))?,
                rule_raw: rule.rule_raw,
                description: rule.description,
            };

            // Duplicate rules in a config are forbidden
            if let Some(existing_rule_idx) = rules.iter().position(|r| *r == rule) {
                return Err(InputConfigError::DuplicateRules(existing_rule_idx, idx));
            }

            rules.push(rule);
        }

        let config = InputConfig {
            schema_version: value.schema_version,
            rules,
        };

        Ok(config)
    }
}

impl From<OutputConfig> for api::OutputConfig {
    fn from(value: OutputConfig) -> Self {
        api::OutputConfig {
            schema_version: value.schema_version,
            rules: value.rules.into_iter().map(|r| r.into()).collect(),
            is_redacted: value.is_redacted,
        }
    }
}

impl From<ConfigResponse> for api::ConfigResponse {
    fn from(value: ConfigResponse) -> Self {
        api::ConfigResponse {
            version: value.version,
            active_since: value.active_since,
            config: value.config.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutputRuleMetadata {
    pub id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
    pub added_in_version: Version,
    pub removed_in_version: Option<Version>,
}

impl From<OutputRuleMetadata> for api::OutputRuleMetadata {
    fn from(value: OutputRuleMetadata) -> Self {
        api::OutputRuleMetadata {
            rule_id: value.id.0.to_string(),
            incident_id: value.incident_id.0.to_string(),
            rule_raw: value.rule_raw,
            description: value.description,
            disclosed_at: value.disclosed_at,
            added_in_version: value.added_in_version,
            removed_in_version: value.removed_in_version,
        }
    }
}

impl TryFrom<api::DiscloseRulesArg> for DiscloseRulesArg {
    type Error = DiscloseRulesError;

    fn try_from(value: api::DiscloseRulesArg) -> Result<DiscloseRulesArg, Self::Error> {
        match value {
            api::DiscloseRulesArg::RuleIds(rule_ids) => {
                let mut rules = Vec::with_capacity(rule_ids.len());
                for (idx, rule_id) in rule_ids.into_iter().enumerate() {
                    let uuid = RuleId::try_from(rule_id)
                        .map_err(|_| DiscloseRulesError::InvalidUuidFormat(idx))?;
                    rules.push(uuid);
                }
                Ok(DiscloseRulesArg::RuleIds(rules))
            }
            api::DiscloseRulesArg::IncidentIds(incident_ids) => {
                let mut incidents = Vec::with_capacity(incident_ids.len());
                for (idx, incident_id) in incident_ids.into_iter().enumerate() {
                    let uuid = IncidentId::try_from(incident_id)
                        .map_err(|_| DiscloseRulesError::InvalidUuidFormat(idx))?;
                    incidents.push(uuid);
                }
                Ok(DiscloseRulesArg::IncidentIds(incidents))
            }
        }
    }
}

impl TryFrom<api::RuleId> for RuleId {
    type Error = uuid::Error;

    fn try_from(value: api::RuleId) -> Result<Self, Self::Error> {
        let uuid = Uuid::parse_str(&value)?;
        Ok(Self(uuid))
    }
}

impl TryFrom<api::IncidentId> for IncidentId {
    type Error = uuid::Error;

    fn try_from(value: api::IncidentId) -> Result<Self, Self::Error> {
        let uuid = Uuid::parse_str(&value)?;
        Ok(Self(uuid))
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for IncidentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
