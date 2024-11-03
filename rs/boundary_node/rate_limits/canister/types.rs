use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub type Version = u64;
pub type Timestamp = u64;
pub type SchemaVersion = u64;

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub struct RuleId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub struct IncidentId(pub Uuid);

pub enum DiscloseRulesArg {
    RuleIds(Vec<RuleId>),
    IncidentIds(Vec<IncidentId>),
}

pub struct ConfigResponse {
    pub version: Version,
    pub active_since: Timestamp,
    pub config: OutputConfig,
}

#[derive(Clone)]
pub struct OutputConfig {
    pub schema_version: SchemaVersion,
    pub rules: Vec<OutputRule>,
}

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

#[derive(Clone)]
pub struct OutputRule {
    pub id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
}

impl From<OutputRule> for rate_limits_api::OutputRule {
    fn from(value: OutputRule) -> Self {
        rate_limits_api::OutputRule {
            description: value.description,
            id: value.id.to_string(),
            incident_id: value.incident_id.to_string(),
            rule_raw: value.rule_raw,
        }
    }
}

#[derive(Debug, Error, Clone)]
pub enum InputConfigError {
    #[error("Invalid JSON encoding of rule_raw for rule at index = {0}")]
    InvalidRuleJsonEncoding(usize),
    #[error("Invalid UUID format of incident_id for rule at index = {0}")]
    InvalidUuidFormatForIncident(usize),
}

impl TryFrom<rate_limits_api::InputConfig> for InputConfig {
    type Error = InputConfigError;

    fn try_from(value: rate_limits_api::InputConfig) -> Result<Self, Self::Error> {
        let mut rules = Vec::with_capacity(value.rules.len());

        for (idx, rule) in value.rules.into_iter().enumerate() {
            // Validate that rule_raw blob encodes a valid JSON object
            serde_json::from_slice::<Value>(rule.rule_raw.as_slice())
                .map_err(|_| InputConfigError::InvalidRuleJsonEncoding(idx))?;

            let rule = InputRule {
                incident_id: IncidentId::try_from(rule.incident_id)
                    .map_err(|_| InputConfigError::InvalidUuidIncidentId(idx))?,
                rule_raw: rule.rule_raw,
                description: rule.description,
            };

            rules.push(rule);
        }

        let config = InputConfig {
            schema_version: value.schema_version,
            rules,
        };

        Ok(config)
    }
}

impl From<OutputConfig> for rate_limits_api::OutputConfig {
    fn from(value: OutputConfig) -> Self {
        rate_limits_api::OutputConfig {
            schema_version: value.schema_version,
            rules: value.rules.into_iter().map(|r| r.into()).collect(),
        }
    }
}

impl From<ConfigResponse> for rate_limits_api::ConfigResponse {
    fn from(value: ConfigResponse) -> Self {
        rate_limits_api::ConfigResponse {
            version: value.version,
            active_since: value.active_since,
            config: value.config.into(),
        }
    }
}

#[derive(Clone)]
pub struct OutputRuleMetadata {
    pub id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
    pub added_in_version: Version,
    pub removed_in_version: Option<Version>,
}

impl From<OutputRuleMetadata> for rate_limits_api::OutputRuleMetadata {
    fn from(value: OutputRuleMetadata) -> Self {
        rate_limits_api::OutputRuleMetadata {
            id: value.id.0.to_string(),
            incident_id: value.incident_id.0.to_string(),
            rule_raw: value.rule_raw,
            description: value.description,
            disclosed_at: value.disclosed_at,
            added_in_version: value.added_in_version,
            removed_in_version: value.removed_in_version,
        }
    }
}

#[derive(Debug, Error, Clone)]
pub enum DiscloseRulesArgError {
    #[error("Invalid UUID at index = {0}")]
    InvalidUuid(usize),
}

impl TryFrom<rate_limits_api::DiscloseRulesArg> for DiscloseRulesArg {
    type Error = DiscloseRulesArgError;

    fn try_from(value: rate_limits_api::DiscloseRulesArg) -> Result<DiscloseRulesArg, Self::Error> {
        match value {
            rate_limits_api::DiscloseRulesArg::RuleIds(rule_ids) => {
                let mut rules = Vec::with_capacity(rule_ids.len());
                for (idx, rule_id) in rule_ids.into_iter().enumerate() {
                    let uuid = RuleId::try_from(rule_id)
                        .map_err(|_| DiscloseRulesArgError::InvalidUuid(idx))?;
                    rules.push(uuid);
                }
                Ok(DiscloseRulesArg::RuleIds(rules))
            }
            rate_limits_api::DiscloseRulesArg::IncidentIds(incident_ids) => {
                let mut incidents = Vec::with_capacity(incident_ids.len());
                for (idx, incident_id) in incident_ids.into_iter().enumerate() {
                    let uuid = IncidentId::try_from(incident_id)
                        .map_err(|_| DiscloseRulesArgError::InvalidUuid(idx))?;
                    incidents.push(uuid);
                }
                Ok(DiscloseRulesArg::IncidentIds(incidents))
            }
        }
    }
}

impl TryFrom<rate_limits_api::RuleId> for RuleId {
    type Error = uuid::Error;

    fn try_from(value: rate_limits_api::RuleId) -> Result<Self, Self::Error> {
        let uuid = Uuid::parse_str(&value)?;
        Ok(Self(uuid))
    }
}

impl TryFrom<rate_limits_api::IncidentId> for IncidentId {
    type Error = uuid::Error;

    fn try_from(value: rate_limits_api::IncidentId) -> Result<Self, Self::Error> {
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
