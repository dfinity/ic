use candid::CandidType;
use candid::Principal;
use serde::{Deserialize, Serialize};
pub type Version = u64;
pub type Timestamp = u64;
pub type RuleId = String;
pub type IncidentId = String;
pub type SchemaVersion = u64;

pub type GetConfigResponse = Result<ConfigResponse, String>;
pub type AddConfigResponse = Result<(), String>;
pub type GetRuleByIdResponse = Result<OutputRuleMetadata, String>;
pub type DiscloseRulesResponse = Result<(), String>;

#[derive(CandidType, Deserialize, Debug)]
pub enum DiscloseRulesArg {
    RuleIds(Vec<RuleId>),
    IncidentIds(Vec<IncidentId>),
}

#[derive(CandidType, Deserialize, Debug)]
pub struct ConfigResponse {
    pub version: Version,
    pub active_since: Timestamp,
    pub config: OutputConfig,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct OutputConfig {
    pub schema_version: SchemaVersion,
    pub rules: Vec<OutputRule>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct InputConfig {
    pub schema_version: SchemaVersion,
    pub rules: Vec<InputRule>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct InputRule {
    pub incident_id: IncidentId,
    pub rule_raw: Vec<u8>,
    pub description: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct OutputRule {
    pub id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct OutputRuleMetadata {
    pub id: RuleId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
    pub added_in_version: Version,
    pub removed_in_version: Option<Version>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct InitArg {
    pub registry_polling_period_secs: u64,
}

#[derive(CandidType, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct GetApiBoundaryNodeIdsRequest {}

#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct ApiBoundaryNodeIdRecord {
    pub id: Option<Principal>,
}
