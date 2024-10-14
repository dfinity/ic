use candid::CandidType;
use serde::Deserialize;

pub type Version = u64;
pub type Timestamp = u64;
pub type RuleId = String;

pub type GetConfigResponse = Result<ConfigResponse, String>;

#[derive(CandidType, Deserialize, Debug)]
pub struct ConfigResponse {
    pub version: Version,
    pub active_since: Timestamp,
    pub config: OutputConfig,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct OutputConfig {
    pub rules: Vec<OutputRule>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct OutputRule {
    pub id: RuleId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct InitArg {
    registry_polling_period_secs: u64,
}
