pub type Version = u64;
pub type Timestamp = u64;
pub type SchemaVersion = u64;
pub type RuleId = String;
pub type IncidentId = String;

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

pub struct InputRule {
    pub incident_id: IncidentId,
    pub rule_raw: Vec<u8>,
    pub description: String,
}

#[derive(Clone)]
pub struct OutputRule {
    pub id: RuleId,
    pub incident_id: IncidentId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
}

impl From<rate_limits_api::InputRule> for InputRule {
    fn from(value: rate_limits_api::InputRule) -> Self {
        InputRule {
            incident_id: value.incident_id,
            description: value.description,
            rule_raw: value.rule_raw,
        }
    }
}

impl From<OutputRule> for rate_limits_api::OutputRule {
    fn from(value: OutputRule) -> Self {
        rate_limits_api::OutputRule {
            description: value.description,
            id: value.id,
            incident_id: value.incident_id,
            rule_raw: value.rule_raw,
        }
    }
}

impl From<rate_limits_api::InputConfig> for InputConfig {
    fn from(value: rate_limits_api::InputConfig) -> Self {
        InputConfig {
            schema_version: value.schema_version,
            rules: value.rules.into_iter().map(|r| r.into()).collect(),
        }
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
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
    pub added_in_version: Version,
    pub removed_in_version: Option<Version>,
}

impl From<OutputRuleMetadata> for rate_limits_api::OutputRuleMetadata {
    fn from(value: OutputRuleMetadata) -> Self {
        rate_limits_api::OutputRuleMetadata {
            id: value.id,
            rule_raw: value.rule_raw,
            description: value.description,
            disclosed_at: value.disclosed_at,
            added_in_version: value.added_in_version,
            removed_in_version: value.removed_in_version,
        }
    }
}

impl From<rate_limits_api::DiscloseRulesArg> for DiscloseRulesArg {
    fn from(value: rate_limits_api::DiscloseRulesArg) -> Self {
        match value {
            rate_limits_api::DiscloseRulesArg::RuleIds(rule_ids) => {
                DiscloseRulesArg::RuleIds(rule_ids)
            }
            rate_limits_api::DiscloseRulesArg::IncidentIds(incident_ids) => {
                DiscloseRulesArg::IncidentIds(incident_ids)
            }
        }
    }
}
