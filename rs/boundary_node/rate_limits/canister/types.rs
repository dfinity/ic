pub type Version = u64;
pub type Timestamp = u64;
pub type RuleId = String;

pub struct ConfigResponse {
    pub version: Version,
    pub active_since: Timestamp,
    pub config: OutputConfig,
}

pub struct OutputConfig {
    pub rules: Vec<OutputRule>,
}

pub struct OutputRule {
    pub id: RuleId,
    pub rule_raw: Option<Vec<u8>>,
    pub description: Option<String>,
    pub disclosed_at: Option<Timestamp>,
}

impl From<OutputRule> for rate_limits_api::OutputRule {
    fn from(value: OutputRule) -> Self {
        rate_limits_api::OutputRule {
            description: value.description,
            disclosed_at: value.disclosed_at,
            id: value.id,
            rule_raw: value.rule_raw,
        }
    }
}

impl From<OutputConfig> for rate_limits_api::OutputConfig {
    fn from(value: OutputConfig) -> Self {
        rate_limits_api::OutputConfig {
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
