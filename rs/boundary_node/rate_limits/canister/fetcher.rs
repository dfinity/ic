use crate::{
    confidentiality_formatting::ConfidentialityFormatting,
    state::CanisterApi,
    types::{ConfigResponse, OutputConfig, OutputRule, OutputRuleMetadata, RuleId, Version},
};

pub trait EntityFetcher {
    type Input;
    type Output;
    type Error;

    fn fetch(&self, input: Self::Input) -> Result<Self::Output, Self::Error>;
}

pub struct ConfigFetcher<R, F> {
    pub canister_api: R,
    pub formatter: F,
}

pub struct RuleFetcher<R, F> {
    pub canister_api: R,
    pub formatter: F,
}

impl<R, F> RuleFetcher<R, F> {
    pub fn new(canister_api: R, formatter: F) -> Self {
        Self {
            canister_api,
            formatter,
        }
    }
}

impl<R, F> ConfigFetcher<R, F> {
    pub fn new(canister_api: R, formatter: F) -> Self {
        Self {
            canister_api,
            formatter,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchConfigError {
    #[error("Config for version={0} not found")]
    NotFound(Version),
    #[error("No existing config versions")]
    NoExistingVersions,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum FetchRuleError {
    #[error("Rule with id={0} not found")]
    NotFound(RuleId),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl<R: CanisterApi, F: ConfidentialityFormatting<Input = OutputConfig>> EntityFetcher
    for ConfigFetcher<R, F>
{
    type Input = Option<Version>;
    type Output = ConfigResponse;
    type Error = FetchConfigError;

    fn fetch(&self, version: Option<Version>) -> Result<ConfigResponse, FetchConfigError> {
        let current_version = self
            .canister_api
            .get_version()
            .ok_or_else(|| FetchConfigError::NoExistingVersions)?;

        let version = version.unwrap_or(current_version.0);

        let stored_config = self
            .canister_api
            .get_config(version)
            .ok_or_else(|| FetchConfigError::NotFound(version))?;

        let mut rules: Vec<OutputRule> = vec![];

        for rule_id in stored_config.rule_ids.iter() {
            let rule = self.canister_api.get_rule(rule_id).ok_or_else(|| {
                FetchConfigError::Unexpected(anyhow::anyhow!("Rule with id = {rule_id} not found"))
            })?;

            let output_rule = OutputRule {
                id: rule_id.clone(),
                incident_id: rule.incident_id,
                rule_raw: Some(rule.rule_raw),
                description: Some(rule.description),
                disclosed_at: rule.disclosed_at,
            };

            rules.push(output_rule);
        }

        let config = OutputConfig {
            schema_version: stored_config.schema_version,
            rules,
        };

        let formatted_config = self.formatter.format(&config);

        let config = ConfigResponse {
            version,
            active_since: stored_config.active_since,
            config: formatted_config,
        };

        Ok(config)
    }
}

impl<R: CanisterApi, F: ConfidentialityFormatting<Input = OutputRuleMetadata>> EntityFetcher
    for RuleFetcher<R, F>
{
    type Input = RuleId;
    type Output = OutputRuleMetadata;
    type Error = FetchRuleError;

    fn fetch(&self, rule_id: RuleId) -> Result<OutputRuleMetadata, FetchRuleError> {
        let stored_metadata = self
            .canister_api
            .get_rule(&rule_id)
            .ok_or_else(|| FetchRuleError::NotFound(rule_id.clone()))?;

        let rule_metadata = OutputRuleMetadata {
            id: rule_id.clone(),
            incident_id: stored_metadata.incident_id,
            rule_raw: Some(stored_metadata.rule_raw),
            description: Some(stored_metadata.description),
            disclosed_at: stored_metadata.disclosed_at,
            added_in_version: stored_metadata.added_in_version,
            removed_in_version: stored_metadata.removed_in_version,
        };

        let formatted_rule = self.formatter.format(&rule_metadata);

        Ok(formatted_rule)
    }
}

impl From<FetchConfigError> for String {
    fn from(value: FetchConfigError) -> Self {
        value.to_string()
    }
}

impl From<FetchRuleError> for String {
    fn from(value: FetchRuleError) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::confidentiality_formatting::MockConfidentialityFormatting;
    use crate::state::MockCanisterApi;
    use crate::storage::{StorableConfig, StorableVersion};

    use super::*;

    #[test]
    fn test_get_config_success() {
        // Arrange
        let mut mock_formatter = MockConfidentialityFormatting::new();
        mock_formatter.expect_format().returning(|_| OutputConfig {
            schema_version: 1,
            rules: vec![],
        });

        let mut mock_canister_api = MockCanisterApi::new();
        mock_canister_api
            .expect_get_version()
            .returning(|| Some(StorableVersion(1)));
        mock_canister_api.expect_get_config().returning(|_| {
            Some(StorableConfig {
                schema_version: 1,
                active_since: 1,
                rule_ids: vec![],
            })
        });

        let fetcher = ConfigFetcher::new(mock_canister_api, mock_formatter);
        // Act + assert
        fetcher.fetch(Some(1)).expect("failed to get a config");
    }
}
