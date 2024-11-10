use crate::{
    access_control::{AccessLevel, ResolveAccessLevel},
    confidentiality_formatting::ConfidentialityFormatting,
    state::CanisterApi,
    types::{OutputConfig, OutputRule, OutputRuleMetadata, RuleId, Version},
};

pub trait EntityFetcher {
    type Input;
    type Output;
    type Error;

    fn fetch(&self, input: Self::Input) -> Result<Self::Output, Self::Error>;
}

pub struct ConfigFetcher<R, F, A> {
    pub canister_api: R,
    pub formatter: F,
    pub access_resolver: A,
}

pub struct RuleFetcher<R, F, A> {
    pub canister_api: R,
    pub formatter: F,
    pub access_resolver: A,
}

impl<R, F, A> ConfigFetcher<R, F, A> {
    pub fn new(canister_api: R, formatter: F, access_resolver: A) -> Self {
        Self {
            canister_api,
            formatter,
            access_resolver,
        }
    }
}

impl<R, F, A> RuleFetcher<R, F, A> {
    pub fn new(canister_api: R, formatter: F, access_resolver: A) -> Self {
        Self {
            canister_api,
            formatter,
            access_resolver,
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
    #[error("Rule with id = {0} not found")]
    NotFound(String),
    #[error("The provided id = {0} is not a valid UUID")]
    InvalidUuidFormat(String),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl<R: CanisterApi, F: ConfidentialityFormatting<Input = OutputConfig>, A: ResolveAccessLevel>
    EntityFetcher for ConfigFetcher<R, F, A>
{
    type Input = Option<Version>;
    type Output = rate_limits_api::ConfigResponse;
    type Error = FetchConfigError;

    fn fetch(
        &self,
        version: Option<Version>,
    ) -> Result<rate_limits_api::ConfigResponse, FetchConfigError> {
        let current_version = self
            .canister_api
            .get_version()
            .ok_or_else(|| FetchConfigError::NoExistingVersions)?;

        let version = version.unwrap_or(current_version);

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
                id: *rule_id,
                incident_id: rule.incident_id,
                rule_raw: Some(rule.rule_raw),
                description: Some(rule.description),
                disclosed_at: rule.disclosed_at,
            };

            rules.push(output_rule);
        }

        let mut config = OutputConfig {
            schema_version: stored_config.schema_version,
            rules,
        };

        let is_authorized_viewer = self.access_resolver.get_access_level()
            == AccessLevel::FullAccess
            || self.access_resolver.get_access_level() == AccessLevel::FullRead;

        if !is_authorized_viewer {
            config = self.formatter.format(&config);
        }

        let config = rate_limits_api::ConfigResponse {
            version,
            active_since: stored_config.active_since,
            config: config.into(),
        };

        Ok(config)
    }
}

impl<
        R: CanisterApi,
        F: ConfidentialityFormatting<Input = OutputRuleMetadata>,
        A: ResolveAccessLevel,
    > EntityFetcher for RuleFetcher<R, F, A>
{
    type Input = rate_limits_api::RuleId;
    type Output = rate_limits_api::OutputRuleMetadata;
    type Error = FetchRuleError;

    fn fetch(
        &self,
        rule_id: rate_limits_api::RuleId,
    ) -> Result<rate_limits_api::OutputRuleMetadata, FetchRuleError> {
        let rule_id = RuleId::try_from(rule_id.clone())
            .map_err(|_| FetchRuleError::InvalidUuidFormat(rule_id))?;

        let stored_metadata = self
            .canister_api
            .get_rule(&rule_id)
            .ok_or_else(|| FetchRuleError::NotFound(rule_id.0.to_string()))?;

        let mut rule_metadata = OutputRuleMetadata {
            id: rule_id,
            incident_id: stored_metadata.incident_id,
            rule_raw: Some(stored_metadata.rule_raw),
            description: Some(stored_metadata.description),
            disclosed_at: stored_metadata.disclosed_at,
            added_in_version: stored_metadata.added_in_version,
            removed_in_version: stored_metadata.removed_in_version,
        };

        let is_authorized_viewer = self.access_resolver.get_access_level()
            == AccessLevel::FullAccess
            || self.access_resolver.get_access_level() == AccessLevel::FullRead;

        if !is_authorized_viewer {
            rule_metadata = self.formatter.format(&rule_metadata);
        }

        Ok(rule_metadata.into())
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
    use crate::access_control::MockResolveAccessLevel;
    use crate::confidentiality_formatting::MockConfidentialityFormatting;
    use crate::state::MockCanisterApi;
    use crate::storage::StorableConfig;

    use super::*;

    #[test]
    fn test_get_config_success() {
        // Arrange
        let mut mock_access = MockResolveAccessLevel::new();
        mock_access
            .expect_get_access_level()
            .returning(|| AccessLevel::FullAccess);

        let mut mock_formatter = MockConfidentialityFormatting::new();
        mock_formatter.expect_format().returning(|_| OutputConfig {
            schema_version: 1,
            rules: vec![],
        });

        let mut mock_canister_api = MockCanisterApi::new();
        mock_canister_api.expect_get_version().returning(|| Some(1));
        mock_canister_api.expect_get_config().returning(|_| {
            Some(StorableConfig {
                schema_version: 1,
                active_since: 1,
                rule_ids: vec![],
            })
        });

        let fetcher = ConfigFetcher::new(mock_canister_api, mock_formatter, mock_access);
        // Act + assert
        fetcher.fetch(Some(1)).expect("failed to get a config");
    }
}
