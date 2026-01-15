use crate::{
    access_control::{AccessLevel, ResolveAccessLevel},
    confidentiality_formatting::ConfidentialityFormatting,
    state::CanisterApi,
    types::{
        GetConfigError, GetEntityError, IncidentId, OutputConfig, OutputRule, OutputRuleMetadata,
        RuleId, Version,
    },
};

use rate_limits_api as api;

/// Defines a generic trait for fetching various types of entities (e.g. config, rules, incidents)
pub trait EntityGetter {
    /// The type of input required to fetch an entity (e.g. RuleId, IncidentId, etc.)
    type Input;
    /// The type of entity being fetched (e.g. Rule, Incident, Config)
    type Output;
    /// The type of error that may occur during fetching
    type Error;

    fn get(&self, input: &Self::Input) -> Result<Self::Output, Self::Error>;
}

/// A structure for fetching the rate-limit configuration
pub struct ConfigGetter<R, F, A> {
    /// The canister API used for interacting with the underlying storage
    pub canister_api: R,
    /// The confidentiality formatter instance responsible for redacting non-disclosed data
    pub formatter: F,
    /// The access resolver instance responsible for authorization
    pub access_resolver: A,
}

/// A structure for fetching the rate-limit rule
pub struct RuleGetter<R, F, A> {
    /// The canister API used for interacting with the underlying storage
    pub canister_api: R,
    /// The confidentiality formatter instance responsible for redacting non-disclosed data
    pub formatter: F,
    /// The access resolver instance responsible for authorization
    pub access_resolver: A,
}

/// A structure for fetching the incident
pub struct IncidentGetter<R, F, A> {
    /// The canister API used for interacting with the underlying storage
    pub canister_api: R,
    /// The confidentiality formatter instance responsible for redacting non-disclosed data
    pub formatter: F,
    /// The access resolver instance responsible for authorization
    pub access_resolver: A,
}

impl<R, F, A> ConfigGetter<R, F, A> {
    pub fn new(canister_api: R, formatter: F, access_resolver: A) -> Self {
        Self {
            canister_api,
            formatter,
            access_resolver,
        }
    }
}

impl<R, F, A> RuleGetter<R, F, A> {
    pub fn new(canister_api: R, formatter: F, access_resolver: A) -> Self {
        Self {
            canister_api,
            formatter,
            access_resolver,
        }
    }
}

impl<R, F, A> IncidentGetter<R, F, A> {
    pub fn new(canister_api: R, formatter: F, access_resolver: A) -> Self {
        Self {
            canister_api,
            formatter,
            access_resolver,
        }
    }
}

impl<R: CanisterApi, F: ConfidentialityFormatting<Input = OutputConfig>, A: ResolveAccessLevel>
    EntityGetter for ConfigGetter<R, F, A>
{
    type Input = Option<Version>;
    type Output = api::ConfigResponse;
    type Error = GetConfigError;

    fn get(&self, version: &Option<Version>) -> Result<Self::Output, Self::Error> {
        let latest_version = self
            .canister_api
            .get_version()
            .ok_or_else(|| GetConfigError::NoExistingConfigsFound)?;

        let version = version.unwrap_or(latest_version);

        let stored_config = self
            .canister_api
            .get_config(version)
            .ok_or_else(|| GetConfigError::NotFound(version))?;

        let mut rules: Vec<OutputRule> = vec![];

        for rule_id in stored_config.rule_ids.iter() {
            let rule = self.canister_api.get_rule(rule_id).ok_or_else(|| {
                // This error should never happen, it means that the stored data is inconsistent.
                GetConfigError::Internal(anyhow::anyhow!("Rule with id={rule_id} not found"))
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

        let config = OutputConfig {
            schema_version: stored_config.schema_version,
            is_redacted: false,
            rules,
        };

        let is_authorized_viewer = self.access_resolver.get_access_level()
            == AccessLevel::FullAccess
            || self.access_resolver.get_access_level() == AccessLevel::FullRead;

        if is_authorized_viewer {
            return Ok(api::ConfigResponse {
                version,
                active_since: stored_config.active_since,
                config: config.into(),
            });
        }

        // Hide non-disclosed rules from unauthorized viewers.
        Ok(api::ConfigResponse {
            version,
            active_since: stored_config.active_since,
            config: self.formatter.format(config).into(),
        })
    }
}

impl<
    R: CanisterApi,
    F: ConfidentialityFormatting<Input = OutputRuleMetadata>,
    A: ResolveAccessLevel,
> EntityGetter for IncidentGetter<R, F, A>
{
    type Input = api::IncidentId;
    type Output = Vec<api::OutputRuleMetadata>;
    type Error = GetEntityError;

    fn get(&self, incident_id: &Self::Input) -> Result<Self::Output, Self::Error> {
        let incident_id = IncidentId::try_from(incident_id.clone())
            .map_err(|_| GetEntityError::InvalidUuidFormat(incident_id.clone()))?;

        let stored_incident = self
            .canister_api
            .get_incident(&incident_id)
            .ok_or_else(|| GetEntityError::NotFound(incident_id.0.to_string()))?;

        let is_authorized_viewer = self.access_resolver.get_access_level()
            == AccessLevel::FullAccess
            || self.access_resolver.get_access_level() == AccessLevel::FullRead;

        let mut output_rules = Vec::with_capacity(stored_incident.rule_ids.len());

        for rule_id in stored_incident.rule_ids.into_iter() {
            let stored_rule = self.canister_api.get_rule(&rule_id).ok_or_else(|| {
                // This error should never happen, it means that the stored data is inconsistent.
                GetEntityError::Internal(anyhow::anyhow!("Rule with id={rule_id} not found"))
            })?;

            let output_rule = OutputRuleMetadata {
                id: rule_id,
                incident_id,
                rule_raw: Some(stored_rule.rule_raw),
                description: Some(stored_rule.description),
                disclosed_at: stored_rule.disclosed_at,
                added_in_version: stored_rule.added_in_version,
                removed_in_version: stored_rule.removed_in_version,
            };

            if is_authorized_viewer {
                output_rules.push(output_rule.into());
            } else {
                // Hide non-disclosed rule from unauthorized viewers.
                let output_rule = self.formatter.format(output_rule);
                output_rules.push(output_rule.into());
            }
        }

        Ok(output_rules)
    }
}

impl<
    R: CanisterApi,
    F: ConfidentialityFormatting<Input = OutputRuleMetadata>,
    A: ResolveAccessLevel,
> EntityGetter for RuleGetter<R, F, A>
{
    type Input = api::RuleId;
    type Output = api::OutputRuleMetadata;
    type Error = GetEntityError;

    fn get(&self, rule_id: &Self::Input) -> Result<Self::Output, Self::Error> {
        let rule_id = RuleId::try_from(rule_id.clone())
            .map_err(|_| GetEntityError::InvalidUuidFormat(rule_id.clone()))?;

        let stored_rule = self
            .canister_api
            .get_rule(&rule_id)
            .ok_or_else(|| GetEntityError::NotFound(rule_id.0.to_string()))?;

        let output_rule = OutputRuleMetadata {
            id: rule_id,
            incident_id: stored_rule.incident_id,
            rule_raw: Some(stored_rule.rule_raw),
            description: Some(stored_rule.description),
            disclosed_at: stored_rule.disclosed_at,
            added_in_version: stored_rule.added_in_version,
            removed_in_version: stored_rule.removed_in_version,
        };

        let is_authorized_viewer = self.access_resolver.get_access_level()
            == AccessLevel::FullAccess
            || self.access_resolver.get_access_level() == AccessLevel::FullRead;

        if is_authorized_viewer {
            return Ok(output_rule.into());
        }

        // Hide non-disclosed rules from unauthorized viewers.
        let output_rule = self.formatter.format(output_rule);

        Ok(output_rule.into())
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::access_control::MockResolveAccessLevel;
    use crate::confidentiality_formatting::{
        ConfigConfidentialityFormatter, RuleConfidentialityFormatter,
    };
    use crate::state::CanisterState;
    use crate::storage::{StorableConfig, StorableIncident, StorableRule};
    use std::collections::HashSet;

    use super::*;

    fn create_mock_access_resolver(level: AccessLevel) -> MockResolveAccessLevel {
        let mut access_resolver = MockResolveAccessLevel::new();
        access_resolver
            .expect_get_access_level()
            .returning(move || level.clone());
        access_resolver
    }

    #[test]
    fn test_get_config_success() {
        // Arrange
        let canister_state = CanisterState::from_static();

        let version = 1;
        let active_since = 2;
        let schema_version = 3;
        let rule_id_1 = RuleId(Uuid::new_v4());
        let rule_id_2 = RuleId(Uuid::new_v4());
        let incident_id = IncidentId(Uuid::new_v4());

        canister_state.add_config(
            version,
            StorableConfig {
                active_since,
                rule_ids: vec![rule_id_1, rule_id_2],
                schema_version,
            },
        );

        // One rule is not disclosed
        canister_state.upsert_rule(
            rule_id_1,
            StorableRule {
                incident_id,
                rule_raw: b"{\"a\": 1}".to_vec(),
                description: "verbose description 1".to_string(),
                disclosed_at: None,
                added_in_version: 1,
                removed_in_version: Some(3),
            },
        );

        // One rule is disclosed
        canister_state.upsert_rule(
            rule_id_2,
            StorableRule {
                incident_id,
                rule_raw: b"{\"b\": 2}".to_vec(),
                description: "verbose description 2".to_string(),
                disclosed_at: Some(1),
                added_in_version: 2,
                removed_in_version: Some(5),
            },
        );

        let getter_authorized = ConfigGetter::new(
            canister_state.clone(),
            ConfigConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::FullAccess),
        );
        let getter_unauthorized = ConfigGetter::new(
            canister_state,
            ConfigConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::RestrictedRead),
        );

        // Act & assert
        let response = getter_authorized.get(&Some(1)).unwrap();
        // config is non-redacted and rules are fully shown
        assert_eq!(
            response,
            api::ConfigResponse {
                version,
                active_since,
                config: api::OutputConfig {
                    schema_version,
                    is_redacted: false,
                    rules: vec![
                        api::OutputRule {
                            rule_id: rule_id_1.0.to_string(),
                            incident_id: incident_id.0.to_string(),
                            rule_raw: Some(b"{\"a\": 1}".to_vec()),
                            description: Some("verbose description 1".to_string()),
                        },
                        api::OutputRule {
                            rule_id: rule_id_2.0.to_string(),
                            incident_id: incident_id.0.to_string(),
                            rule_raw: Some(b"{\"b\": 2}".to_vec()),
                            description: Some("verbose description 2".to_string()),
                        }
                    ]
                }
            }
        );

        let response = getter_unauthorized.get(&Some(1)).unwrap();
        // config is redacted and non-disclosed rules are hidden
        assert_eq!(
            response,
            api::ConfigResponse {
                version,
                active_since,
                config: api::OutputConfig {
                    schema_version,
                    is_redacted: true,
                    rules: vec![
                        api::OutputRule {
                            rule_id: rule_id_1.0.to_string(),
                            incident_id: incident_id.0.to_string(),
                            rule_raw: None,
                            description: None,
                        },
                        api::OutputRule {
                            rule_id: rule_id_2.0.to_string(),
                            incident_id: incident_id.0.to_string(),
                            rule_raw: Some(b"{\"b\": 2}".to_vec()),
                            description: Some("verbose description 2".to_string()),
                        }
                    ]
                }
            }
        );
    }

    #[test]
    fn test_get_rule_success() {
        // Arrange
        let canister_state = CanisterState::from_static();

        let rule_id = RuleId(Uuid::new_v4());
        let incident_id = IncidentId(Uuid::new_v4());

        canister_state.upsert_rule(
            rule_id,
            StorableRule {
                incident_id,
                rule_raw: b"{\"a\": 1}".to_vec(),
                description: "verbose description".to_string(),
                disclosed_at: None,
                added_in_version: 1,
                removed_in_version: Some(3),
            },
        );

        let getter_authorized = RuleGetter::new(
            canister_state.clone(),
            RuleConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::FullAccess),
        );
        let getter_unauthorized = RuleGetter::new(
            canister_state,
            RuleConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::RestrictedRead),
        );

        // Act & assert
        let response = getter_authorized.get(&rule_id.0.to_string()).unwrap();
        // rule is fully shown
        assert_eq!(
            response,
            api::OutputRuleMetadata {
                rule_id: rule_id.0.to_string(),
                incident_id: incident_id.0.to_string(),
                rule_raw: Some(b"{\"a\": 1}".to_vec()),
                description: Some("verbose description".to_string()),
                disclosed_at: None,
                added_in_version: 1,
                removed_in_version: Some(3),
            }
        );
        let response = getter_unauthorized.get(&rule_id.0.to_string()).unwrap();
        // rule fields are hidden
        assert_eq!(
            response,
            api::OutputRuleMetadata {
                rule_id: rule_id.0.to_string(),
                incident_id: incident_id.0.to_string(),
                rule_raw: None,
                description: None,
                disclosed_at: None,
                added_in_version: 1,
                removed_in_version: Some(3),
            }
        );
    }

    #[test]
    fn test_get_incident_success() {
        // Arrange
        let canister_state = CanisterState::from_static();

        // Two rules are linked to one incident
        let rule_id_1 = RuleId(Uuid::new_v4());
        let rule_id_2 = RuleId(Uuid::new_v4());
        let incident_id = IncidentId(Uuid::new_v4());

        // One rule is not disclosed
        canister_state.upsert_rule(
            rule_id_1,
            StorableRule {
                incident_id,
                rule_raw: b"{\"a\": 1}".to_vec(),
                description: "verbose description 1".to_string(),
                disclosed_at: None,
                added_in_version: 1,
                removed_in_version: Some(3),
            },
        );
        // One rule is disclosed
        canister_state.upsert_rule(
            rule_id_2,
            StorableRule {
                incident_id,
                rule_raw: b"{\"b\": 2}".to_vec(),
                description: "verbose description 2".to_string(),
                disclosed_at: Some(1),
                added_in_version: 2,
                removed_in_version: Some(5),
            },
        );
        canister_state.upsert_incident(
            incident_id,
            StorableIncident {
                is_disclosed: false,
                rule_ids: HashSet::from_iter(vec![rule_id_1, rule_id_2]),
            },
        );

        let getter_unauthorized = IncidentGetter::new(
            canister_state,
            RuleConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::RestrictedRead),
        );

        // Act & assert
        let response = getter_unauthorized.get(&incident_id.0.to_string()).unwrap();

        let rule_1 = api::OutputRuleMetadata {
            rule_id: rule_id_1.0.to_string(),
            incident_id: incident_id.0.to_string(),
            rule_raw: None,
            description: None,
            disclosed_at: None,
            added_in_version: 1,
            removed_in_version: Some(3),
        };
        let rule_2 = api::OutputRuleMetadata {
            rule_id: rule_id_2.0.to_string(),
            incident_id: incident_id.0.to_string(),
            rule_raw: Some(b"{\"b\": 2}".to_vec()),
            description: Some("verbose description 2".to_string()),
            disclosed_at: Some(1),
            added_in_version: 2,
            removed_in_version: Some(5),
        };
        // rules are not ordered in the response, so just search
        assert!(response.contains(&rule_1));
        assert!(response.contains(&rule_2));
    }

    #[test]
    fn test_get_config_with_no_existing_configs_fails() {
        // Arrange
        let canister_state = CanisterState::from_static(); // empty state

        let getter = ConfigGetter::new(
            canister_state,
            ConfigConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::RestrictedRead),
        );

        // Act & assert
        let error = getter.get(&None).unwrap_err();
        assert!(matches!(error, GetConfigError::NoExistingConfigsFound));
    }

    #[test]
    fn test_get_config_with_version_not_found_fails() {
        // Arrange
        let canister_state = CanisterState::from_static();
        canister_state.add_config(
            1,
            StorableConfig {
                schema_version: 1,
                active_since: 1,
                rule_ids: vec![],
            },
        );

        let getter = ConfigGetter::new(
            canister_state,
            ConfigConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::RestrictedRead),
        );

        // Act & assert
        let error = getter.get(&Some(2)).unwrap_err();
        assert!(matches!(error, GetConfigError::NotFound(version) if version == 2));
    }

    #[test]
    fn test_get_not_found_fails() {
        // Arrange
        let canister_state = CanisterState::from_static(); // empty state
        let rule_id = "f63c821c-9320-476a-bc89-94cb99d04639".to_string();
        let incident_id = "f63c821c-9320-476a-bc89-94cb99d04639".to_string();

        let rule_getter = RuleGetter::new(
            canister_state.clone(),
            RuleConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::RestrictedRead),
        );
        let incident_getter = IncidentGetter::new(
            canister_state,
            RuleConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::RestrictedRead),
        );

        // Act & assert
        let error = rule_getter.get(&rule_id).unwrap_err();
        assert!(matches!(error, GetEntityError::NotFound(id) if id == rule_id));
        let error = incident_getter.get(&incident_id).unwrap_err();
        assert!(matches!(error, GetEntityError::NotFound(id) if id == incident_id));
    }

    #[test]
    fn test_get_with_invalid_uuid_fails() {
        // Arrange
        let canister_state = CanisterState::from_static(); // empty state
        let input_id = "invalid_uuid".to_string();

        let rule_getter = RuleGetter::new(
            canister_state.clone(),
            RuleConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::FullAccess),
        );
        let incident_getter = IncidentGetter::new(
            canister_state,
            RuleConfidentialityFormatter,
            create_mock_access_resolver(AccessLevel::FullAccess),
        );

        // Act & assert
        let error = rule_getter.get(&input_id).unwrap_err();
        assert!(matches!(error, GetEntityError::InvalidUuidFormat(id) if id == input_id));
        let error = incident_getter.get(&input_id).unwrap_err();
        assert!(matches!(error, GetEntityError::InvalidUuidFormat(id) if id == input_id));
    }
}
