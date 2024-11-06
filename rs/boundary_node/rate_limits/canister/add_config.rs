use crate::{
    storage::StorableIncidentMetadata,
    types::{SchemaVersion, Timestamp},
};
use anyhow::Context;
use getrandom::getrandom;
use rate_limits_api::IncidentId;
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    access_control::{AccessLevel, ResolveAccessLevel},
    state::CanisterApi,
    storage::{StorableConfig, StorableRuleMetadata},
    types::{InputConfig, RuleId, Version},
};

pub const INIT_VERSION: Version = 1;
pub const INIT_SCHEMA_VERSION: SchemaVersion = 1;

pub trait AddsConfig {
    fn add_config(&self, config: InputConfig, time: Timestamp) -> Result<(), AddConfigError>;
}

#[derive(Debug, Error, Clone)]
pub enum RulePolicyError {
    #[error("Rule at index={index} is linked to an already disclosed incident_id={incident_id}")]
    LinkingRuleToDisclosedIncident {
        index: usize,
        incident_id: IncidentId,
    },
}

#[derive(Debug, Error)]
pub enum AddConfigError {
    #[error("Rule at index = {0} doesn't encode a valid JSON object")]
    RuleJsonEncodingError(usize),
    #[error("Rule violates policy: {0}")]
    RulePolicyViolation(#[from] RulePolicyError),
    #[error("Configuration for version={0} was not found")]
    NoConfigFound(Version),
    #[error("Unauthorized operation")]
    Unauthorized,
    #[error("An unexpected error occurred: {0}")]
    Unexpected(#[from] anyhow::Error),
}

pub struct ConfigAdder<R, A> {
    pub canister_api: R,
    pub access_resolver: A,
}

impl<R, A> ConfigAdder<R, A> {
    pub fn new(canister_api: R, access_resolver: A) -> Self {
        Self {
            canister_api,
            access_resolver,
        }
    }
}

// Definitions:
// - A rate-limit config is an ordered set of rate-limit rules: config = [rule_1, rule_2, ..., rule_N].
// - Rules order within a config is significant, as rules are applied in the order they appear in the config.
// - Adding a new config requires providing an entire list of ordered rules; config version is increment by one for 'add' operation.
// - Each rule is identified by its unique ID and its non-mutable context provided by the caller:
//   - incident_id: each rule must be linked to a certain incident_id; multiple rules can be linked to the same incident_id
//   - rule_raw: binary encoded JSON of the rate-limit rule
//   - description: some info why this rule was introduced
// - Alongside an immutable context, each rule includes metadata:
//   - disclosed_at
//   - added_in_version
//   - removed_in_version
// - The canister generates a unique, random ID for each newly submitted rule.
// - Rules can persist across config versions, if resubmitted.
// - Non-resubmitted rules are considered as "removed" and their metadata fields are updated.
// - Individual rules or incidents (a set of rules sharing the same incident_id) can be disclosed. This implies that the context of the rule becomes visible for the callers with `RestrictedRead` access level.
// - Disclosing rules or incidents multiple times has no additional effect.

// Policies:
// - Immutability: rule's context (incident_id, rule_raw, description) cannot be modified.
// - Operation of resubmitting a "removed" rule would result in creation of a rule with a new ID.
// - New rules cannot be linked to already disclosed incidents (LinkingRuleToDisclosedIncident error)

impl<R: CanisterApi, A: ResolveAccessLevel> AddsConfig for ConfigAdder<R, A> {
    fn add_config(&self, new_config: InputConfig, time: Timestamp) -> Result<(), AddConfigError> {
        // Only privileged users can perform this operation
        if self.access_resolver.get_access_level() != AccessLevel::FullAccess {
            return Err(AddConfigError::Unauthorized);
        }

        // Verify that all rules in the config are valid JSON-encoded blobs
        validate_config_encoding(&new_config)?;

        let current_version = self
            .canister_api
            .get_version()
            .unwrap_or(INIT_VERSION.into())
            .0;

        let new_version = current_version + 1;

        let current_config: StorableConfig = self
            .canister_api
            .get_config(current_version)
            .ok_or_else(|| AddConfigError::NoConfigFound(current_version))?;

        let current_full_config: InputConfig =
            self.canister_api
                .get_full_config(current_version)
                .ok_or_else(|| AddConfigError::NoConfigFound(current_version))?;

        // IDs of all rules in the submitted config
        let mut rule_ids = Vec::<RuleId>::new();
        // Metadata of the newly submitted rules
        let mut new_rules_metadata = Vec::<(RuleId, StorableRuleMetadata)>::new();
        // Hashmap of the newly submitted incident IDs
        let mut new_incidents = HashMap::<IncidentId, Vec<RuleId>>::new();
        // Hashmap of the already existing incident IDs
        let mut existing_incidents = HashMap::<IncidentId, Vec<RuleId>>::new();

        for (rule_idx, input_rule) in new_config.rules.iter().enumerate() {
            // Check if the rule is resubmitted or if it is a new rule
            let existing_rule_idx =
                if current_full_config.schema_version != new_config.schema_version {
                    None
                } else {
                    current_full_config
                        .rules
                        .iter()
                        .position(|rule| rule == input_rule)
                };

            let rule_id = if let Some(rule_idx) = existing_rule_idx {
                let rule_id = current_config.rule_ids[rule_idx].clone();

                existing_incidents
                    .entry(input_rule.incident_id.clone())
                    .and_modify(|value| value.push(rule_id.clone()))
                    .or_insert(vec![rule_id.clone()]);

                rule_id
            } else {
                // TODO: check for collisions and regenerate if needed
                let rule_id = generate_random_uuid()?.to_string();

                // Check if the new rule is linked to an existing incident
                let existing_incident = self.canister_api.get_incident(&input_rule.incident_id);

                if let Some(incident) = existing_incident {
                    // A new rule can't be linked to a disclosed incident
                    if incident.is_disclosed {
                        Err(AddConfigError::RulePolicyViolation(
                            RulePolicyError::LinkingRuleToDisclosedIncident {
                                index: rule_idx,
                                incident_id: input_rule.incident_id.clone(),
                            },
                        ))?;
                    }
                    existing_incidents
                        .entry(input_rule.incident_id.clone())
                        .and_modify(|value| value.push(rule_id.clone()))
                        .or_insert(vec![rule_id.clone()]);
                } else {
                    new_incidents
                        .entry(input_rule.incident_id.clone())
                        .and_modify(|value| value.push(rule_id.clone()))
                        .or_insert(vec![rule_id.clone()]);
                }

                let rule_metadata = StorableRuleMetadata {
                    incident_id: input_rule.incident_id.clone(),
                    rule_raw: input_rule.rule_raw.clone(),
                    description: input_rule.description.clone(),
                    disclosed_at: None,
                    added_in_version: new_version,
                    removed_in_version: None,
                };

                new_rules_metadata.push((rule_id.clone(), rule_metadata));

                rule_id
            };

            rule_ids.push(rule_id);
        }

        // Commit all changes to stable memory.
        // Note: if any operation below fails canister state can become inconsistent.
        // TODO: maybe it is better to panic to rollback changes

        // Update metadata of the "removed" rules
        for rule_id in current_config.rule_ids.iter() {
            // ID is not present in the submitted rule IDs, thus this rule is removed
            if !rule_ids.iter().any(|id| id == rule_id) {
                if let Some(mut metadata) = self.canister_api.get_rule(rule_id) {
                    metadata.removed_in_version = Some(new_version);
                    if !self.canister_api.update_rule(rule_id.clone(), metadata) {
                        return Err(AddConfigError::Unexpected(anyhow::anyhow!(
                            "rule_id={rule_id} didn't exist, failed to update rule"
                        )));
                    }
                }
            }
        }

        // Add new rules
        for (rule_id, metadata) in new_rules_metadata.iter().cloned() {
            if !self.canister_api.add_rule(rule_id.clone(), metadata) {
                return Err(AddConfigError::Unexpected(anyhow::anyhow!(
                    "rule_id={rule_id} already existed, failed to add rule"
                )));
            }
        }

        // Add new incidents
        for (incident_id, rule_ids) in new_incidents {
            let incident_metadata = StorableIncidentMetadata {
                is_disclosed: false,
                rule_ids,
            };
            if !self
                .canister_api
                .add_incident(incident_id.clone(), incident_metadata)
            {
                return Err(AddConfigError::Unexpected(anyhow::anyhow!(
                    "incident_id={incident_id} already exists, failed to add incident"
                )));
            }
        }

        // Update rule IDs for existing incidents
        for (incident_id, rule_ids) in existing_incidents {
            if let Some(mut incident_metadata) = self.canister_api.get_incident(&incident_id) {
                incident_metadata.rule_ids = rule_ids;
                if !self
                    .canister_api
                    .update_incident(incident_id.clone(), incident_metadata)
                {
                    return Err(AddConfigError::Unexpected(anyhow::anyhow!(
                        "incident={incident_id} doesn't exist, failed to update"
                    )));
                }
            }
        }

        // Add new config
        let storable_config = StorableConfig {
            schema_version: new_config.schema_version,
            active_since: time,
            rule_ids,
        };

        if !self.canister_api.add_config(new_version, storable_config) {
            return Err(AddConfigError::Unexpected(anyhow::anyhow!(
                "Config for version {new_version} already exists, failed to add"
            )));
        }

        Ok(())
    }
}

impl From<AddConfigError> for String {
    fn from(value: AddConfigError) -> Self {
        value.to_string()
    }
}

fn validate_config_encoding(config: &InputConfig) -> Result<(), AddConfigError> {
    for (idx, rule) in config.rules.iter().enumerate() {
        serde_json::from_slice::<Value>(rule.rule_raw.as_slice())
            .map_err(|_| AddConfigError::RuleJsonEncodingError(idx))?;
    }
    Ok(())
}

// TODO: make it work with canister upgrade, post_upgrade
fn generate_random_uuid() -> Result<Uuid, anyhow::Error> {
    let mut buf = [0u8; 16];
    getrandom(&mut buf)
        .map_err(|e| anyhow::anyhow!(e))
        .context("Failed to generate random bytes")?;
    let uuid = Uuid::from_slice(&buf).context("Failed to create UUID from bytes")?;
    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use crate::access_control::MockResolveAccessLevel;
    use crate::state::MockCanisterApi;

    use super::*;

    #[test]
    fn test_add_config_success() {
        let config = InputConfig {
            schema_version: 1,
            rules: vec![],
        };
        let current_time = 0u64;

        let mut mock_access = MockResolveAccessLevel::new();
        mock_access
            .expect_get_access_level()
            .returning(|| AccessLevel::FullAccess);
        let mut mock_canister_api = MockCanisterApi::new();

        mock_canister_api.expect_get_rule().returning(|_| None);
        mock_canister_api.expect_get_version().returning(|| None);
        mock_canister_api.expect_get_config().returning(|_| {
            Some(StorableConfig {
                schema_version: 1,
                active_since: 1,
                rule_ids: vec![],
            })
        });
        mock_canister_api.expect_get_full_config().returning(|_| {
            Some(InputConfig {
                schema_version: 1,
                rules: vec![],
            })
        });
        mock_canister_api.expect_add_config().returning(|_, _| true);

        let writer = ConfigAdder::new(mock_canister_api, mock_access);

        writer
            .add_config(config, current_time)
            .expect("failed to add a new config");
    }
}
