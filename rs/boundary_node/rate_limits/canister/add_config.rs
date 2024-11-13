use crate::{
    storage::StorableIncidentMetadata,
    types::{self, IncidentId, InputConfigError, Timestamp},
};
use anyhow::Context;
use getrandom::getrandom;
use std::collections::{HashMap, HashSet};
use strum::AsRefStr;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    state::CanisterApi,
    storage::{StorableConfig, StorableRuleMetadata},
    types::{InputConfig, RuleId, Version},
};

pub const INIT_SCHEMA_VERSION: Version = 1;
pub const INIT_VERSION: Version = 1;

pub trait AddsConfig {
    fn add_config(
        &self,
        config: rate_limits_api::InputConfig,
        time: Timestamp,
    ) -> Result<(), AddConfigError>;
}

#[derive(Debug, Error, Clone)]
pub enum RulePolicyError {
    #[error("Rule at index={index} is linked to an already disclosed incident_id={incident_id}")]
    LinkingRuleToDisclosedIncident {
        index: usize,
        incident_id: IncidentId,
    },
}

#[derive(Debug, Error, AsRefStr)]
pub enum AddConfigError {
    #[error("Unauthorized operation")]
    #[strum(serialize = "unauthorized_error")]
    Unauthorized,
    #[error("Invalid input configuration: {0}")]
    #[strum(serialize = "invalid_input_error")]
    InvalidInput(#[from] InputConfigError),
    #[error("Rule violates policy: {0}")]
    #[strum(serialize = "policy_violation_error")]
    PolicyViolation(#[from] RulePolicyError),
    #[error("Initial version and configuration were not set")]
    #[strum(serialize = "missing_initial_version_error")]
    MissingInitialVersion,
    #[error("An unexpected internal error occurred: {0}")]
    #[strum(serialize = "internal_error")]
    Internal(#[from] anyhow::Error),
}

pub struct ConfigAdder<A> {
    pub canister_api: A,
}

impl<A> ConfigAdder<A> {
    pub fn new(canister_api: A) -> Self {
        Self { canister_api }
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

impl<A: CanisterApi> AddsConfig for ConfigAdder<A> {
    fn add_config(
        &self,
        input_config: rate_limits_api::InputConfig,
        time: Timestamp,
    ) -> Result<(), AddConfigError> {
        // Convert config from api type
        let next_config = types::InputConfig::try_from(input_config)?;

        let current_version = self
            .canister_api
            .get_version()
            .ok_or_else(|| AddConfigError::MissingInitialVersion)?;

        let next_version = current_version + 1;

        let current_config: StorableConfig = self
            .canister_api
            .get_config(current_version)
            .ok_or_else(|| AddConfigError::MissingInitialVersion)?;

        let current_full_config: InputConfig =
            self.canister_api
                .get_full_config(current_version)
                .ok_or_else(|| AddConfigError::MissingInitialVersion)?;

        // Ordered IDs of all rules in the submitted config
        let mut rule_ids = Vec::<RuleId>::new();
        // Metadata of the newly submitted rules
        let mut new_rules_metadata = Vec::<(RuleId, StorableRuleMetadata)>::new();
        // Hashmap of the submitted incident IDs
        let mut incidents_map = HashMap::<IncidentId, HashSet<RuleId>>::new();

        for (rule_idx, input_rule) in next_config.rules.iter().enumerate() {
            // Check if the rule is resubmitted or if it is a new rule
            let existing_rule_idx =
                if current_full_config.schema_version != next_config.schema_version {
                    None
                } else {
                    current_full_config
                        .rules
                        .iter()
                        .position(|rule| rule == input_rule)
                };

            let rule_id = if let Some(rule_idx) = existing_rule_idx {
                current_config.rule_ids[rule_idx]
            } else {
                // TODO: check for collisions and regenerate if needed
                let rule_id = RuleId(generate_random_uuid()?);

                // Check if the new rule is linked to an existing incident
                let existing_incident = self.canister_api.get_incident(&input_rule.incident_id);

                if let Some(incident) = existing_incident {
                    // A new rule can't be linked to a disclosed incident
                    if incident.is_disclosed {
                        Err(AddConfigError::PolicyViolation(
                            RulePolicyError::LinkingRuleToDisclosedIncident {
                                index: rule_idx,
                                incident_id: input_rule.incident_id,
                            },
                        ))?;
                    }
                }

                let rule_metadata = StorableRuleMetadata {
                    incident_id: input_rule.incident_id,
                    rule_raw: input_rule.rule_raw.clone(),
                    description: input_rule.description.clone(),
                    disclosed_at: None,
                    added_in_version: next_version,
                    removed_in_version: None,
                };

                new_rules_metadata.push((rule_id, rule_metadata));

                rule_id
            };

            incidents_map
                .entry(input_rule.incident_id)
                .or_default()
                .insert(rule_id);

            rule_ids.push(rule_id);
        }

        let removed_rule_ids = {
            let rule_ids_set: HashSet<RuleId> = HashSet::from_iter(rule_ids.clone());
            current_config
                .rule_ids
                .into_iter()
                .filter(|&rule_id| !rule_ids_set.contains(&rule_id))
                .collect()
        };

        let storable_config = StorableConfig {
            schema_version: next_config.schema_version,
            active_since: time,
            rule_ids,
        };

        commit_changes(
            &self.canister_api,
            next_version,
            storable_config,
            removed_rule_ids,
            new_rules_metadata,
            incidents_map,
        );

        Ok(())
    }
}

impl From<AddConfigError> for String {
    fn from(value: AddConfigError) -> Self {
        value.to_string()
    }
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

fn commit_changes(
    canister_api: &impl CanisterApi,
    next_version: u64,
    storable_config: StorableConfig,
    removed_rules: Vec<RuleId>,
    new_rules_metadata: Vec<(RuleId, StorableRuleMetadata)>,
    incidents_map: HashMap<IncidentId, HashSet<RuleId>>,
) {
    // Update metadata of the removed rules
    for rule_id in removed_rules {
        let mut rule_metadata = canister_api
            .get_rule(&rule_id)
            .expect("rule_id = {rule_id} not found");

        rule_metadata.removed_in_version = Some(next_version);

        assert!(
            canister_api.upsert_rule(rule_id, rule_metadata).is_some(),
            "Rule with rule_id = {rule_id} not found, failed to update"
        );
    }

    // Add new rules
    for (rule_id, rule_metadata) in new_rules_metadata {
        assert!(
            canister_api.upsert_rule(rule_id, rule_metadata).is_none(),
            "Rule with rule_id = {rule_id} already exists, failed to add"
        );
    }

    // Upsert incidents, some of the incidents can be new, some already existed before
    for (incident_id, rule_ids) in incidents_map {
        let incident_metadata = canister_api
            .get_incident(&incident_id)
            .map(|mut metadata| {
                metadata.rule_ids.extend(rule_ids.clone());
                metadata
            })
            .unwrap_or_else(|| StorableIncidentMetadata {
                is_disclosed: false,
                rule_ids: rule_ids.clone(),
            });

        let _ = canister_api.upsert_incident(incident_id, incident_metadata);
    }

    assert!(
        canister_api
            .upsert_config(next_version, storable_config)
            .is_none(),
        "Failed to add config for version {next_version}, config already exists"
    );
}

#[cfg(test)]
mod tests {
    use crate::access_control::{AccessLevel, MockResolveAccessLevel};
    use crate::state::MockCanisterApi;

    use super::*;

    #[test]
    fn test_add_config_success() {
        let config = rate_limits_api::InputConfig {
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
        mock_canister_api.expect_get_version().returning(|| Some(1));
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
        mock_canister_api
            .expect_upsert_config()
            .returning(|_, _| None);

        let writer = ConfigAdder::new(mock_canister_api);

        writer
            .add_config(config, current_time)
            .expect("failed to add a new config");
    }
}
