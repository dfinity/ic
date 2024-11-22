use crate::{
    state::CanisterApi,
    types::{DiscloseRulesArg, DiscloseRulesError, IncidentId, RuleId, Timestamp},
};

/// Defines a trait for disclosing rules, enabling them to be publicly accessible.
pub trait DisclosesRules {
    /// # Arguments
    /// * `arg` - the argument specifying which rules or incidents to be disclosed
    /// * `disclosure_time` - the timestamp to use for disclosure
    ///
    /// # Returns
    /// A result indicating success or a specific disclosure error
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
        disclosure_time: Timestamp,
    ) -> Result<(), DiscloseRulesError>;
}

/// Struct responsible for managing rules disclosure operations
pub struct RulesDiscloser<A> {
    /// The canister API used for interacting with the underlying storage
    pub canister_api: A,
}

impl<A> RulesDiscloser<A> {
    pub fn new(canister_api: A) -> Self {
        Self { canister_api }
    }
}

impl<A: CanisterApi> DisclosesRules for RulesDiscloser<A> {
    /// Handles disclosure for both individual rule IDs and incident IDs
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
        disclosure_time: Timestamp,
    ) -> Result<(), DiscloseRulesError> {
        // Convert the input argument and handle specific disclosure scenarios
        let arg = DiscloseRulesArg::try_from(arg)?;

        match arg {
            DiscloseRulesArg::RuleIds(rule_ids) => {
                disclose_rules(&self.canister_api, disclosure_time, &rule_ids)?;
            }
            DiscloseRulesArg::IncidentIds(incident_ids) => {
                disclose_incidents(&self.canister_api, disclosure_time, &incident_ids)?;
            }
        }
        Ok(())
    }
}

/// Discloses specified rules by their IDs
fn disclose_rules(
    canister_api: &impl CanisterApi,
    time: Timestamp,
    rule_ids: &[RuleId],
) -> Result<(), DiscloseRulesError> {
    let mut rules = Vec::with_capacity(rule_ids.len());

    // Validate and collect rules, failing fast on first missing rule
    for rule_id in rule_ids.iter() {
        let rule = canister_api
            .get_rule(rule_id)
            .ok_or_else(|| DiscloseRulesError::RuleIdNotFound(*rule_id))?;
        rules.push((rule_id, rule));
    }

    // Update disclosed rules, marking them with current timestamp
    for (rule_id, mut rule) in rules {
        if rule.disclosed_at.is_none() {
            rule.disclosed_at = Some(time);
            canister_api.upsert_rule(*rule_id, rule);
        }
    }

    Ok(())
}

/// Discloses incidents and their associated rules
fn disclose_incidents(
    canister_api: &impl CanisterApi,
    time: Timestamp,
    incident_ids: &[IncidentId],
) -> Result<(), DiscloseRulesError> {
    let mut incidents: Vec<(_, _)> = Vec::with_capacity(incident_ids.len());

    // Validate and collect incidents, failing fast on first missing incident
    for incident_id in incident_ids.iter() {
        let incident = canister_api
            .get_incident(incident_id)
            .ok_or_else(|| DiscloseRulesError::IncidentIdNotFound(*incident_id))?;
        incidents.push((*incident_id, incident));
    }

    // Disclose incidents and their associated rules
    for (incident_id, mut incident) in incidents {
        if !incident.is_disclosed {
            // Ensure all associated rules are disclosed first
            let rule_ids: Vec<RuleId> = incident.rule_ids.iter().cloned().collect();
            disclose_rules(canister_api, time, &rule_ids)?;
            // Mark incident as disclosed too
            incident.is_disclosed = true;
            canister_api.upsert_incident(incident_id, incident);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    use crate::disclose::DisclosesRules;
    use crate::state::with_canister_state;
    use std::collections::HashSet;

    use crate::state::MockCanisterApi;
    use crate::storage::{StorableIncident, StorableRule};

    // Helper to create a mock rule
    fn create_mock_rule(disclosed_at: Option<Timestamp>) -> StorableRule {
        StorableRule {
            incident_id: IncidentId(Uuid::new_v4()),
            rule_raw: vec![],
            description: "".to_string(),
            disclosed_at,
            added_in_version: 1,
            removed_in_version: None,
        }
    }

    #[test]
    fn test_disclose_rules_incidents_succeeds() {
        with_canister_state(|state| {
            // Disclosure times
            let current_time_1 = 10u64;
            let current_time_2 = 15u64;
            let current_time_3 = 20u64;
            // Five rules
            let rule_id_1 = RuleId(Uuid::new_v4());
            let rule_id_2 = RuleId(Uuid::new_v4());
            let rule_id_3 = RuleId(Uuid::new_v4());
            let rule_id_4 = RuleId(Uuid::new_v4());
            let rule_id_5 = RuleId(Uuid::new_v4());
            // Two rules are disclosed, and three are not
            let rule_1 = create_mock_rule(None);
            let rule_2 = create_mock_rule(Some(25u64));
            let rule_3 = create_mock_rule(None);
            let rule_4 = create_mock_rule(Some(30u64));
            let rule_5 = create_mock_rule(None);
            // Two incidents
            let incident_id_1 = IncidentId(Uuid::new_v4());
            let incident_id_2 = IncidentId(Uuid::new_v4());
            // One incident is disclosed and one is not
            let incident_1 = StorableIncident {
                is_disclosed: false,
                rule_ids: HashSet::from_iter(vec![rule_id_1, rule_id_2, rule_id_3]),
            };
            let incident_2 = StorableIncident {
                is_disclosed: true,
                rule_ids: HashSet::from_iter(vec![rule_id_4]),
            };
            // Add rules/incidents
            state.upsert_rule(rule_id_1, rule_1);
            state.upsert_rule(rule_id_2, rule_2);
            state.upsert_rule(rule_id_3, rule_3);
            state.upsert_rule(rule_id_4, rule_4);
            state.upsert_rule(rule_id_5, rule_5);
            state.upsert_incident(incident_id_1, incident_1);
            state.upsert_incident(incident_id_2, incident_2);
            // Disclose two incidents at time_1
            let arg = rate_limits_api::DiscloseRulesArg::IncidentIds(vec![
                incident_id_1.to_string(),
                incident_id_2.to_string(),
            ]);
            let discloser = RulesDiscloser::new(state.clone());
            discloser
                .disclose_rules(arg.clone(), current_time_1)
                .expect("Failed to disclose rules");
            //Disclose again at time_2 (should have no impact)
            discloser
                .disclose_rules(arg, current_time_2)
                .expect("Failed to disclose rules");
            // Assert rules disclosure time
            let rule = state.get_rule(&rule_id_1).unwrap();
            assert_eq!(rule.disclosed_at, Some(current_time_1));
            let rule = state.get_rule(&rule_id_2).unwrap();
            assert_eq!(rule.disclosed_at, Some(25u64));
            let rule = state.get_rule(&rule_id_3).unwrap();
            assert_eq!(rule.disclosed_at, Some(current_time_1));
            let rule = state.get_rule(&rule_id_4).unwrap();
            assert_eq!(rule.disclosed_at, Some(30u64));
            let rule = state.get_rule(&rule_id_5).unwrap();
            assert_eq!(rule.disclosed_at, None);
            let incident = state.get_incident(&incident_id_1).unwrap();
            // Assert incident disclosure status
            assert!(incident.is_disclosed);
            let incident = state.get_incident(&incident_id_2).unwrap();
            assert!(incident.is_disclosed);
            // Disclose one rule individually at time_2
            let arg = rate_limits_api::DiscloseRulesArg::RuleIds(vec![rule_id_5.to_string()]);
            discloser
                .disclose_rules(arg, current_time_2)
                .expect("Failed to disclose rules");
            let rule = state.get_rule(&rule_id_5).unwrap();
            assert_eq!(rule.disclosed_at, Some(current_time_2));
            // Check disclosing already disclosed rules again has no impact
            let arg = rate_limits_api::DiscloseRulesArg::RuleIds(vec![
                rule_id_1.to_string(),
                rule_id_5.to_string(),
            ]);
            discloser
                .disclose_rules(arg, current_time_3)
                .expect("Failed to disclose rules");
            let rule = state.get_rule(&rule_id_1).unwrap();
            assert_eq!(rule.disclosed_at, Some(current_time_1));
            let rule = state.get_rule(&rule_id_5).unwrap();
            assert_eq!(rule.disclosed_at, Some(current_time_2));
        });
    }

    #[test]
    fn test_disclose_fails_with_invalid_input() {
        // Arrange
        let current_time = 10u64;
        let id_1 = Uuid::new_v4();
        let id_2 = "not_a_uuid".to_string();
        let arg_1 =
            rate_limits_api::DiscloseRulesArg::RuleIds(vec![id_1.to_string(), id_2.to_string()]);
        let arg_2 = rate_limits_api::DiscloseRulesArg::IncidentIds(vec![
            id_1.to_string(),
            id_2.to_string(),
        ]);
        let mock_canister_api = MockCanisterApi::new();
        let discloser = RulesDiscloser::new(mock_canister_api);
        // Act
        let error = discloser.disclose_rules(arg_1, current_time).unwrap_err();
        assert!(matches!(error, DiscloseRulesError::InvalidUuidFormat(idx) if idx == 1));
        let error = discloser.disclose_rules(arg_2, current_time).unwrap_err();
        assert!(matches!(error, DiscloseRulesError::InvalidUuidFormat(idx) if idx == 1));
    }

    #[test]
    fn test_disclose_fails_with_id_not_found() {
        // Arrange
        let current_time = 10u64;
        let uuid = Uuid::new_v4();
        let arg_1 = rate_limits_api::DiscloseRulesArg::RuleIds(vec![uuid.to_string()]);
        let arg_2 = rate_limits_api::DiscloseRulesArg::IncidentIds(vec![uuid.to_string()]);
        let mut mock_canister_api = MockCanisterApi::new();
        mock_canister_api.expect_get_rule().returning(|_| None);
        mock_canister_api.expect_get_incident().returning(|_| None);
        let discloser = RulesDiscloser::new(mock_canister_api);
        // Act
        let error = discloser.disclose_rules(arg_1, current_time).unwrap_err();
        assert!(matches!(error, DiscloseRulesError::RuleIdNotFound(RuleId(ref id)) if id == &uuid));
        let error = discloser.disclose_rules(arg_2, current_time).unwrap_err();
        assert!(
            matches!(error, DiscloseRulesError::IncidentIdNotFound(IncidentId(ref id)) if id == &uuid)
        );
    }
}
