use crate::{
    state::CanisterApi,
    types::{DiscloseRulesArg, DiscloseRulesArgError, IncidentId, RuleId, Timestamp},
};
use strum::AsRefStr;
use thiserror::Error;

pub trait DisclosesRules {
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
        current_time: Timestamp,
    ) -> Result<(), DiscloseRulesError>;
}

#[derive(Debug, Error, AsRefStr)]
pub enum DiscloseRulesError {
    #[error("Unauthorized operation")]
    #[strum(serialize = "unauthorized_error")]
    Unauthorized,
    #[error("Invalid input: {0}")]
    #[strum(serialize = "invalid_input_error")]
    InvalidInput(#[from] DiscloseRulesArgError),
    #[error("Incident with ID={0} not found")]
    #[strum(serialize = "incident_id_not_found_error")]
    IncidentIdNotFound(IncidentId),
    #[error("Rule with ID={0} not found")]
    #[strum(serialize = "rule_id_not_found_error")]
    RuleIdNotFound(RuleId),
    #[error("An unexpected internal error occurred: {0}")]
    #[strum(serialize = "internal_error")]
    Internal(#[from] anyhow::Error),
}

pub struct RulesDiscloser<A> {
    pub canister_api: A,
}

impl<A> RulesDiscloser<A> {
    pub fn new(canister_api: A) -> Self {
        Self { canister_api }
    }
}

impl<A: CanisterApi> DisclosesRules for RulesDiscloser<A> {
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
        current_time: Timestamp,
    ) -> Result<(), DiscloseRulesError> {
        let arg = DiscloseRulesArg::try_from(arg)?;
        match arg {
            DiscloseRulesArg::RuleIds(rule_ids) => {
                disclose_rules(&self.canister_api, current_time, &rule_ids)?;
            }
            DiscloseRulesArg::IncidentIds(incident_ids) => {
                disclose_incidents(&self.canister_api, current_time, &incident_ids)?;
            }
        }
        Ok(())
    }
}

fn disclose_rules(
    canister_api: &impl CanisterApi,
    time: Timestamp,
    rule_ids: &[RuleId],
) -> Result<(), DiscloseRulesError> {
    let mut rules = Vec::with_capacity(rule_ids.len());

    // Return the first error found while assembling metadata
    for rule_id in rule_ids.iter() {
        match canister_api.get_rule(rule_id) {
            Some(rule_metadata) => {
                rules.push((rule_id, rule_metadata));
            }
            None => {
                return Err(DiscloseRulesError::RuleIdNotFound(*rule_id));
            }
        }
    }

    for (rule_id, mut metadata) in rules {
        if metadata.disclosed_at.is_none() {
            metadata.disclosed_at = Some(time);
            let _ = canister_api.upsert_rule(*rule_id, metadata);
        }
    }

    Ok(())
}

fn disclose_incidents(
    canister_api: &impl CanisterApi,
    time: Timestamp,
    incident_ids: &[IncidentId],
) -> Result<(), DiscloseRulesError> {
    let mut incidents_metadata: Vec<(_, _)> = Vec::with_capacity(incident_ids.len());

    // Return the first error while assembling the metadata
    for incident_id in incident_ids.iter() {
        match canister_api.get_incident(incident_id) {
            Some(incident_metadata) => {
                incidents_metadata.push((*incident_id, incident_metadata));
            }
            None => {
                return Err(DiscloseRulesError::IncidentIdNotFound(*incident_id));
            }
        }
    }

    for (incident_id, mut metadata) in incidents_metadata {
        if !metadata.is_disclosed {
            let rule_ids: Vec<RuleId> = metadata.rule_ids.iter().cloned().collect();
            disclose_rules(canister_api, time, &rule_ids)?;
            metadata.is_disclosed = true;
            let _ = canister_api.upsert_incident(incident_id, metadata);
        }
    }

    Ok(())
}

impl From<DiscloseRulesError> for String {
    fn from(value: DiscloseRulesError) -> Self {
        value.to_string()
    }
}
