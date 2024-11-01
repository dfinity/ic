use ic_cdk::api::time;

use crate::{
    access_control::{AccessLevel, ResolveAccessLevel},
    state::CanisterApi,
    types::{DiscloseRulesArg, DiscloseRulesArgError, IncidentId, RuleId, Timestamp},
};

pub trait DisclosesRules {
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
    ) -> Result<(), DiscloseRulesError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DiscloseRulesError {
    #[error("Invalid input: {0}")]
    InvalidInput(#[from] DiscloseRulesArgError),
    #[error("Operation is not permitted")]
    Unauthorized,
    #[error("Incident with ID={0} not found")]
    IncidentIdNotFound(IncidentId),
    #[error("Rule with ID={0} not found")]
    RuleIdNotFound(RuleId),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub struct RulesDiscloser<S, A> {
    pub state: S,
    pub access_resolver: A,
}

impl<S, A> RulesDiscloser<S, A> {
    pub fn new(state: S, access_resolver: A) -> Self {
        Self {
            state,
            access_resolver,
        }
    }
}

impl<S: CanisterApi, A: ResolveAccessLevel> DisclosesRules for RulesDiscloser<S, A> {
    fn disclose_rules(
        &self,
        arg: rate_limits_api::DiscloseRulesArg,
    ) -> Result<(), DiscloseRulesError> {
        let arg = DiscloseRulesArg::try_from(arg)?;

        if self.access_resolver.get_access_level() == AccessLevel::FullAccess {
            match arg {
                DiscloseRulesArg::RuleIds(rule_ids) => {
                    disclose_rules(&self.state, time(), &rule_ids)?;
                }
                DiscloseRulesArg::IncidentIds(incident_ids) => {
                    disclose_incidents(&self.state, time(), &incident_ids)?;
                }
            }
            return Ok(());
        }
        Err(DiscloseRulesError::Unauthorized)
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
            assert!(
                canister_api.update_rule(*rule_id, metadata),
                "rule id not found"
            );
        }
    }

    Ok(())
}

fn disclose_incidents(
    canister_api: &impl CanisterApi,
    time: Timestamp,
    incident_ids: &[IncidentId],
) -> Result<(), DiscloseRulesError> {
    let mut incidents_metadata = Vec::with_capacity(incident_ids.len());

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
            disclose_rules(canister_api, time, &metadata.rule_ids)?;
            metadata.is_disclosed = true;
            // TODO: consider aggregating errors
            canister_api
                .update_incident(incident_id, metadata)
                .then_some(())
                .ok_or_else(|| DiscloseRulesError::IncidentIdNotFound(incident_id))?;
        }
    }

    Ok(())
}

impl From<DiscloseRulesError> for String {
    fn from(value: DiscloseRulesError) -> Self {
        value.to_string()
    }
}
