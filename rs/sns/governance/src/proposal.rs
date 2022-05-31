use std::collections::BTreeMap;
use std::convert::TryFrom;

use crate::canister_control::perform_execute_generic_nervous_system_function_validate_and_render_call;
use crate::governance::{log_prefix, NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER};
use crate::pb::v1::nervous_system_function::{FunctionType, GenericNervousSystemFunction};
use crate::pb::v1::{
    proposal, ExecuteGenericNervousSystemFunction, Motion, NervousSystemFunction,
    NervousSystemParameters, Proposal, ProposalData, ProposalDecisionStatus, ProposalRewardStatus,
    Tally, UpgradeSnsControlledCanister, Vote,
};
use crate::types::{Environment, ONE_DAY_SECONDS};
use crate::{validate_chars_count, validate_len, validate_required_field};

use dfn_core::api::CanisterId;
use ic_base_types::PrincipalId;
use ic_crypto_sha::Sha256;

/// The maximum number of bytes in an SNS proposal's title.
pub const PROPOSAL_TITLE_BYTES_MAX: usize = 256;
/// The maximum number of bytes in an SNS proposal's summary.
pub const PROPOSAL_SUMMARY_BYTES_MAX: usize = 15000;
/// The maximum number of bytes in an SNS proposal's URL.
pub const PROPOSAL_URL_CHAR_MAX: usize = 2048;
/// The maximum number of bytes in an SNS motion proposal's motion_text.
pub const PROPOSAL_MOTION_TEXT_BYTES_MAX: usize = 10000;

/// The minimum number of votes a proposal must have at the end of the voting period to be
/// adopted with a plurality of the voting power submitted rather than a majority of the
/// total available voting power.
///
/// A proposal is adopted if either a majority of the total voting power available voted
/// in favor of the proposal or if the proposal reaches the end of the voting period,
/// there is a minimum amount of votes, and a plurality of the used voting power is in
/// favor of the proposal. This minimum of votes is expressed as a ratio of the used
/// voting power in favor of the proposal divided by the total available voting power.
pub const MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO: f64 = 0.03;

/// The value that determines the maximum time that a proposal's initial deadline can be
/// increased by the wait-for-quiet algorithm.
/// This maximum total voting period extension is 2 * WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS.
pub const WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS: u64 = ONE_DAY_SECONDS;

/// The maximum number of proposals returned by one call to the method `list_proposals`,
/// which can be used to list all proposals in a paginated fashion.
pub const MAX_LIST_PROPOSAL_RESULTS: u32 = 100;

/// The maximum number of unsettled proposals (proposals for which ballots are still stored).
pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS: usize = 700;

/// The maximum number of GenericNervousSystemFunctions the system allows.
pub const MAX_NUMBER_OF_GENERIC_NERVOUS_SYSTEM_FUNCTIONS: usize = 200_000;

impl Proposal {
    /// Returns whether a proposal is allowed to be submitted when
    /// the heap growth potential is low.
    pub(crate) fn allowed_when_resources_are_low(&self) -> bool {
        self.action
            .as_ref()
            .map_or(false, |a| a.allowed_when_resources_are_low())
    }
}

/// Validates a proposal and returns a displayable text rendering of the payload
/// if the proposal is valid.
///
/// Takes in the GovernanceProto as to be able to validate agaisnt the current
/// state of governance.
pub async fn validate_and_render_proposal(
    proposal: &Proposal,
    env: &dyn Environment,
    parameters: &NervousSystemParameters,
    functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    let mut defects = Vec::new();

    let mut defects_push = |r| {
        if let Err(err) = r {
            defects.push(err);
        }
    };

    const NO_MIN: usize = 0;

    // Inspect (the length of) string fields.
    defects_push(validate_len(
        "title",
        &proposal.title,
        NO_MIN,
        PROPOSAL_TITLE_BYTES_MAX,
    ));
    defects_push(validate_len(
        "summary",
        &proposal.summary,
        NO_MIN,
        PROPOSAL_SUMMARY_BYTES_MAX,
    ));
    defects_push(validate_chars_count(
        "url",
        &proposal.url,
        NO_MIN,
        PROPOSAL_URL_CHAR_MAX,
    ));

    // Even if we already found defects, still validate as to return all the errors found.
    match validate_and_render_action(&proposal.action, env, parameters, functions).await {
        Err(err) => {
            defects.push(err);
            Err(format!(
                "{} defects in Proposal:\n{}",
                defects.len(),
                defects.join("\n"),
            ))
        }
        Ok(rendering) => {
            if !defects.is_empty() {
                Err(format!(
                    "{} defects in Proposal:\n{}",
                    defects.len(),
                    defects.join("\n"),
                ))
            } else {
                Ok(rendering)
            }
        }
    }
}

/// Validates and renders a proposal by calling the method that implements this logic for a given
/// proposal action.
pub async fn validate_and_render_action(
    action: &Option<proposal::Action>,
    env: &dyn Environment,
    current_parameters: &NervousSystemParameters,
    existing_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    let action = match action.as_ref() {
        None => return Err("No action was specified.".into()),
        Some(action) => action,
    };

    match action {
        proposal::Action::Unspecified(_unspecified) => {
            Err("`unspecified` was used, but is not a valid Proposal action.".into())
        }
        proposal::Action::Motion(motion) => validate_and_render_motion(motion),
        proposal::Action::ManageNervousSystemParameters(manage) => {
            validate_and_render_manage_nervous_system_parameters(manage, current_parameters)
        }
        proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
            validate_and_render_upgrade_sns_controlled_canister(upgrade)
        }
        proposal::Action::AddGenericNervousSystemFunction(function_to_add) => {
            validate_and_render_add_generic_nervous_system_function(
                function_to_add,
                existing_functions,
            )
        }
        proposal::Action::RemoveGenericNervousSystemFunction(id_to_remove) => {
            validate_and_render_remove_nervous_generic_system_function(
                *id_to_remove,
                existing_functions,
            )
        }
        proposal::Action::ExecuteGenericNervousSystemFunction(execute) => {
            validate_and_render_execute_nervous_system_function(env, execute, existing_functions)
                .await
        }
    }
}

/// Validates and renders a proposal with action Motion.
fn validate_and_render_motion(motion: &Motion) -> Result<String, String> {
    validate_len(
        "motion.motion_text",
        &motion.motion_text,
        0, // min
        PROPOSAL_MOTION_TEXT_BYTES_MAX,
    )?;

    Ok(format!(
        r"# Motion Proposal:
## Motion Text:

{}",
        &motion.motion_text
    ))
}

/// Validates and renders a proposal with action ManageNervousSystemParameters.
fn validate_and_render_manage_nervous_system_parameters(
    new_parameters: &NervousSystemParameters,
    current_parameters: &NervousSystemParameters,
) -> Result<String, String> {
    new_parameters.inherit_from(current_parameters).validate()?;

    Ok(format!(
        r"# Proposal to change nervous system parameters:
## Current nervous system parameters:

{:?}

## New nervous system parameters:

{:?}",
        &current_parameters, new_parameters
    ))
}

/// Validates and renders a proposal with action UpgradeSnsControlledCanister.
fn validate_and_render_upgrade_sns_controlled_canister(
    upgrade: &UpgradeSnsControlledCanister,
) -> Result<String, String> {
    let mut defects = vec![];

    // Inspect canister_id.
    let canister_id = match validate_required_field("canister_id", &upgrade.canister_id) {
        Err(err) => {
            defects.push(err);
        }
        Ok(canister_id) => {
            if let Err(err) = CanisterId::new(*canister_id) {
                defects.push(format!("Specified canister ID was invalid: {}", err));
            }
        }
    };

    // Inspect wasm.
    const WASM_HEADER: [u8; 4] = [0, 0x61, 0x73, 0x6d];
    const MIN_WASM_LEN: usize = 8;
    if let Err(err) = validate_len(
        "new_canister_wasm",
        &upgrade.new_canister_wasm,
        MIN_WASM_LEN,
        usize::MAX,
    ) {
        defects.push(err);
    } else if upgrade.new_canister_wasm[..4] != WASM_HEADER[..] {
        defects.push("new_canister_wasm lacks the magic value in its header.".into());
    }

    // Generate final report.
    if !defects.is_empty() {
        return Err(format!(
            "UpgradeSnsControlledCanister was invalid for the following reason(s):\n{}",
            defects.join("\n"),
        ));
    }

    let mut state = Sha256::new();
    state.write(&upgrade.new_canister_wasm);
    let sha = state.finish();

    // TODO calculate and display the new wasm's hash.
    Ok(format!(
        r"# Proposal to upgrade SNS controlled canister:

## Canister id: {:?}

## Canister wasm sha256: {}",
        canister_id,
        hex::encode(sha)
    ))
}

#[derive(Debug)]
pub(crate) struct ValidGenericNervousSystemFunction {
    pub id: u64,
    pub target_canister_id: CanisterId,
    pub target_method: String,
    pub validator_canister_id: CanisterId,
    pub validator_method: String,
}

/// Validates a given canister id and adds a defect to a given list of defects if the there was no
/// canister id given or if it was invalid.
fn validate_canister_id(
    field_name: &str,
    canister_id: &Option<PrincipalId>,
    defects: &mut Vec<String>,
) -> Option<CanisterId> {
    match canister_id {
        None => {
            defects.push(format!("{} field was not populated.", field_name));
            None
        }
        Some(canister_id) => match CanisterId::new(*canister_id) {
            Err(err) => {
                defects.push(format!("{} was invalid: {}", field_name, err));
                None
            }
            Ok(target_canister_id) => Some(target_canister_id),
        },
    }
}

impl TryFrom<&NervousSystemFunction> for ValidGenericNervousSystemFunction {
    type Error = String;

    fn try_from(value: &NervousSystemFunction) -> Result<Self, Self::Error> {
        if value == &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER {
            return Err(
                "NervousSystemFunction is a deletion marker and not an actual function."
                    .to_string(),
            );
        }

        if value.is_native() {
            return Err("NervousSystemFunction is not generic.".to_string());
        }

        let NervousSystemFunction {
            id,
            name,
            description,
            function_type,
        } = value;

        let mut defects = vec![];

        if *id < 1000 {
            defects.push("NervousSystemFunction's must have ids starting at 1000".to_string());
        }

        if name.is_empty() || name.len() > 256 {
            defects.push(
                "NervousSystemFunction's must have set name with a max of 255 bytes".to_string(),
            );
        }

        if description.is_some() && description.as_ref().unwrap().len() > 10000 {
            defects.push(
                "NervousSystemFunction's description must be at most 10000 bytes".to_string(),
            );
        }

        match function_type {
            Some(FunctionType::GenericNervousSystemFunction(GenericNervousSystemFunction {
                target_canister_id,
                target_method_name,
                validator_canister_id,
                validator_method_name,
            })) => {
                // Validate the target_canister_id field.
                let target_canister_id =
                    validate_canister_id("target_canister_id", target_canister_id, &mut defects);

                // Validate the validator_canister_id field.
                let validator_canister_id = validate_canister_id(
                    "validator_canister_id",
                    validator_canister_id,
                    &mut defects,
                );

                // Validate the target_method_name field.
                if target_method_name.is_none() || target_method_name.as_ref().unwrap().is_empty() {
                    defects.push("target_method_name was empty.".to_string());
                }

                if validator_method_name.is_none()
                    || validator_method_name.as_ref().unwrap().is_empty()
                {
                    defects.push("validator_method_name was empty.".to_string());
                }

                if !defects.is_empty() {
                    return Err(format!(
                        "ExecuteNervousSystemFunction was invalid for the following reason(s):\n{}",
                        defects.join("\n")
                    ));
                }

                Ok(ValidGenericNervousSystemFunction {
                    id: *id,
                    target_canister_id: target_canister_id.unwrap(),
                    target_method: target_method_name.as_ref().unwrap().clone(),
                    validator_canister_id: validator_canister_id.unwrap(),
                    validator_method: validator_method_name.as_ref().unwrap().clone(),
                })
            }
            _ => {
                defects.push("NervousSystemFunction must have a function_type set to GenericNervousSystemFunction".to_string());
                return Err(format!(
                    "ExecuteNervousSystemFunction was invalid for the following reason(s):\n{}",
                    defects.join("\n")
                ));
            }
        }
    }
}

/// Validates and renders a proposal with action AddNervousSystemFunction.
pub fn validate_and_render_add_generic_nervous_system_function(
    add: &NervousSystemFunction,
    existing_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    let validated_function = ValidGenericNervousSystemFunction::try_from(add)?;
    if existing_functions.contains_key(&validated_function.id) {
        return Err(format!(
            "There is already a NervousSystemFunction with id: {}",
            validated_function.id
        ));
    }

    if existing_functions.len() >= MAX_NUMBER_OF_GENERIC_NERVOUS_SYSTEM_FUNCTIONS {
        return Err("Reached maximum number of allowed GenericNervousSystemFunctions".to_string());
    }

    Ok(format!(
        r"Proposal to add new NervousSystemFunction:

## Function:

{:?}",
        add
    ))
}

/// Validates and renders a proposal with action RemoveNervousSystemFunction.
pub fn validate_and_render_remove_nervous_generic_system_function(
    remove: u64,
    existing_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    match existing_functions.get(&remove) {
        None => Err(format!("NervousSystemFunction: {} doesn't exist", remove)),
        Some(function) => Ok(format!(
            r"# Proposal to remove existing NervousSystemFunction:

## Function:

{:?}",
            function
        )),
    }
}

/// Validates and renders a proposal with action ExecuteNervousSystemFunction.
/// This retrieves the nervous system function's validator method and calls it.
pub async fn validate_and_render_execute_nervous_system_function(
    env: &dyn Environment,
    execute: &ExecuteGenericNervousSystemFunction,
    existing_functions: &BTreeMap<u64, NervousSystemFunction>,
) -> Result<String, String> {
    let id = execute.function_id;
    match existing_functions.get(&execute.function_id) {
        None => Err(format!("There is no NervousSystemFunction with id: {}", id)),
        Some(function) => {
            // Make sure this isn't a NervousSystemFunction which has been deleted.
            if function == &*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER {
                Err(format!("There is no NervousSystemFunction with id: {}", id))
            } else {
                // To validate the proposal we try and call the validation method,
                // which should produce a payload rendering if the proposal is valid
                // or an error if it isn't.
                let rendering =
                    perform_execute_generic_nervous_system_function_validate_and_render_call(
                        env,
                        function.clone(),
                        execute.clone(),
                    )
                    .await?;

                Ok(format!(
                    r"# Proposal to execute nervous system function:

## Nervous system function:

{:?}

## Payload:

{}",
                    function, rendering
                ))
            }
        }
    }
}

impl ProposalData {
    /// Returns the proposal's decision status. See [ProposalDecisionStatus] in the SNS's
    /// proto for more information.
    pub fn status(&self) -> ProposalDecisionStatus {
        if self.decided_timestamp_seconds == 0 {
            ProposalDecisionStatus::ProposalStatusOpen
        } else if self.is_accepted() {
            if self.executed_timestamp_seconds > 0 {
                ProposalDecisionStatus::ProposalStatusExecuted
            } else if self.failed_timestamp_seconds > 0 {
                ProposalDecisionStatus::ProposalStatusFailed
            } else {
                ProposalDecisionStatus::ProposalStatusAdopted
            }
        } else {
            ProposalDecisionStatus::ProposalStatusRejected
        }
    }

    /// Returns the proposal's reward status. See [ProposalRewardStatus] in the SNS's
    /// proto for more information.
    pub fn reward_status(&self, now_seconds: u64) -> ProposalRewardStatus {
        match self.reward_event_round {
            0 => {
                if self.accepts_vote(now_seconds) {
                    ProposalRewardStatus::AcceptVotes
                } else {
                    ProposalRewardStatus::ReadyToSettle
                }
            }
            _ => ProposalRewardStatus::Settled,
        }
    }

    /// Returns the proposal's current voting period deadline in seconds from the Unix epoch.
    pub fn get_deadline_timestamp_seconds(&self) -> u64 {
        self.wait_for_quiet_state
            .as_ref()
            .expect("Proposal must have a wait_for_quiet_state.")
            .current_deadline_timestamp_seconds
    }

    /// Returns true if votes are still accepted for the proposal and
    /// false otherwise.
    ///
    /// For voting reward purposes, votes may be accepted even after a
    /// proposal has been decided. Thus, this method may return true
    /// even if the proposal is already decided.
    /// (As soon as a majority is reached, the result cannot turn anymore,
    /// thus the proposal is decided. We still give time to other voters
    /// to cast their votes until the voting period ends so that they can
    /// collect voting rewards).
    pub fn accepts_vote(&self, now_seconds: u64) -> bool {
        // Checks if the proposal's deadline is still in the future.
        now_seconds < self.get_deadline_timestamp_seconds()
    }

    /// Possibly extends a proposal's voting period. The underlying idea is
    /// that if a proposal has a clear result, then there is no need to have
    /// a long voting period. However, if a proposal is controversial and the
    /// result keeps flipping, we should give voters more time to contribute
    /// to the decision.
    /// To this end, this method applies the so called wait-for-quiet algorithm
    /// to the given proposal: It evaluates whether the proposal's voting result
    /// has turned (a yes-result turned into a no-result or vice versa) and, if
    /// this is the case, extends the proposal's deadline.
    /// The initial voting period is extended by at most
    /// 2 * WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS.
    pub fn evaluate_wait_for_quiet(
        &mut self,
        now_seconds: u64,
        voting_period_seconds: u64,
        old_tally: &Tally,
        new_tally: &Tally,
    ) {
        let wait_for_quiet_state = self
            .wait_for_quiet_state
            .as_mut()
            .expect("Proposal must have a wait_for_quiet_state.");

        // Do not evaluate wait-for-quiet if there is already a decision, or the
        // proposal's voting deadline has been reached. The deciding amount for yes
        // and no are slightly different, because yes needs a majority to succeed, while
        // no only needs a tie.
        let current_deadline = wait_for_quiet_state.current_deadline_timestamp_seconds;
        let deciding_amount_yes = new_tally.total / 2 + 1;
        let deciding_amount_no = (new_tally.total + 1) / 2;
        if new_tally.yes >= deciding_amount_yes
            || new_tally.no >= deciding_amount_no
            || now_seconds > current_deadline
        {
            return;
        }

        // Returns whether the tally result has turned, i.e. if the result now
        // favors yes, but it used to favor no or vice versa.
        fn vote_has_turned(old_tally: &Tally, new_tally: &Tally) -> bool {
            (old_tally.yes > old_tally.no && new_tally.yes <= new_tally.no)
                || (old_tally.yes <= old_tally.no && new_tally.yes > new_tally.no)
        }
        if !vote_has_turned(old_tally, new_tally) {
            return;
        }

        // Let W be short for WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS. A proposal's voting
        // period starts with an initial_voting_period and can be extended
        // to at most initial_voting_period + 2 * W.
        // The required_margin reflects the proposed deadline extension to be
        // made beyond the current moment, so long as that extends beyond the
        // current wait-for-quiet deadline. We calculate the required_margin a
        // bit indirectly here so as to keep with unsigned integers, but the
        // idea is:
        //
        //     W + (initial_voting_period - elapsed) / 2
        //
        // Thus, while we are still within the initial voting period, we add
        // to W, but once we are beyond that window, we subtract from W until
        // reaching the limit where required_margin remains at zero. This
        // occurs when:
        //
        //     elapsed = initial_voting_period + 2 * W
        //
        // As an example, given that W = 12h, if the initial_voting_period is
        // 24h then the maximum deadline will be 24h + 2 * 12h = 48h.
        //
        // The required_margin ends up being a linearly decreasing value,
        // starting at W + initial_voting_period / 2 and reducing to zero at the
        // furthest possible deadline. When the vote does not flip, we do not
        // update the deadline, and so there is a chance of ending prior to
        // the extreme limit. But each time the vote flips, we "re-enter" the
        // linear progression according to the elapsed time.
        //
        // This means that whenever there is a flip, the deadline is always
        // set to the current time plus the required_margin, which places us
        // along the a linear path that was determined by the starting
        // variables.
        let elapsed_seconds = now_seconds.saturating_sub(self.proposal_creation_timestamp_seconds);
        let required_margin = WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS
            .saturating_add(voting_period_seconds / 2)
            .saturating_sub(elapsed_seconds / 2);
        let new_deadline = std::cmp::max(
            current_deadline,
            now_seconds.saturating_add(required_margin),
        );

        if new_deadline != current_deadline {
            println!(
                "{}Updating WFQ deadline for proposal: {:?}. Old: {}, New: {}, Ext: {}",
                log_prefix(),
                self.id.as_ref().unwrap(),
                current_deadline,
                new_deadline,
                new_deadline - current_deadline
            );

            wait_for_quiet_state.current_deadline_timestamp_seconds = new_deadline;
        }
    }

    /// Recomputes the proposal's tally.
    /// This is an expensive operation.
    pub fn recompute_tally(&mut self, now_seconds: u64, voting_period_seconds: u64) {
        // Tally proposal
        let mut yes = 0;
        let mut no = 0;
        let mut undecided = 0;
        for ballot in self.ballots.values() {
            let lhs: &mut u64 = if let Some(vote) = Vote::from_i32(ballot.vote) {
                match vote {
                    Vote::Unspecified => &mut undecided,
                    Vote::Yes => &mut yes,
                    Vote::No => &mut no,
                }
            } else {
                &mut undecided
            };
            *lhs = (*lhs).saturating_add(ballot.voting_power)
        }

        // It is validated in `make_proposal` that the total does not
        // exceed u64::MAX: the `saturating_add` is just a precaution.
        let total = yes.saturating_add(no).saturating_add(undecided);

        let new_tally = Tally {
            timestamp_seconds: now_seconds,
            yes,
            no,
            total,
        };

        // Every time the tally changes, (possibly) update the wait-for-quiet
        // dynamic deadline.
        if let Some(old_tally) = self.latest_tally.clone() {
            if new_tally.yes == old_tally.yes
                && new_tally.no == old_tally.no
                && new_tally.total == old_tally.total
            {
                return;
            }

            self.evaluate_wait_for_quiet(
                now_seconds,
                voting_period_seconds,
                &old_tally,
                &new_tally,
            );
        }

        self.latest_tally = Some(new_tally);
    }

    /// Returns true if the proposal meets the conditions to be accepted, also called "adopted".
    /// The result is only meaningful if a decision on the proposal's result can be made, i.e.,
    /// either there is a majority of yes-votes or the proposal's deadline has passed.
    pub fn is_accepted(&self) -> bool {
        if let Some(tally) = self.latest_tally.as_ref() {
            (tally.yes as f64 >= tally.total as f64 * MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO)
                && tally.yes > tally.no
        } else {
            false
        }
    }

    /// Returns true if a decision can be made right now to adopt or reject the proposal.
    /// The proposal must be tallied prior to calling this method.
    pub(crate) fn can_make_decision(&self, now_seconds: u64) -> bool {
        if let Some(tally) = &self.latest_tally {
            // Even when a proposal's deadline has not passed, a proposal is
            // adopted if strictly more than half of the votes are 'yes' and
            // rejected if at least half of the votes are 'no'. The conditions
            // are described as below to avoid overflow. In the absence of overflow,
            // the below is equivalent to (2 * yes > total) || (2 * no >= total).
            let majority =
                (tally.yes > tally.total - tally.yes) || (tally.no >= tally.total - tally.no);
            let expired = !self.accepts_vote(now_seconds);
            let decision_reason = match (majority, expired) {
                (true, true) => Some("majority and expiration"),
                (true, false) => Some("majority"),
                (false, true) => Some("expiration"),
                (false, false) => None,
            };
            if let Some(reason) = decision_reason {
                println!(
                    "{}Proposal {} decided, thanks to {}. Tally at decision time: {:?}",
                    log_prefix(),
                    self.id
                        .as_ref()
                        .map_or("unknown".to_string(), |i| format!("{}", i.id)),
                    reason,
                    tally
                );
                return true;
            }
        }
        false
    }

    /// Return true if the proposal can be purged from storage, e.g.,
    /// if it is allowed to be garbage collected.
    pub(crate) fn can_be_purged(&self, now_seconds: u64) -> bool {
        self.status().is_final() && self.reward_status(now_seconds).is_final()
    }
}

impl ProposalDecisionStatus {
    /// Return true if the proposal decision status is 'final', i.e., the proposal
    /// decision status is one that cannot be changed anymore.
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            ProposalDecisionStatus::ProposalStatusRejected
                | ProposalDecisionStatus::ProposalStatusExecuted
                | ProposalDecisionStatus::ProposalStatusFailed
        )
    }
}

impl ProposalRewardStatus {
    /// Return true if this reward status is 'final', i.e., the proposal
    /// reward status is one that cannot be changed anymore.
    pub fn is_final(&self) -> bool {
        matches!(self, ProposalRewardStatus::Settled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pb::v1::Empty,
        tests::{assert_is_err, assert_is_ok},
        types::test_helpers::NativeEnvironment,
    };
    use futures::FutureExt;
    use ic_base_types::PrincipalId;
    use lazy_static::lazy_static;
    use std::convert::TryFrom;

    lazy_static! {
        static ref FAKE_ENV: Box<dyn Environment> = Box::new(NativeEnvironment::default());
        static ref DEFAULT_PARAMS: NervousSystemParameters =
            NervousSystemParameters::with_default_values();
        static ref EMPTY_FUNCTIONS: BTreeMap<u64, NervousSystemFunction> = BTreeMap::new();
    }

    fn validate_default_proposal(proposal: &Proposal) -> Result<String, String> {
        validate_and_render_proposal(proposal, &**FAKE_ENV, &DEFAULT_PARAMS, &EMPTY_FUNCTIONS)
            .now_or_never()
            .unwrap()
    }

    fn validate_default_action(action: &Option<proposal::Action>) -> Result<String, String> {
        validate_and_render_action(action, &**FAKE_ENV, &DEFAULT_PARAMS, &EMPTY_FUNCTIONS)
            .now_or_never()
            .unwrap()
    }

    fn basic_principal_id() -> PrincipalId {
        PrincipalId::try_from(vec![42_u8]).unwrap()
    }

    fn basic_motion_proposal() -> Proposal {
        let result = Proposal {
            title: "title".into(),
            summary: "summary".into(),
            url: "http://www.example.com".into(),
            action: Some(proposal::Action::Motion(Motion::default())),
        };
        assert_is_ok(validate_default_proposal(&result));
        result
    }

    #[test]
    fn proposal_title_is_not_too_long() {
        let mut proposal = basic_motion_proposal();
        proposal.title = "".into();

        assert_is_ok(validate_default_proposal(&proposal));

        for _ in 0..PROPOSAL_TITLE_BYTES_MAX {
            proposal.title.push('x');
            assert_is_ok(validate_default_proposal(&proposal));
        }

        // Kaboom!
        proposal.title.push('z');
        assert_is_err(validate_default_proposal(&proposal));
    }

    #[test]
    fn proposal_summary_is_not_too_long() {
        let mut proposal = basic_motion_proposal();
        proposal.summary = "".into();
        assert_is_ok(validate_default_proposal(&proposal));

        for _ in 0..PROPOSAL_SUMMARY_BYTES_MAX {
            proposal.summary.push('x');
            assert_is_ok(validate_default_proposal(&proposal));
        }

        // Kaboom!
        proposal.summary.push('z');
        assert_is_err(validate_default_proposal(&proposal));
    }

    #[test]
    fn proposal_url_is_not_too_long() {
        let mut proposal = basic_motion_proposal();
        proposal.url = "".into();
        assert_is_ok(validate_default_proposal(&proposal));

        for _ in 0..PROPOSAL_URL_CHAR_MAX {
            proposal.url.push('x');
            assert_is_ok(validate_default_proposal(&proposal));
        }

        // Kaboom!
        proposal.url.push('z');
        assert_is_err(validate_default_proposal(&proposal));
    }

    #[test]
    fn proposal_action_is_required() {
        assert_is_err(validate_default_action(&None));
    }

    #[test]
    fn unspecified_action_is_invalid() {
        assert_is_err(validate_default_action(&Some(
            proposal::Action::Unspecified(Empty {}),
        )));
    }

    #[test]
    fn motion_text_not_too_long() {
        let mut proposal = basic_motion_proposal();

        fn validate_is_ok(proposal: &Proposal) {
            assert_is_ok(validate_default_proposal(proposal));
            assert_is_ok(validate_default_action(&proposal.action));
            match proposal.action.as_ref().unwrap() {
                proposal::Action::Motion(motion) => {
                    assert_is_ok(validate_and_render_motion(motion))
                }
                _ => panic!("proposal.action is not Motion."),
            }
        }

        validate_is_ok(&proposal);
        for _ in 0..PROPOSAL_MOTION_TEXT_BYTES_MAX {
            // Push a character to motion_text.
            match proposal.action.as_mut().unwrap() {
                proposal::Action::Motion(motion) => motion.motion_text.push('a'),
                _ => panic!("proposal.action is not Motion."),
            }

            validate_is_ok(&proposal);
        }

        // The straw that breaks the camel's back: push one more character to motion_text.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::Motion(motion) => motion.motion_text.push('a'),
            _ => panic!("proposal.action is not Motion."),
        }

        // Assert that proposal is no longer ok.
        assert_is_err(validate_default_proposal(&proposal));
        assert_is_err(validate_default_action(&proposal.action));
        match proposal.action.as_ref().unwrap() {
            proposal::Action::Motion(motion) => assert_is_err(validate_and_render_motion(motion)),
            _ => panic!("proposal.action is not Motion."),
        }
    }

    fn basic_upgrade_sns_controlled_canister_proposal() -> Proposal {
        let upgrade = UpgradeSnsControlledCanister {
            canister_id: Some(basic_principal_id()),
            new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        };
        assert_is_ok(validate_and_render_upgrade_sns_controlled_canister(
            &upgrade,
        ));

        let mut result = basic_motion_proposal();
        result.action = Some(proposal::Action::UpgradeSnsControlledCanister(upgrade));

        assert_is_ok(validate_default_action(&result.action));
        assert_is_ok(validate_default_proposal(&result));

        result
    }

    fn assert_validate_upgrade_sns_controlled_canister_is_err(proposal: &Proposal) {
        assert_is_err(validate_default_proposal(proposal));
        assert_is_err(validate_default_action(&proposal.action));

        match proposal.action.as_ref().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade))
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }
    }

    #[test]
    fn upgrade_must_have_canister_id() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                upgrade.canister_id = None;
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    /// The minimum WASM is 8 bytes long. Therefore, we must not allow the
    /// new_canister_wasm field to be empty.
    #[test]
    fn upgrade_wasm_must_be_non_empty() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                upgrade.new_canister_wasm = vec![];
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    #[test]
    fn upgrade_wasm_must_not_be_dead_beef() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                // This is invalid, because it does not have the magical first
                // four bytes that a WASM is supposed to have. (Instead, the
                // first four bytes of this Vec are 0xDeadBeef.)
                upgrade.new_canister_wasm = vec![0xde, 0xad, 0xbe, 0xef, 1, 0, 0, 0];
                assert!(upgrade.new_canister_wasm.len() == 8); // The minimum wasm len.
                assert_is_err(validate_and_render_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    fn basic_add_nervous_system_function_proposal() -> Proposal {
        let nervous_system_function = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from_u64(1).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };
        assert_is_ok(validate_and_render_add_generic_nervous_system_function(
            &nervous_system_function,
            &EMPTY_FUNCTIONS,
        ));

        let mut result = basic_motion_proposal();
        result.action = Some(proposal::Action::AddGenericNervousSystemFunction(
            nervous_system_function,
        ));

        assert_is_ok(validate_default_action(&result.action));
        assert_is_ok(validate_default_proposal(&result));

        result
    }

    #[test]
    fn add_nervous_system_function_function_must_have_fields_set() {
        let mut proposal = basic_add_nervous_system_function_proposal();

        // Make sure function type is invalid
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.function_type = None;
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure invalid/unset ids are invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.id = 100;
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure name is set
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.name = "".to_string();
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure name is not too big
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.name = "X".repeat(257);
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure description is not too big
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                nervous_system_function.description = Some("X".repeat(10010));
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the target canister is invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            target_canister_id, ..
                        },
                    )) => {
                        *target_canister_id = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the target method name is invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            target_method_name, ..
                        },
                    )) => {
                        *target_method_name = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the validator canister id is invalid.
        match proposal.clone().action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            validator_canister_id,
                            ..
                        },
                    )) => {
                        *validator_canister_id = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }

        // Make sure not setting the validator method name is invalid.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::AddGenericNervousSystemFunction(nervous_system_function) => {
                match nervous_system_function.function_type.as_mut() {
                    Some(FunctionType::GenericNervousSystemFunction(
                        GenericNervousSystemFunction {
                            validator_method_name,
                            ..
                        },
                    )) => {
                        *validator_method_name = None;
                    }
                    _ => panic!("FunctionType is not GenericNervousSystemFunction"),
                }
                assert_is_err(validate_and_render_add_generic_nervous_system_function(
                    nervous_system_function,
                    &EMPTY_FUNCTIONS,
                ));
            }
            _ => panic!("Proposal.action is not AddGenericNervousSystemFunction"),
        }
    }

    #[test]
    fn add_nervous_system_function_cant_reuse_ids() {
        let nervous_system_function = NervousSystemFunction {
            id: 1000,
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from_u64(1).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(1).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };

        let mut functions_map = BTreeMap::new();
        assert_is_ok(validate_and_render_add_generic_nervous_system_function(
            &nervous_system_function,
            &functions_map,
        ));

        functions_map.insert(1000, nervous_system_function.clone());

        assert_is_ok(validate_and_render_remove_nervous_generic_system_function(
            1000,
            &functions_map,
        ));

        functions_map.insert(1000, (*NERVOUS_SYSTEM_FUNCTION_DELETION_MARKER).clone());

        assert_is_err(validate_and_render_add_generic_nervous_system_function(
            &nervous_system_function,
            &functions_map,
        ));
    }

    #[test]
    fn add_nervous_system_function_cant_exceed_maximum() {
        let mut functions_map = BTreeMap::new();

        // Fill up the functions_map with the allowed number of functions
        for i in 0..MAX_NUMBER_OF_GENERIC_NERVOUS_SYSTEM_FUNCTIONS {
            let nervous_system_function = NervousSystemFunction {
                id: i as u64 + 1000, // Valid ids for GenericNervousSystemFunction start at 1000
                name: "a".to_string(),
                description: None,
                function_type: Some(FunctionType::GenericNervousSystemFunction(
                    GenericNervousSystemFunction {
                        target_canister_id: Some(CanisterId::from_u64(i as u64).get()),
                        target_method_name: Some("test_method".to_string()),
                        validator_canister_id: Some(CanisterId::from_u64(i as u64).get()),
                        validator_method_name: Some("test_validator_method".to_string()),
                    },
                )),
            };
            functions_map.insert(i as u64, nervous_system_function);
        }

        let nervous_system_function = NervousSystemFunction {
            id: u64::MAX, // id that is not taken
            name: "a".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(CanisterId::from(u64::MAX).get()),
                    target_method_name: Some("test_method".to_string()),
                    validator_canister_id: Some(CanisterId::from_u64(u64::MAX).get()),
                    validator_method_name: Some("test_validator_method".to_string()),
                },
            )),
        };

        // Attempting to insert another GenericNervousSystemFunction should fail validation
        assert_is_err(validate_and_render_add_generic_nervous_system_function(
            &nervous_system_function,
            &functions_map,
        ));
    }
} // mod test
