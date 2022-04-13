use crate::governance::log_prefix;
use crate::pb::v1::{
    proposal, CallCanisterMethod, ExecuteNervousSystemFunction, Motion, NervousSystemParameters,
    Proposal, ProposalData, ProposalDecisionStatus, ProposalRewardStatus, Tally,
    UpgradeSnsControlledCanister, Vote,
};
use crate::types::ONE_DAY_SECONDS;
use crate::{validate_chars_count, validate_len, validate_required_field};

use dfn_core::api::CanisterId;

/// The maximum number of bytes in an SNS proposal's title.
pub const PROPOSAL_TITLE_BYTES_MAX: usize = 256;
/// The maximum number of bytes in an SNS proposal's summary.
pub const PROPOSAL_SUMMARY_BYTES_MAX: usize = 15000;
/// The maximum number of bytes in an SNS proposal's URL.
pub const PROPOSAL_URL_CHAR_MAX: usize = 2048;
/// The maximum number of bytes in an SNS motion proposal's motion_text
pub const PROPOSAL_MOTION_TEXT_BYTES_MAX: usize = 10000;

/// A proposal does not need to reach absolute majority to be accepted. However
/// there is a minimum amount of votes needed for a simple majority to be
/// enough. This minimum is expressed as a ratio of the total possible votes for
/// the proposal.
pub const MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO: f64 = 0.03;

/// Parameter of the wait for quiet algorithm. This is the maximum amount the
/// deadline can be delayed on each vote.
pub const WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS: u64 = ONE_DAY_SECONDS;

/// The maximum number results returned by the method `list_proposals`.
pub const MAX_LIST_PROPOSAL_RESULTS: u32 = 100;

/// The max number of unsettled proposals -- that is proposals for which ballots
/// are still stored.
pub const MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS: usize = 700;

impl Proposal {
    /// Returns whether such a proposal should be allowed to
    /// be submitted when the heap growth potential is low.
    pub(crate) fn allowed_when_resources_are_low(&self) -> bool {
        self.action
            .as_ref()
            .map_or(false, |a| a.allowed_when_resources_are_low())
    }
}

/// current_nervous_system_paramters is only used when self is a
/// ManageNervousSystemParameters proposal.
///
/// Pro tip: If it is difficult to get the current NervousSystemParameters, you
/// may be able to use NervousSystemParameters::with_default_values() instead.
pub fn validate_proposal(
    proposal: &Proposal,
    current_nervous_system_parameters: &NervousSystemParameters,
) -> Result<(), String> {
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

    defects_push(validate_action(
        &proposal.action,
        current_nervous_system_parameters,
    ));

    // Concatenate defects (if any).
    if !defects.is_empty() {
        return Err(format!(
            "{} defects in Proposal:\n{}",
            defects.len(),
            defects.join("\n"),
        ));
    }

    Ok(())
}

pub fn validate_action(
    action: &Option<proposal::Action>,
    current_nervous_system_parameters: &NervousSystemParameters,
) -> Result<(), String> {
    let action = match action.as_ref() {
        None => return Err("No action was specified.".into()),
        Some(action) => action,
    };

    match action {
        proposal::Action::Unspecified(_unspecified) => {
            Err("`unspecified` was used, but is not a valid Proposal action.".into())
        }
        proposal::Action::Motion(motion) => validate_motion(motion),
        proposal::Action::ManageNervousSystemParameters(manage) => {
            validate_manage_nervous_system_parameters(manage, current_nervous_system_parameters)
        }
        proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
            validate_upgrade_sns_controlled_canister(upgrade)
        }
        proposal::Action::ExecuteNervousSystemFunction(execute) => {
            validate_execute_nervous_system_function(execute)
        }
        proposal::Action::CallCanisterMethod(call) => validate_call_canister_method(call),
    }
}

fn validate_motion(motion: &Motion) -> Result<(), String> {
    validate_len(
        "motion.motion_text",
        &motion.motion_text,
        0, // min
        PROPOSAL_MOTION_TEXT_BYTES_MAX,
    )
}

fn validate_manage_nervous_system_parameters(
    new: &NervousSystemParameters,
    current: &NervousSystemParameters,
) -> Result<(), String> {
    new.inherit_from(current).validate()
}

fn validate_upgrade_sns_controlled_canister(
    upgrade: &UpgradeSnsControlledCanister,
) -> Result<(), String> {
    let mut defects = vec![];

    // Inspect canister_id.
    match validate_required_field("canister_id", &upgrade.canister_id) {
        Err(err) => {
            defects.push(err);
        }
        Ok(canister_id) => {
            if let Err(err) = CanisterId::new(*canister_id) {
                defects.push(format!("Specified canister ID was invalid: {}", err));
            }
        }
    }

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

    Ok(())
}

pub fn validate_execute_nervous_system_function(
    _execute: &ExecuteNervousSystemFunction,
) -> Result<(), String> {
    todo!();
}

pub(crate) fn validate_call_canister_method(call: &CallCanisterMethod) -> Result<(), String> {
    let CallCanisterMethod {
        target_canister_id,
        target_method_name,
        payload: _,
    } = call;

    let mut defects = vec![];

    // Validate the target_canister_id field.
    match target_canister_id {
        None => defects.push("target_canister_id field was not populated.".to_string()),
        Some(id) => {
            if let Err(err) = CanisterId::new(*id) {
                defects.push(format!("target_canister_id was invalid: {}", err));
            }
        }
    }

    // Validate the target_method_name field.
    if target_method_name.is_empty() {
        defects.push("target_method_name was empty.".to_string());
    }

    if !defects.is_empty() {
        return Err(format!(
            "CallCanisterMethod was invalid for the following reason(s):\n{}",
            defects.join("\n")
        ));
    }

    Ok(())
}

impl ProposalData {
    /// Compute the 'status' of a proposal. See [ProposalDecisionStatus] for
    /// more information.
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

    pub fn get_deadline_timestamp_seconds(&self) -> u64 {
        self.wait_for_quiet_state
            .as_ref()
            .expect("Proposal must have a wait_for_quiet_state.")
            .current_deadline_timestamp_seconds
    }

    /// Returns true if votes are still accepted for this proposal and
    /// false otherwise.
    ///
    /// For voting reward purposes, votes may be accepted even after a
    /// decision has been made on a proposal. Such votes will not
    /// affect the decision on the proposal, but they affect the
    /// voting rewards of the voting neuron.
    ///
    /// This method can return true even if the proposal is
    /// already decided.
    pub fn accepts_vote(&self, now_seconds: u64) -> bool {
        // Naive version of the wait-for-quiet mechanics. For now just tests
        // that the proposal duration is smaller than the threshold, which
        // we're just currently setting as seconds.
        //
        // Wait for quiet is meant to be able to decide proposals without
        // quorum. The tally must have been done above already.
        now_seconds < self.get_deadline_timestamp_seconds()
    }

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

        // Dont evaluate wait for quiet if there is already a decision, or the
        // deadline has been met. The deciding amount for yes and no are
        // slightly different, because yes needs a majority to succeed, while
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

        // Returns whether the vote has turned, i.e. if the vote is now yes, when it was
        // previously no, or if the vote is now no if it was previously yes.
        fn vote_has_turned(old_tally: &Tally, new_tally: &Tally) -> bool {
            (old_tally.yes > old_tally.no && new_tally.yes <= new_tally.no)
                || (old_tally.yes <= old_tally.no && new_tally.yes > new_tally.no)
        }
        if !vote_has_turned(old_tally, new_tally) {
            return;
        }

        // The required_margin reflects the proposed deadline extension to be
        // made beyond the current moment, so long as that extends beyond the
        // current wait-for-quiet deadline. We calculate the required_margin a
        // bit indirectly here so as to keep with unsigned integers, but the
        // idea is:
        //
        //     W + (voting_period - elapsed) / 2
        //
        // Thus, while we are still within the original voting period, we add
        // to W, but once we are beyond that window, we subtract from W until
        // reaching the limit where required_margin remains at zero. This
        // occurs when:
        //
        //     elapsed = voting_period + 2 * W
        //
        // As an example, given that W = 12h, if the initial voting_period is
        // 24h then the maximum deadline will be 48h.
        //
        // The required_margin ends up being a linearly decreasing value,
        // starting at W + voting_period / 2 and reducing to zero at the
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

    /// Returns true if a proposal meets the conditions to be accepted. The
    /// result is only meaningful if the proposal can be decided, i.e., either there is a majority or the deadline has passed.
    pub fn is_accepted(&self) -> bool {
        if let Some(tally) = self.latest_tally.as_ref() {
            (tally.yes as f64 >= tally.total as f64 * MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO)
                && tally.yes > tally.no
        } else {
            false
        }
    }

    /// Returns true if a decision may be made right now to adopt or
    /// reject this proposal. The proposal must be tallied prior to
    /// calling this method.
    pub(crate) fn can_make_decision(&self, now_seconds: u64) -> bool {
        if let Some(tally) = &self.latest_tally {
            // A proposal is adopted if strictly more than half of the
            // votes are 'yes' and rejected if at least half of the votes
            // are 'no'. The conditions are described as below to avoid
            // overflow. In the absence of overflow, the below is
            // equivalent to (2 * yes > total) || (2 * no >= total).
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

    /// Return true if this proposal can be purged from storage, e.g.,
    /// if it is allowed to be garbage collected.
    pub(crate) fn can_be_purged(&self, now_seconds: u64) -> bool {
        self.status().is_final() && self.reward_status(now_seconds).is_final()
    }
}

impl ProposalDecisionStatus {
    /// Return true if this status is 'final' in the sense that no
    /// further state transitions are possible.
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
    /// Return true if this reward status is 'final' in the sense that
    /// no further state transitions are possible.
    pub fn is_final(&self) -> bool {
        matches!(self, ProposalRewardStatus::Settled)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pb::v1::Empty;
    use crate::test::{assert_is_err, assert_is_ok};
    use ic_base_types::PrincipalId;
    use std::convert::TryFrom;

    fn validate_default_proposal(proposal: &Proposal) -> Result<(), String> {
        let parameters = NervousSystemParameters::with_default_values();
        validate_proposal(proposal, &parameters)
    }

    fn validate_default_action(action: &Option<proposal::Action>) -> Result<(), String> {
        let parameters = NervousSystemParameters::with_default_values();
        validate_action(action, &parameters)
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
                proposal::Action::Motion(motion) => assert_is_ok(validate_motion(motion)),
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
            proposal::Action::Motion(motion) => assert_is_err(validate_motion(motion)),
            _ => panic!("proposal.action is not Motion."),
        }
    }

    fn basic_upgrade_sns_controlled_canister_proposal() -> Proposal {
        let upgrade = UpgradeSnsControlledCanister {
            canister_id: Some(basic_principal_id()),
            new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        };
        assert_is_ok(validate_upgrade_sns_controlled_canister(&upgrade));

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
                assert_is_err(validate_upgrade_sns_controlled_canister(upgrade))
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
                assert_is_err(validate_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    /// Fun fact: the minimum WASM is 8 bytes long.
    ///
    /// A corollary of the above fact is that we must not allow the
    /// new_canister_wasm field to be empty.
    #[test]
    fn upgrade_wasm_must_be_non_empty() {
        let mut proposal = basic_upgrade_sns_controlled_canister_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::UpgradeSnsControlledCanister(upgrade) => {
                upgrade.new_canister_wasm = vec![];
                assert_is_err(validate_upgrade_sns_controlled_canister(upgrade));
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
                assert_is_err(validate_upgrade_sns_controlled_canister(upgrade));
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }

        assert_validate_upgrade_sns_controlled_canister_is_err(&proposal);
    }

    fn basic_call_canister_method_proposal() -> Proposal {
        let call = CallCanisterMethod {
            target_canister_id: Some(basic_principal_id()),
            target_method_name: "enact_awesomeness".into(),
            payload: vec![],
        };
        assert_is_ok(validate_call_canister_method(&call));

        let mut result = basic_motion_proposal();
        result.action = Some(proposal::Action::CallCanisterMethod(call));

        assert_is_ok(validate_default_action(&result.action));
        assert_is_ok(validate_default_proposal(&result));

        result
    }

    fn assert_validate_call_canister_method_is_err(proposal: &Proposal) {
        assert_is_err(validate_default_action(&proposal.action));
        assert_is_err(validate_default_proposal(proposal));

        match proposal.action.as_ref().unwrap() {
            proposal::Action::CallCanisterMethod(call) => {
                assert_is_err(validate_call_canister_method(call))
            }
            _ => panic!("Proposal.action is not an UpgradeSnsControlledCanister."),
        }
    }

    #[test]
    fn test_validate_call_canister_method_fail_no_target_canister_id() {
        let mut proposal = basic_call_canister_method_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::CallCanisterMethod(call) => {
                call.target_canister_id = None;
                assert_is_err(validate_call_canister_method(call));
            }
            _ => panic!("Proposal.action is not a CallCanisterMethod."),
        }

        assert_validate_call_canister_method_is_err(&proposal);
    }

    #[test]
    fn test_validate_call_canister_method_fail_empty_target_method_name() {
        let mut proposal = basic_call_canister_method_proposal();

        // Create a defect.
        match proposal.action.as_mut().unwrap() {
            proposal::Action::CallCanisterMethod(call) => {
                call.target_method_name = "".into();
                assert_is_err(validate_call_canister_method(call));
            }
            _ => panic!("Proposal.action is not a CallCanisterMethod."),
        }

        assert_validate_call_canister_method_is_err(&proposal);
    }
} // mod test
