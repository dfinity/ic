use crate::governance::log_prefix;
use crate::pb::v1::{
    Proposal, ProposalData, ProposalDecisionStatus, ProposalRewardStatus, Tally, Vote,
};
use crate::types::ONE_DAY_SECONDS;

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

    pub fn reward_status(
        &self,
        now_seconds: u64,
        voting_period_seconds: u64,
    ) -> ProposalRewardStatus {
        match self.reward_event_round {
            0 => {
                if self.accepts_vote(now_seconds, voting_period_seconds) {
                    ProposalRewardStatus::AcceptVotes
                } else {
                    ProposalRewardStatus::ReadyToSettle
                }
            }
            _ => ProposalRewardStatus::Settled,
        }
    }

    pub fn get_deadline_timestamp_seconds(&self, voting_period_seconds: u64) -> u64 {
        if let Some(wait_for_quiet_state) = &self.wait_for_quiet_state {
            wait_for_quiet_state.current_deadline_timestamp_seconds
        } else {
            self.proposal_creation_timestamp_seconds
                .saturating_add(voting_period_seconds)
        }
    }

    /// Returns true if votes are still accepted for this proposal and
    /// false otherwise.
    ///
    /// For voting reward purposes, votes may be accepted even after a
    /// decision has been made on a proposal. Such votes will not
    /// affect the decision on the proposal, but they affect the
    /// voting rewards of the voting neuron.
    ///
    /// This, this method can return true even if the proposal is
    /// already decided.
    pub fn accepts_vote(&self, now_seconds: u64, voting_period_seconds: u64) -> bool {
        // Naive version of the wait-for-quiet mechanics. For now just tests
        // that the proposal duration is smaller than the threshold, which
        // we're just currently setting as seconds.
        //
        // Wait for quiet is meant to be able to decide proposals without
        // quorum. The tally must have been done above already.
        now_seconds < self.get_deadline_timestamp_seconds(voting_period_seconds)
    }

    pub fn evaluate_wait_for_quiet(
        &mut self,
        now_seconds: u64,
        voting_period_seconds: u64,
        old_tally: &Tally,
        new_tally: &Tally,
    ) {
        let wait_for_quiet_state = match self.wait_for_quiet_state.as_mut() {
            Some(wait_for_quiet_state) => wait_for_quiet_state,
            None => return,
        };

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
    /// result is only meaningful if the deadline has passed.
    pub fn is_accepted(&self) -> bool {
        if let Some(tally) = self.latest_tally.as_ref() {
            if self.wait_for_quiet_state.is_none() {
                tally.is_absolute_majority_for_yes()
            } else {
                (tally.yes as f64 >= tally.total as f64 * MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO)
                    && tally.yes > tally.no
            }
        } else {
            false
        }
    }

    /// Returns true if a decision may be made right now to adopt or
    /// reject this proposal. The proposal must be tallied prior to
    /// calling this method.
    pub(crate) fn can_make_decision(&self, now_seconds: u64, voting_period_seconds: u64) -> bool {
        if let Some(tally) = &self.latest_tally {
            // A proposal is adopted if strictly more than half of the
            // votes are 'yes' and rejected if at least half of the votes
            // are 'no'. The conditions are described as below to avoid
            // overflow. In the absence of overflow, the below is
            // equivalent to (2 * yes > total) || (2 * no >= total).
            let majority =
                (tally.yes > tally.total - tally.yes) || (tally.no >= tally.total - tally.no);
            let expired = !self.accepts_vote(now_seconds, voting_period_seconds);
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
    pub(crate) fn can_be_purged(&self, now_seconds: u64, voting_period_seconds: u64) -> bool {
        self.status().is_final()
            && self
                .reward_status(now_seconds, voting_period_seconds)
                .is_final()
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
