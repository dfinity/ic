use crate::{
    governance::{Governance, LOG_PREFIX},
    proposals::ValidProposalAction,
};

use async_trait::async_trait;
use ic_cdk::println;
use ic_nervous_system_timer_task::RecurringAsyncTask;
use std::{cell::RefCell, ops::Bound, thread::LocalKey, time::Duration};

const BACKFILL_INTERVAL: Duration = Duration::from_secs(5);
const NO_PROPOSALS_TO_BACKFILL_INTERVAL: Duration = Duration::from_secs(86_400); // 1 day

/// A task that backfills the self_describing_action field one proposal at a time.
///
/// This is done as a timer task (as opposed to within post_upgrade) because inter-canister calls
/// are needed to get the self-describing action for ExecuteNnsFunction proposals (and post_upgrade
/// cannot make inter-canister calls).
///
/// We are not doing the backfill in a single for-loop because there is a small risk or running out
/// of the instruction limit (50B) if there are a lot of consecutive proposals that are not
/// ExecuteNnsFunction proposals (some proposals are large as they contain WASMs). Instead, we
/// backfill one proposal, wait for 5s, and then backfill the next proposal.
pub(super) struct BackfillSelfDescribingActionTask {
    governance: &'static LocalKey<RefCell<Governance>>,

    /// The start bound for searching proposals needing backfill.
    /// - `Bound::Unbounded` - start from the beginning
    /// - `Bound::Excluded(id)` - start after proposal with given ID
    start_bound: Bound<u64>,
}

impl BackfillSelfDescribingActionTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self {
            governance,
            start_bound: Bound::Unbounded,
        }
    }

    fn with_start_bound(mut self, start_bound: Bound<u64>) -> Self {
        self.start_bound = start_bound;
        self
    }
}

#[async_trait]
impl RecurringAsyncTask for BackfillSelfDescribingActionTask {
    const NAME: &'static str = "backfill_self_describing_action";

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    async fn execute(self) -> (Duration, Self) {
        // Find one proposal that needs backfilling (self_describing_action is None)
        // starting from `start_bound`.
        let proposal_to_backfill = self.governance.with_borrow(|governance| {
            governance
                .heap_data
                .proposals
                .range((self.start_bound, Bound::Unbounded))
                .find_map(|(&proposal_id, proposal_data)| {
                    let proposal = proposal_data.proposal.as_ref()?;
                    if proposal.self_describing_action.is_none() {
                        let action = proposal.action.clone()?;
                        Some((proposal_id, action))
                    } else {
                        None
                    }
                })
        });

        let (proposal_id, action) = match proposal_to_backfill {
            Some(data) => data,
            None => {
                // No proposals need backfilling, schedule with longer delay and reset
                // start_bound to Unbounded so next run starts from the beginning.
                println!(
                    "{}Backfill self_describing_action: No more proposals need backfilling, \
                    scheduling with longer delay",
                    LOG_PREFIX
                );
                return (
                    NO_PROPOSALS_TO_BACKFILL_INTERVAL,
                    self.with_start_bound(Bound::Unbounded),
                );
            }
        };

        let valid_action = match ValidProposalAction::try_from(Some(action)) {
            Ok(valid_action) => valid_action,
            Err(e) => {
                // This should not happen, as existing proposals should be valid. However, it's not
                // harmful to skip it. Ideally, we would NOT try again in the next loop, but that's
                // also not harmful as we don't retry very often.
                println!(
                    "{}Backfill self_describing_action: Failed to convert action for \
                    proposal {} to ValidProposalAction: {:?}",
                    LOG_PREFIX, proposal_id, e
                );
                return (
                    BACKFILL_INTERVAL,
                    self.with_start_bound(Bound::Excluded(proposal_id)),
                );
            }
        };

        let env = self
            .governance
            .with_borrow(|governance| governance.env.clone());

        let result = valid_action.to_self_describing(env).await;

        match result {
            Ok(self_describing_action) => {
                // Update the proposal with the self-describing action
                self.governance.with_borrow_mut(|governance| {
                    let proposal = governance
                        .heap_data
                        .proposals
                        .get_mut(&proposal_id)
                        .and_then(|proposal_data| proposal_data.proposal.as_mut());
                    if let Some(proposal) = proposal {
                        println!(
                            "{}Backfill self_describing_action: Successfully backfilled proposal {}: {:?}",
                            LOG_PREFIX, proposal_id, self_describing_action
                        );
                        proposal.self_describing_action = Some(self_describing_action);
                    }
                });
            }
            Err(e) => {
                // This is the main reason why we loop back to the beginning of the proposal list
                // after all proposals have been tried - the failure can be transient and retrying
                // later can succeed.
                println!(
                    "{}Backfill self_describing_action: Failed for proposal {}: {:?}",
                    LOG_PREFIX, proposal_id, e
                );
            }
        }

        // Continue from this proposal on the next run (whether success or failure)
        (
            BACKFILL_INTERVAL,
            self.with_start_bound(Bound::Excluded(proposal_id)),
        )
    }
}

#[cfg(test)]
#[path = "backfill_self_describing_action_tests.rs"]
mod tests;
