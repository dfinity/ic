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
                    "{}Backfill self_describing_action: No proposals need backfilling, \
                    scheduling with longer delay",
                    LOG_PREFIX
                );
                return (
                    NO_PROPOSALS_TO_BACKFILL_INTERVAL,
                    self.with_start_bound(Bound::Unbounded),
                );
            }
        };

        // Try to convert the action to ValidProposalAction
        let valid_action = match ValidProposalAction::try_from(Some(action)) {
            Ok(valid_action) => valid_action,
            Err(e) => {
                // Conversion to ValidProposalAction failed - skip this proposal and continue
                // from this point on the next run.
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

        // Get the environment for the async call
        let env = self
            .governance
            .with_borrow(|governance| governance.env.clone());

        // Try to get the self-describing action
        let result = valid_action.to_self_describing(env).await;

        match result {
            Ok(self_describing_action) => {
                // Update the proposal with the self-describing action
                self.governance.with_borrow_mut(|governance| {
                    if let Some(proposal_data) =
                        governance.heap_data.proposals.get_mut(&proposal_id)
                        && let Some(proposal) = proposal_data.proposal.as_mut()
                    {
                        proposal.self_describing_action = Some(self_describing_action.clone());
                    }
                });

                println!(
                    "{}Backfill self_describing_action: Successfully backfilled proposal {}: {:?}",
                    LOG_PREFIX, proposal_id, self_describing_action
                );
            }
            Err(e) => {
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

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "backfill_self_describing_action";
}

#[cfg(test)]
#[path = "backfill_self_describing_action_tests.rs"]
mod tests;
