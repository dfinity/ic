use crate::{
    governance::{Governance, LOG_PREFIX},
    proposals::ValidProposalAction,
};

use async_trait::async_trait;
use ic_cdk::println;
use ic_nervous_system_timer_task::RecurringAsyncTask;
use std::{cell::RefCell, thread::LocalKey, time::Duration};

const BACKFILL_INTERVAL: Duration = Duration::from_secs(5);
const NO_PROPOSALS_TO_BACKFILL_INTERVAL: Duration = Duration::from_secs(86_400); // 1 day

pub(super) struct BackfillSelfDescribingActionTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl BackfillSelfDescribingActionTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

#[async_trait]
impl RecurringAsyncTask for BackfillSelfDescribingActionTask {
    async fn execute(self) -> (Duration, Self) {
        // Find one proposal that needs backfilling (self_describing_action is None)
        let proposal_to_backfill = self.governance.with_borrow(|governance| {
            governance
                .heap_data
                .proposals
                .iter()
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
                // No proposals need backfilling, schedule with longer delay
                println!(
                    "{}Backfill self_describing_action: No proposals need backfilling, scheduling with longer delay",
                    LOG_PREFIX
                );
                return (NO_PROPOSALS_TO_BACKFILL_INTERVAL, self);
            }
        };

        // Try to convert the action to ValidProposalAction
        let valid_action = match ValidProposalAction::try_from(Some(action)) {
            Ok(valid_action) => valid_action,
            Err(e) => {
                println!(
                    "{}Backfill self_describing_action: Failed to convert action for \
                    proposal {} to ValidProposalAction: {:?}",
                    LOG_PREFIX, proposal_id, e
                );
                return (BACKFILL_INTERVAL, self);
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

        (BACKFILL_INTERVAL, self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "backfill_self_describing_action";
}
