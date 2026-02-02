use crate::governance::{Governance, LOG_PREFIX, REWARD_DISTRIBUTION_PERIOD_SECONDS};
use crate::pb::v1::GovernanceError;
use async_trait::async_trait;
use ic_cdk::println;
use ic_nervous_system_timer_task::RecurringAsyncTask;
use std::cell::RefCell;
use std::thread::LocalKey;
use std::time::Duration;

pub(super) struct CalculateDistributableRewardsTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl CalculateDistributableRewardsTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }

    fn next_reward_task_from_now(&self) -> Duration {
        self.governance.with_borrow(|governance| {
            let latest_day_after_genesis = governance.latest_reward_event().day_after_genesis;
            let now = governance.env.now();
            let genesis_timestamp_seconds = governance.heap_data.genesis_timestamp_seconds;

            delay_until_next_run(now, genesis_timestamp_seconds, latest_day_after_genesis)
        })
    }
}

fn delay_until_next_run(
    now: u64,
    genesis_timestamp_seconds: u64,
    latest_reward_day_after_genesis: u64,
) -> Duration {
    let latest_distribution_nominal_end_timestamp_seconds = latest_reward_day_after_genesis
        .saturating_mul(REWARD_DISTRIBUTION_PERIOD_SECONDS)
        .saturating_add(genesis_timestamp_seconds);

    // We add 1 to the end of the period to make sure we always run after the period is over, to
    // avoid missing any proposals that would be ready to settle right on the edge of the period.
    let next = latest_distribution_nominal_end_timestamp_seconds
        .saturating_add(REWARD_DISTRIBUTION_PERIOD_SECONDS)
        .saturating_add(1);

    // We want the difference between next and now.  If it's in the past, we want to run
    // immediately
    Duration::from_secs(next.saturating_sub(now))
}

#[async_trait]
impl RecurringAsyncTask for CalculateDistributableRewardsTask {
    async fn execute(self) -> (Duration, Self) {
        let total_supply = self
            .governance
            .with_borrow(|governance| governance.get_ledger())
            .total_supply()
            .await;
        match total_supply {
            Ok(total_supply) => {
                self.governance.with_borrow_mut(|governance| {
                    governance.distribute_voting_rewards_to_neurons(total_supply);
                });
            }
            Err(err) => {
                println!(
                    "{}Error when getting total ICP supply: {}",
                    LOG_PREFIX,
                    GovernanceError::from(err)
                )
            }
        }

        let next_run = self.next_reward_task_from_now();
        (next_run, self)
    }

    fn initial_delay(&self) -> Duration {
        self.next_reward_task_from_now()
    }

    const NAME: &'static str = "calculate_distributable_rewards";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister_state::{CanisterRandomnessGenerator, set_governance_for_tests};
    use crate::governance::Governance;
    use crate::test_utils::{MockEnvironment, StubCMC, StubIcpLedger};
    use ic_nns_governance_api as api;
    use std::sync::Arc;

    fn test_delay_until_next_run(
        now: u64,
        genesis_timestamp_seconds: u64,
        latest_reward_day_after_genesis: u64,
        expected: Duration,
    ) {
        let next = delay_until_next_run(
            now,
            genesis_timestamp_seconds,
            latest_reward_day_after_genesis,
        );
        assert_eq!(next, expected);
    }

    #[test]
    fn test_delay_until_next_run_all_zero() {
        let now = 0;
        let genesis_timestamp_seconds = 0;
        let latest_reward_day_after_genesis = 0;

        test_delay_until_next_run(
            now,
            genesis_timestamp_seconds,
            latest_reward_day_after_genesis,
            Duration::from_secs(REWARD_DISTRIBUTION_PERIOD_SECONDS + 1),
        );
    }

    #[test]
    fn test_delay_until_next_run_missed_days() {
        let now = REWARD_DISTRIBUTION_PERIOD_SECONDS * 3;
        let genesis_timestamp_seconds = 0;
        let latest_reward_day_after_genesis = 1;

        test_delay_until_next_run(
            now,
            genesis_timestamp_seconds,
            latest_reward_day_after_genesis,
            Duration::from_secs(0),
        );
    }

    #[test]
    fn test_delay_until_next_run_exactly_at_event() {
        let now = REWARD_DISTRIBUTION_PERIOD_SECONDS + 1;
        let genesis_timestamp_seconds = 0;
        let latest_reward_day_after_genesis = 1;

        test_delay_until_next_run(
            now,
            genesis_timestamp_seconds,
            latest_reward_day_after_genesis,
            Duration::from_secs(REWARD_DISTRIBUTION_PERIOD_SECONDS),
        );
    }

    #[test]
    fn test_delay_until_next_run_with_positive_genesis_value() {
        let now = 10_000 + REWARD_DISTRIBUTION_PERIOD_SECONDS * 5 + 500;
        let genesis_timestamp_seconds = 10_000;
        let latest_reward_day_after_genesis = 5;

        test_delay_until_next_run(
            now,
            genesis_timestamp_seconds,
            latest_reward_day_after_genesis,
            Duration::from_secs(REWARD_DISTRIBUTION_PERIOD_SECONDS - 500 + 1),
        );
    }

    #[test]
    fn test_governance_integration_with_delay_calculation() {
        let now = 10_000 + REWARD_DISTRIBUTION_PERIOD_SECONDS * 5 + 500;
        let genesis_timestamp_seconds = 10_000;
        let latest_reward_day_after_genesis = 5;

        let gov = Governance::new(
            api::Governance {
                genesis_timestamp_seconds,
                latest_reward_event: Some(api::RewardEvent {
                    day_after_genesis: latest_reward_day_after_genesis,
                    ..Default::default()
                }),
                ..Default::default()
            },
            Arc::new(MockEnvironment::new(vec![], now)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(CanisterRandomnessGenerator::new()),
        );
        set_governance_for_tests(gov);

        let task = CalculateDistributableRewardsTask::new(&crate::canister_state::GOVERNANCE);

        let next = task.next_reward_task_from_now();
        assert_eq!(
            next,
            Duration::from_secs(REWARD_DISTRIBUTION_PERIOD_SECONDS - 500 + 1)
        );
    }
}
