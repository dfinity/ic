use crate::governance::{Governance, LOG_PREFIX, REWARD_DISTRIBUTION_PERIOD_SECONDS};
use crate::pb::v1::GovernanceError;
use async_trait::async_trait;
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
        // TODO DO NOT MERGE, test this logic, and think about edge cases for it.
        self.governance.with_borrow(|governance| {
            let latest_day_after_genesis = governance.latest_reward_event().day_after_genesis;
            let now = governance.env.now();
            let genesis_timestamp_seconds = governance.heap_data.genesis_timestamp_seconds;

            next_reward_task_from_now(now, genesis_timestamp_seconds, latest_day_after_genesis)
        })
    }
}

fn next_reward_task_from_now(
    now: u64,
    genesis_timestamp_seconds: u64,
    latest_reward_day_after_genesis: u64,
) -> Duration {
    let latest_distribution_nominal_end_timestamp_seconds = latest_reward_day_after_genesis
        * REWARD_DISTRIBUTION_PERIOD_SECONDS
        + genesis_timestamp_seconds;

    let next =
        latest_distribution_nominal_end_timestamp_seconds + REWARD_DISTRIBUTION_PERIOD_SECONDS;

    Duration::from_secs(next.saturating_sub(now) + 1)
}

const REWARD_DISTRIBUTION_INTERVAL: Duration =
    Duration::from_secs(REWARD_DISTRIBUTION_PERIOD_SECONDS);

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
                    governance.distribute_rewards(total_supply);
                });
            }
            Err(err) => {
                ic_cdk::println!(
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
        println!(
            "Calling Initial delay {:?}",
            self.next_reward_task_from_now()
        );
        self.next_reward_task_from_now()
    }

    const NAME: &'static str = "RewardDistribution";
}
