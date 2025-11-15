use crate::governance::{Governance, LOG_PREFIX};
use crate::neuron_store::NeuronStore;
use crate::pb::v1::RewardsDistributionInProgress;
use crate::storage::with_rewards_distribution_state_machine_mut;
#[cfg(not(feature = "canbench-rs"))]
use crate::timer_tasks::run_distribute_rewards_periodic_task;
use ic_cdk::println;
use ic_nervous_system_long_message::is_message_over_threshold;
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{StableBTreeMap, Storable};
use prost::Message;
use std::borrow::Cow;
use std::collections::BTreeMap;

const BILLION: u64 = 1_000_000_000;
const DISTRIBUTION_MESSAGE_LIMIT: u64 = BILLION;

impl Governance {
    pub(crate) fn schedule_pending_rewards_distribution(
        &self,
        day_after_genesis: u64,
        distribution: RewardsDistribution,
    ) {
        let result =
            with_rewards_distribution_state_machine_mut(|rewards_distribution_state_machine| {
                rewards_distribution_state_machine
                    .add_rewards_distribution(day_after_genesis, distribution)
            });

        if let Err(e) = result {
            println!("{}Error scheduling rewards distribution: {}", LOG_PREFIX, e);
        }

        // TODO(NNS1-3643) Determine if there is a way we can refactor this so that
        // canbench can call timer setting function stubs (or even immediately execute the work)
        #[cfg(not(feature = "canbench-rs"))]
        run_distribute_rewards_periodic_task();
    }

    // Returns if there is work left to do
    pub fn distribute_pending_rewards(&mut self) -> bool {
        let is_over_instructions_limit = || is_message_over_threshold(DISTRIBUTION_MESSAGE_LIMIT);
        with_rewards_distribution_state_machine_mut(|rewards_distribution_state_machine| {
            rewards_distribution_state_machine.with_next_distribution(|(_, distribution)| {
                distribution
                    .continue_processing(&mut self.neuron_store, is_over_instructions_limit);
            });
            // Work left?
            !rewards_distribution_state_machine.distributions.is_empty()
        })
    }
}

pub(crate) struct RewardsDistributionStateMachine<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    // Map is reward_event_round (day_after_genesis) => rewards_distribution
    // This allows us to see if the latest_reward_event has finished distributing rewards
    // to neurons
    distributions: StableBTreeMap<u64, RewardsDistributionInProgress, Memory>,
}

impl<Memory: ic_stable_structures::Memory> RewardsDistributionStateMachine<Memory> {
    pub(crate) fn new(memory: Memory) -> Self {
        Self {
            distributions: StableBTreeMap::init(memory),
        }
    }

    fn with_next_distribution<R>(
        &mut self,
        callback: impl FnOnce((u64, &mut RewardsDistribution)) -> R,
    ) -> Option<R> {
        if let Some((day_after_genesis, proto)) = self.distributions.pop_first() {
            let mut distribution = RewardsDistribution::from(proto);
            let result = callback((day_after_genesis, &mut distribution));
            if !distribution.is_completely_finished() {
                self.distributions.insert(
                    day_after_genesis,
                    RewardsDistributionInProgress::from(distribution),
                );
            }
            Some(result)
        } else {
            None
        }
    }

    fn add_rewards_distribution(
        &mut self,
        day_after_genesis: u64,
        distribution: RewardsDistribution,
    ) -> Result<(), String> {
        if self.distributions.contains_key(&day_after_genesis) {
            return Err(format!(
                "{LOG_PREFIX}Rewards distribution already exists for day_after_genesis: {day_after_genesis}"
            ));
        }
        self.distributions.insert(
            day_after_genesis,
            RewardsDistributionInProgress::from(distribution),
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_distribution_for_event<R>(
        &mut self,
        day_after_genesis: u64,
        callback: impl FnOnce(&mut RewardsDistribution) -> R,
    ) -> R {
        let mut distribution = self
            .distributions
            .remove(&day_after_genesis)
            .map(RewardsDistribution::from)
            .unwrap_or_default();

        let result = callback(&mut distribution);

        if !distribution.is_completely_finished() {
            self.distributions.insert(
                day_after_genesis,
                RewardsDistributionInProgress::from(distribution),
            );
        }

        result
    }
}

#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct RewardsDistribution {
    // NeuronId -> amount in e8s
    rewards: BTreeMap<NeuronId, u64>,
}

impl RewardsDistribution {
    pub(crate) fn new() -> Self {
        Self {
            rewards: BTreeMap::new(),
        }
    }

    pub(crate) fn add_reward(&mut self, neuron_id: NeuronId, amount: u64) {
        self.rewards.insert(neuron_id, amount);
    }

    fn is_completely_finished(&self) -> bool {
        self.rewards.is_empty()
    }

    fn continue_processing(
        &mut self,
        neuron_store: &mut NeuronStore,
        is_over_instructions_limit: fn() -> bool,
    ) {
        while let Some((id, reward_e8s)) = self.rewards.pop_first() {
            match neuron_store.with_neuron_mut(&id, |neuron| {
                let auto_stake = neuron.auto_stake_maturity.unwrap_or(false);
                if auto_stake {
                    neuron.staked_maturity_e8s_equivalent = Some(
                        neuron
                            .staked_maturity_e8s_equivalent
                            .unwrap_or_default()
                            .saturating_add(reward_e8s),
                    );
                } else {
                    neuron.maturity_e8s_equivalent =
                        neuron.maturity_e8s_equivalent.saturating_add(reward_e8s);
                }
            }) {
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "{}Error rewarding neuron {:?} during reward_distribution.\
                    This should not be possible as neuron existence is checked when \
                    rewards are calculated: {}",
                        LOG_PREFIX, id, e
                    );
                }
            };
            if is_over_instructions_limit() {
                break;
            }
        }
    }
}

impl Storable for RewardsDistributionInProgress {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self::decode(&bytes[..])
            // Convert from Result to Self. (Unfortunately, it seems that
            // panic is unavoidable in the case of Err.)
            .expect("Unable to decode RewardsDistribution")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl From<RewardsDistribution> for RewardsDistributionInProgress {
    fn from(rewards_distribution: RewardsDistribution) -> Self {
        Self {
            neuron_ids_to_e8_amounts: rewards_distribution
                .rewards
                .into_iter()
                .map(|(neuron_id, e8s)| (neuron_id.id, e8s))
                .collect(),
        }
    }
}

impl From<RewardsDistributionInProgress> for RewardsDistribution {
    fn from(value: RewardsDistributionInProgress) -> Self {
        Self {
            rewards: value
                .neuron_ids_to_e8_amounts
                .into_iter()
                .map(|(neuron_id, e8s)| (NeuronId { id: neuron_id }, e8s))
                .collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::governance::Governance;
    use crate::neuron::{DissolveStateAndAge, Neuron, NeuronBuilder};
    use crate::pb::v1::VotingPowerEconomics;
    use crate::test_utils::{
        MockEnvironment, MockRandomness, StubCMC, StubIcpLedger, test_subaccount_for_neuron_id,
    };
    use ic_base_types::PrincipalId;
    use ic_nervous_system_timers::test::run_pending_timers_every_interval_for_count;
    use ic_stable_structures::DefaultMemoryImpl;
    use icp_ledger::Subaccount;
    use std::sync::Arc;

    fn make_neuron(id: u64, maturity_e8s: u64, staked_maturity_e8s: u64) -> Neuron {
        let subaccount =
            Subaccount::try_from(test_subaccount_for_neuron_id(id).as_slice()).unwrap();

        let now = 123_456_789;
        let dissolve_delay_seconds =
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
        let aging_since_timestamp_seconds = now - dissolve_delay_seconds;

        let dissolve_state_and_age = DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds,
            aging_since_timestamp_seconds,
        };

        NeuronBuilder::new(
            NeuronId { id },
            subaccount,
            PrincipalId::new_user_test_id(id),
            dissolve_state_and_age,
            now,
        )
        .with_maturity_e8s_equivalent(maturity_e8s)
        .with_staked_maturity_e8s_equivalent(staked_maturity_e8s)
        .build()
    }

    #[test]
    fn test_add_and_retrieve_rewards_distribution() {
        let mut rewards_distribution_state_machine =
            RewardsDistributionStateMachine::new(DefaultMemoryImpl::default());

        let neuron_id = NeuronId { id: 1 };
        let input_day_after_genesis = 1;

        rewards_distribution_state_machine
            .with_distribution_for_event(input_day_after_genesis, |distribution| {
                distribution.add_reward(neuron_id, 1000)
            });

        let (day_after_genesis, rewards_distribution) = rewards_distribution_state_machine
            .with_next_distribution(|(day_after_genesis, distribution)| {
                (day_after_genesis, distribution.clone())
            })
            .unwrap();

        assert_eq!(rewards_distribution.rewards.get(&neuron_id), Some(&1000));
        assert_eq!(day_after_genesis, input_day_after_genesis);
    }

    #[test]
    fn test_distribute_rewards_for_multiple_events_to_neurons() {
        let mut neurons = BTreeMap::new();
        for i in 0..5 {
            neurons.insert(i, make_neuron(i, 1000, 1000));
        }
        for i in 5..10 {
            let mut neuron = make_neuron(i, 1000, 1000);
            neuron.auto_stake_maturity = Some(true);
            neurons.insert(i, neuron);
        }

        let mut neuron_store = NeuronStore::new(neurons.clone());

        let mut rewards_distribution_state_machine =
            RewardsDistributionStateMachine::new(DefaultMemoryImpl::default());

        // create 2 distributions
        for day_after_genesis in 1..=2 {
            rewards_distribution_state_machine.with_distribution_for_event(
                day_after_genesis,
                |distribution| {
                    for id in neurons.keys() {
                        distribution.add_reward(NeuronId { id: *id }, 10);
                    }
                },
            );
        }

        // We are testing that rewards are always distributed even if there are more than
        // one distribution event that needs to get processed.  Each timer task would continue the
        // work, and we ensure the next distribution is picked up.
        rewards_distribution_state_machine.with_next_distribution(
            |(_day_after_genesis, distribution)| {
                distribution.continue_processing(&mut neuron_store, || false);
            },
        );

        rewards_distribution_state_machine.with_next_distribution(
            |(_day_after_genesis, distribution)| {
                distribution.continue_processing(&mut neuron_store, || false);
            },
        );

        for i in 0..5 {
            neuron_store
                .with_neuron(&NeuronId { id: i }, |neuron| {
                    assert_eq!(neuron.maturity_e8s_equivalent, 1020);
                    assert_eq!(neuron.staked_maturity_e8s_equivalent, Some(1000));
                })
                .unwrap();
        }
        for i in 5..10 {
            neuron_store
                .with_neuron(&NeuronId { id: i }, |neuron| {
                    assert_eq!(neuron.maturity_e8s_equivalent, 1000);
                    assert_eq!(neuron.staked_maturity_e8s_equivalent, Some(1020));
                })
                .unwrap();
        }
    }

    #[test]
    fn test_distributions_always_at_least_distributes_one() {
        // This test ensures that in the worst case, the task will always distribute at least one
        // reward (i.e. it does not check instructions before trying to do at least a single piece
        // of work)

        let mut neurons = BTreeMap::new();
        for i in 0..5 {
            neurons.insert(i, make_neuron(i, 1000, 1000));
        }
        for i in 5..10 {
            let mut neuron = make_neuron(i, 1000, 1000);
            neuron.auto_stake_maturity = Some(true);
            neurons.insert(i, neuron);
        }

        let mut neuron_store = NeuronStore::new(neurons.clone());

        let mut rewards_distribution_state_machine =
            RewardsDistributionStateMachine::new(DefaultMemoryImpl::default());

        rewards_distribution_state_machine.with_distribution_for_event(1, |distribution| {
            for id in neurons.keys() {
                distribution.add_reward(NeuronId { id: *id }, 10);
            }
        });

        for i in 0..10 {
            rewards_distribution_state_machine.with_next_distribution(
                |(_day_after_genesis, distribution)| {
                    distribution.continue_processing(&mut neuron_store, || true);
                    assert_eq!(distribution.rewards.len(), 9 - i);
                },
            );
        }

        assert!(rewards_distribution_state_machine.distributions.is_empty());
    }

    #[tokio::test]
    async fn test_distribute_pending_rewards() {
        // We are testing recoverability of the system (i.e. it got stalled, but we didnt' lose data, and now
        // it is able to finish processing)
        let mut governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        for i in 1..=5 {
            governance
                .add_neuron(i, make_neuron(i, 1000, 1000))
                .unwrap();
        }
        for i in 6..=10 {
            let mut neuron = make_neuron(i, 1000, 1000);
            neuron.auto_stake_maturity = Some(true);
            governance.add_neuron(i, neuron).unwrap();
        }

        let mut distribution = RewardsDistribution::new();
        for id in 0..10 {
            distribution.add_reward(NeuronId { id }, 10);
        }
        // create 2 distributions
        governance.schedule_pending_rewards_distribution(1, distribution.clone());
        governance.schedule_pending_rewards_distribution(2, distribution);

        // We have to run this more times b/c the test version of is_over_instructions_limit returns true every
        // other time it's called.
        run_pending_timers_every_interval_for_count(std::time::Duration::from_secs(2), 10).await;

        with_rewards_distribution_state_machine_mut(|rewards_distribution_state_machine| {
            assert!(rewards_distribution_state_machine.distributions.is_empty())
        });
    }
}
