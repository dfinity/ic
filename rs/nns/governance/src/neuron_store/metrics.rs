use super::NeuronStore;
use crate::{
    governance::ONE_MONTH_SECONDS, pb::v1::NeuronState, storage::with_stable_neuron_store,
};
use std::collections::HashMap;

/// Metrics calculated based on neurons in the neuron store.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct NeuronMetrics {
    pub dissolving_neurons_count: u64,
    pub dissolving_neurons_e8s_buckets: HashMap<u64, f64>,
    pub dissolving_neurons_count_buckets: HashMap<u64, u64>,
    pub not_dissolving_neurons_count: u64,
    pub not_dissolving_neurons_e8s_buckets: HashMap<u64, f64>,
    pub not_dissolving_neurons_count_buckets: HashMap<u64, u64>,
    pub dissolved_neurons_count: u64,
    pub dissolved_neurons_e8s: u64,
    pub garbage_collectable_neurons_count: u64,
    pub neurons_with_invalid_stake_count: u64,
    pub total_staked_e8s: u64,
    pub neurons_with_less_than_6_months_dissolve_delay_count: u64,
    pub neurons_with_less_than_6_months_dissolve_delay_e8s: u64,
    pub community_fund_total_staked_e8s: u64,
    pub community_fund_total_maturity_e8s_equivalent: u64,
    pub neurons_fund_total_active_neurons: u64,
    pub total_locked_e8s: u64,
    pub total_maturity_e8s_equivalent: u64,
    pub total_staked_maturity_e8s_equivalent: u64,
    pub dissolving_neurons_staked_maturity_e8s_equivalent_buckets: HashMap<u64, f64>,
    pub dissolving_neurons_staked_maturity_e8s_equivalent_sum: u64,
    pub not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets: HashMap<u64, f64>,
    pub not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: u64,
    pub seed_neuron_count: u64,
    pub ect_neuron_count: u64,
    pub total_staked_e8s_seed: u64,
    pub total_staked_e8s_ect: u64,
    pub total_staked_maturity_e8s_equivalent_seed: u64,
    pub total_staked_maturity_e8s_equivalent_ect: u64,
    pub dissolving_neurons_e8s_buckets_seed: HashMap<u64, f64>,
    pub dissolving_neurons_e8s_buckets_ect: HashMap<u64, f64>,
    pub not_dissolving_neurons_e8s_buckets_seed: HashMap<u64, f64>,
    pub not_dissolving_neurons_e8s_buckets_ect: HashMap<u64, f64>,
}

impl NeuronStore {
    /// Computes neuron metrics.
    pub fn compute_neuron_metrics(
        &self,
        now_seconds: u64,
        minimum_stake_e8s: u64,
    ) -> NeuronMetrics {
        let mut metrics = NeuronMetrics {
            garbage_collectable_neurons_count: with_stable_neuron_store(|stable_neuron_store| {
                stable_neuron_store.len() as u64
            }),
            neurons_fund_total_active_neurons: self.list_active_neurons_fund_neurons().len() as u64,
            ..Default::default()
        };

        for neuron in self.heap_neurons.values() {
            metrics.total_staked_e8s += neuron.minted_stake_e8s();
            metrics.total_staked_maturity_e8s_equivalent +=
                neuron.staked_maturity_e8s_equivalent.unwrap_or(0);
            metrics.total_maturity_e8s_equivalent += neuron.maturity_e8s_equivalent;

            if neuron.joined_community_fund_timestamp_seconds.unwrap_or(0) > 0 {
                metrics.community_fund_total_staked_e8s += neuron.minted_stake_e8s();
                metrics.community_fund_total_maturity_e8s_equivalent +=
                    neuron.maturity_e8s_equivalent;
            }

            if neuron.is_inactive(now_seconds) {
                metrics.garbage_collectable_neurons_count += 1;
            }

            if 0 < neuron.cached_neuron_stake_e8s
                && neuron.cached_neuron_stake_e8s < minimum_stake_e8s
            {
                metrics.neurons_with_invalid_stake_count += 1;
            }

            let dissolve_delay_seconds = neuron.dissolve_delay_seconds(now_seconds);
            println!("Neuron dissolve delay seconds: {}", dissolve_delay_seconds);

            if dissolve_delay_seconds < 6 * ONE_MONTH_SECONDS {
                metrics.neurons_with_less_than_6_months_dissolve_delay_count += 1;
                metrics.neurons_with_less_than_6_months_dissolve_delay_e8s +=
                    neuron.minted_stake_e8s();
            }

            if neuron.is_seed_neuron() {
                metrics.seed_neuron_count += 1;
                metrics.total_staked_e8s_seed += neuron.minted_stake_e8s();
                metrics.total_staked_maturity_e8s_equivalent_seed +=
                    neuron.staked_maturity_e8s_equivalent.unwrap_or(0);
            }

            if neuron.is_ect_neuron() {
                metrics.ect_neuron_count += 1;
                metrics.total_staked_e8s_ect += neuron.minted_stake_e8s();
                metrics.total_staked_maturity_e8s_equivalent_ect +=
                    neuron.staked_maturity_e8s_equivalent.unwrap_or(0);
            }

            let bucket = dissolve_delay_seconds / (6 * ONE_MONTH_SECONDS);
            match neuron.state(now_seconds) {
                NeuronState::Unspecified => (),
                NeuronState::Spawning => (),
                NeuronState::Dissolved => {
                    metrics.dissolved_neurons_count += 1;
                    metrics.dissolved_neurons_e8s += neuron.cached_neuron_stake_e8s;
                }
                NeuronState::Dissolving => {
                    {
                        // Neurons with minted stake count metrics
                        increment_e8s_bucket(
                            &mut metrics.dissolving_neurons_e8s_buckets,
                            bucket,
                            neuron.minted_stake_e8s(),
                        );
                        increment_count_bucket(
                            &mut metrics.dissolving_neurons_count_buckets,
                            bucket,
                        );

                        metrics.dissolving_neurons_count += 1;
                    }
                    {
                        // Staked maturity metrics
                        let increment = neuron.staked_maturity_e8s_equivalent.unwrap_or(0);
                        increment_e8s_bucket(
                            &mut metrics.dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
                            bucket,
                            increment,
                        );
                        metrics.dissolving_neurons_staked_maturity_e8s_equivalent_sum += increment;
                    }
                    {
                        if neuron.is_seed_neuron() {
                            increment_e8s_bucket(
                                &mut metrics.dissolving_neurons_e8s_buckets_seed,
                                bucket,
                                neuron.minted_stake_e8s(),
                            );
                        } else if neuron.is_ect_neuron() {
                            increment_e8s_bucket(
                                &mut metrics.dissolving_neurons_e8s_buckets_ect,
                                bucket,
                                neuron.minted_stake_e8s(),
                            );
                        }
                    }
                }
                NeuronState::NotDissolving => {
                    {
                        // Neurons with minted stake count metrics
                        increment_e8s_bucket(
                            &mut metrics.not_dissolving_neurons_e8s_buckets,
                            bucket,
                            neuron.minted_stake_e8s(),
                        );

                        increment_count_bucket(
                            &mut metrics.not_dissolving_neurons_count_buckets,
                            bucket,
                        );
                        metrics.not_dissolving_neurons_count += 1;
                    }
                    {
                        // Staked maturity metrics
                        let increment = neuron.staked_maturity_e8s_equivalent.unwrap_or(0);
                        increment_e8s_bucket(
                            &mut metrics
                                .not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
                            bucket,
                            increment,
                        );
                        metrics.not_dissolving_neurons_staked_maturity_e8s_equivalent_sum +=
                            increment;
                    }
                    {
                        if neuron.is_seed_neuron() {
                            increment_e8s_bucket(
                                &mut metrics.not_dissolving_neurons_e8s_buckets_seed,
                                bucket,
                                neuron.minted_stake_e8s(),
                            );
                        } else if neuron.is_ect_neuron() {
                            increment_e8s_bucket(
                                &mut metrics.not_dissolving_neurons_e8s_buckets_ect,
                                bucket,
                                neuron.minted_stake_e8s(),
                            );
                        }
                    }
                }
            }
        }

        // Compute total amount of locked ICP.
        metrics.total_locked_e8s = metrics
            .total_staked_e8s
            .saturating_sub(metrics.dissolved_neurons_e8s);

        metrics
    }
}

fn increment_e8s_bucket(buckets: &mut HashMap<u64, f64>, bucket: u64, increment: u64) {
    let e8s_entry = buckets.entry(bucket).or_insert(0.0);
    *e8s_entry += increment as f64;
}

fn increment_count_bucket(buckets: &mut HashMap<u64, u64>, bucket: u64) {
    let count_entry = buckets.entry(bucket).or_insert(0);
    *count_entry += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        governance::{ONE_DAY_SECONDS, ONE_YEAR_SECONDS},
        neuron::types::{DissolveStateAndAge, NeuronBuilder},
        pb::v1::NeuronType,
    };
    use ic_base_types::PrincipalId;
    use ic_nns_common::pb::v1::NeuronId;
    use icp_ledger::Subaccount;
    use maplit::hashmap;
    use std::collections::BTreeMap;

    fn create_test_neuron_builder(
        id: u64,
        dissolve_state_and_age: DissolveStateAndAge,
    ) -> NeuronBuilder {
        // Among the required neuron fields, only the id and dissolve state and age are meaningful
        // for neuron metrics tests.
        NeuronBuilder::new(
            NeuronId { id },
            Subaccount::try_from([0u8; 32].as_ref()).unwrap(),
            PrincipalId::new_user_test_id(123),
            dissolve_state_and_age,
            123_456_789,
        )
    }

    #[test]
    fn test_compute_metrics() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let now = neuron_store.now();

        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    1,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 1,
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(100_000_000)
                .with_neuron_type(Some(NeuronType::Seed as i32))
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    2,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: ONE_YEAR_SECONDS,
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(234_000_000)
                .with_joined_community_fund_timestamp_seconds(Some(1))
                .with_maturity_e8s_equivalent(450_988_012)
                .with_neuron_type(Some(NeuronType::Ect as i32))
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    3,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: ONE_YEAR_SECONDS * 4,
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(568_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    4,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: ONE_YEAR_SECONDS * 4,
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(1_123_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    5,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: ONE_YEAR_SECONDS * 8,
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(6_087_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    6,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 5,
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(0)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    7,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 5,
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(100)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    8,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now + ONE_YEAR_SECONDS,
                    },
                )
                .with_cached_neuron_stake_e8s(234_000_000)
                .with_staked_maturity_e8s_equivalent(100_000_000)
                .with_neuron_type(Some(NeuronType::Seed as i32))
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    9,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now + ONE_YEAR_SECONDS * 3,
                    },
                )
                .with_cached_neuron_stake_e8s(568_000_000)
                .with_staked_maturity_e8s_equivalent(100_000_000)
                .with_neuron_type(Some(NeuronType::Ect as i32))
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    10,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now + ONE_YEAR_SECONDS * 5,
                    },
                )
                .with_cached_neuron_stake_e8s(1_123_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    11,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now + ONE_YEAR_SECONDS * 5,
                    },
                )
                .with_cached_neuron_stake_e8s(6_087_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    12,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now + ONE_YEAR_SECONDS * 7,
                    },
                )
                .with_cached_neuron_stake_e8s(18_000_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    13,
                    DissolveStateAndAge::LegacyNoneDissolveState {
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(4_450_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    14,
                    DissolveStateAndAge::LegacyNoneDissolveState {
                        aging_since_timestamp_seconds: now,
                    },
                )
                .with_cached_neuron_stake_e8s(1_220_000_000)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    15,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: 1,
                    },
                )
                .with_cached_neuron_stake_e8s(100_000_000)
                .build(),
            )
            .unwrap();

        let metrics = neuron_store.compute_neuron_metrics(now, 100_000_000);

        let expected_metrics = NeuronMetrics {
            dissolving_neurons_count: 5,
            dissolving_neurons_e8s_buckets: hashmap! {
                2 => 234000000.0,
                6 => 568000000.0,
                10 => 7210000000.0,
                14 => 18000000000.0
            },
            dissolving_neurons_count_buckets: hashmap! { 2 => 1, 6 => 1, 10 => 2, 14 => 1 },
            not_dissolving_neurons_count: 7,
            not_dissolving_neurons_e8s_buckets: hashmap! {
                0 => 100000100.0,
                2 => 234000000.0,
                8 => 1691000000.0,
                16 => 6087000000.0,
            },
            not_dissolving_neurons_count_buckets: hashmap! {0 => 3, 2 => 1, 8 => 2, 16 => 1},
            dissolved_neurons_count: 3,
            dissolved_neurons_e8s: 5770000000,
            garbage_collectable_neurons_count: 0,
            neurons_with_invalid_stake_count: 1,
            total_staked_e8s: 39_894_000_100,
            neurons_with_less_than_6_months_dissolve_delay_count: 6,
            neurons_with_less_than_6_months_dissolve_delay_e8s: 5870000100,
            community_fund_total_staked_e8s: 234_000_000,
            community_fund_total_maturity_e8s_equivalent: 450_988_012,
            neurons_fund_total_active_neurons: 1,
            total_locked_e8s: 34_124_000_100,
            total_maturity_e8s_equivalent: 450_988_012,
            total_staked_maturity_e8s_equivalent: 200_000_000_u64,
            dissolving_neurons_staked_maturity_e8s_equivalent_buckets: hashmap! {
                2 => 100000000.0,
                6 => 100000000.0,
                10 => 0.0,
                14 => 0.0,
            },
            dissolving_neurons_staked_maturity_e8s_equivalent_sum: 200_000_000_u64,
            not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets: hashmap! {
                0 => 0.0,
                2 => 0.0,
                8 => 0.0,
                16 => 0.0,
            },
            not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: 0_u64,
            seed_neuron_count: 2_u64,
            ect_neuron_count: 2_u64,
            total_staked_e8s_seed: 334000000,
            total_staked_e8s_ect: 802000000,
            total_staked_maturity_e8s_equivalent_seed: 100_000_000_u64,
            total_staked_maturity_e8s_equivalent_ect: 100_000_000_u64,
            dissolving_neurons_e8s_buckets_seed: hashmap! { 2 => 234000000.0 },
            dissolving_neurons_e8s_buckets_ect: hashmap! { 6 => 568000000.0 },
            not_dissolving_neurons_e8s_buckets_seed: hashmap! { 0 => 100000000.0 },
            not_dissolving_neurons_e8s_buckets_ect: hashmap! { 2 => 234000000.0 },
        };
        assert_eq!(metrics, expected_metrics);
    }

    #[test]
    fn test_compute_metrics_inactive_neuron_in_heap() {
        // Step 1: prepare 3 neurons with different dissolved time: 1 day ago, 13 days ago, and 30
        // days ago.
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        let now = neuron_store.now();

        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    1,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now - ONE_DAY_SECONDS,
                    },
                )
                .with_cached_neuron_stake_e8s(0)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    2,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now - 13 * ONE_DAY_SECONDS,
                    },
                )
                .with_cached_neuron_stake_e8s(0)
                .build(),
            )
            .unwrap();
        neuron_store
            .add_neuron(
                create_test_neuron_builder(
                    3,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: now - 30 * ONE_DAY_SECONDS,
                    },
                )
                .with_cached_neuron_stake_e8s(0)
                .build(),
            )
            .unwrap();

        // Step 2: verify that 1 neuron (3) are inactive.
        let actual_metrics = neuron_store.compute_neuron_metrics(now, 100_000_000);
        assert_eq!(actual_metrics.garbage_collectable_neurons_count, 1);

        // Step 3: 2 days pass, and now neuron (2) is dissolved 15 days ago, and becomes inactive.
        let now = now + 2 * ONE_DAY_SECONDS;
        let actual_metrics = neuron_store.compute_neuron_metrics(now, 100_000_000);
        assert_eq!(actual_metrics.garbage_collectable_neurons_count, 2);
    }
}
