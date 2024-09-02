use super::NeuronStore;
use crate::{
    neuron_store::Neuron, pb::v1::NeuronState, pb::v1::Visibility,
    storage::with_stable_neuron_store,
};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nns_constants::GENESIS_TOKEN_CANISTER_ID;
use std::collections::HashMap;

/// Metrics calculated based on neurons in the neuron store.
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct NeuronMetrics {
    pub(crate) dissolving_neurons_count: u64,
    // This maps floor(dissolve delay / 6 months) to total e8s.
    //
    // The keys used by Other fields (with names of the form `*_buckets`) are
    // also like this.
    //
    // Also, notice that the value type is f64. Presumably, the reasoning there
    // is that these are eventually turned into Prometheus metrics.
    pub(crate) dissolving_neurons_e8s_buckets: HashMap<
        u64, // floor(dissolve delay / 6 months)
        f64, // total e8s
    >,
    pub(crate) dissolving_neurons_count_buckets: HashMap<u64, u64>,
    pub(crate) not_dissolving_neurons_count: u64,
    pub(crate) not_dissolving_neurons_e8s_buckets: HashMap<u64, f64>,
    pub(crate) not_dissolving_neurons_count_buckets: HashMap<u64, u64>,
    pub(crate) dissolved_neurons_count: u64,
    pub(crate) dissolved_neurons_e8s: u64,
    pub(crate) garbage_collectable_neurons_count: u64,
    pub(crate) neurons_with_invalid_stake_count: u64,
    pub(crate) total_staked_e8s: u64,
    pub(crate) neurons_with_less_than_6_months_dissolve_delay_count: u64,
    pub(crate) neurons_with_less_than_6_months_dissolve_delay_e8s: u64,
    pub(crate) community_fund_total_staked_e8s: u64,
    pub(crate) community_fund_total_maturity_e8s_equivalent: u64,
    pub(crate) neurons_fund_total_active_neurons: u64,
    pub(crate) total_locked_e8s: u64,
    pub(crate) total_maturity_e8s_equivalent: u64,
    pub(crate) total_staked_maturity_e8s_equivalent: u64,
    pub(crate) dissolving_neurons_staked_maturity_e8s_equivalent_buckets: HashMap<u64, f64>,
    pub(crate) dissolving_neurons_staked_maturity_e8s_equivalent_sum: u64,
    pub(crate) not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets: HashMap<u64, f64>,
    pub(crate) not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: u64,
    pub(crate) seed_neuron_count: u64,
    pub(crate) ect_neuron_count: u64,
    pub(crate) total_staked_e8s_seed: u64,
    pub(crate) total_staked_e8s_ect: u64,
    pub(crate) total_staked_maturity_e8s_equivalent_seed: u64,
    pub(crate) total_staked_maturity_e8s_equivalent_ect: u64,
    pub(crate) dissolving_neurons_e8s_buckets_seed: HashMap<u64, f64>,
    pub(crate) dissolving_neurons_e8s_buckets_ect: HashMap<u64, f64>,
    pub(crate) not_dissolving_neurons_e8s_buckets_seed: HashMap<u64, f64>,
    pub(crate) not_dissolving_neurons_e8s_buckets_ect: HashMap<u64, f64>,

    // Much of the above could also be done like this, but we leave such refactoring as an exercise
    // to the reader.
    pub(crate) non_self_authenticating_controller_neuron_subset_metrics: NeuronSubsetMetrics,
    pub(crate) public_neuron_subset_metrics: NeuronSubsetMetrics,
}

impl NeuronMetrics {
    fn increment_non_self_authenticating_controller_neuron_subset_metrics(
        &mut self,
        now_seconds: u64,
        neuron: &Neuron,
    ) {
        let controller: PrincipalId = neuron.controller();

        if controller.is_self_authenticating() {
            return;
        }

        // Do not count neurons controlled by the GTC.
        if controller == PrincipalId::from(GENESIS_TOKEN_CANISTER_ID) {
            return;
        }

        self.non_self_authenticating_controller_neuron_subset_metrics
            .increment(now_seconds, neuron);
    }

    fn increment_public_neuron_subset_metrics(&mut self, now_seconds: u64, neuron: &Neuron) {
        let is_public = neuron.visibility() == Some(Visibility::Public);
        if !is_public {
            return;
        }

        self.public_neuron_subset_metrics
            .increment(now_seconds, neuron);
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct NeuronSubsetMetrics {
    pub count: u64,

    // ICP-like resources.
    pub total_staked_e8s: u64, // staked = (most recently seen) balance - fees
    pub total_staked_maturity_e8s_equivalent: u64,
    pub total_maturity_e8s_equivalent: u64,

    // Voting power.
    pub total_voting_power: u64,

    // Broken out by dissolve delay (rounded down to the nearest multiple of 0.5
    // years). For example, if the current dissolve delay of a neuron is 7
    // months, then, it would contribute to the entries keyed by floor(7 / 6) =
    // 1.

    // Analogous to the vanilla count field.
    pub count_buckets: HashMap<u64, u64>,

    // ICP-like resources.
    pub staked_e8s_buckets: HashMap<u64, u64>,
    pub staked_maturity_e8s_equivalent_buckets: HashMap<u64, u64>,
    pub maturity_e8s_equivalent_buckets: HashMap<u64, u64>,

    // Analogous to total_voting_power.
    pub voting_power_buckets: HashMap<u64, u64>,
}

impl NeuronSubsetMetrics {
    fn increment(&mut self, now_seconds: u64, neuron: &Neuron) {
        let staked_e8s = neuron.minted_stake_e8s();
        let staked_maturity_e8s_equivalent =
            neuron.staked_maturity_e8s_equivalent.unwrap_or_default();
        let maturity_e8s_equivalent = neuron.maturity_e8s_equivalent;

        let voting_power = neuron.voting_power(now_seconds);

        let increment = |total: &mut u64, additional_amount| {
            *total = total.saturating_add(additional_amount);
        };

        increment(&mut self.count, 1);

        increment(&mut self.total_staked_e8s, staked_e8s);
        increment(
            &mut self.total_staked_maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent,
        );
        increment(
            &mut self.total_maturity_e8s_equivalent,
            maturity_e8s_equivalent,
        );

        increment(&mut self.total_voting_power, voting_power);

        // Increment metrics broken out by dissolve delay.
        let dissolve_delay_bucket = neuron
            .dissolve_delay_seconds(now_seconds)
            .saturating_div(6 * ONE_MONTH_SECONDS);
        let increment = |subtotals: &mut HashMap<u64, u64>, additional_amount| {
            let subtotal = subtotals.entry(dissolve_delay_bucket).or_default();
            *subtotal = subtotal.saturating_add(additional_amount);
        };

        increment(&mut self.count_buckets, 1);

        increment(&mut self.staked_e8s_buckets, staked_e8s);
        increment(
            &mut self.staked_maturity_e8s_equivalent_buckets,
            staked_maturity_e8s_equivalent,
        );
        increment(
            &mut self.maturity_e8s_equivalent_buckets,
            maturity_e8s_equivalent,
        );

        increment(&mut self.voting_power_buckets, voting_power);
    }
}

impl NeuronStore {
    /// Computes neuron metrics.
    pub(crate) fn compute_neuron_metrics(
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
            metrics.increment_non_self_authenticating_controller_neuron_subset_metrics(
                now_seconds,
                neuron,
            );
            metrics.increment_public_neuron_subset_metrics(now_seconds, neuron);

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
mod tests;
