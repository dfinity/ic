use super::NeuronStore;
use crate::{
    neuron::Visibility,
    neuron_store::Neuron,
    pb::v1::{NeuronState, VotingPowerEconomics},
    storage::{neurons::NeuronSections, with_stable_neuron_store},
};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nns_constants::GENESIS_TOKEN_CANISTER_ID;
use std::collections::HashMap;

/// Metrics calculated based on neurons in the neuron store.
#[derive(Clone, PartialEq, Debug, Default)]
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
    pub(crate) spawning_neurons_count: u64,

    // Much of the above could also be done like this, but we leave such refactoring as an exercise
    // to the reader.
    pub(crate) non_self_authenticating_controller_neuron_subset_metrics: NeuronSubsetMetrics,
    pub(crate) public_neuron_subset_metrics: NeuronSubsetMetrics,
    pub(crate) declining_voting_power_neuron_subset_metrics: NeuronSubsetMetrics,
    pub(crate) fully_lost_voting_power_neuron_subset_metrics: NeuronSubsetMetrics,
}

impl NeuronMetrics {
    fn increment_non_self_authenticating_controller_neuron_subset_metrics(
        &mut self,
        voting_power_economics: &VotingPowerEconomics,
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
            .increment(voting_power_economics, now_seconds, neuron);
    }

    fn increment_public_neuron_subset_metrics(
        &mut self,
        voting_power_economics: &VotingPowerEconomics,
        now_seconds: u64,
        neuron: &Neuron,
    ) {
        let is_public = neuron.visibility() == Visibility::Public;
        if !is_public {
            return;
        }

        self.public_neuron_subset_metrics
            .increment(voting_power_economics, now_seconds, neuron);
    }

    /// This could modify either declining_voting_power_neuron_subset_metrics, or
    /// fully_lost_voting_power_neuron_subset_metrics (but not both), since
    /// those categories are mutually exclusive.
    fn increment_declining_voting_power_or_fully_lost_voting_power_neuron_subset_metrics(
        &mut self,
        voting_power_economics: &VotingPowerEconomics,
        now_seconds: u64,
        neuron: &Neuron,
    ) {
        // The substraction here assumes that the neuron was not refreshed in
        // the future. (This doesn't always hold in tests though, due to the
        // difficulty of constructing realistic data/scenarios.)
        let seconds_since_voting_power_refreshed =
            now_seconds.saturating_sub(neuron.voting_power_refreshed_timestamp_seconds());

        let is_recently_refreshed = seconds_since_voting_power_refreshed
            < voting_power_economics.get_start_reducing_voting_power_after_seconds();
        if is_recently_refreshed {
            return;
        }

        let is_moderately_refreshed = seconds_since_voting_power_refreshed
            < voting_power_economics
                .get_start_reducing_voting_power_after_seconds()
                .saturating_add(voting_power_economics.get_clear_following_after_seconds());
        if is_moderately_refreshed {
            self.declining_voting_power_neuron_subset_metrics.increment(
                voting_power_economics,
                now_seconds,
                neuron,
            );
        } else {
            self.fully_lost_voting_power_neuron_subset_metrics
                .increment(voting_power_economics, now_seconds, neuron);
        }
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
pub(crate) struct NeuronSubsetMetrics {
    pub count: u64,

    // ICP-like resources.
    pub total_staked_e8s: u64, // staked = (most recently seen) balance - fees
    pub total_staked_maturity_e8s_equivalent: u64,
    pub total_maturity_e8s_equivalent: u64,

    // Voting power.
    pub total_voting_power: u64, // Deprecated. Use one of the following instead.
    pub total_deciding_voting_power: u64, // Used to decide proposals.
    pub total_potential_voting_power: u64, // Used for voting rewards.

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
    pub voting_power_buckets: HashMap<u64, u64>, // Deprecated. Use one of the following instead.
    pub deciding_voting_power_buckets: HashMap<u64, u64>, // See earlier comments.
    pub potential_voting_power_buckets: HashMap<u64, u64>, // See earlier comments.
}

impl NeuronSubsetMetrics {
    fn increment(
        &mut self,
        voting_power_economics: &VotingPowerEconomics,
        now_seconds: u64,
        neuron: &Neuron,
    ) {
        let staked_e8s = neuron.minted_stake_e8s();
        let staked_maturity_e8s_equivalent =
            neuron.staked_maturity_e8s_equivalent.unwrap_or_default();
        let maturity_e8s_equivalent = neuron.maturity_e8s_equivalent;

        let potential_voting_power = neuron.potential_voting_power(now_seconds);
        let deciding_voting_power =
            neuron.deciding_voting_power(voting_power_economics, now_seconds);

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

        increment(&mut self.total_voting_power, potential_voting_power);
        increment(&mut self.total_deciding_voting_power, deciding_voting_power);
        increment(
            &mut self.total_potential_voting_power,
            potential_voting_power,
        );

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

        increment(&mut self.voting_power_buckets, potential_voting_power);
        increment(
            &mut self.deciding_voting_power_buckets,
            deciding_voting_power,
        );
        increment(
            &mut self.potential_voting_power_buckets,
            potential_voting_power,
        );
    }
}

impl NeuronStore {
    /// Computes neuron metrics.
    pub(crate) fn compute_neuron_metrics(
        &self,
        neuron_minimum_stake_e8s: u64,
        voting_power_economics: &VotingPowerEconomics,
        now_seconds: u64,
    ) -> NeuronMetrics {
        let mut metrics = NeuronMetrics::default();

        with_stable_neuron_store(|stable_neuron_store| {
            let neuron_sections = NeuronSections {
                // This is needed for `Neuron::visibility``
                known_neuron_data: true,
                ..NeuronSections::NONE
            };

            for neuron in stable_neuron_store.range_neurons_sections(.., neuron_sections) {
                let neuron = &neuron;
                metrics.increment_non_self_authenticating_controller_neuron_subset_metrics(
                    voting_power_economics,
                    now_seconds,
                    neuron,
                );
                metrics.increment_public_neuron_subset_metrics(
                    voting_power_economics,
                    now_seconds,
                    neuron,
                );
                metrics.increment_declining_voting_power_or_fully_lost_voting_power_neuron_subset_metrics(
                    voting_power_economics,
                    now_seconds,
                    neuron,
                );

                metrics.total_staked_e8s = metrics
                    .total_staked_e8s
                    .saturating_add(neuron.minted_stake_e8s());
                metrics.total_staked_maturity_e8s_equivalent = metrics
                    .total_staked_maturity_e8s_equivalent
                    .saturating_add(neuron.staked_maturity_e8s_equivalent.unwrap_or(0));
                metrics.total_maturity_e8s_equivalent = metrics
                    .total_maturity_e8s_equivalent
                    .saturating_add(neuron.maturity_e8s_equivalent);

                if Self::is_active_neurons_fund_neuron(neuron, now_seconds) {
                    metrics.neurons_fund_total_active_neurons =
                        metrics.neurons_fund_total_active_neurons.saturating_add(1);
                }

                if neuron.joined_community_fund_timestamp_seconds.unwrap_or(0) > 0 {
                    metrics.community_fund_total_staked_e8s = metrics
                        .community_fund_total_staked_e8s
                        .saturating_add(neuron.minted_stake_e8s());
                    metrics.community_fund_total_maturity_e8s_equivalent = metrics
                        .community_fund_total_maturity_e8s_equivalent
                        .saturating_add(neuron.maturity_e8s_equivalent);
                }

                if neuron.is_inactive(now_seconds) {
                    metrics.garbage_collectable_neurons_count =
                        metrics.garbage_collectable_neurons_count.saturating_add(1);
                }

                if 0 < neuron.cached_neuron_stake_e8s
                    && neuron.cached_neuron_stake_e8s < neuron_minimum_stake_e8s
                {
                    metrics.neurons_with_invalid_stake_count =
                        metrics.neurons_with_invalid_stake_count.saturating_add(1);
                }

                let dissolve_delay_seconds = neuron.dissolve_delay_seconds(now_seconds);

                // the constant value 6 * ONE_MONTH_SECONDS cannot overflow.
                if dissolve_delay_seconds < 6 * ONE_MONTH_SECONDS {
                    metrics.neurons_with_less_than_6_months_dissolve_delay_count = metrics
                        .neurons_with_less_than_6_months_dissolve_delay_count
                        .saturating_add(1);
                    metrics.neurons_with_less_than_6_months_dissolve_delay_e8s = metrics
                        .neurons_with_less_than_6_months_dissolve_delay_e8s
                        .saturating_add(neuron.minted_stake_e8s());
                }

                if neuron.is_seed_neuron() {
                    metrics.seed_neuron_count = metrics.seed_neuron_count.saturating_add(1);
                    metrics.total_staked_e8s_seed = metrics
                        .total_staked_e8s_seed
                        .saturating_add(neuron.minted_stake_e8s());
                    metrics.total_staked_maturity_e8s_equivalent_seed = metrics
                        .total_staked_maturity_e8s_equivalent_seed
                        .saturating_add(neuron.staked_maturity_e8s_equivalent.unwrap_or(0));
                }

                if neuron.is_ect_neuron() {
                    metrics.ect_neuron_count = metrics.ect_neuron_count.saturating_add(1);
                    metrics.total_staked_e8s_ect = metrics
                        .total_staked_e8s_ect
                        .saturating_add(neuron.minted_stake_e8s());
                    metrics.total_staked_maturity_e8s_equivalent_ect = metrics
                        .total_staked_maturity_e8s_equivalent_ect
                        .saturating_add(neuron.staked_maturity_e8s_equivalent.unwrap_or(0));
                }

                let bucket = dissolve_delay_seconds / (6 * ONE_MONTH_SECONDS);
                match neuron.state(now_seconds) {
                    NeuronState::Unspecified => (),
                    NeuronState::Spawning => {
                        metrics.spawning_neurons_count =
                            metrics.spawning_neurons_count.saturating_add(1);
                    }
                    NeuronState::Dissolved => {
                        metrics.dissolved_neurons_count =
                            metrics.dissolved_neurons_count.saturating_add(1);
                        metrics.dissolved_neurons_e8s = metrics
                            .dissolved_neurons_e8s
                            .saturating_add(neuron.cached_neuron_stake_e8s);
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

                            metrics.dissolving_neurons_count =
                                metrics.dissolving_neurons_count.saturating_add(1);
                        }
                        {
                            // Staked maturity metrics
                            let increment = neuron.staked_maturity_e8s_equivalent.unwrap_or(0);
                            increment_e8s_bucket(
                                &mut metrics
                                    .dissolving_neurons_staked_maturity_e8s_equivalent_buckets,
                                bucket,
                                increment,
                            );
                            metrics.dissolving_neurons_staked_maturity_e8s_equivalent_sum = metrics
                                .dissolving_neurons_staked_maturity_e8s_equivalent_sum
                                .saturating_add(increment);
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
                            metrics.not_dissolving_neurons_count =
                                metrics.not_dissolving_neurons_count.saturating_add(1);
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
                            metrics.not_dissolving_neurons_staked_maturity_e8s_equivalent_sum =
                                metrics
                                    .not_dissolving_neurons_staked_maturity_e8s_equivalent_sum
                                    .saturating_add(increment);
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
        });

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
