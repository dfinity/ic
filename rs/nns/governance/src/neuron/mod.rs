use crate::pb::v1::{
    neuron::DissolveState, Neuron as NeuronProto, NeuronInfo, NeuronState, NeuronType,
};
use ic_nns_common::pb::v1::NeuronId;
use std::ops::RangeBounds;

pub mod dissolve_state_and_age;
pub use dissolve_state_and_age::*;
pub mod types;
pub use types::*;

fn neuron_stake_e8s(
    cached_neuron_stake_e8s: u64,
    neuron_fees_e8s: u64,
    staked_maturity_e8s_equivalent: Option<u64>,
) -> u64 {
    cached_neuron_stake_e8s
        .saturating_sub(neuron_fees_e8s)
        .saturating_add(staked_maturity_e8s_equivalent.unwrap_or(0))
}

// The following methods are conceptually methods for the API type of the neuron.
impl NeuronProto {
    pub fn state(&self, now_seconds: u64) -> NeuronState {
        if self.spawn_at_timestamp_seconds.is_some() {
            return NeuronState::Spawning;
        }
        match self.dissolve_state {
            Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)) => {
                if dissolve_delay_seconds > 0 {
                    NeuronState::NotDissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            Some(DissolveState::WhenDissolvedTimestampSeconds(
                when_dissolved_timestamp_seconds,
            )) => {
                if when_dissolved_timestamp_seconds > now_seconds {
                    NeuronState::Dissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            None => NeuronState::Dissolved,
        }
    }
}

/// Convert a RangeBounds<NeuronId> to RangeBounds<u64> which is useful for methods
/// that operate on NeuronId ranges with internal u64 representations in data.
pub fn neuron_id_range_to_u64_range(range: &impl RangeBounds<NeuronId>) -> impl RangeBounds<u64> {
    let first = match range.start_bound() {
        std::ops::Bound::Included(start) => start.id,
        std::ops::Bound::Excluded(start) => start.id + 1,
        std::ops::Bound::Unbounded => 0,
    };
    let last = match range.end_bound() {
        std::ops::Bound::Included(end) => end.id,
        std::ops::Bound::Excluded(end) => end.id - 1,
        std::ops::Bound::Unbounded => u64::MAX,
    };
    first..=last
}

/// Given two quantities of stake with possible associated age, return the
/// combined stake and the combined age.
pub fn combine_aged_stakes(
    x_stake_e8s: u64,
    x_age_seconds: u64,
    y_stake_e8s: u64,
    y_age_seconds: u64,
) -> (u64, u64) {
    if x_stake_e8s == 0 && y_stake_e8s == 0 {
        (0, 0)
    } else {
        let total_age_seconds: u128 = (x_stake_e8s as u128 * x_age_seconds as u128
            + y_stake_e8s as u128 * y_age_seconds as u128)
            / (x_stake_e8s as u128 + y_stake_e8s as u128);

        // Note that age is adjusted in proportion to the stake, but due to the
        // discrete nature of u64 numbers, some resolution is lost due to the
        // division above. Only if x_age * x_stake is a multiple of y_stake does
        // the age remain constant after this operation. However, in the end, the
        // most that can be lost due to rounding from the actual age, is always
        // less than 1 second, so this is not a problem.
        (x_stake_e8s + y_stake_e8s, total_age_seconds as u64)
    }
}

impl NeuronInfo {
    pub fn is_seed_neuron(&self) -> bool {
        self.neuron_type == Some(NeuronType::Seed as i32)
    }

    pub fn is_ect_neuron(&self) -> bool {
        self.neuron_type == Some(NeuronType::Ect as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};

    #[test]
    fn test_combine_aged_stakes() {
        let cases = [
            // x_stake_e8s, x_age_seconds, y_stake_e8s, y_age_seconds, expected_stake_e8s, expected_age_seconds
            (0, ONE_DAY_SECONDS, 0, 2 * ONE_DAY_SECONDS, 0, 0),
            (
                E8,
                ONE_DAY_SECONDS,
                2 * E8,
                ONE_DAY_SECONDS,
                3 * E8,
                ONE_DAY_SECONDS,
            ),
            (
                E8,
                ONE_DAY_SECONDS,
                2 * E8,
                4 * ONE_DAY_SECONDS,
                3 * E8,
                3 * ONE_DAY_SECONDS,
            ),
        ];
        for (
            x_stake_e8s,
            x_age_seconds,
            y_stake_e8s,
            y_age_seconds,
            expected_stake_e8s,
            expected_age_seconds,
        ) in cases
        {
            let (stake_e8s, age_seconds) =
                combine_aged_stakes(x_stake_e8s, x_age_seconds, y_stake_e8s, y_age_seconds);
            assert_eq!(stake_e8s, expected_stake_e8s);
            assert_eq!(age_seconds, expected_age_seconds);
        }
    }

    use proptest::{prelude::*, proptest};

    proptest! {
        #[test]
        fn test_combine_aged_stakes_invariant(
            x_stake_e8s in 0..10_000_000_000 * E8, // Choosing u64::MAX can cause overflow for the combined stake
            x_age_seconds in 0..u64::MAX,
            y_stake_e8s in 0..10_000_000_000 * E8,
            y_age_seconds in 0..u64::MAX,
        ) {
            let (stake_e8s, age_seconds) = combine_aged_stakes(x_stake_e8s, x_age_seconds, y_stake_e8s, y_age_seconds);
            prop_assert_eq!(stake_e8s, x_stake_e8s + y_stake_e8s);

            // The combined age should be between the two input ages.
            let is_combined_age_between_input_ages = (y_age_seconds <= age_seconds && age_seconds <= x_age_seconds) ||
               (x_age_seconds <= age_seconds && age_seconds <= y_age_seconds);
            let are_both_stakes_zero = x_stake_e8s == 0 && y_stake_e8s == 0;
            prop_assert!(are_both_stakes_zero || is_combined_age_between_input_ages);
        }
    }
}
