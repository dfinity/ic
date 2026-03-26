/// The effect of splitting a neuron. This only includes maturity, staked maturity, and
/// grandfathered dissolve delay bonus base.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SplitNeuronEffect {
    pub transfer_maturity_e8s: u64,
    pub transfer_staked_maturity_e8s: u64,
    pub transfer_eight_year_gang_bonus_base_e8s: u64,
}

/// Calculates the effect of splitting a neuron for maturity and staked maturity transfer between
/// the parent and child neurons. Precondition: `split_amount_e8s` must be less than
/// `source_neuron_stake_e8s`.
pub fn calculate_split_neuron_effect(
    split_amount_e8s: u64,
    source_neuron_stake_e8s: u64,
    source_neuron_maturity_e8s: u64,
    source_neuron_staked_maturity_e8s: u64,
    source_neuron_eight_year_gang_bonus_base_e8s: u64,
) -> SplitNeuronEffect {
    let transfer_maturity_e8s: u64 = (source_neuron_maturity_e8s as u128)
        .checked_mul(split_amount_e8s as u128)
        .expect("Two u64s can't overflow when multiplied")
        .checked_div(source_neuron_stake_e8s as u128)
        .expect("The input source_neuron_stake_e8s should be greater than zero")
        .try_into()
        .expect("The result should be smaller than source_neuron_maturity_e8s which should fit into u64");

    let transfer_staked_maturity_e8s: u64 = (source_neuron_staked_maturity_e8s as u128)
        .checked_mul(split_amount_e8s as u128)
        .expect("Two u64s can't overflow when multiplied")
        .checked_div(source_neuron_stake_e8s as u128)
        .expect("The input source_neuron_stake_e8s should be greater than zero")
        .try_into()
        .expect("The result should be smaller than source_neuron_staked_maturity_e8s which should fit into u64");
    let transfer_eight_year_gang_bonus_base_e8s = (source_neuron_eight_year_gang_bonus_base_e8s
        as u128)
        .checked_mul(split_amount_e8s as u128)
        .expect("Two u64s can't overflow when multiplied")
        .checked_div(source_neuron_stake_e8s as u128)
        .expect("The input source_neuron_stake_e8s should be greater than zero")
        .try_into()
        .expect("The result should be smaller than source_neuron_eight_year_gang_bonus_base_e8s which should fit into u64");

    SplitNeuronEffect {
        transfer_maturity_e8s,
        transfer_staked_maturity_e8s,
        transfer_eight_year_gang_bonus_base_e8s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_split_neuron_effect() {
        let effect = calculate_split_neuron_effect(
            100_000_000,   // Split 1 ICP to the child neuron
            1_000_000_000, // 10 ICP for the parent neuron
            500_000_000,   // 5 ICP maturity for the parent neuron
            400_000_000,   // 4 ICP staked maturity for the parent neuron
            1_400_000_000, // 14 ICP grandfathered dissolve delay bonus base
        );

        assert_eq!(
            effect,
            SplitNeuronEffect {
                transfer_maturity_e8s: 50_000_000, // 0.5 ICP maturity for the child neuron
                transfer_staked_maturity_e8s: 40_000_000, // 0.4 ICP staked maturity for the child neuron
                transfer_eight_year_gang_bonus_base_e8s: 140_000_000, // 1.4 ICP bonus base for the child neuron
            }
        );
    }

    use proptest::prelude::*;
    use proptest::proptest;

    proptest! {

        // Test the calculation in more cases while asserting the invariants, without asserting the
        // exact values, since it would just be a repetition of the calculation.
        #[test]
        fn test_calculate_split_neuron_effect_invariants(
            split_amount_e8s in 1..u64::MAX,
            source_neuron_stake_e8s in 1..u64::MAX,
            source_neuron_maturity_e8s in 1..u64::MAX,
            source_neuron_staked_maturity_e8s in 1..u64::MAX,
            source_neuron_eight_year_gang_bonus_base_e8s in 1..u64::MAX,
        ) {
            prop_assume!(split_amount_e8s < source_neuron_stake_e8s);
            let effect = calculate_split_neuron_effect(
                split_amount_e8s,
                source_neuron_stake_e8s,
                source_neuron_maturity_e8s,
                source_neuron_staked_maturity_e8s,
                source_neuron_eight_year_gang_bonus_base_e8s,
            );

            assert!(effect.transfer_maturity_e8s <= source_neuron_maturity_e8s);
            assert!(effect.transfer_staked_maturity_e8s <= source_neuron_staked_maturity_e8s);
            assert!(
                effect.transfer_eight_year_gang_bonus_base_e8s
                    <= source_neuron_eight_year_gang_bonus_base_e8s
            );
        }
    }
}
