use super::*;
use crate::pb::v1::neuron::DissolveState;
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS};
use proptest::{prelude::proptest, sample::select};

const AMOUNTS_OF_ICP_E8S: [u64; 14] = [
    0,
    1,
    2,
    3,
    10,
    100,
    1000,
    10_000,
    100_000,
    E8 - 1,
    E8,
    E8 + 1,
    2 * E8,
    10 * E8,
];

const DURATIONS_SECONDS: [u64; 18] = [
    0,
    1,
    2,
    3,
    10,
    30,
    60,
    90,
    600,
    60 * 60,
    ONE_DAY_SECONDS,
    7 * ONE_DAY_SECONDS,
    ONE_MONTH_SECONDS,
    6 * ONE_MONTH_SECONDS,
    ONE_YEAR_SECONDS,
    2 * ONE_YEAR_SECONDS,
    4 * ONE_YEAR_SECONDS,
    8 * ONE_YEAR_SECONDS,
];

/// This is just DURATIONS_SECONDS + realistic_timestamp. I.e. element i is
/// DURATIONS_SECONDS[i] + realistic_timestamp.
const TIMESTAMPS: [u64; DURATIONS_SECONDS.len()] = {
    let mut result = [0; DURATIONS_SECONDS.len()];
    let now_timestamp_seconds = 1720425933;
    let mut i = 0;
    while i < result.len() {
        result[i] = DURATIONS_SECONDS[i] + now_timestamp_seconds;
        i += 1;
    }
    result
};

const PERCENTAGES: [u64; 15] = [
    0, 1, 2, 3, 10, 25, 50, 75, 95, 99, 100, 101, 200, 500, 1_000,
];

#[test]
fn test_is_vesting() {
    let mut neuron = Neuron {
        created_timestamp_seconds: 3400,
        ..Default::default()
    };

    assert!(!neuron.is_vesting(0));
    assert!(!neuron.is_vesting(10000));
    neuron.vesting_period_seconds = Some(600);
    assert!(neuron.is_vesting(3600));
    assert!(neuron.is_vesting(4000));
    assert!(!neuron.is_vesting(4001));
    assert!(!neuron.is_vesting(10000));
}

#[test]
fn test_voting_power_fully_boosted() {
    let base_stake = 100;
    let neuron = Neuron {
        cached_neuron_stake_e8s: base_stake,
        neuron_fees_e8s: 0,
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(100)),
        aging_since_timestamp_seconds: 0,
        voting_power_percentage_multiplier: 100,
        ..Neuron::default()
    };

    assert_eq!(
        neuron.voting_power(100, 100, 100, 100, 25),
        base_stake
        * 2 // dissolve_delay boost
        * 5 / 4 // voting power boost
    );
}

#[test]
fn test_voting_power_with_bonus_thresholds_zero() {
    let base_stake = 100;
    let neuron = Neuron {
        cached_neuron_stake_e8s: base_stake,
        neuron_fees_e8s: 0,
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(100)),
        aging_since_timestamp_seconds: 0,
        voting_power_percentage_multiplier: 100,
        ..Neuron::default()
    };

    assert_eq!(
        neuron.voting_power(
            100, // now_seconds
            // These are the operative data of this test.
            // In an earlier implementation, these would have cause divide by zero.
            0,   // max_dissolve_delay_seconds
            0,   // max_neuron_age_for_age_bonus
            100, // max_dissolve_delay_bonus_percentage
            25   // max_age_bonus_percentage
        ),
        base_stake
    );
}

proptest! {
    /// Tests that the voting power is increased by max_dissolve_delay_bonus_percentage
    /// when the neuron's dissolve delay == max_dissolve_delay_seconds.
    #[test]
    fn test_voting_power_dissolve_delay_boost(
        base_stake                          in select(&AMOUNTS_OF_ICP_E8S),
        dissolve_delay_seconds              in select(&DURATIONS_SECONDS),
        max_dissolve_delay_bonus_percentage in select(&PERCENTAGES),
    ) {
        let neuron = Neuron {
            cached_neuron_stake_e8s: base_stake,
            neuron_fees_e8s: 0,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
            aging_since_timestamp_seconds: 0,
            voting_power_percentage_multiplier: 100,
            ..Neuron::default()
        };

        let expected_additional_voting_power = if dissolve_delay_seconds > 0 {
            base_stake * max_dissolve_delay_bonus_percentage / 100
        } else {
            0
        };

        assert_eq!(
            neuron.voting_power(
                0, // now_seconds
                dissolve_delay_seconds,
                100, // max_neuron_age_for_age_bonus
                max_dissolve_delay_bonus_percentage,
                25 // max_age_bonus_percentage
            ),
            base_stake + expected_additional_voting_power,
        );
    }

    /// Tests that the voting power is increased by max_age_bonus_percentage
    /// when the neuron's age == max_neuron_age_for_age_bonus.
    #[test]
    fn test_voting_power_age_boost(
        base_stake                   in select(&AMOUNTS_OF_ICP_E8S),
        max_neuron_age_for_age_bonus in select(&DURATIONS_SECONDS),
        max_age_bonus_percentage     in select(&PERCENTAGES),
    ) {
        if max_neuron_age_for_age_bonus == 0 {
            return Ok(());
        }

        let neuron = Neuron {
            cached_neuron_stake_e8s: base_stake,
            neuron_fees_e8s: 0,
            dissolve_state: None,
            aging_since_timestamp_seconds: 0,
            voting_power_percentage_multiplier: 100,
            ..Neuron::default()
        };

        assert_eq!(
            neuron.voting_power(
                max_neuron_age_for_age_bonus,
                100, // max_dissolve_delay_seconds
                max_neuron_age_for_age_bonus,
                100, // max_dissolve_delay_bonus_percentage
                max_age_bonus_percentage
            ),
            base_stake + (base_stake * max_age_bonus_percentage / 100)
        );
    }

    /// Tests that the voting power is increased by half of max_dissolve_delay_bonus_percentage
    /// when the neuron's dissolve delay == max_dissolve_delay_seconds / 2.
    #[test]
    fn test_voting_power_dissolve_delay_boost_half(
        base_stake                          in select(&AMOUNTS_OF_ICP_E8S),
        dissolve_delay_seconds              in select(&DURATIONS_SECONDS),
        max_dissolve_delay_bonus_percentage in select(&PERCENTAGES),
    ) {
        let neuron = Neuron {
            cached_neuron_stake_e8s: base_stake,
            neuron_fees_e8s: 0,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
            aging_since_timestamp_seconds: 0,
            voting_power_percentage_multiplier: 100,
            ..Neuron::default()
        };

        let expected_additional_voting_power = if dissolve_delay_seconds > 0 {
            base_stake * max_dissolve_delay_bonus_percentage / 2 / 100
        } else {
            0
        };

        assert_eq!(
            neuron.voting_power(
                0, // now_seconds
                dissolve_delay_seconds * 2,
                100, // max_neuron_age_for_age_bonus
                max_dissolve_delay_bonus_percentage,
                25 // max_age_bonus_percentage
            ),
            base_stake + expected_additional_voting_power,
        );
    }

    /// Tests that the voting power is increased by half of max_age_bonus_percentage
    /// when the neuron's age == max_neuron_age_for_age_bonus / 2.
    #[test]
    fn test_voting_power_age_boost_half(
        base_stake               in select(&AMOUNTS_OF_ICP_E8S),
        age_seconds              in select(&DURATIONS_SECONDS),
        max_age_bonus_percentage in select(&PERCENTAGES),
    ) {
        let neuron = Neuron {
            cached_neuron_stake_e8s: base_stake,
            neuron_fees_e8s: 0,
            dissolve_state: None,
            aging_since_timestamp_seconds: 0,
            voting_power_percentage_multiplier: 100,
            ..Neuron::default()
        };

        let expected_additional_voting_power = if age_seconds > 0 {
            base_stake * max_age_bonus_percentage / 2 / 100
        } else {
            0
        };

        assert_eq!(
            neuron.voting_power(
                age_seconds,             // now_seconds
                100,                     // max_dissolve_delay_seconds
                age_seconds * 2,         // max_neuron_age_for_age_bonus
                100,                     // max_dissolve_delay_bonus_percentage
                max_age_bonus_percentage // max_age_bonus_percentage
            ),
            base_stake + expected_additional_voting_power,
        );
    }

    /// Tests that the voting power is not increased when the neuron meets
    /// neither bonus criteria (age or dissolve delay)
    #[test]
    fn test_voting_power_not_eligible_for_boost(
        base_stake                          in select(&AMOUNTS_OF_ICP_E8S),
        max_dissolve_delay_seconds          in select(&DURATIONS_SECONDS),
        max_dissolve_delay_bonus_percentage in select(&PERCENTAGES),
        age_seconds                         in select(&DURATIONS_SECONDS),
        max_age_bonus_percentage            in select(&PERCENTAGES),
    ) {
        let neuron = Neuron {
            cached_neuron_stake_e8s: base_stake,
            neuron_fees_e8s: 0,
            dissolve_state: None,
            aging_since_timestamp_seconds: age_seconds,
            voting_power_percentage_multiplier: 100,
            ..Neuron::default()
        };

        assert_eq!(
            neuron.voting_power(
                age_seconds,
                max_dissolve_delay_seconds,
                max_age_bonus_percentage,
                max_dissolve_delay_bonus_percentage,
                max_age_bonus_percentage
            ),
            base_stake
        );
    }

    /// This makes up random data and puts it into Neuron::voting_power,
    /// which has asserts internally. This is testing that those asserts do not fire regardless of the inputs.
    #[test]
    fn test_no_voting_power_calculation_causes_panic(
        base_stake                          in select(&AMOUNTS_OF_ICP_E8S),
        neuron_fees_e8s                     in select(&AMOUNTS_OF_ICP_E8S),
        aging_since_timestamp_seconds       in select(&DURATIONS_SECONDS),
        voting_power_percentage_multiplier  in select(&PERCENTAGES),

        now_seconds                         in select(&TIMESTAMPS),
        dissolve_delay_seconds              in select(&DURATIONS_SECONDS),
        max_dissolve_delay_seconds          in select(&DURATIONS_SECONDS),
        max_neuron_age_for_age_bonus        in select(&DURATIONS_SECONDS),
        max_dissolve_delay_bonus_percentage in select(&PERCENTAGES),
        max_age_bonus_percentage            in select(&PERCENTAGES),
    ) {
        let neuron = Neuron {
            cached_neuron_stake_e8s: base_stake,
            neuron_fees_e8s,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
            aging_since_timestamp_seconds,
            voting_power_percentage_multiplier,
            ..Neuron::default()
        };

        neuron.voting_power(
            now_seconds,
            max_dissolve_delay_seconds,
            max_neuron_age_for_age_bonus,
            max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage
        );
    }
}

/// Tests that the normal stake is computed as
/// cached neuron stake - neurons fees.  
#[test]
fn test_neuron_normal_stake() {
    // create neuron with staked maturity
    let neuron_id = NeuronId { id: vec![1, 2, 3] };
    let neuron = Neuron {
        id: Some(neuron_id),
        cached_neuron_stake_e8s: 100,
        neuron_fees_e8s: 10,
        staked_maturity_e8s_equivalent: Some(50),
        ..Default::default()
    };

    // The normal stake should corresponds to cached_neuron_stake - fees
    let normal_stake: u64 = neuron.stake_e8s();
    assert_eq!(normal_stake, 100 - 10);
}

/// Tests that the voting power stake is computed as
/// cached neuron stake - neurons fees + staked maturity.  
#[test]
fn test_neuron_voting_power_stake() {
    // create neuron with staked maturity
    let neuron_id = NeuronId { id: vec![1, 2, 3] };
    let neuron = Neuron {
        id: Some(neuron_id),
        cached_neuron_stake_e8s: 100,
        neuron_fees_e8s: 10,
        staked_maturity_e8s_equivalent: Some(50),
        ..Default::default()
    };

    // The voting power stake should correspond to cached stake - fee + staked maturity
    let voting_power_stake: u64 = neuron.voting_power_stake_e8s();
    assert_eq!(voting_power_stake, 100 - 10 + 50);
}

#[test]
fn increase_dissolve_delay_sets_age_correctly_for_dissolved_neurons() {
    // We set NOW to const in the test since it's shared in the cases and the test impl fn
    const NOW: u64 = 1000;
    const MAX_DISSOLVE: u64 = 2000;
    fn test_increase_dissolve_delay_by_1_on_dissolved_neuron(
        current_aging_since_timestamp_seconds: u64,
        current_dissolve_state: Option<DissolveState>,
    ) {
        let mut neuron = Neuron {
            aging_since_timestamp_seconds: current_aging_since_timestamp_seconds,
            dissolve_state: current_dissolve_state,
            ..Default::default()
        };
        // precondition, neuron is considered dissolved
        assert_eq!(neuron.state(NOW), NeuronState::Dissolved);

        neuron
            .increase_dissolve_delay(NOW, 1, MAX_DISSOLVE)
            .expect("Dissolve failed");

        // Post-condition - always aging_since_timestamp_seconds = now
        // always DissolveState::DissolveDelaySeconds(1)
        assert_eq!(
            neuron,
            Neuron {
                aging_since_timestamp_seconds: NOW,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(1)),
                ..Default::default()
            }
        );
    }

    #[rustfmt::skip]
        let cases = [
        // These invalid cases ensure that the method actually transforms "now" correctly
        (0, Some(DissolveState::DissolveDelaySeconds(0))),
        (0, Some(DissolveState::WhenDissolvedTimestampSeconds(NOW))),
        (0, Some(DissolveState::WhenDissolvedTimestampSeconds(NOW - 1))),
        (0, Some(DissolveState::WhenDissolvedTimestampSeconds(0))),
        (0, None),
        // These are also inconsistent with what should be observed.
        (NOW + 100, Some(DissolveState::DissolveDelaySeconds(0))),
        (NOW + 100, Some(DissolveState::WhenDissolvedTimestampSeconds(NOW))),
        (NOW + 100, Some(DissolveState::WhenDissolvedTimestampSeconds(NOW - 1))),
        (NOW + 100, Some(DissolveState::WhenDissolvedTimestampSeconds(0))),
        (NOW + 100, None),
        // Consistent with observations
        (NOW - 100, Some(DissolveState::DissolveDelaySeconds(0))),
        (NOW - 100, None),
        (u64::MAX, Some(DissolveState::WhenDissolvedTimestampSeconds(NOW))),
        (u64::MAX, Some(DissolveState::WhenDissolvedTimestampSeconds(NOW - 1))),
        (u64::MAX, Some(DissolveState::WhenDissolvedTimestampSeconds(0))),
    ];

    for (current_aging_since_timestamp_seconds, current_dissolve_state) in cases {
        test_increase_dissolve_delay_by_1_on_dissolved_neuron(
            current_aging_since_timestamp_seconds,
            current_dissolve_state,
        );
    }
}

#[test]
fn increase_dissolve_delay_does_not_set_age_for_non_dissolving_neurons() {
    const NOW: u64 = 1000;
    const MAX_DISSOLVE: u64 = 2000;
    fn test_increase_dissolve_delay_by_1_for_non_dissolving_neuron(
        current_aging_since_timestamp_seconds: u64,
        current_dissolve_delay_seconds: u64,
    ) {
        let mut non_dissolving_neuron = Neuron {
            aging_since_timestamp_seconds: current_aging_since_timestamp_seconds,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                current_dissolve_delay_seconds,
            )),
            ..Default::default()
        };

        assert_eq!(non_dissolving_neuron.state(NOW), NeuronState::NotDissolving);

        non_dissolving_neuron
            .increase_dissolve_delay(NOW, 1, MAX_DISSOLVE)
            .expect("Dissolve failed");

        assert_eq!(
            non_dissolving_neuron,
            Neuron {
                // This field should be unaffected
                aging_since_timestamp_seconds: current_aging_since_timestamp_seconds,
                // This field's inner value should increment by 1
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                    current_dissolve_delay_seconds + 1
                )),
                ..Default::default()
            }
        );
    }

    // Test cases
    for current_aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1, 2000] {
        for current_dissolve_delay_seconds in [1, 10, 100, NOW, 1000, MAX_DISSOLVE - 1] {
            test_increase_dissolve_delay_by_1_for_non_dissolving_neuron(
                current_aging_since_timestamp_seconds,
                current_dissolve_delay_seconds,
            );
        }
    }
}

#[test]
fn increase_dissolve_delay_set_age_to_u64_max_for_dissolving_neurons() {
    const NOW: u64 = 1000;
    const MAX_DISSOLVE: u64 = 2000;
    fn test_increase_dissolve_delay_by_1_for_dissolving_neuron(
        current_aging_since_timestamp_seconds: u64,
        dissolved_at_timestamp_seconds: u64,
    ) {
        let mut neuron = Neuron {
            aging_since_timestamp_seconds: current_aging_since_timestamp_seconds,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                dissolved_at_timestamp_seconds,
            )),
            ..Default::default()
        };

        assert_eq!(neuron.state(NOW), NeuronState::Dissolving);

        neuron
            .increase_dissolve_delay(NOW, 1, MAX_DISSOLVE)
            .expect("Dissolve failed");

        assert_eq!(
            neuron,
            Neuron {
                aging_since_timestamp_seconds: u64::MAX,
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                    dissolved_at_timestamp_seconds + 1
                )),
                ..Default::default()
            }
        );
    }

    for current_aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1, 2000] {
        for dissolved_at_timestamp_seconds in [NOW + 1, NOW + 1000, NOW + MAX_DISSOLVE - 1] {
            test_increase_dissolve_delay_by_1_for_dissolving_neuron(
                current_aging_since_timestamp_seconds,
                dissolved_at_timestamp_seconds,
            );
        }
    }
}

#[test]
fn neurons_with_governance_controller_are_nf() {
    let neuron = Neuron {
        permissions: vec![NeuronPermission {
            principal: Some(PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID)),
            permission_type: vec![NeuronPermissionType::ManagePrincipals as i32],
        }],
        ..Default::default()
    };
    assert!(neuron.is_neurons_fund_controlled())
}

#[test]
fn neurons_without_governance_controller_are_nf() {
    let neuron = Neuron {
        permissions: vec![NeuronPermission {
            principal: Some(PrincipalId::new_user_test_id(1)),
            permission_type: vec![NeuronPermissionType::ManagePrincipals as i32],
        }],
        ..Default::default()
    };
    assert!(!neuron.is_neurons_fund_controlled())
}
