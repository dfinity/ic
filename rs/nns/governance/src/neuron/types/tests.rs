use super::*;
use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::manage_neuron::{SetDissolveTimestamp, StartDissolving},
};

use ic_nervous_system_common::{E8, ONE_YEAR_SECONDS};
use ic_stable_structures::Storable;
use icp_ledger::Subaccount;
use prost::Message;

const NOW: u64 = 123_456_789;

const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

#[test]
fn test_dissolve_state_and_age_conversion() {
    let test_cases = vec![
        (
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 100,
                aging_since_timestamp_seconds: 200,
            },
            StoredDissolveStateAndAge {
                dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(100)),
                aging_since_timestamp_seconds: 200,
            },
        ),
        // TODO(NNS1-2951): have a more strict guarantee about the
        // aging_since_timestamp_seconds. This case is theoretically possible, while we should
        // never have such a neuron. The aging_since_timestamp_seconds should be in the past.
        (
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 100,
                aging_since_timestamp_seconds: u64::MAX,
            },
            StoredDissolveStateAndAge {
                dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(100)),
                aging_since_timestamp_seconds: u64::MAX,
            },
        ),
        (
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 300,
            },
            StoredDissolveStateAndAge {
                dissolve_state: Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(300)),
                aging_since_timestamp_seconds: u64::MAX,
            },
        ),
    ];

    for (dissolve_state_and_age, stored_dissolve_state_and_age) in test_cases {
        assert_eq!(
            StoredDissolveStateAndAge::from(dissolve_state_and_age),
            stored_dissolve_state_and_age.clone()
        );
        assert_eq!(
            DissolveStateAndAge::try_from(stored_dissolve_state_and_age),
            Ok(dissolve_state_and_age)
        );
    }
}

#[test]
fn test_dissolve_state_and_age_conversion_failure() {
    let test_cases = vec![
        (
            StoredDissolveStateAndAge {
                dissolve_state: None,
                aging_since_timestamp_seconds: 200,
            },
            "Dissolve state is missing",
        ),
        (
            StoredDissolveStateAndAge {
                dissolve_state: Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(300)),
                aging_since_timestamp_seconds: 200,
            },
            "Aging since timestamp must be u64::MAX for dissolving or dissolved neurons",
        ),
        (
            StoredDissolveStateAndAge {
                dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(0)),
                aging_since_timestamp_seconds: 200,
            },
            "Dissolve delay must be greater than 0",
        ),
    ];

    for (invalid_stored_dissolve_state_and_age, error) in test_cases {
        assert_eq!(
            DissolveStateAndAge::try_from(invalid_stored_dissolve_state_and_age),
            Err(error.to_string())
        );
    }
}

#[test]
fn test_abridged_neuron_size() {
    // All VARINT encoded fields (e.g. int32, uint64, ..., as opposed to fixed32/fixed64) have
    // larger serialized size for larger numbers (10 bytes for u64::MAX as uint64, while 1 byte for
    // 0u64). Therefore, we make the numbers below as large as possible even though they aren't
    // realistic.
    let abridged_neuron = AbridgedNeuron {
        account: vec![u8::MAX; 32],
        controller: Some(PrincipalId::new(
            PrincipalId::MAX_LENGTH_IN_BYTES,
            [u8::MAX; PrincipalId::MAX_LENGTH_IN_BYTES],
        )),
        cached_neuron_stake_e8s: u64::MAX,
        neuron_fees_e8s: u64::MAX,
        created_timestamp_seconds: u64::MAX,
        aging_since_timestamp_seconds: u64::MAX,
        spawn_at_timestamp_seconds: Some(u64::MAX),
        kyc_verified: true,
        maturity_e8s_equivalent: u64::MAX,
        staked_maturity_e8s_equivalent: Some(u64::MAX),
        auto_stake_maturity: Some(true),
        not_for_profit: true,
        joined_community_fund_timestamp_seconds: Some(u64::MAX),
        neuron_type: Some(i32::MAX),
        dissolve_state: Some(AbridgedNeuronDissolveState::WhenDissolvedTimestampSeconds(
            u64::MAX,
        )),
        visibility: None,
    };

    assert!(abridged_neuron.encoded_len() as u32 <= AbridgedNeuron::BOUND.max_size());
    // This size can be updated. This assertion is created so that we are aware of the available
    // headroom.
    assert_eq!(abridged_neuron.encoded_len(), 184);
}

fn create_neuron_with_stake_dissolve_state_and_age(
    stake_e8s: u64,
    dissolve_state_and_age: DissolveStateAndAge,
) -> Neuron {
    NeuronBuilder::new(
        NeuronId { id: 1 },
        Subaccount::try_from(vec![0u8; 32].as_slice()).unwrap(),
        PrincipalId::new_user_test_id(1),
        dissolve_state_and_age,
        123_456_789,
    )
    .with_cached_neuron_stake_e8s(stake_e8s)
    .build()
}

#[test]
fn test_update_stake_adjust_age_for_dissolved_neuron_variant_a_now() {
    // WhenDissolvedTimestampSeconds(NOW) ==> dissolved
    let mut neuron = create_neuron_with_stake_dissolve_state_and_age(
        10 * E8,
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW,
        },
    );

    let new_stake_e8s = 1_500_000_000_u64; // 15 ICP
    neuron.update_stake_adjust_age(new_stake_e8s, NOW);

    assert_eq!(neuron.cached_neuron_stake_e8s, new_stake_e8s);
    assert_eq!(
        neuron.dissolve_state_and_age(),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW,
        }
    );
}

#[test]
fn test_update_stake_adjust_age_for_dissolved_neuron_variant_a_past() {
    // WhenDissolvedTimestampSeconds(past) ==> dissolved
    let mut neuron = create_neuron_with_stake_dissolve_state_and_age(
        10 * E8,
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW.saturating_sub(TWELVE_MONTHS_SECONDS),
        },
    );

    let new_stake_e8s = 1_500_000_000_u64; // 15 ICP
    neuron.update_stake_adjust_age(new_stake_e8s, NOW);

    assert_eq!(neuron.cached_neuron_stake_e8s, new_stake_e8s);
    assert_eq!(
        neuron.dissolve_state_and_age(),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW.saturating_sub(TWELVE_MONTHS_SECONDS),
        }
    );
}

#[test]
fn test_update_stake_adjust_age_for_non_dissolving_neuron() {
    let mut neuron = create_neuron_with_stake_dissolve_state_and_age(
        10 * E8,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: TWELVE_MONTHS_SECONDS,
            aging_since_timestamp_seconds: NOW.saturating_sub(TWELVE_MONTHS_SECONDS),
        },
    );

    let new_stake_e8s = 1_500_000_000_u64; // 15 ICP
    neuron.update_stake_adjust_age(new_stake_e8s, NOW);

    // This is the weighted average that tells us what the age should be
    // in seconds.
    let expected_new_age_seconds = TWELVE_MONTHS_SECONDS.saturating_mul(10).saturating_div(15);
    // Decrease the age that we expect from now to get the expected timestamp
    // since when the neurons should be aging.
    assert_eq!(
        neuron.dissolve_state_and_age(),
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: TWELVE_MONTHS_SECONDS,
            aging_since_timestamp_seconds: NOW.saturating_sub(expected_new_age_seconds),
        }
    );
    assert_eq!(neuron.age_seconds(NOW), expected_new_age_seconds);
}

#[test]
fn test_update_stake_adjust_age_for_dissolving_neuron() {
    // WhenDissolvedTimestampSeconds(future) <==> dissolving
    let mut neuron = create_neuron_with_stake_dissolve_state_and_age(
        10 * E8,
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW + TWELVE_MONTHS_SECONDS,
        },
    );

    let new_stake_e8s = 15 * E8;
    neuron.update_stake_adjust_age(new_stake_e8s, NOW);

    assert_eq!(neuron.cached_neuron_stake_e8s, new_stake_e8s);
    assert_eq!(
        neuron.dissolve_state_and_age(),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW + TWELVE_MONTHS_SECONDS,
        }
    );
}

#[test]
fn test_update_stake_adjust_age_for_invalid_cache() {
    // For a neuron N, the value of the `N.cached_neuron_stake_e8s` should
    // monotonically grow over time. If this invariant is violated, that
    // means the cache was invalid. Calling `N.update_stake_adjust_age(X)`
    // should recover an invalid cache by setting it to `X`.
    let mut neuron = create_neuron_with_stake_dissolve_state_and_age(
        10 * E8,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: TWELVE_MONTHS_SECONDS,
            aging_since_timestamp_seconds: NOW.saturating_sub(TWELVE_MONTHS_SECONDS),
        },
    );

    // We expect that the age does not change in this scenario.
    let new_stake_e8s = 5 * E8;
    neuron.update_stake_adjust_age(new_stake_e8s, NOW);

    // The only effect of the above call should be an update of
    // `cached_neuron_stake_e8s`; e.g., the operation does not simply fail.
    assert_eq!(neuron.cached_neuron_stake_e8s, new_stake_e8s);
    assert_eq!(
        neuron.dissolve_state_and_age(),
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: TWELVE_MONTHS_SECONDS,
            aging_since_timestamp_seconds: NOW.saturating_sub(TWELVE_MONTHS_SECONDS),
        }
    );
}

fn create_neuron_with_dissolve_state_and_age(
    dissolve_state_and_age: DissolveStateAndAge,
) -> Neuron {
    NeuronBuilder::new(
        NeuronId { id: 1 },
        Subaccount::try_from(vec![0u8; 32].as_slice()).unwrap(),
        PrincipalId::new_user_test_id(1),
        dissolve_state_and_age,
        123_456_789,
    )
    .build()
}

#[test]
fn increase_dissolve_delay_sets_age_correctly_for_dissolved_neurons() {
    // We set NOW to const in the test since it's shared in the cases and the test impl fn
    const NOW: u64 = 1000;
    fn test_increase_dissolve_delay_by_1_on_dissolved_neuron(
        dissolve_state_and_age: DissolveStateAndAge,
    ) {
        let mut neuron = create_neuron_with_dissolve_state_and_age(dissolve_state_and_age);

        // precondition, neuron is considered dissolved
        assert_eq!(neuron.state(NOW), NeuronState::Dissolved);

        neuron.increase_dissolve_delay(NOW, 1);

        // Post-condition - always aging_since_timestamp_seconds = now
        // always DissolveState::DissolveDelaySeconds(1)
        assert_eq!(
            neuron.dissolve_state_and_age(),
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1,
                aging_since_timestamp_seconds: NOW
            }
        );
    }

    #[rustfmt::skip]
    let cases = [
        DissolveStateAndAge::DissolvingOrDissolved { when_dissolved_timestamp_seconds: NOW, },
        DissolveStateAndAge::DissolvingOrDissolved { when_dissolved_timestamp_seconds: NOW - 1, },
        DissolveStateAndAge::DissolvingOrDissolved { when_dissolved_timestamp_seconds: 0, },
    ];

    for dissolve_state_and_age in cases {
        ic_cdk::println!("Testing case {:?}", dissolve_state_and_age);
        test_increase_dissolve_delay_by_1_on_dissolved_neuron(dissolve_state_and_age);
    }
}

#[test]
fn increase_dissolve_delay_does_not_set_age_for_non_dissolving_neurons() {
    const NOW: u64 = 1000;
    fn test_increase_dissolve_delay_by_1_for_non_dissolving_neuron(
        current_aging_since_timestamp_seconds: u64,
        current_dissolve_delay_seconds: u64,
    ) {
        let mut non_dissolving_neuron =
            create_neuron_with_dissolve_state_and_age(DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: current_dissolve_delay_seconds,
                aging_since_timestamp_seconds: current_aging_since_timestamp_seconds,
            });

        // Precondition - the neuron is non-dissolving
        assert_eq!(non_dissolving_neuron.state(NOW), NeuronState::NotDissolving);

        non_dissolving_neuron.increase_dissolve_delay(NOW, 1);

        assert_eq!(
            non_dissolving_neuron.dissolve_state_and_age(),
            DissolveStateAndAge::NotDissolving {
                // This field's inner value should increment by 1
                dissolve_delay_seconds: current_dissolve_delay_seconds + 1,
                // This field should be unaffected
                aging_since_timestamp_seconds: current_aging_since_timestamp_seconds
            }
        );
    }

    // Test cases
    for current_aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1, NOW + 2000] {
        for current_dissolve_delay_seconds in
            [1, 10, 100, NOW, NOW + 1000, (ONE_DAY_SECONDS * 365 * 8)]
        {
            test_increase_dissolve_delay_by_1_for_non_dissolving_neuron(
                current_aging_since_timestamp_seconds,
                current_dissolve_delay_seconds,
            );
        }
    }
}

#[test]
fn test_neuron_configure_dissolve_delay() {
    // Step 0: prepare the neuron.
    let now = 123_456_789;
    let mut neuron =
        create_neuron_with_dissolve_state_and_age(DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now - 1000,
        });
    let controller = neuron.controller();

    // Step 1: try to set the dissolve delay to the past, expecting to fail.
    assert!(neuron
        .configure(
            &controller,
            now,
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: now - 1,
                })),
            },
        )
        .is_err());

    // Step 2: set the dissolve delay to a value in the future, and verify that the neuron is
    // now non-dissolving.
    neuron
        .configure(
            &controller,
            now,
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: now + 100,
                })),
            },
        )
        .unwrap();
    assert_eq!(neuron.state(now), NeuronState::NotDissolving);

    // Step 3: try to increase the dissolve delay by more than u32::MAX, which should fail.
    neuron
        .configure(
            &controller,
            now,
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: now + 100 + u32::MAX as u64 + 1,
                })),
            },
        )
        .unwrap_err();

    // Step 4: try to set the dissolve delay to more than 8 years, which should succeed but capped at 8 years.
    neuron
        .configure(
            &controller,
            now,
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: now + 8 * ONE_YEAR_SECONDS + 1,
                })),
            },
        )
        .unwrap();
    assert_eq!(neuron.state(now), NeuronState::NotDissolving);
    assert_eq!(neuron.dissolve_delay_seconds(now), 8 * ONE_YEAR_SECONDS);

    // Step 5: start dissolving the neuron.
    neuron
        .configure(
            &controller,
            now,
            &Configure {
                operation: Some(Operation::StartDissolving(StartDissolving {})),
            },
        )
        .unwrap();
    assert_eq!(neuron.state(now), NeuronState::Dissolving);

    // Step 7: advance the time by 8 years - 1 second and see that the neuron is still dissolving.
    let now = now + 8 * ONE_YEAR_SECONDS - 1;
    assert_eq!(neuron.state(now), NeuronState::Dissolving);

    // Step 8: advance the time by 1 second and see that the neuron is now dissolved.
    let now = now + 1;
    assert_eq!(neuron.state(now), NeuronState::Dissolved);
}
