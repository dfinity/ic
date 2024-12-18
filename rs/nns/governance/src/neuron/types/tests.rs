use super::*;
use crate::{
    neuron::{DissolveStateAndAge, NeuronBuilder},
    pb::v1::{
        manage_neuron::{SetDissolveTimestamp, StartDissolving},
        VotingPowerEconomics,
    },
    temporarily_disable_private_neuron_enforcement, temporarily_disable_voting_power_adjustment,
    temporarily_enable_private_neuron_enforcement, temporarily_enable_voting_power_adjustment,
};
use ic_cdk::println;

use ic_nervous_system_common::{E8, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS};
use icp_ledger::Subaccount;

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
        println!("Testing case {:?}", dissolve_state_and_age);
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

#[test]
fn test_visibility_when_converting_neuron_to_neuron_info_and_neuron_proto() {
    // (These are not actually used by code under test.)
    let principal_id = PrincipalId::new_user_test_id(42);
    let timestamp_seconds = 1729791574;

    let builder = NeuronBuilder::new(
        NeuronId { id: 42 },
        Subaccount::try_from(vec![42u8; 32].as_slice()).unwrap(),
        principal_id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 1_000_000,
            aging_since_timestamp_seconds: timestamp_seconds,
        },
        timestamp_seconds, // created
    );

    // Case 1: visibility is explicitly set.
    for set_enforcement in [
        temporarily_enable_private_neuron_enforcement,
        temporarily_disable_private_neuron_enforcement,
    ] {
        let _restore_on_drop = set_enforcement();

        for visibility in [Visibility::Public, Visibility::Private] {
            let neuron = builder.clone().with_visibility(Some(visibility)).build();

            assert_eq!(neuron.visibility(), Some(visibility),);

            let neuron_info = neuron.get_neuron_info(
                &VotingPowerEconomics::DEFAULT,
                timestamp_seconds,
                principal_id,
            );
            assert_eq!(neuron_info.visibility, Some(visibility as i32),);

            let neuron_proto = neuron.into_proto(&VotingPowerEconomics::DEFAULT, timestamp_seconds);
            assert_eq!(neuron_proto.visibility, Some(visibility as i32),);
        }
    }

    // Case 2: visibility is not set.
    let neuron = builder.clone().build();
    {
        let _restore_on_drop = temporarily_disable_private_neuron_enforcement();

        assert_eq!(neuron.visibility(), None,);

        let neuron_info = neuron.get_neuron_info(
            &VotingPowerEconomics::DEFAULT,
            timestamp_seconds,
            principal_id,
        );
        assert_eq!(neuron_info.visibility, None,);

        let neuron_proto = neuron
            .clone()
            .into_proto(&VotingPowerEconomics::DEFAULT, timestamp_seconds);
        assert_eq!(neuron_proto.visibility, None,);
    }
    {
        let _restore_on_drop = temporarily_enable_private_neuron_enforcement();

        assert_eq!(neuron.visibility(), Some(Visibility::Private),);

        let neuron_info = neuron.get_neuron_info(
            &VotingPowerEconomics::DEFAULT,
            timestamp_seconds,
            principal_id,
        );
        assert_eq!(neuron_info.visibility, Some(Visibility::Private as i32),);

        let neuron_proto = neuron.into_proto(&VotingPowerEconomics::DEFAULT, timestamp_seconds);
        assert_eq!(neuron_proto.visibility, Some(Visibility::Private as i32),);
    }

    // Case 3: Known neurons are always public.
    let neuron = builder
        .with_known_neuron_data(Some(KnownNeuronData {
            name: "neuron name".to_string(),
            description: Some("neuron description".to_string()),
        }))
        .build();
    for set_enforcement in [
        temporarily_enable_private_neuron_enforcement,
        temporarily_disable_private_neuron_enforcement,
    ] {
        let _restore_on_drop = set_enforcement();

        assert_eq!(neuron.visibility(), Some(Visibility::Public),);

        let neuron_info = neuron.get_neuron_info(
            &VotingPowerEconomics::DEFAULT,
            timestamp_seconds,
            principal_id,
        );
        assert_eq!(neuron_info.visibility, Some(Visibility::Public as i32),);

        let neuron_proto = neuron
            .clone()
            .into_proto(&VotingPowerEconomics::DEFAULT, timestamp_seconds);
        assert_eq!(neuron_proto.visibility, Some(Visibility::Public as i32),);
    }
}

#[test]
fn test_adjust_voting_power_enabled() {
    let _restore_on_drop = temporarily_enable_voting_power_adjustment();

    let principal_id = PrincipalId::new_user_test_id(42);
    let created_timestamp_seconds = 1729791574;

    let neuron = NeuronBuilder::new(
        NeuronId { id: 42 },
        Subaccount::try_from(vec![42u8; 32].as_slice()).unwrap(),
        principal_id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 12 * ONE_MONTH_SECONDS,
            aging_since_timestamp_seconds: created_timestamp_seconds + 42,
        },
        created_timestamp_seconds, // created
    )
    .with_cached_neuron_stake_e8s(100 * E8)
    .build();
    let original_potential_voting_power = neuron.potential_voting_power(created_timestamp_seconds);
    assert!(original_potential_voting_power > 0);

    // At first, there is no difference between deciding and potential voting
    // power. The neuron is considered "current".
    assert_eq!(
        neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, created_timestamp_seconds),
        original_potential_voting_power,
    );

    // In fact, for the next 6 months, the two remain the same.
    let mut previous_potential_voting_power = original_potential_voting_power;
    for months in 1..=6 {
        let now_seconds = created_timestamp_seconds + months * ONE_MONTH_SECONDS;
        let current_potential_voting_power = neuron.potential_voting_power(now_seconds);

        assert_eq!(
            neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now_seconds),
            current_potential_voting_power,
        );

        // This is not verifying the code under test, but is here just as a
        // sanity check. The reason we expect potential voting power to keep
        // rising is because of age bonus.
        assert!(
            current_potential_voting_power > previous_potential_voting_power,
            "at {} months: {} vs. {}",
            months,
            original_potential_voting_power,
            previous_potential_voting_power,
        );

        previous_potential_voting_power = current_potential_voting_power;
    }

    // Now, we are in the adjustment period where the neuron has not been
    // updated in "too long" of a time, and as a result, it is now experiencing
    // voting power reduction penalties.
    for months in [0.0, 0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99] {
        let now_seconds =
            created_timestamp_seconds + ((6.0 + months) * ONE_MONTH_SECONDS as f64) as u64;

        fn relative_error(observed_value: f64, expected_value: f64) -> f64 {
            assert!(expected_value.abs() > 1e-9);
            (observed_value - expected_value) / expected_value
        }

        let observed = neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now_seconds);
        let current_potential_voting_power = neuron.potential_voting_power(now_seconds);
        let expected = (1.0 - months) * current_potential_voting_power as f64;
        let err = relative_error(
            observed as f64,
            // Expected value.
            expected,
        );
        assert!(
            err < 1e-6, // Relative error is less than 1 ppm (parts per million).
            "at {} months: {} vs. {} ({:+0.}% off potential {})",
            6.0 + months,
            observed,
            expected,
            100.0 * err,
            current_potential_voting_power,
        );
    }

    // Starting at 7 months of no voting power refresh, deciding voting power
    // goes all the way down to 0.
    for months in 7..=10 {
        let now_seconds = created_timestamp_seconds + months * ONE_MONTH_SECONDS;
        assert_eq!(
            neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now_seconds),
            0
        );
    }
}

#[test]
fn test_adjust_voting_power_disabled() {
    let _restore_on_drop = temporarily_disable_voting_power_adjustment();

    let principal_id = PrincipalId::new_user_test_id(42);
    let created_timestamp_seconds = 1729791574;

    let neuron = NeuronBuilder::new(
        NeuronId { id: 42 },
        Subaccount::try_from(vec![42u8; 32].as_slice()).unwrap(),
        principal_id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 12 * ONE_MONTH_SECONDS,
            aging_since_timestamp_seconds: created_timestamp_seconds + 42,
        },
        created_timestamp_seconds, // created
    )
    .with_cached_neuron_stake_e8s(100 * E8)
    .build();
    let original_potential_voting_power = neuron.potential_voting_power(created_timestamp_seconds);
    assert!(original_potential_voting_power > 0);

    // At all times, deciding voting power is exactly the same as potential
    // voting power, because adjustment is disabled.
    for months in [
        0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 6.001, 6.1, 6.25, 6.5, 6.75, 6.9, 6.999, 7.0, 7.001,
        7.1, 7.25, 7.5, 8.0, 9.0, 10.0,
    ] {
        let now_seconds = created_timestamp_seconds + (months * ONE_MONTH_SECONDS as f64) as u64;
        let current_potential_voting_power = neuron.potential_voting_power(now_seconds);

        assert_eq!(
            neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, now_seconds),
            current_potential_voting_power,
        );
    }
}

#[test]
fn test_conversion_from_old_ballot_storage_full() {
    let principal_id = PrincipalId::new_user_test_id(42);
    let created_timestamp_seconds = 1729791574;

    let recent_ballots: Vec<_> = (0..100)
        .map(|id| BallotInfo {
            proposal_id: Some(ProposalId { id }),
            vote: Vote::Yes as i32,
        })
        .collect();

    let mut neuron = NeuronBuilder::new(
        NeuronId { id: 42 },
        Subaccount::try_from(vec![42u8; 32].as_slice()).unwrap(),
        principal_id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 12 * ONE_MONTH_SECONDS,
            aging_since_timestamp_seconds: created_timestamp_seconds + 42,
        },
        created_timestamp_seconds, // created
    )
    .with_recent_ballots(recent_ballots.clone())
    .build();
    neuron.recent_ballots_next_entry_index = None;

    assert_eq!(neuron.recent_ballots, recent_ballots);

    neuron.register_recent_ballot(Topic::NetworkEconomics, &ProposalId { id: 100 }, Vote::No);

    assert_eq!(neuron.recent_ballots_next_entry_index, Some(1));

    let expected_updated_ballots = {
        let mut recent_ballots = recent_ballots.clone();
        recent_ballots.reverse();
        recent_ballots[0] = BallotInfo {
            proposal_id: Some(ProposalId { id: 100 }),
            vote: Vote::No as i32,
        };
        recent_ballots
    };

    assert_eq!(neuron.recent_ballots, expected_updated_ballots);
}

#[test]
fn test_conversion_from_old_ballot_storage_not_full() {
    let principal_id = PrincipalId::new_user_test_id(42);
    let created_timestamp_seconds = 1729791574;

    let recent_ballots: Vec<_> = (0..75)
        .map(|id| BallotInfo {
            proposal_id: Some(ProposalId { id }),
            vote: Vote::Yes as i32,
        })
        .collect();

    let mut neuron = NeuronBuilder::new(
        NeuronId { id: 42 },
        Subaccount::try_from(vec![42u8; 32].as_slice()).unwrap(),
        principal_id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 12 * ONE_MONTH_SECONDS,
            aging_since_timestamp_seconds: created_timestamp_seconds + 42,
        },
        created_timestamp_seconds, // created
    )
    .with_recent_ballots(recent_ballots.clone())
    .build();
    neuron.recent_ballots_next_entry_index = None;

    assert_eq!(neuron.recent_ballots, recent_ballots);

    neuron.register_recent_ballot(Topic::NetworkEconomics, &ProposalId { id: 100 }, Vote::No);

    assert_eq!(neuron.recent_ballots_next_entry_index, Some(76));

    let expected_updated_ballots = {
        let mut recent_ballots = recent_ballots.clone();
        recent_ballots.reverse();
        recent_ballots.push(BallotInfo {
            proposal_id: Some(ProposalId { id: 100 }),
            vote: Vote::No as i32,
        });
        recent_ballots
    };

    assert_eq!(neuron.recent_ballots, expected_updated_ballots);
}

#[test]
fn test_recent_ballots_accessor_pre_and_post_migration() {
    let principal_id = PrincipalId::new_user_test_id(42);
    let created_timestamp_seconds = 1729791574;

    let recent_ballots: Vec<_> = (0..100)
        .map(|id| BallotInfo {
            proposal_id: Some(ProposalId { id }),
            vote: Vote::Yes as i32,
        })
        .collect();

    let mut neuron = NeuronBuilder::new(
        NeuronId { id: 42 },
        Subaccount::try_from(vec![42u8; 32].as_slice()).unwrap(),
        principal_id,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 12 * ONE_MONTH_SECONDS,
            aging_since_timestamp_seconds: created_timestamp_seconds + 42,
        },
        created_timestamp_seconds, // created
    )
    .with_recent_ballots(recent_ballots.clone())
    .build();
    neuron.recent_ballots_next_entry_index = None;

    assert_eq!(neuron.sorted_recent_ballots(), recent_ballots);

    neuron.register_recent_ballot(Topic::NetworkEconomics, &ProposalId { id: 100 }, Vote::No);
    assert_eq!(neuron.recent_ballots_next_entry_index, Some(1));

    let expected_updated_ballots = {
        let mut recent_ballots = recent_ballots.clone();
        recent_ballots.insert(
            0,
            BallotInfo {
                proposal_id: Some(ProposalId { id: 100 }),
                vote: Vote::No as i32,
            },
        );
        recent_ballots.pop();
        recent_ballots
    };

    assert_eq!(neuron.sorted_recent_ballots(), expected_updated_ballots);
}

#[test]
fn test_ready_to_unstake_maturity() {
    let now = 123_456_789;

    let create_neuron_with_state_and_staked_maturity =
        |dissolve_state_and_age, staked_maturity| -> Neuron {
            NeuronBuilder::new(
                NeuronId { id: 1 },
                Subaccount::try_from(vec![0u8; 32].as_slice()).unwrap(),
                PrincipalId::new_user_test_id(1),
                dissolve_state_and_age,
                123_456_789,
            )
            .with_staked_maturity_e8s_equivalent(staked_maturity)
            .build()
        };

    // Ready to unstake maturity since it's both dissolved and has staked maturity.
    assert!(create_neuron_with_state_and_staked_maturity(
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now,
        },
        1
    )
    .ready_to_unstake_maturity(now));

    // Not ready to unstake maturity since it's not dissolved yet.
    assert!(!create_neuron_with_state_and_staked_maturity(
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now + 1,
        },
        1
    )
    .ready_to_unstake_maturity(now));

    // Not ready to unstake maturity since it is non-dissolving.
    assert!(!create_neuron_with_state_and_staked_maturity(
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 1,
            aging_since_timestamp_seconds: now,
        },
        1
    )
    .ready_to_unstake_maturity(now));

    // Not ready to unstake maturity since it has no staked maturity.
    assert!(!create_neuron_with_state_and_staked_maturity(
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now,
        },
        0
    )
    .ready_to_unstake_maturity(now));
}

#[test]
fn test_ready_to_spawn() {
    let now = 123_456_789;

    // Ready to spawn since it has a spawn timestamp in the past.
    let neuron_ready_to_spawn = NeuronBuilder::new(
        NeuronId { id: 1 },
        Subaccount::try_from(vec![0u8; 32].as_slice()).unwrap(),
        PrincipalId::new_user_test_id(1),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now - 1,
        },
        0, // created
    )
    .with_spawn_at_timestamp_seconds(now - 1)
    .build();
    assert!(neuron_ready_to_spawn.ready_to_spawn(now));

    // Not ready to spawn since it has a spawn timestamp in the future.
    let neuron_not_ready_to_spawn = NeuronBuilder::new(
        NeuronId { id: 1 },
        Subaccount::try_from(vec![0u8; 32].as_slice()).unwrap(),
        PrincipalId::new_user_test_id(1),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now + 1,
        },
        0, // created
    )
    .with_spawn_at_timestamp_seconds(now + 1)
    .build();
    assert!(!neuron_not_ready_to_spawn.ready_to_spawn(now));

    // Not ready to spawn since it has no spawn timestamp.
    let neuron_no_spawn_timestamp = NeuronBuilder::new(
        NeuronId { id: 1 },
        Subaccount::try_from(vec![0u8; 32].as_slice()).unwrap(),
        PrincipalId::new_user_test_id(1),
        DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: now - 1,
        },
        0, // created
    )
    .build();
    assert!(!neuron_no_spawn_timestamp.ready_to_spawn(now));
}
