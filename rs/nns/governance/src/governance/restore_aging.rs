use crate::{
    audit_event::{add_audit_event, reset_aging_audit_events},
    governance::{Governance, LOG_PREFIX},
    neuron::types::Neuron,
    neuron_store::NeuronStore,
    pb::v1::{
        audit_event::{
            restore_aging::NeuronDissolveState as RestoreAgingDissolveState, Payload, ResetAging,
            RestoreAging,
        },
        neuron::DissolveState,
        restore_aging_summary::{NeuronGroupType, RestoreAgingNeuronGroup},
        AuditEvent, RestoreAgingSummary,
    },
};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_nns_common::pb::v1::NeuronId;
use std::collections::BTreeMap;

/// This is approximately 18 months before genesis (2021-05-06), when
/// [GenesisTokenCanisterInitPayloadBuilder::new] was run.
pub const PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS: u64 = 1_572_990_062;

impl Governance {
    /// Restores aging of neurons that were pre-aged before the reset. This function should only be
    /// executed once if successful, as it will set the `restore_aging_summary` field in the
    /// Governance state.
    pub(super) fn maybe_restore_pre_aged_neurons(&mut self) {
        if self.heap_data.restore_aging_summary.is_some() {
            return;
        }

        let restore_pre_aged_neurons_result = restore_pre_aged_neurons(
            &mut self.neuron_store,
            reset_aging_audit_events(),
            self.env.now(),
        );

        match restore_pre_aged_neurons_result {
            Ok(restore_aging_summary) => {
                self.heap_data.restore_aging_summary = Some(restore_aging_summary);
            }
            Err(err) => {
                println!("{}Failed to restore pre-aged neurons: {}", LOG_PREFIX, err);
            }
        }
    }

    pub fn get_restore_aging_summary(&self) -> Option<RestoreAgingSummary> {
        self.heap_data.restore_aging_summary.clone()
    }
}

impl NeuronGroupType {
    /// Determines the group type by the neuron and fields in the reset aging audit log.
    pub fn from_neuron_and_reset_aging_log(
        neuron: &Neuron,
        reset_aging_audit_event: &ResetAging,
    ) -> Self {
        let ResetAging {
            previous_aging_since_timestamp_seconds: aging_since_timestamp_seconds_before_reset,
            new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            neuron_stake_e8s: previous_neuron_stake_e8s,
            neuron_id: _,
            neuron_dissolve_state: _,
        } = reset_aging_audit_event;

        if *aging_since_timestamp_seconds_before_reset
            != PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS
        {
            return Self::NotPreAging;
        }

        // Make sure the neuron is non-dissolving now.
        match neuron.dissolve_state {
            Some(DissolveState::WhenDissolvedTimestampSeconds(_)) => {
                // The neuron is already dissolving/disolved.
                return Self::DissolvingOrDissolved;
            }
            Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)) => {
                // Dissolve delay being 0 means the neuron is already dissolved.
                if dissolve_delay_seconds == 0 {
                    return Self::DissolvingOrDissolved;
                }
            }
            // Dissolve state equal to None shouldn't exist, but it is considered as dissolved.
            None => return Self::DissolvingOrDissolved,
        };

        if neuron.cached_neuron_stake_e8s != *previous_neuron_stake_e8s {
            return Self::StakeChanged;
        }

        if neuron.aging_since_timestamp_seconds == *aging_since_timestamp_seconds_after_reset {
            Self::StakeSameAgingSame
        } else {
            Self::StakeSameAgingChanged
        }
    }

    /// Returns whether aging of a neuron in the group should be restored.
    pub fn should_restore_aging(self) -> bool {
        match self {
            Self::NotPreAging => false,
            Self::DissolvingOrDissolved => false,
            Self::Unspecified => false,

            // In all of the following cases we should restore aging. We break down the eligible
            // neurons into groups so that we can check the count and total stake change for each
            // group.
            Self::StakeChanged => true,
            Self::StakeSameAgingSame => true,
            Self::StakeSameAgingChanged => true,
        }
    }
}

#[derive(Default, PartialEq, Eq, Clone, Debug)]
struct NeuronGroup {
    count: u64,
    previous_total_stake_e8s: u64,
    current_total_stake_e8s: u64,
}

fn restore_pre_aged_neurons(
    neuron_store: &mut NeuronStore,
    reset_aging_audit_events: Vec<ResetAging>,
    now_seconds: u64,
) -> Result<RestoreAgingSummary, String> {
    let mut neuron_groups = BTreeMap::new();
    let mut neuron_ids_to_restore = Vec::new();
    for reset_aging_audit_event in reset_aging_audit_events {
        let neuron_id = reset_aging_audit_event.neuron_id;
        neuron_store
            .with_neuron(&NeuronId { id: neuron_id }, |neuron| {
                let neuron_group_type = NeuronGroupType::from_neuron_and_reset_aging_log(
                    neuron,
                    &reset_aging_audit_event,
                );

                let neuron_group = neuron_groups
                    .entry(neuron_group_type)
                    .or_insert(NeuronGroup::default());
                neuron_group.count += 1;
                neuron_group.previous_total_stake_e8s += reset_aging_audit_event.neuron_stake_e8s;
                neuron_group.current_total_stake_e8s += neuron.cached_neuron_stake_e8s;

                if neuron_group_type.should_restore_aging() {
                    neuron_ids_to_restore.push(neuron_id);
                }
            })
            .map_err(|err| format!("Failed to get neuron {}: {}", neuron_id, err))?;
    }

    check_stake_increase_low_enough(&neuron_groups)?;

    // After this point, all checks are performed, and mutation can happen after, while any failure
    // beyond this point will panick.

    for neuron_id in neuron_ids_to_restore.into_iter() {
        neuron_store
            .with_neuron_mut(&NeuronId { id: neuron_id }, |neuron| {
                let previous_aging_since_timestamp_seconds = neuron.aging_since_timestamp_seconds;
                let new_aging_since_timestamp_seconds =
                    PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS;
                neuron.aging_since_timestamp_seconds = new_aging_since_timestamp_seconds;

                println!(
                    "{}Restored the age of neuron {} to {}",
                    LOG_PREFIX, neuron_id, new_aging_since_timestamp_seconds
                );

                add_audit_event(AuditEvent {
                    timestamp_seconds: now_seconds,
                    payload: Some(Payload::RestoreAging(RestoreAging {
                        neuron_id: Some(neuron_id),
                        previous_aging_since_timestamp_seconds: Some(
                            previous_aging_since_timestamp_seconds,
                        ),
                        new_aging_since_timestamp_seconds: Some(new_aging_since_timestamp_seconds),
                        neuron_dissolve_state: neuron
                            .dissolve_state
                            .clone()
                            .map(RestoreAgingDissolveState::from),
                        neuron_stake_e8s: Some(neuron.cached_neuron_stake_e8s),
                    })),
                });
            })
            .expect("Failed to get neuron");
    }

    Ok(RestoreAgingSummary {
        timestamp_seconds: Some(now_seconds),
        groups: neuron_groups
            .into_iter()
            .map(|(neuron_group_type, group)| RestoreAgingNeuronGroup {
                group_type: neuron_group_type as i32,
                count: Some(group.count),
                previous_total_stake_e8s: Some(group.previous_total_stake_e8s),
                current_total_stake_e8s: Some(group.current_total_stake_e8s),
            })
            .collect(),
    })
}

fn check_stake_increase_low_enough(
    neuron_groups: &BTreeMap<NeuronGroupType, NeuronGroup>,
) -> Result<(), String> {
    let mut previous_total_stake_e8s_about_to_restore: f64 = 0.0;
    let mut current_total_stake_e8s_about_to_restore: f64 = 0.0;

    for (neuron_group_type, group) in neuron_groups.iter() {
        if !neuron_group_type.should_restore_aging() {
            continue;
        }
        previous_total_stake_e8s_about_to_restore += group.previous_total_stake_e8s as f64;
        current_total_stake_e8s_about_to_restore += group.current_total_stake_e8s as f64;
    }

    if current_total_stake_e8s_about_to_restore > previous_total_stake_e8s_about_to_restore * 1.1 {
        Err(format!(
            "The total stake of neurons about to restore aging increased too much: {} -> {}, neuron groups: {:?}",
            previous_total_stake_e8s_about_to_restore, current_total_stake_e8s_about_to_restore, neuron_groups
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        neuron::types::{DissolveStateAndAge, NeuronBuilder},
        storage::with_audit_events_log,
    };

    use ic_base_types::PrincipalId;
    use icp_ledger::Subaccount;

    fn make_test_neuron_with_dissolve_state_and_age_and_stake(
        id: u64,
        dissolve_state_and_age: DissolveStateAndAge,
        cached_neuron_stake_e8s: u64,
    ) -> Neuron {
        NeuronBuilder::new(
            NeuronId { id },
            Subaccount::try_from(&[0u8; 32] as &[u8]).unwrap(),
            PrincipalId::new_user_test_id(1),
            dissolve_state_and_age,
            42,
        )
        .with_cached_neuron_stake_e8s(cached_neuron_stake_e8s)
        .build()
    }

    #[test]
    fn test_neuron_group_type() {
        // Some time on 2024-04-18.
        let aging_since_timestamp_seconds_after_reset = 1713446366;

        // The neuron was not pre-aged before reset.
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 123_456_789,
                        aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset
                    },
                    1_000_000_000
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS + 1,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    neuron_stake_e8s: 1_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::NotPreAging
        );

        // The neuron is dissolving/dissolved now.
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: 42
                    },
                    1_000_000_000
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    neuron_stake_e8s: 1_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::DissolvingOrDissolved
        );
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::LegacyDissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: 42,
                        aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    },
                    1_000_000_000
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    neuron_stake_e8s: 1_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::DissolvingOrDissolved
        );
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::LegacyDissolved {
                        aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    },
                    1_000_000_000
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    neuron_stake_e8s: 1_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::DissolvingOrDissolved
        );
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::LegacyNoneDissolveState {
                        aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    },
                    1_000_000_000,
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    neuron_stake_e8s: 1_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::DissolvingOrDissolved
        );

        // The neuron has its stake changed since the reset.
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 123_456_789,
                        aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset
                    },
                    1_000_000_000
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    neuron_stake_e8s: 2_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::StakeChanged
        );

        // The neuron has its age changed since the reset.
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 123_456_789,
                        aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset
                    },
                    1_000_000_000
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset
                        + 1,
                    neuron_stake_e8s: 1_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::StakeSameAgingChanged
        );

        // The neuron has the same stake and age since the reset.
        assert_eq!(
            NeuronGroupType::from_neuron_and_reset_aging_log(
                &make_test_neuron_with_dissolve_state_and_age_and_stake(
                    1,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: 123_456_789,
                        aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset
                    },
                    1_000_000_000
                ),
                &ResetAging {
                    neuron_id: 1,
                    previous_aging_since_timestamp_seconds:
                        PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
                    new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
                    neuron_stake_e8s: 1_000_000_000,
                    neuron_dissolve_state: None,
                },
            ),
            NeuronGroupType::StakeSameAgingSame
        );
    }

    #[test]
    fn test_restore_pre_aged_neurons() {
        let mut neuron_store = NeuronStore::new(BTreeMap::new());
        // 2021-05-06 00:00:00 UTC.
        let aging_since_timestamp_seconds_after_reset = 1_620_259_200;
        // 200 days. The dissolve delay doesn't matter in this test.
        let dissolve_delay_seconds = 86_400 * 200;

        // Neuron 1: not pre-aging
        let neuron_1 = make_test_neuron_with_dissolve_state_and_age_and_stake(
            1,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: 1_000_000_000,
            },
            1_000_000_000_000,
        );
        let reset_aging_1 = ResetAging {
            neuron_id: 1,
            previous_aging_since_timestamp_seconds: 1,
            new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            neuron_stake_e8s: 1_000_000_000_000,
            neuron_dissolve_state: None,
        };

        // Neuron 2: dissolving/dissolved
        let neuron_2 = make_test_neuron_with_dissolve_state_and_age_and_stake(
            2,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 42,
            },
            200_000_000_000,
        );
        let reset_aging_2 = ResetAging {
            neuron_id: 2,
            previous_aging_since_timestamp_seconds: PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
            new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            neuron_stake_e8s: 100_000_000_000,
            neuron_dissolve_state: None,
        };

        // Neuron 3: stake changed
        let neuron_3 = make_test_neuron_with_dissolve_state_and_age_and_stake(
            3,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            },
            200_000_000_000,
        );
        let reset_aging_3 = ResetAging {
            neuron_id: 3,
            previous_aging_since_timestamp_seconds: PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
            new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            neuron_stake_e8s: 100_000_000_000,
            neuron_dissolve_state: None,
        };

        // Neuron 4: age changed
        let neuron_4 = make_test_neuron_with_dissolve_state_and_age_and_stake(
            4,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            },
            10_000_000_000,
        );
        let reset_aging_4 = ResetAging {
            neuron_id: 4,
            previous_aging_since_timestamp_seconds: PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
            new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset - 1,
            neuron_stake_e8s: 10_000_000_000,
            neuron_dissolve_state: None,
        };

        // Neuron 5: stake and age the same. This is the most common case with most of the stake.
        let neuron_5 = make_test_neuron_with_dissolve_state_and_age_and_stake(
            5,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            },
            10_000_000_000_000,
        );
        let reset_aging_5 = ResetAging {
            neuron_id: 5,
            previous_aging_since_timestamp_seconds: PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS,
            new_aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            neuron_stake_e8s: 10_000_000_000_000,
            neuron_dissolve_state: None,
        };

        // Neuron 6: no audit log
        let neuron_6 = make_test_neuron_with_dissolve_state_and_age_and_stake(
            6,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: aging_since_timestamp_seconds_after_reset,
            },
            1_000_000_000,
        );

        // Assemble input.
        for neuron in vec![
            neuron_1.clone(),
            neuron_2.clone(),
            neuron_3,
            neuron_4,
            neuron_5,
            neuron_6.clone(),
        ] {
            neuron_store.add_neuron(neuron).unwrap();
        }
        for audit_event in vec![
            reset_aging_1,
            reset_aging_2,
            reset_aging_3.clone(),
            reset_aging_4.clone(),
            reset_aging_5.clone(),
        ] {
            add_audit_event(AuditEvent {
                timestamp_seconds: 42,
                payload: Some(Payload::ResetAging(audit_event)),
            });
        }

        // Execute the restore function.
        let restore_aging_summary =
            restore_pre_aged_neurons(&mut neuron_store, reset_aging_audit_events(), 43).unwrap();

        // Verifies the summary.
        assert_eq!(
            restore_aging_summary,
            RestoreAgingSummary {
                timestamp_seconds: Some(43),
                groups: vec![
                    RestoreAgingNeuronGroup {
                        group_type: NeuronGroupType::NotPreAging as i32,
                        count: Some(1),
                        previous_total_stake_e8s: Some(1_000_000_000_000),
                        current_total_stake_e8s: Some(1_000_000_000_000),
                    },
                    RestoreAgingNeuronGroup {
                        group_type: NeuronGroupType::DissolvingOrDissolved as i32,
                        count: Some(1),
                        previous_total_stake_e8s: Some(100_000_000_000),
                        current_total_stake_e8s: Some(200_000_000_000),
                    },
                    RestoreAgingNeuronGroup {
                        group_type: NeuronGroupType::StakeChanged as i32,
                        count: Some(1),
                        previous_total_stake_e8s: Some(100_000_000_000),
                        current_total_stake_e8s: Some(200_000_000_000),
                    },
                    RestoreAgingNeuronGroup {
                        group_type: NeuronGroupType::StakeSameAgingChanged as i32,
                        count: Some(1),
                        previous_total_stake_e8s: Some(10_000_000_000),
                        current_total_stake_e8s: Some(10_000_000_000),
                    },
                    RestoreAgingNeuronGroup {
                        group_type: NeuronGroupType::StakeSameAgingSame as i32,
                        count: Some(1),
                        previous_total_stake_e8s: Some(10_000_000_000_000),
                        current_total_stake_e8s: Some(10_000_000_000_000),
                    },
                ],
            }
        );

        // Verifies the neurons that should not be restored.
        let assert_neuron_state_and_age_not_changed = |neuron: Neuron| {
            let current_state_and_age = neuron_store
                .with_neuron(&neuron.id(), |neuron| neuron.dissolve_state_and_age())
                .unwrap();
            assert_eq!(current_state_and_age, neuron.dissolve_state_and_age());
        };
        assert_neuron_state_and_age_not_changed(neuron_1);
        assert_neuron_state_and_age_not_changed(neuron_2);
        assert_neuron_state_and_age_not_changed(neuron_6);

        // Verifies the neurons that should be restored.
        let assert_neuron_state_and_age_changed =
            |neuron_id: u64, reset_aging_audit_event: ResetAging| {
                let current_state_and_age = neuron_store
                    .with_neuron(&NeuronId { id: neuron_id }, |neuron| {
                        neuron.dissolve_state_and_age()
                    })
                    .unwrap();
                match current_state_and_age {
                    DissolveStateAndAge::NotDissolving {
                        aging_since_timestamp_seconds,
                        ..
                    } => {
                        assert_eq!(
                            aging_since_timestamp_seconds,
                            reset_aging_audit_event.previous_aging_since_timestamp_seconds
                        );
                    }
                    _ => {
                        panic!("Unexpected state and age: {:?}", current_state_and_age);
                    }
                }
            };
        assert_neuron_state_and_age_changed(3, reset_aging_3);
        assert_neuron_state_and_age_changed(4, reset_aging_4);
        assert_neuron_state_and_age_changed(5, reset_aging_5);

        let restore_audit_event_log = with_audit_events_log(|log| {
            log.iter()
                .filter(|event| matches!(event.payload, Some(Payload::RestoreAging(_))))
                .collect::<Vec<_>>()
        });
        assert_eq!(
            restore_audit_event_log,
            vec![
                AuditEvent {
                    timestamp_seconds: 43,
                    payload: Some(Payload::RestoreAging(RestoreAging {
                        neuron_id: Some(3),
                        previous_aging_since_timestamp_seconds: Some(
                            aging_since_timestamp_seconds_after_reset
                        ),
                        new_aging_since_timestamp_seconds: Some(
                            PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS
                        ),
                        neuron_stake_e8s: Some(200_000_000_000),
                        neuron_dissolve_state: Some(
                            RestoreAgingDissolveState::DissolveDelaySeconds(dissolve_delay_seconds)
                        )
                    }))
                },
                AuditEvent {
                    timestamp_seconds: 43,
                    payload: Some(Payload::RestoreAging(RestoreAging {
                        neuron_id: Some(4),
                        previous_aging_since_timestamp_seconds: Some(
                            aging_since_timestamp_seconds_after_reset
                        ),
                        new_aging_since_timestamp_seconds: Some(
                            PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS
                        ),
                        neuron_stake_e8s: Some(10_000_000_000),
                        neuron_dissolve_state: Some(
                            RestoreAgingDissolveState::DissolveDelaySeconds(dissolve_delay_seconds)
                        )
                    }))
                },
                AuditEvent {
                    timestamp_seconds: 43,
                    payload: Some(Payload::RestoreAging(RestoreAging {
                        neuron_id: Some(5),
                        previous_aging_since_timestamp_seconds: Some(
                            aging_since_timestamp_seconds_after_reset
                        ),
                        new_aging_since_timestamp_seconds: Some(
                            PRE_AGED_NEURON_AGING_SINCE_TIMESTAMP_SECONDS
                        ),
                        neuron_stake_e8s: Some(10_000_000_000_000),
                        neuron_dissolve_state: Some(
                            RestoreAgingDissolveState::DissolveDelaySeconds(dissolve_delay_seconds)
                        )
                    }))
                }
            ]
        );
    }
}
