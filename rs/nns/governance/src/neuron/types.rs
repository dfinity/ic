use crate::pb::v1::neuron::DissolveState;

/// An enum to represent different combinations of a neurons dissolve_state and
/// aging_since_timestamp_seconds. Currently, the back-and-forth conversions should make sure the
/// legacy states remain the same unless some operations performed on the neuron makes the state/age
/// changes. After we make sure all neuron mutations or creations must mutate states to valid ones
/// and the invalid states have been migrated to valid ones on the mainnet, we can panic in
/// conversion when invalid states are encountered. 2 of the legacy states
/// (LegacyDissolvingOrDissolved and LegacyDissolved) are the cases we already know to be existing
/// on the mainnet.
#[derive(Clone, Debug, PartialEq)]
pub enum DissolveStateAndAge {
    /// A non-dissolving neuron has a dissolve delay and an aging since timestamp.
    NotDissolving {
        dissolve_delay_seconds: u64,
        aging_since_timestamp_seconds: u64,
    },
    /// A dissolving or dissolved neuron has a dissolved timestamp and no aging since timestamp.
    DissolvingOrDissolved {
        when_dissolved_timestamp_seconds: u64,
    },
    /// We used to allow neurons to have age when they were dissolving or dissolved. This should be
    /// mapped to DissolvingOrDissolved { when_dissolved_timestamp_seconds } and its aging singe
    /// timestamp removed.
    LegacyDissolvingOrDissolved {
        when_dissolved_timestamp_seconds: u64,
        aging_since_timestamp_seconds: u64,
    },
    /// When claiming a neuron, the dissolve delay is set to 0 while the neuron is considered
    /// dissolved. Its aging_since_timestamp_seconds is set to the neuron was claimed. This state
    /// should be mapped to DissolvingOrDissolved { when_dissolved_timestamp_seconds:
    /// aging_since_timestamp_seconds }.
    LegacyDissolved { aging_since_timestamp_seconds: u64 },

    /// The dissolve state is None, which should have never existed, but we keep the current
    /// behavior of considering it as a dissolved neuron.
    LegacyNoneDissolveState { aging_since_timestamp_seconds: u64 },
}

/// An intermediate struct to represent a neuron's dissolve state and age on the storage layer.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct StoredDissolvedStateAndAge {
    pub dissolve_state: Option<DissolveState>,
    pub aging_since_timestamp_seconds: u64,
}

impl From<DissolveStateAndAge> for StoredDissolvedStateAndAge {
    fn from(dissolve_state_and_age: DissolveStateAndAge) -> Self {
        match dissolve_state_and_age {
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
                aging_since_timestamp_seconds,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                aging_since_timestamp_seconds: u64::MAX,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                aging_since_timestamp_seconds,
            },
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(0)),
                aging_since_timestamp_seconds,
            },
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: None,
                aging_since_timestamp_seconds,
            },
        }
    }
}

impl From<StoredDissolvedStateAndAge> for DissolveStateAndAge {
    fn from(stored: StoredDissolvedStateAndAge) -> Self {
        match (stored.dissolve_state, stored.aging_since_timestamp_seconds) {
            (None, aging_since_timestamp_seconds) => DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds,
            },
            (Some(DissolveState::DissolveDelaySeconds(0)), aging_since_timestamp_seconds) => {
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds,
                }
            }
            (
                Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
                // TODO(NNS1-2951): have a stricter guarantee about the aging_since_timestamp_seconds.
                aging_since_timestamp_seconds,
            ) => DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            },
            (
                Some(DissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                u64::MAX,
            ) => DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            },
            (
                Some(DissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                aging_since_timestamp_seconds,
            ) => DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dissolve_state_and_age_conversion() {
        let test_cases = vec![
            (
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds: 200,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(100)),
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
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(100)),
                    aging_since_timestamp_seconds: u64::MAX,
                },
            ),
            (
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: 300,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(300)),
                    aging_since_timestamp_seconds: u64::MAX,
                },
            ),
            (
                DissolveStateAndAge::LegacyDissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: 400,
                    aging_since_timestamp_seconds: 500,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(400)),
                    aging_since_timestamp_seconds: 500,
                },
            ),
            (
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds: 600,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(0)),
                    aging_since_timestamp_seconds: 600,
                },
            ),
            (
                DissolveStateAndAge::LegacyNoneDissolveState {
                    aging_since_timestamp_seconds: 700,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: None,
                    aging_since_timestamp_seconds: 700,
                },
            ),
        ];

        for (dissolve_state_and_age, stored_dissolved_state_and_age) in test_cases {
            assert_eq!(
                StoredDissolvedStateAndAge::from(dissolve_state_and_age.clone()),
                stored_dissolved_state_and_age.clone()
            );
            assert_eq!(
                DissolveStateAndAge::from(stored_dissolved_state_and_age),
                dissolve_state_and_age
            );
        }
    }
}
