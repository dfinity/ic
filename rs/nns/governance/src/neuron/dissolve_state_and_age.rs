use crate::{governance::MAX_DISSOLVE_DELAY_SECONDS, pb::v1::NeuronState};

/// An enum to represent different combinations of a neurons dissolve_state and
/// aging_since_timestamp_seconds. Currently, the back-and-forth conversions should make sure the
/// legacy states remain the same unless some operations performed on the neuron makes the state/age
/// changes. After we make sure all neuron mutations or creations must mutate states to valid ones
/// and the invalid states have been migrated to valid ones on the mainnet, we can panic in
/// conversion when invalid states are encountered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

impl DissolveStateAndAge {
    /// Returns the current state given the current time. Mainly for differentiating between
    /// dissolving and dissolved neurons.
    pub fn current_state(self, now_seconds: u64) -> NeuronState {
        match self {
            DissolveStateAndAge::NotDissolving { .. } => NeuronState::NotDissolving,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => {
                if now_seconds >= when_dissolved_timestamp_seconds {
                    NeuronState::Dissolved
                } else {
                    NeuronState::Dissolving
                }
            }
        }
    }

    /// Returns the age of the neuron in seconds. When its age isn't well-defined (e.g. dissolving
    /// or dissolved), the age is 0. However, in the legacy cases where we still have
    /// aging_since_timestamp_seconds, the neuron still has an age, and the legacy cases will be
    /// cleaned up soon.
    pub fn age_seconds(self, now_seconds: u64) -> u64 {
        match self {
            Self::NotDissolving {
                aging_since_timestamp_seconds,
                ..
            } => now_seconds.saturating_sub(aging_since_timestamp_seconds),
            Self::DissolvingOrDissolved { .. } => 0,
        }
    }

    pub fn dissolve_delay_seconds(self, now_seconds: u64) -> u64 {
        match self {
            Self::NotDissolving {
                dissolve_delay_seconds,
                ..
            } => dissolve_delay_seconds,
            // For the dissolving/dissolved case (legacy or not), the dissolve delay is the time remaining until the
            // dissolve timestamp.
            Self::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => when_dissolved_timestamp_seconds.saturating_sub(now_seconds),
        }
    }

    /// Returns the timestamp when the neuron will be dissolved. If the neuron is not dissolving, it
    /// returns None.
    pub fn dissolved_at_timestamp_seconds(self) -> Option<u64> {
        match self {
            Self::NotDissolving { .. } => None,
            Self::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => Some(when_dissolved_timestamp_seconds),
        }
    }

    /// Increases the dissolve delay of the neuron by the given number of seconds. If the neuron is
    /// already dissolved, it transitions to a non-dissolving state with the new dissolve delay. If
    /// the neuron is dissolving, the dissolve timestamp is increased by the given number of
    /// seconds. If the neuron is not dissolving, the dissolve delay is increased by the given
    /// number of seconds. The new dissolve delay is capped at MAX_DISSOLVE_DELAY_SECONDS.
    pub fn increase_dissolve_delay(
        self,
        now_seconds: u64,
        additional_dissolve_delay_seconds: u32,
    ) -> Self {
        // If there is no dissolve delay, this is a no-op.  Upstream validation can decide if
        // an error should be returned to the user.
        if additional_dissolve_delay_seconds == 0 {
            return self;
        }
        let additional_dissolve_delay_seconds = additional_dissolve_delay_seconds as u64;

        match self {
            Self::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } => {
                let new_delay_dissolve_delay_seconds = std::cmp::min(
                    dissolve_delay_seconds.saturating_add(additional_dissolve_delay_seconds),
                    MAX_DISSOLVE_DELAY_SECONDS,
                );
                Self::NotDissolving {
                    dissolve_delay_seconds: new_delay_dissolve_delay_seconds,
                    aging_since_timestamp_seconds,
                }
            }
            Self::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => {
                if now_seconds < when_dissolved_timestamp_seconds {
                    // Not dissolved yet. Increase the dissolve delay by increasing the dissolve timestamp.
                    let dissolve_delay_seconds =
                        when_dissolved_timestamp_seconds.saturating_sub(now_seconds);
                    let new_delay_seconds = std::cmp::min(
                        dissolve_delay_seconds.saturating_add(additional_dissolve_delay_seconds),
                        MAX_DISSOLVE_DELAY_SECONDS,
                    );
                    let new_when_dissolved_timestamp_seconds =
                        now_seconds.saturating_add(new_delay_seconds);
                    Self::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: new_when_dissolved_timestamp_seconds,
                    }
                } else {
                    // This neuron is dissolved. Set it to non-dissolving.
                    let new_delay_seconds = std::cmp::min(
                        additional_dissolve_delay_seconds,
                        MAX_DISSOLVE_DELAY_SECONDS,
                    );
                    Self::NotDissolving {
                        dissolve_delay_seconds: new_delay_seconds,
                        aging_since_timestamp_seconds: now_seconds,
                    }
                }
            }
        }
    }

    /// Starts dissolving if the neuron is non-dissolving. Otherwise it is a no-op.
    pub fn start_dissolving(self, now_seconds: u64) -> Self {
        match self {
            Self::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: _,
            } => Self::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: now_seconds
                    .saturating_add(dissolve_delay_seconds),
            },
            _ => self,
        }
    }

    /// Stops dissolving if the neuron is dissolving. Otherwise it is a no-op.
    pub fn stop_dissolving(self, now_seconds: u64) -> Self {
        // The operation only applies to dissolving neurons, so we get the dissolve timestamp, and
        // returns `self` otherwise as it is a no-op.
        let when_dissolved_timestamp_seconds = match self {
            Self::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => when_dissolved_timestamp_seconds,
            _ => return self,
        };

        let dissolve_delay_seconds = when_dissolved_timestamp_seconds.saturating_sub(now_seconds);
        if dissolve_delay_seconds > 0 {
            Self::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: now_seconds,
            }
        } else {
            // Note that we could have fixed the legacy case here, but it's counter-intuitive to
            // modify the state for a no-op. We will clean up the legacy cases soon.
            self
        }
    }

    // Adjusts the neuron age while respecting the invariant that dissolving/dissolved should not
    // have age.
    pub fn adjust_age(self, new_aging_since_timestamp_seconds: u64) -> Self {
        match self {
            // The is the only meaningful case where we adjust the age.
            Self::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: _,
            } => Self::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds: new_aging_since_timestamp_seconds,
            },
            // This is a no-op.
            Self::DissolvingOrDissolved { .. } => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 123_456_789;

    fn assert_current_state(
        dissolve_state_and_age: DissolveStateAndAge,
        expected_neuron_state: NeuronState,
    ) {
        assert_eq!(
            dissolve_state_and_age.current_state(NOW),
            expected_neuron_state
        );
    }

    #[test]
    fn test_current_state() {
        assert_current_state(
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1000,
                aging_since_timestamp_seconds: NOW,
            },
            NeuronState::NotDissolving,
        );
        for when_dissolved_timestamp_seconds in [0, NOW - 1, NOW] {
            assert_current_state(
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                },
                NeuronState::Dissolved,
            );
        }
        for when_dissolved_timestamp_seconds in [NOW + 1, NOW + 100] {
            assert_current_state(
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                },
                NeuronState::Dissolving,
            );
        }
    }

    fn assert_dissolve_delay_seconds(
        dissolve_state_and_age: DissolveStateAndAge,
        expected_dissolve_delay_seconds: u64,
    ) {
        assert_eq!(
            dissolve_state_and_age.dissolve_delay_seconds(NOW),
            expected_dissolve_delay_seconds
        );
    }

    #[test]
    fn test_dissolve_delay_seconds_non_dissolving() {
        for aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1] {
            assert_dissolve_delay_seconds(
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds,
                },
                100,
            );
        }
    }

    #[test]
    fn test_dissolve_delay_seconds_dissolving_or_dissolved() {
        for (when_dissolved_timestamp_seconds, expected_dissolve_delay_seconds) in [
            (0, 0),
            (NOW - 1, 0),
            (NOW, 0),
            (NOW + 1, 1),
            (NOW + 100, 100),
        ] {
            assert_dissolve_delay_seconds(
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                },
                expected_dissolve_delay_seconds,
            );
        }
    }

    fn assert_age_seconds(dissolve_state_and_age: DissolveStateAndAge, expected_age_seconds: u64) {
        assert_eq!(
            dissolve_state_and_age.age_seconds(NOW),
            expected_age_seconds
        );
    }

    #[test]
    fn test_age_seconds_non_dissolving() {
        for (aging_since_timestamp_seconds, expected_age_seconds) in
            [(0, NOW), (NOW - 1, 1), (NOW, 0), (NOW + 1, 0)]
        {
            for dissolve_delay_seconds in [0, 1, 100, MAX_DISSOLVE_DELAY_SECONDS] {
                assert_age_seconds(
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds,
                        aging_since_timestamp_seconds,
                    },
                    expected_age_seconds,
                );
            }
        }
    }

    #[test]
    fn test_age_seconds_dissolving_or_dissolved() {
        // Dissolving or dissolved neurons have an age of 0.
        for when_dissolved_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1] {
            assert_age_seconds(
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                },
                0,
            );
        }
    }

    fn assert_increase_dissolve_delay(
        original_dissolve_state_and_age: DissolveStateAndAge,
        additional_dissolve_delay_seconds: u32,
        expected_dissolve_state_and_age: DissolveStateAndAge,
    ) {
        assert_eq!(
            original_dissolve_state_and_age
                .increase_dissolve_delay(NOW, additional_dissolve_delay_seconds),
            expected_dissolve_state_and_age
        );
    }

    #[test]
    fn test_increase_dissolve_delay_for_dissolved_neurons() {
        for dissolve_state_and_age in [
            // Valid cases
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 0,
            },
        ] {
            assert_increase_dissolve_delay(
                dissolve_state_and_age,
                1,
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 1,
                    aging_since_timestamp_seconds: NOW,
                },
            );

            // Test that the dissolve delay is capped at MAX_DISSOLVE_DELAY_SECONDS.
            assert_increase_dissolve_delay(
                dissolve_state_and_age,
                MAX_DISSOLVE_DELAY_SECONDS as u32 + 1000,
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: MAX_DISSOLVE_DELAY_SECONDS,
                    aging_since_timestamp_seconds: NOW,
                },
            );
        }
    }

    #[test]
    fn test_increase_dissolve_delay_for_not_dissolving_neurons() {
        for current_aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1, NOW + 2000] {
            for current_dissolve_delay_seconds in
                [1, 10, 100, NOW, NOW + 1000, MAX_DISSOLVE_DELAY_SECONDS - 1]
            {
                assert_increase_dissolve_delay(
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: current_dissolve_delay_seconds,
                        aging_since_timestamp_seconds: current_aging_since_timestamp_seconds,
                    },
                    1,
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds: current_dissolve_delay_seconds + 1,
                        aging_since_timestamp_seconds: current_aging_since_timestamp_seconds,
                    },
                );
            }
        }

        // Test that the dissolve delay is capped at MAX_DISSOLVE_DELAY_SECONDS.
        assert_increase_dissolve_delay(
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1000,
                aging_since_timestamp_seconds: NOW,
            },
            MAX_DISSOLVE_DELAY_SECONDS as u32,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: MAX_DISSOLVE_DELAY_SECONDS,
                aging_since_timestamp_seconds: NOW,
            },
        );
    }

    #[test]
    fn test_increase_dissolve_delay_for_dissolving_neurons() {
        for when_dissolved_timestamp_seconds in
            [NOW + 1, NOW + 1000, NOW + MAX_DISSOLVE_DELAY_SECONDS - 1]
        {
            assert_increase_dissolve_delay(
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                },
                1,
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: when_dissolved_timestamp_seconds + 1,
                },
            );
        }

        // Test that the dissolve delay is capped at MAX_DISSOLVE_DELAY_SECONDS.
        assert_increase_dissolve_delay(
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1000,
            },
            MAX_DISSOLVE_DELAY_SECONDS as u32,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + MAX_DISSOLVE_DELAY_SECONDS,
            },
        );
    }

    #[test]
    fn test_start_dissolving() {
        let not_dissolving = DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 1000,
            aging_since_timestamp_seconds: NOW - 100,
        };

        let dissolving = not_dissolving.start_dissolving(NOW);

        assert_eq!(
            dissolving,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1000
            }
        );
    }

    #[test]
    fn test_start_dissolving_no_op() {
        let test_cases = vec![
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1,
            },
        ];

        for test_case in test_cases {
            // The operation should be a no-op.
            assert_eq!(test_case.start_dissolving(NOW), test_case);
        }
    }

    #[test]
    fn test_stop_dissolving() {
        let dissolving = DissolveStateAndAge::DissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW + 1000,
        };

        let not_dissolving = dissolving.stop_dissolving(NOW);

        assert_eq!(
            not_dissolving,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1000,
                aging_since_timestamp_seconds: NOW
            }
        );
    }

    #[test]
    fn test_stop_dissolving_no_op() {
        let test_cases = vec![
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1000,
                aging_since_timestamp_seconds: NOW - 100,
            },
            // Cannot stop dissolving when it's dissolved.
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
            },
        ];

        for test_case in test_cases {
            // The operation should be a no-op.
            assert_eq!(test_case.stop_dissolving(NOW), test_case);
        }
    }

    #[test]
    fn test_adjust_age() {
        let original = DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 1000,
            aging_since_timestamp_seconds: NOW - 100,
        };
        let adjusted = original.adjust_age(NOW - 200);
        assert_eq!(
            adjusted,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 1000,
                aging_since_timestamp_seconds: NOW - 200
            }
        );
    }

    #[test]
    fn test_adjust_age_no_op() {
        let test_cases = vec![
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1,
            },
        ];

        for test_case in test_cases {
            // The operation should be a no-op.
            assert_eq!(test_case.adjust_age(NOW - 100), test_case);
        }
    }
}
