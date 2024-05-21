use crate::{
    governance::MAX_DISSOLVE_DELAY_SECONDS,
    pb::v1::{audit_event::NeuronLegacyCase, NeuronState},
};

/// An enum to represent different combinations of a neurons dissolve_state and
/// aging_since_timestamp_seconds. Currently, the back-and-forth conversions should make sure the
/// legacy states remain the same unless some operations performed on the neuron makes the state/age
/// changes. After we make sure all neuron mutations or creations must mutate states to valid ones
/// and the invalid states have been migrated to valid ones on the mainnet, we can panic in
/// conversion when invalid states are encountered. 2 of the legacy states
/// (LegacyDissolvingOrDissolved and LegacyDissolved) are the cases we already know to be existing
/// on the mainnet.
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

impl DissolveStateAndAge {
    /// Returns true if the neuron is in a legacy state.
    pub fn is_legacy(self) -> bool {
        match self {
            Self::NotDissolving { .. } | Self::DissolvingOrDissolved { .. } => false,
            Self::LegacyDissolvingOrDissolved { .. }
            | Self::LegacyDissolved { .. }
            | Self::LegacyNoneDissolveState { .. } => true,
        }
    }

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
            DissolveStateAndAge::LegacyDissolved { .. } => NeuronState::Dissolved,
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds: _,
            } => {
                if now_seconds >= when_dissolved_timestamp_seconds {
                    NeuronState::Dissolved
                } else {
                    NeuronState::Dissolving
                }
            }
            DissolveStateAndAge::LegacyNoneDissolveState { .. } => NeuronState::Dissolved,
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
            Self::LegacyDissolvingOrDissolved {
                aging_since_timestamp_seconds,
                ..
            } => now_seconds.saturating_sub(aging_since_timestamp_seconds),
            Self::LegacyDissolved {
                aging_since_timestamp_seconds,
                ..
            } => now_seconds.saturating_sub(aging_since_timestamp_seconds),
            Self::LegacyNoneDissolveState {
                aging_since_timestamp_seconds,
            } => now_seconds.saturating_sub(aging_since_timestamp_seconds),
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
            Self::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                ..
            } => when_dissolved_timestamp_seconds.saturating_sub(now_seconds),
            // The below cases are considered dissolved, so the dissolve delay is 0.
            Self::LegacyDissolved { .. } => 0,
            Self::LegacyNoneDissolveState { .. } => 0,
        }
    }

    /// Returns the timestamp when the neuron will be dissolved. If the neuron is not dissolving, it
    /// returns None. Note that when self == LegacyDissolved {..}, even though the Neuron is
    /// dissolved, we do not know when that happened. This tends to happen when Neurons are first
    /// created. We will clean up this case soon.
    pub fn dissolved_at_timestamp_seconds(self) -> Option<u64> {
        match self {
            Self::NotDissolving { .. } => None,
            Self::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => Some(when_dissolved_timestamp_seconds),
            Self::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                ..
            } => Some(when_dissolved_timestamp_seconds),
            // The dissolved neurons in this case have DissolveDelaySeconds(0), which are created
            // when the neurons are first claimed. We don't know exactly when they are dissolved
            // from their dissolve state.
            Self::LegacyDissolved { .. } => None,
            Self::LegacyNoneDissolveState { .. } => None,
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
            } => Self::increase_dissolve_delay_for_dissolving_or_dissolved(
                when_dissolved_timestamp_seconds,
                now_seconds,
                additional_dissolve_delay_seconds,
            ),
            // In the legacy case where we still have an aging_since_timestamp_seconds for
            // dissolving neurons, we transition them into a valid case, and its original
            // aging_since_timestamp_seconds is ignored.
            Self::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds: _,
            } => Self::increase_dissolve_delay_for_dissolving_or_dissolved(
                when_dissolved_timestamp_seconds,
                now_seconds,
                additional_dissolve_delay_seconds,
            ),
            Self::LegacyDissolved {
                aging_since_timestamp_seconds: _,
            } => {
                let dissolve_delay_seconds = std::cmp::min(
                    additional_dissolve_delay_seconds,
                    MAX_DISSOLVE_DELAY_SECONDS,
                );
                // We transition from `Dissolved` to `NotDissolving`: reset age.
                Self::NotDissolving {
                    dissolve_delay_seconds,
                    aging_since_timestamp_seconds: now_seconds,
                }
            }
            Self::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: _,
            } => {
                let dissolve_delay_seconds = std::cmp::min(
                    additional_dissolve_delay_seconds,
                    MAX_DISSOLVE_DELAY_SECONDS,
                );
                // We transition from `Dissolved` to `NotDissolving`: reset age.
                Self::NotDissolving {
                    dissolve_delay_seconds,
                    aging_since_timestamp_seconds: now_seconds,
                }
            }
        }
    }

    /// Helper function to make sure legacy dissolving/dissolved case is handled exactly the same as
    /// the non-legacy case.
    fn increase_dissolve_delay_for_dissolving_or_dissolved(
        when_dissolved_timestamp_seconds: u64,
        now_seconds: u64,
        additional_dissolve_delay_seconds: u64,
    ) -> Self {
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
            Self::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds: _,
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
            // Restores the invariant - dissolving/dissolved neurons should not have an age.
            Self::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds: _,
            } => Self::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            },
            // We could have restored the invariant here, but we try to keep the previous behavior,
            // and clean up the legacy cases soon.
            Self::LegacyDissolved {
                aging_since_timestamp_seconds: _,
            } => Self::LegacyDissolved {
                aging_since_timestamp_seconds: new_aging_since_timestamp_seconds,
            },
            Self::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: _,
            } => Self::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: new_aging_since_timestamp_seconds,
            },
        }
    }

    /// Returns the normalized neuron dissolve state and age. If the neuron is in a legacy state, it
    /// returns the valid state, as well as the audit event log for logging purposes. Otherwise it
    /// returns the existing state and None.
    pub fn normalize(self, created_timestamp_seconds: u64) -> Option<(Self, NeuronLegacyCase)> {
        match self {
            Self::NotDissolving { .. } | Self::DissolvingOrDissolved { .. } => None,

            Self::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds: _,
            } => Some((
                Self::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                },
                NeuronLegacyCase::DissolvingOrDissolved,
            )),

            Self::LegacyDissolved { .. } => Some((
                Self::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: created_timestamp_seconds,
                },
                NeuronLegacyCase::Dissolved,
            )),

            // This case should be impossible, but treating it the same way as LegacyDissolved is
            // also reasonable.
            Self::LegacyNoneDissolveState { .. } => Some((
                Self::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: created_timestamp_seconds,
                },
                NeuronLegacyCase::NoneDissolveState,
            )),
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
            assert_current_state(
                DissolveStateAndAge::LegacyDissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                    aging_since_timestamp_seconds: NOW,
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
            assert_current_state(
                DissolveStateAndAge::LegacyDissolvingOrDissolved {
                    when_dissolved_timestamp_seconds,
                    aging_since_timestamp_seconds: NOW,
                },
                NeuronState::Dissolving,
            );
        }
        assert_current_state(
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds: NOW,
            },
            NeuronState::Dissolved,
        );
        assert_current_state(
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: NOW,
            },
            NeuronState::Dissolved,
        );
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

    // TODO(NNS1-2951): clean up when the legacy cases are removed.
    #[test]
    fn test_dissolve_delay_seconds_legacy_dissolving_or_dissolved() {
        for (when_dissolved_timestamp_seconds, expected_dissolve_delay_seconds) in [
            (0, 0),
            (NOW - 1, 0),
            (NOW, 0),
            (NOW + 1, 1),
            (NOW + 100, 100),
        ] {
            // The aging_since_timestamp_seconds is ignored in the dissolve delay calculation.
            for aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1] {
                assert_dissolve_delay_seconds(
                    DissolveStateAndAge::LegacyDissolvingOrDissolved {
                        when_dissolved_timestamp_seconds,
                        aging_since_timestamp_seconds,
                    },
                    expected_dissolve_delay_seconds,
                );
            }
        }
    }

    // TODO(NNS1-2951): clean up when the legacy cases are removed.
    #[test]
    fn test_dissolve_delay_seconds_legacy_dissolved() {
        for aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1] {
            assert_dissolve_delay_seconds(
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds,
                },
                0,
            );
        }
    }

    // TODO(NNS1-2951): clean up when the legacy cases are removed.
    #[test]
    fn test_dissolve_delay_seconds_legacy_none_dissolve_state() {
        for aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1] {
            assert_dissolve_delay_seconds(
                DissolveStateAndAge::LegacyNoneDissolveState {
                    aging_since_timestamp_seconds,
                },
                0,
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

    // TODO(NNS1-2951): clean up when the legacy cases are removed.
    #[test]
    fn test_age_seconds_legacy_cases() {
        for (aging_since_timestamp_seconds, expected_age_seconds) in
            [(0, NOW), (NOW - 1, 1), (NOW, 0), (NOW + 1, 0)]
        {
            // The dissolve timestamp does not matter for calculating the age.
            for when_dissolved_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1] {
                assert_age_seconds(
                    DissolveStateAndAge::LegacyDissolvingOrDissolved {
                        when_dissolved_timestamp_seconds,
                        aging_since_timestamp_seconds,
                    },
                    expected_age_seconds,
                );
            }

            assert_age_seconds(
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds,
                },
                expected_age_seconds,
            );

            assert_age_seconds(
                DissolveStateAndAge::LegacyNoneDissolveState {
                    aging_since_timestamp_seconds,
                },
                expected_age_seconds,
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
            // TODO(NNS1-2951): clean up when the legacy cases are removed.
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW,
                aging_since_timestamp_seconds: 0,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
                aging_since_timestamp_seconds: 0,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 0,
                aging_since_timestamp_seconds: 0,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW,
                aging_since_timestamp_seconds: NOW + 100,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
                aging_since_timestamp_seconds: NOW + 100,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: 0,
                aging_since_timestamp_seconds: NOW + 100,
            },
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds: 0,
            },
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds: NOW - 100,
            },
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds: NOW + 100,
            },
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: 0,
            },
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: NOW - 100,
            },
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: NOW + 100,
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

            // TODO(NNS1-2951): clean up when the legacy cases are removed.
            for aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1, NOW + 2000] {
                assert_increase_dissolve_delay(
                    DissolveStateAndAge::LegacyDissolvingOrDissolved {
                        when_dissolved_timestamp_seconds,
                        aging_since_timestamp_seconds,
                    },
                    1,
                    DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds: when_dissolved_timestamp_seconds + 1,
                    },
                );
            }
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

        // TODO(NNS1-2951): clean up when the legacy cases are removed.
        for aging_since_timestamp_seconds in [0, NOW - 1, NOW, NOW + 1, NOW + 2000] {
            assert_increase_dissolve_delay(
                DissolveStateAndAge::LegacyDissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: NOW + 1000,
                    aging_since_timestamp_seconds,
                },
                MAX_DISSOLVE_DELAY_SECONDS as u32,
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: NOW + MAX_DISSOLVE_DELAY_SECONDS,
                },
            );
        }
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
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
                aging_since_timestamp_seconds: NOW - 1000,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1,
                aging_since_timestamp_seconds: NOW - 1000,
            },
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds: NOW - 1000,
            },
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: NOW - 1000,
            },
        ];

        for test_case in test_cases {
            // The operation should be a no-op.
            assert_eq!(test_case.start_dissolving(NOW), test_case);
        }
    }

    #[test]
    fn test_stop_dissolving() {
        let dissolving_cases = vec![
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1000,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1000,
                aging_since_timestamp_seconds: NOW - 1000,
            },
        ];

        for dissolving in dissolving_cases {
            let not_dissolving = dissolving.stop_dissolving(NOW);

            assert_eq!(
                not_dissolving,
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 1000,
                    aging_since_timestamp_seconds: NOW
                }
            );
        }
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
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW - 1,
                aging_since_timestamp_seconds: NOW - 1000,
            },
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds: NOW - 1000,
            },
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds: NOW - 1000,
            },
        ];

        for test_case in test_cases {
            // The operation should be a no-op.
            assert_eq!(test_case.stop_dissolving(NOW), test_case);
        }
    }

    #[test]
    fn test_adjust_age() {
        let test_cases = vec![
            (
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 1000,
                    aging_since_timestamp_seconds: NOW - 100,
                },
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 1000,
                    aging_since_timestamp_seconds: NOW - 200,
                },
            ),
            // Ideally we don't want to allow having age for neurons that are considered dissolved,
            // but we keep the existing behavior, and will rely on migration to clean up the legacy
            // states.
            (
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds: NOW - 100,
                },
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds: NOW - 200,
                },
            ),
            (
                DissolveStateAndAge::LegacyNoneDissolveState {
                    aging_since_timestamp_seconds: NOW - 100,
                },
                DissolveStateAndAge::LegacyNoneDissolveState {
                    aging_since_timestamp_seconds: NOW - 200,
                },
            ),
        ];

        for (original, expected) in test_cases {
            let adjusted = original.adjust_age(NOW - 200);

            assert_eq!(adjusted, expected);
        }
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

    #[test]
    fn test_adjust_age_restore_invariant() {
        let dissolving = DissolveStateAndAge::LegacyDissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW + 1000,
            aging_since_timestamp_seconds: NOW - 1000,
        };

        let adjusted_dissolving = dissolving.adjust_age(NOW - 200);

        assert_eq!(
            adjusted_dissolving,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1000
            }
        );
    }

    #[test]
    fn test_normalize() {
        let created_timestamp_seconds = 123_456_789;

        {
            let normal_cases = vec![
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 1000,
                    aging_since_timestamp_seconds: NOW - 100,
                },
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: NOW + 1000,
                },
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: NOW - 1000,
                },
            ];
            for normal_case in normal_cases {
                assert_eq!(normal_case.normalize(created_timestamp_seconds), None);
            }
        }

        // In the legacy dissolving/dissolved case, we remove the age bonus.
        let legacy_dissolving_or_dissolved = DissolveStateAndAge::LegacyDissolvingOrDissolved {
            when_dissolved_timestamp_seconds: NOW + 1000,
            aging_since_timestamp_seconds: NOW - 1000,
        };
        let (normalized, legacy_case) = legacy_dissolving_or_dissolved
            .normalize(created_timestamp_seconds)
            .unwrap();
        assert_eq!(
            normalized,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: NOW + 1000
            }
        );
        assert_eq!(legacy_case, NeuronLegacyCase::DissolvingOrDissolved);

        // In the legacy dissolved case, we normalize it to dissolving/dissolved case while setting
        // the dissolved timestamp to the creation timestamp.
        let legacy_dissolved = DissolveStateAndAge::LegacyDissolved {
            aging_since_timestamp_seconds: NOW - 1000,
        };
        let (normalized, legacy_case) = legacy_dissolved
            .normalize(created_timestamp_seconds)
            .unwrap();
        assert_eq!(
            normalized,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: created_timestamp_seconds
            }
        );
        assert_eq!(legacy_case, NeuronLegacyCase::Dissolved);

        // In the legacy none-dissolve state case, we normalize it to dissolving/dissolved case while setting
        // the dissolved timestamp to the creation timestamp.
        let legacy_none_dissolve_state = DissolveStateAndAge::LegacyNoneDissolveState {
            aging_since_timestamp_seconds: NOW - 1000,
        };
        let (normalized, legacy_case) = legacy_none_dissolve_state
            .normalize(created_timestamp_seconds)
            .unwrap();
        assert_eq!(
            normalized,
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds: created_timestamp_seconds
            }
        );
        assert_eq!(legacy_case, NeuronLegacyCase::NoneDissolveState);
    }
}
