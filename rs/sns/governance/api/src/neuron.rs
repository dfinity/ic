use crate::pb::v1::{governance_error::ErrorType, neuron::DissolveState, GovernanceError, Neuron};
use crate::types::Subaccount;

impl Neuron {
    pub fn stake_e8s(&self) -> u64 {
        self.cached_neuron_stake_e8s
            .saturating_sub(self.neuron_fees_e8s)
    }

    pub fn subaccount(&self) -> Result<Subaccount, GovernanceError> {
        if let Some(nid) = &self.id {
            nid.subaccount()
        } else {
            Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                "Neuron must have a subaccount",
            ))
        }
    }

    pub fn age_seconds(&self, now_seconds: u64) -> u64 {
        now_seconds.saturating_sub(self.aging_since_timestamp_seconds)
    }

    pub fn state(&self, now_seconds: u64) -> NeuronState {
        match self.dissolve_state {
            Some(DissolveState::DissolveDelaySeconds(d)) => {
                if d > 0 {
                    NeuronState::NotDissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            Some(DissolveState::WhenDissolvedTimestampSeconds(ts)) => {
                if ts > now_seconds {
                    NeuronState::Dissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            None => NeuronState::Dissolved,
        }
    }
}

/// The state of a neuron
#[derive(Eq, PartialEq, Debug)]
pub enum NeuronState {
    /// In this state, the neuron is not dissolving and has a specific
    /// `dissolve_delay` that is larger than zero.
    NotDissolving,
    /// In this state, the neuron's dissolve clock is running down with
    /// the passage of time. The neuron has a defined
    /// `when_dissolved_timestamp` that specifies at what time (in the
    /// future) it will be dissolved.
    Dissolving,
    /// In this state, the neuron is dissolved and can be disbursed.
    /// This captures all the remaining cases. In particular a neuron
    /// is dissolved if its `when_dissolved_timestamp` is in the past
    /// or when its `dissolve_delay` is zero.
    Dissolved,
}
