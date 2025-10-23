use crate::{
    neuron_store::NeuronStore,
    pb::v1::{DeregisterKnownNeuron, GovernanceError, governance_error::ErrorType},
    proposals::generic::LocalProposalType,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::GenericValue;
use maplit::hashmap;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidDeregisterKnownNeuron {
    id: NeuronId,
}

impl TryFrom<DeregisterKnownNeuron> for ValidDeregisterKnownNeuron {
    type Error = String;

    fn try_from(value: DeregisterKnownNeuron) -> Result<Self, Self::Error> {
        let id = value.id.ok_or_else(|| {
            "No neuron ID specified in the request to deregister a known neuron.".to_string()
        })?;

        Ok(ValidDeregisterKnownNeuron { id })
    }
}

impl LocalProposalType for ValidDeregisterKnownNeuron {
    const TYPE_NAME: &'static str = "Deregister Known Neuron";
    const TYPE_DESCRIPTION: &'static str =
        "Remove the name and metadata from a known neuron, making it a regular neuron again.";

    fn to_generic_value(&self) -> GenericValue {
        GenericValue::Map(hashmap! {
            "id".to_string() => GenericValue::Text(self.id.id.to_string()),
        })
    }
}

impl ValidDeregisterKnownNeuron {
    pub fn validate(&self, neuron_store: &NeuronStore) -> Result<(), GovernanceError> {
        // Check if the neuron has known neuron data
        let is_known_neuron =
            neuron_store.with_neuron(&self.id, |neuron| neuron.known_neuron_data().is_some())?;

        if !is_known_neuron {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Neuron {} is not a known neuron", self.id.id),
            ));
        }

        Ok(())
    }

    pub fn execute(&self, neuron_store: &mut NeuronStore) -> Result<(), GovernanceError> {
        // Remove the known neuron data
        neuron_store.with_neuron_mut(&self.id, |neuron| neuron.clear_known_neuron_data())?;

        Ok(())
    }
}

impl DeregisterKnownNeuron {
    /// Validates the deregister known neuron request.
    ///
    /// Preconditions:
    ///  - A Neuron ID is given in the request and this ID identifies an existing neuron.
    ///  - The neuron currently has known neuron data to be removed.
    pub fn validate(&self, neuron_store: &NeuronStore) -> Result<(), GovernanceError> {
        let neuron_id = self.id.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "No neuron ID specified in the request to deregister a known neuron.",
            )
        })?;

        // Check if the neuron has known neuron data
        let is_known_neuron =
            neuron_store.with_neuron(neuron_id, |neuron| neuron.known_neuron_data().is_some())?;

        if !is_known_neuron {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Neuron {} is not a known neuron", neuron_id.id),
            ));
        }

        Ok(())
    }

    /// Executes the deregister known neuron action.
    ///
    /// This method removes the known neuron data (name and description) from the neuron,
    /// making it a regular neuron again.
    pub fn execute(&self, neuron_store: &mut NeuronStore) -> Result<(), GovernanceError> {
        let neuron_id = self.id.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "No neuron ID specified in the request to deregister a known neuron.",
            )
        })?;

        // Remove the known neuron data
        neuron_store.with_neuron_mut(neuron_id, |neuron| neuron.clear_known_neuron_data())?;

        Ok(())
    }
}

#[cfg(test)]
#[path = "deregister_known_neuron_tests.rs"]
mod tests;
