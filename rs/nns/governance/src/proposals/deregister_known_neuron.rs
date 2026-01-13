use crate::{
    neuron_store::NeuronStore,
    pb::v1::{
        DeregisterKnownNeuron, GovernanceError, SelfDescribingValue, governance_error::ErrorType,
    },
    proposals::self_describing::{LocallyDescribableProposalAction, ValueBuilder},
};

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

impl LocallyDescribableProposalAction for DeregisterKnownNeuron {
    const TYPE_NAME: &'static str = "Deregister Known Neuron";
    const TYPE_DESCRIPTION: &'static str = "Deregisters a known neuron, removing its known neuron \
        data (name, description, etc.) and making it a regular neuron.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        ValueBuilder::new()
            .add_field("neuron_id", self.id.map(|id| id.id))
            .build()
    }
}

#[cfg(test)]
#[path = "deregister_known_neuron_tests.rs"]
mod tests;
