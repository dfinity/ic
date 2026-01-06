use crate::{
    neuron_store::NeuronStore,
    pb::v1::{
        GovernanceError, KnownNeuron, KnownNeuronData, SelfDescribingValue, Topic,
        governance_error::ErrorType,
    },
    proposals::self_describing::{
        LocallyDescribableProposalAction, SelfDescribingProstEnum, ValueBuilder,
    },
};

use ic_nervous_system_common_validation::validate_url;
use std::collections::HashSet;

/// Maximum size in bytes for a neuron's name, in KnownNeuronData.
pub const KNOWN_NEURON_NAME_MAX_LEN: usize = 200;

/// Maximum size in bytes for the field "description" in KnownNeuronData.
pub const KNOWN_NEURON_DESCRIPTION_MAX_LEN: usize = 3000;

// Maximum number of links allowed per known neuron
const MAX_KNOWN_NEURON_LINKS: usize = 10;
// Maximum size in bytes for each link
const MAX_KNOWN_NEURON_LINK_SIZE: usize = 100;

impl KnownNeuron {
    /// Validates the register known neuron request.
    ///
    /// Preconditions:
    ///  - A Neuron ID is given in the request and this ID identifies an existing neuron.
    ///  - Known Neuron Data is specified in the request.
    ///  - Name is not empty and is at most of length KNOWN_NEURON_NAME_MAX_LEN.
    ///  - Description, if present, is at most of length KNOWN_NEURON_DESCRIPTION_MAX_LEN.
    ///  - Name is not already used in another known neuron.
    ///  - Links array has at most MAX_KNOWN_NEURON_LINKS entries.
    ///  - Each link is a valid URL and at most MAX_KNOWN_NEURON_LINK_SIZE bytes.
    ///  - Committed_topics array contains no duplicate topics.
    pub fn validate(&self, neuron_store: &NeuronStore) -> Result<(), GovernanceError> {
        let neuron_id = self.id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "No neuron ID specified in the request to register a known neuron.",
            )
        })?;

        // Check that the neuron exists
        if !neuron_store.contains(neuron_id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Neuron {} not found", neuron_id.id),
            ));
        }

        let known_neuron_data = self.known_neuron_data.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "No known neuron data specified in the register neuron request.",
            )
        })?;

        // Validate name length
        if known_neuron_data.name.is_empty() {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "The neuron's name is empty.",
            ));
        }
        if known_neuron_data.name.len() > KNOWN_NEURON_NAME_MAX_LEN {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "The maximum number of bytes for a neuron's name, which is {}, \
                    has been exceeded. Current length: {}",
                    KNOWN_NEURON_NAME_MAX_LEN,
                    known_neuron_data.name.len()
                ),
            ));
        }

        // Validate description length
        if let Some(description) = &known_neuron_data.description
            && description.len() > KNOWN_NEURON_DESCRIPTION_MAX_LEN
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "The maximum number of bytes for a neuron's description, which is {}, \
                        has been exceeded. Current length: {}",
                    KNOWN_NEURON_DESCRIPTION_MAX_LEN,
                    description.len()
                ),
            ));
        }

        // Validate links
        if known_neuron_data.links.len() > MAX_KNOWN_NEURON_LINKS {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "The maximum number of links, which is {}, has been exceeded. \
                    Current number of links: {}",
                    MAX_KNOWN_NEURON_LINKS,
                    known_neuron_data.links.len()
                ),
            ));
        }
        for (index, link) in known_neuron_data.links.iter().enumerate() {
            validate_url(link, 0, MAX_KNOWN_NEURON_LINK_SIZE, "links", None).map_err(|error| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!("Link at index {index} is not valid. Error: {error}"),
                )
            })?;
        }

        // Validate committed_topics for duplicates
        let mut topic_set = HashSet::new();
        for (index, topic) in known_neuron_data.committed_topics.iter().enumerate() {
            if !topic_set.insert(topic) {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!(
                        "Duplicate topic found in committed_topics at index {}: {:?}",
                        index, topic
                    ),
                ));
            }
        }

        // Check that the name is not already used by another known neuron
        // Allow registration if:
        // - No existing known neuron has this name (None), OR
        // - An existing known neuron has this name but it's the same neuron ID (clobbering OK)
        if let Some(existing_neuron_id) =
            neuron_store.known_neuron_id_by_name(&known_neuron_data.name)
            && existing_neuron_id != neuron_id
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "The name '{}' already belongs to a different known neuron with ID {}",
                    known_neuron_data.name, existing_neuron_id.id
                ),
            ));
        }

        Ok(())
    }

    /// Executes the register known neuron action.
    ///
    /// This method adds the known neuron data (name, description, and links) to the neuron,
    /// making it a known neuron. The validation is performed again during execution for safety.
    pub fn execute(&self, neuron_store: &mut NeuronStore) -> Result<(), GovernanceError> {
        // Validate again for safety
        self.validate(neuron_store)?;

        let neuron_id = self.id.ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "No neuron ID specified in the request to register a known neuron.",
            )
        })?;

        let known_neuron_data = self.known_neuron_data.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "No known neuron data specified in the register neuron request.",
            )
        })?;

        // Set the known neuron data
        neuron_store.with_neuron_mut(&neuron_id, |neuron| {
            neuron.set_known_neuron_data(known_neuron_data.clone())
        })?;

        Ok(())
    }
}

impl LocallyDescribableProposalAction for KnownNeuron {
    const TYPE_NAME: &'static str = "Register Known Neuron";
    const TYPE_DESCRIPTION: &'static str = "Registers a neuron as a known neuron. This allows the \
        neuron to be looked up by name and displayed more prominently in the NNS UI.";

    fn to_self_describing_value(&self) -> SelfDescribingValue {
        ValueBuilder::new()
            .add_field("neuron_id", self.id.map(|id| id.id))
            .add_field("known_neuron_data", self.known_neuron_data.clone())
            .build()
    }
}

impl From<KnownNeuronData> for SelfDescribingValue {
    fn from(data: KnownNeuronData) -> Self {
        let KnownNeuronData {
            name,
            description,
            links,
            committed_topics,
        } = data;

        let committed_topics: Vec<_> = committed_topics
            .into_iter()
            .map(SelfDescribingProstEnum::<Topic>::new)
            .collect();

        ValueBuilder::new()
            .add_field("name", name)
            .add_field("description", description)
            .add_field("links", links)
            .add_field("committed_topics", committed_topics)
            .build()
    }
}

#[cfg(test)]
#[path = "register_known_neuron_tests.rs"]
mod tests;
