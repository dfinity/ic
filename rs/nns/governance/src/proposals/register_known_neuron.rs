use crate::{
    neuron_store::NeuronStore,
    pb::v1::{GovernanceError, KnownNeuron, KnownNeuronData, governance_error::ErrorType},
    proposals::generic::LocalProposalType,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::GenericValue;
use maplit::hashmap;
use std::collections::HashSet;

use ic_nervous_system_common_validation::validate_url;

/// Maximum size in bytes for a neuron's name, in KnownNeuronData.
pub const KNOWN_NEURON_NAME_MAX_LEN: usize = 200;

/// Maximum size in bytes for the field "description" in KnownNeuronData.
pub const KNOWN_NEURON_DESCRIPTION_MAX_LEN: usize = 3000;

// Maximum number of links allowed per known neuron
const MAX_KNOWN_NEURON_LINKS: usize = 10;
// Maximum size in bytes for each link
const MAX_KNOWN_NEURON_LINK_SIZE: usize = 100;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidRegisterKnownNeuron {
    id: NeuronId,
    known_neuron_data: KnownNeuronData,
}

impl TryFrom<KnownNeuron> for ValidRegisterKnownNeuron {
    type Error = String;

    fn try_from(value: KnownNeuron) -> Result<Self, Self::Error> {
        let id = value.id.ok_or_else(|| {
            "No neuron ID specified in the request to register a known neuron.".to_string()
        })?;

        let known_neuron_data = value.known_neuron_data.ok_or_else(|| {
            "No known neuron data specified in the register neuron request.".to_string()
        })?;

        // Validate name length
        if known_neuron_data.name.is_empty() {
            return Err("The neuron's name is empty.".to_string());
        }
        if known_neuron_data.name.len() > KNOWN_NEURON_NAME_MAX_LEN {
            return Err(format!(
                "The maximum number of bytes for a neuron's name, which is {}, \
                has been exceeded. Current length: {}",
                KNOWN_NEURON_NAME_MAX_LEN,
                known_neuron_data.name.len()
            ));
        }

        // Validate description length
        if let Some(description) = &known_neuron_data.description
            && description.len() > KNOWN_NEURON_DESCRIPTION_MAX_LEN
        {
            return Err(format!(
                "The maximum number of bytes for a neuron's description, which is {}, \
                    has been exceeded. Current length: {}",
                KNOWN_NEURON_DESCRIPTION_MAX_LEN,
                description.len()
            ));
        }

        // Validate links
        if known_neuron_data.links.len() > MAX_KNOWN_NEURON_LINKS {
            return Err(format!(
                "The maximum number of links, which is {}, has been exceeded. \
                Current number of links: {}",
                MAX_KNOWN_NEURON_LINKS,
                known_neuron_data.links.len()
            ));
        }
        for (index, link) in known_neuron_data.links.iter().enumerate() {
            validate_url(link, 0, MAX_KNOWN_NEURON_LINK_SIZE, "links", None)
                .map_err(|error| format!("Link at index {index} is not valid. Error: {error}"))?;
        }

        // Validate committed_topics for duplicates
        let mut topic_set = HashSet::new();
        for (index, topic) in known_neuron_data.committed_topics.iter().enumerate() {
            if !topic_set.insert(topic) {
                return Err(format!(
                    "Duplicate topic found in committed_topics at index {}: {:?}",
                    index, topic
                ));
            }
        }

        Ok(ValidRegisterKnownNeuron {
            id,
            known_neuron_data,
        })
    }
}

impl LocalProposalType for ValidRegisterKnownNeuron {
    const TYPE_NAME: &'static str = "Register Known Neuron";
    const TYPE_DESCRIPTION: &'static str = "Assign a name and metadata to a neuron, making it a known neuron that is publicly discoverable.";

    fn to_generic_value(&self) -> GenericValue {
        let mut values = hashmap! {
            "id".to_string() => GenericValue::Text(self.id.id.to_string()),
            "name".to_string() => GenericValue::Text(self.known_neuron_data.name.clone()),
        };
        if let Some(description) = &self.known_neuron_data.description {
            values.insert(
                "description".to_string(),
                GenericValue::Text(description.clone()),
            );
        }
        if !self.known_neuron_data.links.is_empty() {
            values.insert(
                "links".to_string(),
                GenericValue::Array(
                    self.known_neuron_data
                        .links
                        .iter()
                        .map(|link| GenericValue::Text(link.clone()))
                        .collect(),
                ),
            );
        }
        if !self.known_neuron_data.committed_topics.is_empty() {
            values.insert(
                "committed_topics".to_string(),
                GenericValue::Array(
                    self.known_neuron_data
                        .committed_topics
                        .iter()
                        .map(|topic| GenericValue::Text(topic.to_string()))
                        .collect(),
                ),
            );
        }
        GenericValue::Map(values)
    }
}

impl ValidRegisterKnownNeuron {
    pub fn validate(&self, neuron_store: &NeuronStore) -> Result<(), GovernanceError> {
        // Check that the neuron exists
        if !neuron_store.contains(self.id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!("Neuron {} not found", self.id.id),
            ));
        }

        // Check that the name is not already used by another known neuron
        // Allow registration if:
        // - No existing known neuron has this name (None), OR
        // - An existing known neuron has this name but it's the same neuron ID (clobbering OK)
        if let Some(existing_neuron_id) =
            neuron_store.known_neuron_id_by_name(&self.known_neuron_data.name)
            && existing_neuron_id != self.id
        {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "The name '{}' already belongs to a different known neuron with ID {}",
                    self.known_neuron_data.name, existing_neuron_id.id
                ),
            ));
        }

        Ok(())
    }

    pub fn execute(&self, neuron_store: &mut NeuronStore) -> Result<(), GovernanceError> {
        // Validate again for safety
        self.validate(neuron_store)?;

        // Set the known neuron data
        neuron_store.with_neuron_mut(&self.id, |neuron| {
            neuron.set_known_neuron_data(self.known_neuron_data.clone())
        })?;

        Ok(())
    }
}

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

#[cfg(test)]
#[path = "register_known_neuron_tests.rs"]
mod tests;
