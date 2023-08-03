#![allow(dead_code)] // TODO(NNS1-2409): remove when it is used by NNS Governance.

use crate::governance::KNOWN_NEURON_NAME_MAX_LEN;
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::{BoundedStorable, Memory, StableBTreeMap, Storable};

/// An index to make it easy to check whether a known neuron with the same name exists,
/// as well as listing all known neuron's ids.
/// Note that the index only cares about the uniqueness of the names, not the ids -
/// the caller should make sure the name-id is removed from the index when a neuron
/// is removed or its name is changed.

pub struct KnownNeuronIndex<M: Memory> {
    known_neuron_name_to_id: StableBTreeMap<KnownNeuronName, u64, M>,
}

#[derive(Debug)]
pub enum AddKnownNeuronError {
    AlreadyExists,
    ExceedsSizeLimit,
}

impl<M: Memory> KnownNeuronIndex<M> {
    pub fn new(memory: M) -> Self {
        Self {
            known_neuron_name_to_id: StableBTreeMap::init(memory),
        }
    }

    /// Adds a known neuron to the index. Returns whether the known neuron is added.
    /// The reason the known neuron might not gets added into the index might be that:
    /// (1) the known neuron name already exists (caller should call `contains_known_neuron_name`
    /// first)
    /// (2) the known neuron name exceeds the maximum size.
    /// In both cases, the clients should check the condition before adding to the index.
    pub fn add_known_neuron(
        &mut self,
        name: &str,
        neuron_id: NeuronId,
    ) -> Result<(), AddKnownNeuronError> {
        let known_neuron_name =
            KnownNeuronName::new(name).ok_or(AddKnownNeuronError::ExceedsSizeLimit)?;
        if self
            .known_neuron_name_to_id
            .contains_key(&known_neuron_name)
        {
            return Err(AddKnownNeuronError::AlreadyExists);
        }
        self.known_neuron_name_to_id
            .insert(known_neuron_name, neuron_id.id);
        Ok(())
    }

    /// Removes a known neuron to from index. Returns the neuron id if a neuron is removed.
    #[must_use]
    pub fn remove_known_neuron(&mut self, name: &str) -> Option<NeuronId> {
        KnownNeuronName::new(name)
            .and_then(|known_neuron_name| self.known_neuron_name_to_id.remove(&known_neuron_name))
            .map(|id| NeuronId { id })
    }

    /// Checks whether the known neuron name already exists in the index.
    pub fn contains_known_neuron_name(&self, name: &str) -> bool {
        KnownNeuronName::new(name)
            .map(|known_neuron_name| {
                self.known_neuron_name_to_id
                    .contains_key(&known_neuron_name)
            })
            .unwrap_or(false)
    }

    /// Lists all known neuron ids.
    pub fn list_known_neuron_ids(&self) -> Vec<NeuronId> {
        self.known_neuron_name_to_id
            .iter()
            .map(|(_name, id)| NeuronId { id })
            .collect()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
struct KnownNeuronName(String);

impl KnownNeuronName {
    fn new(name: &str) -> Option<Self> {
        if name.len() > KNOWN_NEURON_NAME_MAX_LEN {
            None
        } else {
            Some(Self(name.to_string()))
        }
    }
}

impl Storable for KnownNeuronName {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }
}

impl BoundedStorable for KnownNeuronName {
    const MAX_SIZE: u32 = KNOWN_NEURON_NAME_MAX_LEN as u32;
    const IS_FIXED_SIZE: bool = false;
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use ic_stable_structures::VectorMemory;

    #[test]
    fn add_single_known_neuron() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        index
            .add_known_neuron("known neuron", NeuronId { id: 1 })
            .unwrap();

        assert!(index.contains_known_neuron_name("known neuron"));
        assert!(!index.contains_known_neuron_name("another known neuron"));
        assert_eq!(index.list_known_neuron_ids(), vec![NeuronId { id: 1 }]);
    }

    #[test]
    fn add_multiple_and_remove_one_known_neuron() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        // Adds 2 known neurons.
        index
            .add_known_neuron("known neuron", NeuronId { id: 1 })
            .unwrap();
        index
            .add_known_neuron("another known neuron", NeuronId { id: 2 })
            .unwrap();

        let mut known_neuron_ids = index.list_known_neuron_ids();
        known_neuron_ids.sort();
        assert_eq!(
            known_neuron_ids,
            vec![NeuronId { id: 1 }, NeuronId { id: 2 }]
        );

        // Removes one of them.
        assert_eq!(
            index.remove_known_neuron("another known neuron"),
            Some(NeuronId { id: 2 })
        );
        assert_eq!(index.list_known_neuron_ids(), vec![NeuronId { id: 1 }]);
    }

    #[test]
    fn replace_known_neuron_name() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        // Adds one known neuron.
        index
            .add_known_neuron("known neuron", NeuronId { id: 1 })
            .unwrap();

        assert!(index.contains_known_neuron_name("known neuron"));
        assert_eq!(index.list_known_neuron_ids(), vec![NeuronId { id: 1 }]);

        // Removes old name and adds new when the neurons' name is changed.
        assert_eq!(
            index.remove_known_neuron("known neuron"),
            Some(NeuronId { id: 1 })
        );
        index
            .add_known_neuron("known neuron with another name", NeuronId { id: 1 })
            .unwrap();

        assert!(!index.contains_known_neuron_name("known neuron"));
        assert!(index.contains_known_neuron_name("known neuron with another name"));
        assert_eq!(index.list_known_neuron_ids(), vec![NeuronId { id: 1 }]);
    }

    #[test]
    fn add_known_neuron_with_max_length() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        let known_neuron_name_max_length = "a".to_string().repeat(200);
        index
            .add_known_neuron(&known_neuron_name_max_length, NeuronId { id: 1 })
            .unwrap();
        assert!(index.contains_known_neuron_name(&known_neuron_name_max_length));
    }

    #[test]
    fn add_known_neuron_fails_when_name_too_long() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        let very_long_name = "a".to_string().repeat(201);

        assert_matches!(
            index.add_known_neuron(&very_long_name, NeuronId { id: 1 }),
            Err(AddKnownNeuronError::ExceedsSizeLimit)
        );
        assert!(!index.contains_known_neuron_name(&very_long_name));
    }
}
