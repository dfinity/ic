use crate::{governance::KNOWN_NEURON_NAME_MAX_LEN, storage::validate_stable_btree_map};
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{Memory, StableBTreeMap, Storable};

/// An index to make it easy to check whether a known neuron with the same name exists,
/// as well as listing all known neuron's ids.
/// Note that the index only cares about the uniqueness of the names, not the ids -
/// the caller should make sure the name-id is removed from the index when a neuron
/// is removed or its name is changed.

pub struct KnownNeuronIndex<M: Memory> {
    known_neuron_name_to_id: StableBTreeMap<KnownNeuronName, NeuronId, M>,
}

#[derive(Debug)]
pub enum AddKnownNeuronError {
    AlreadyExists,
    ExceedsSizeLimit,
}

#[derive(Debug)]
pub enum RemoveKnownNeuronError {
    AlreadyAbsent,
    NameExistsWithDifferentNeuronId(NeuronId),
}

impl<M: Memory> KnownNeuronIndex<M> {
    pub fn new(memory: M) -> Self {
        Self {
            known_neuron_name_to_id: StableBTreeMap::init(memory),
        }
    }

    /// Returns the number of entries (known_neuron_name, neuron_id) in the index. This is for
    /// validation purpose: this should be equal to the known_neuron_data collection in the primary
    /// storage.
    pub fn num_entries(&self) -> usize {
        self.known_neuron_name_to_id.len() as usize
    }

    /// Returns whether the (known_neuron_name, neuron_id) entry exists in the index. This is for
    /// validation purpose: each such pair in the primary storage should exist in the index.
    pub fn contains_entry(&self, neuron_id: NeuronId, known_neuron_name: &str) -> bool {
        KnownNeuronName::new(known_neuron_name)
            .and_then(|known_neuron_name| self.known_neuron_name_to_id.get(&known_neuron_name))
            .map(|known_neuron_id| known_neuron_id == neuron_id)
            .unwrap_or_default()
    }

    /// Adds a known neuron to the index. Returns error if nothing is added.
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
            .insert(known_neuron_name, neuron_id);
        Ok(())
    }

    /// Removes a known neuron to from index. Returns error when nothing is removed. Possible
    /// errors: (1) NameExistsWithDifferentNeuronId if (name, other_neuron_id) exists for another
    /// neuron (2) AlreadyAbsent if no entry with given known neuron name exists.
    pub fn remove_known_neuron(
        &mut self,
        name: &str,
        neuron_id: NeuronId,
    ) -> Result<(), RemoveKnownNeuronError> {
        let known_neuron_name = KnownNeuronName::new(name);
        let known_neuron_name = match known_neuron_name {
            Some(known_neuron_name) => known_neuron_name,
            // Exceeding limit means it cannot exist in the index.
            None => return Err(RemoveKnownNeuronError::AlreadyAbsent),
        };

        let removed_neuron_id = self.known_neuron_name_to_id.remove(&known_neuron_name);

        match removed_neuron_id {
            None => Err(RemoveKnownNeuronError::AlreadyAbsent),
            Some(removed_neuron_id) => {
                if removed_neuron_id == neuron_id {
                    Ok(())
                } else {
                    // The removed known neuron id does not match the given neuron id. There is
                    // probably some inconsistencies between the index and primary data. Insert the
                    // original value back and return error.
                    self.known_neuron_name_to_id
                        .insert(known_neuron_name, removed_neuron_id);
                    Err(RemoveKnownNeuronError::NameExistsWithDifferentNeuronId(
                        removed_neuron_id,
                    ))
                }
            }
        }
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
            .map(|(_name, neuron_id)| neuron_id)
            .collect()
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    pub fn validate(&self) {
        validate_stable_btree_map(&self.known_neuron_name_to_id);
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
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

    const BOUND: Bound = Bound::Bounded {
        max_size: KNOWN_NEURON_NAME_MAX_LEN as u32,
        is_fixed_size: false,
    };
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
        index
            .remove_known_neuron("another known neuron", NeuronId { id: 2 })
            .unwrap();
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
        index
            .remove_known_neuron("known neuron", NeuronId { id: 1 })
            .unwrap();

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

    #[test]
    fn remove_known_neuron_fails_different_neuron() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());
        index
            .add_known_neuron("known neuron", NeuronId { id: 1 })
            .unwrap();
        assert!(index.contains_known_neuron_name("known neuron"));

        assert_matches!(
            index.remove_known_neuron("known neuron", NeuronId { id: 2 }),
            Err(RemoveKnownNeuronError::NameExistsWithDifferentNeuronId(neuron_id))
            if neuron_id.id == 1
        );

        // After attempting to remove known neuron with the wrong id, the original entry still
        // exists.
        assert!(index.contains_known_neuron_name("known neuron"));
        assert_eq!(index.list_known_neuron_ids(), vec![NeuronId { id: 1 }]);
    }

    #[test]
    fn remove_known_neuron_fails_name_does_not_exist() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        assert_matches!(
            index.remove_known_neuron("known neuron", NeuronId { id: 1 }),
            Err(RemoveKnownNeuronError::AlreadyAbsent)
        );
    }

    #[test]
    fn index_len() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        assert_eq!(index.num_entries(), 0);

        index
            .add_known_neuron("known neuron", NeuronId { id: 1 })
            .unwrap();

        assert_eq!(index.num_entries(), 1);
    }

    #[test]
    fn index_contains_entry() {
        let mut index = KnownNeuronIndex::new(VectorMemory::default());

        index
            .add_known_neuron("known neuron", NeuronId { id: 1 })
            .unwrap();

        assert!(index.contains_entry(NeuronId { id: 1 }, "known neuron"));
    }
}
