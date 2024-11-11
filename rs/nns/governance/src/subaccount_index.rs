use crate::{
    pb::v1::{governance_error::ErrorType, GovernanceError},
    storage::validate_stable_btree_map,
};

use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::{Memory, StableBTreeMap};
use icp_ledger::Subaccount;

#[cfg(feature = "test")]
use ic_stable_structures::btreemap::Iter as SBTIter;

/// An index to make it easy to lookup neuron id by subaccount.
pub struct NeuronSubaccountIndex<M: Memory> {
    subaccount_to_id: StableBTreeMap<[u8; 32], NeuronId, M>,
}

impl<M: Memory> NeuronSubaccountIndex<M> {
    pub fn new(memory: M) -> Self {
        Self {
            subaccount_to_id: StableBTreeMap::init(memory),
        }
    }

    /// Returns the number of entries (subaccount, neuron_id) in the index. This is for validation
    /// purpose: this should be equal to the size of the primary neuron storage since subaccount is
    /// required.
    pub fn num_entries(&self) -> usize {
        self.subaccount_to_id.len() as usize
    }

    /// Returns whether the (subaccount, neuron_id) entry exists in the index. This is for
    /// validation purpose: each such pair in the primary storage should exist in the index.
    pub fn contains_entry(&self, neuron_id: NeuronId, subaccount: &Subaccount) -> bool {
        self.subaccount_to_id
            .get(&subaccount.0)
            .map(|value| value == neuron_id)
            .unwrap_or_default()
    }

    /// Adds a neuron into the index. Returns error if the subaccount already exists
    /// in the index and the index should remain unchanged.
    pub fn add_neuron_subaccount(
        &mut self,
        neuron_id: NeuronId,
        subaccount: &Subaccount,
    ) -> Result<(), GovernanceError> {
        let previous_neuron_id = self.subaccount_to_id.insert(subaccount.0, neuron_id);
        match previous_neuron_id {
            None => Ok(()),
            Some(previous_neuron_id) => {
                self.subaccount_to_id
                    .insert(subaccount.0, previous_neuron_id);
                Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Subaccount {:?} already exists in the index", subaccount.0),
                ))
            }
        }
    }

    /// Removes a neuron from the index. Returns error if the neuron_id removed from the index is
    /// unexpected, and the index should remain unchanged if that happens.
    pub fn remove_neuron_subaccount(
        &mut self,
        neuron_id: NeuronId,
        subaccount: &Subaccount,
    ) -> Result<(), GovernanceError> {
        let previous_neuron_id = self.subaccount_to_id.remove(&subaccount.0);

        match previous_neuron_id {
            Some(previous_neuron_id) => {
                if previous_neuron_id == neuron_id {
                    Ok(())
                } else {
                    self.subaccount_to_id
                        .insert(subaccount.0, previous_neuron_id);
                    Err(GovernanceError::new_with_message(
                        ErrorType::PreconditionFailed,
                        format!(
                            "Subaccount {:?} exists in the index with a different neuron id {}",
                            subaccount.0, previous_neuron_id.id
                        ),
                    ))
                }
            }
            None => Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Subaccount {:?} already absent in the index", subaccount.0),
            )),
        }
    }

    /// Finds the neuron id by subaccount if it exists.
    pub fn get_neuron_id_by_subaccount(&self, subaccount: &Subaccount) -> Option<NeuronId> {
        self.subaccount_to_id.get(&subaccount.0)
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    pub fn validate(&self) {
        validate_stable_btree_map(&self.subaccount_to_id);
    }

    #[cfg(feature = "test")]
    pub fn iter(&self) -> SBTIter<[u8; 32], NeuronId, M> {
        self.subaccount_to_id.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use ic_stable_structures::VectorMemory;

    #[test]
    fn add_single_neuron() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        assert!(index
            .add_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());

        assert_eq!(
            index.get_neuron_id_by_subaccount(&Subaccount([1u8; 32])),
            Some(NeuronId { id: 1 })
        );
    }

    #[test]
    fn add_and_remove_neuron() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        assert!(index
            .add_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());
        assert!(index
            .remove_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());

        assert_eq!(
            index.get_neuron_id_by_subaccount(&Subaccount([1u8; 32])),
            None
        );
    }

    #[test]
    fn add_neuron_with_same_subaccount_fails() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        assert!(index
            .add_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());
        assert_matches!(
            index.add_neuron_subaccount(NeuronId { id: 2 }, &Subaccount([1u8; 32])),
            Err(GovernanceError{error_type, error_message: message})
                if error_type == ErrorType::PreconditionFailed as i32 && message.contains("already exists in the index")
        );

        // The index should still have the first neuron.
        assert_eq!(
            index.get_neuron_id_by_subaccount(&Subaccount([1u8; 32])),
            Some(NeuronId { id: 1 })
        );
    }

    #[test]
    fn remove_neuron_already_absent_fails() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        // The index is empty so remove should fail.
        assert_matches!(
            index.remove_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32])),
            Err(GovernanceError{error_type, error_message: message})
                if error_type == ErrorType::PreconditionFailed as i32 && message.contains("already absent in the index")
        );
    }

    #[test]
    fn remove_neuron_with_wrong_neuron_id_fails() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        assert!(index
            .add_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());
        assert_matches!(
            index.remove_neuron_subaccount(NeuronId { id: 2 }, &Subaccount([1u8; 32])),
            Err(GovernanceError{error_type, error_message: message})
                if error_type == ErrorType::PreconditionFailed as i32 && message.contains("exists in the index with a different neuron id")
        );

        // The index should still have the first neuron.
        assert_eq!(
            index.get_neuron_id_by_subaccount(&Subaccount([1u8; 32])),
            Some(NeuronId { id: 1 })
        );
    }

    #[test]
    fn add_multiple_neurons() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        assert!(index
            .add_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());
        assert!(index
            .add_neuron_subaccount(NeuronId { id: 2 }, &Subaccount([2u8; 32]))
            .is_ok());

        assert_eq!(
            index.get_neuron_id_by_subaccount(&Subaccount([1u8; 32])),
            Some(NeuronId { id: 1 })
        );
        assert_eq!(
            index.get_neuron_id_by_subaccount(&Subaccount([2u8; 32])),
            Some(NeuronId { id: 2 })
        );
    }

    #[test]
    fn index_num_entries() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        assert_eq!(index.num_entries(), 0);

        assert!(index
            .add_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());

        assert_eq!(index.num_entries(), 1);
    }

    #[test]
    fn index_contains() {
        let mut index = NeuronSubaccountIndex::new(VectorMemory::default());

        assert!(index
            .add_neuron_subaccount(NeuronId { id: 1 }, &Subaccount([1u8; 32]))
            .is_ok());

        assert!(index.contains_entry(NeuronId { id: 1 }, &Subaccount([1u8; 32])));
    }
}
