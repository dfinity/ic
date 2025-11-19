use crate::{
    account_id_index::NeuronAccountIdIndex,
    pb::v1::{GovernanceError, governance_error::ErrorType},
};
use assert_matches::assert_matches;
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::VectorMemory;
use icp_ledger::AccountIdentifier;

#[test]
fn add_single_neuron() {
    let mut index = NeuronAccountIdIndex::new(VectorMemory::default());
    let account_id = AccountIdentifier::from_slice(&[1u8; 28]).unwrap();

    assert!(
        index
            .add_neuron_account_id(NeuronId { id: 1 }, account_id)
            .is_ok()
    );

    assert_eq!(
        index.get_neuron_id_by_account_id(&account_id),
        Some(NeuronId { id: 1 })
    );
}

#[test]
fn add_and_remove_neuron() {
    let mut index = NeuronAccountIdIndex::new(VectorMemory::default());
    let account_id = AccountIdentifier::from_slice(&[1u8; 28]).unwrap();

    assert!(
        index
            .add_neuron_account_id(NeuronId { id: 1 }, account_id)
            .is_ok()
    );
    assert!(
        index
            .remove_neuron_account_id(NeuronId { id: 1 }, account_id)
            .is_ok()
    );

    assert_eq!(index.get_neuron_id_by_account_id(&account_id), None,);
}

#[test]
fn add_neuron_with_same_account_id_fails() {
    let mut index = NeuronAccountIdIndex::new(VectorMemory::default());
    let account_id = AccountIdentifier::from_slice(&[1u8; 28]).unwrap();

    assert!(
        index
            .add_neuron_account_id(NeuronId { id: 1 }, account_id)
            .is_ok()
    );
    assert_matches!(
        index.add_neuron_account_id(NeuronId { id: 2 }, account_id),
        Err(GovernanceError{error_type, error_message: message})
            if error_type == ErrorType::PreconditionFailed as i32 && message.contains("already exists in the index")
    );

    // The index should still have the first neuron.
    assert_eq!(
        index.get_neuron_id_by_account_id(&account_id),
        Some(NeuronId { id: 1 })
    );
}

#[test]
fn remove_neuron_already_absent_fails() {
    let mut index = NeuronAccountIdIndex::new(VectorMemory::default());
    let account_id = AccountIdentifier::from_slice(&[1u8; 28]).unwrap();

    // The index is empty so remove should fail.
    assert_matches!(
        index.remove_neuron_account_id(NeuronId { id: 1 }, account_id),
        Err(GovernanceError{error_type, error_message: message})
            if error_type == ErrorType::PreconditionFailed as i32 && message.contains("already absent in the index")
    );
}

#[test]
fn remove_neuron_with_wrong_neuron_id_fails() {
    let mut index = NeuronAccountIdIndex::new(VectorMemory::default());
    let account_id = AccountIdentifier::from_slice(&[1u8; 28]).unwrap();

    assert!(
        index
            .add_neuron_account_id(NeuronId { id: 1 }, account_id)
            .is_ok()
    );
    assert_matches!(
        index.remove_neuron_account_id(NeuronId { id: 2 }, account_id),
        Err(GovernanceError{error_type, error_message: message})
            if error_type == ErrorType::PreconditionFailed as i32 && message.contains("exists in the index with a different neuron id")
    );

    // The index should still have the first neuron.
    assert_eq!(
        index.get_neuron_id_by_account_id(&account_id),
        Some(NeuronId { id: 1 })
    );
}

#[test]
fn add_multiple_neurons() {
    let mut index = NeuronAccountIdIndex::new(VectorMemory::default());
    let account_id_1 = AccountIdentifier::from_slice(&[1u8; 28]).unwrap();
    let account_id_2 = AccountIdentifier::from_slice(&[2u8; 28]).unwrap();

    assert!(
        index
            .add_neuron_account_id(NeuronId { id: 1 }, account_id_1)
            .is_ok()
    );
    assert!(
        index
            .add_neuron_account_id(NeuronId { id: 2 }, account_id_2)
            .is_ok()
    );

    assert_eq!(
        index.get_neuron_id_by_account_id(&account_id_1),
        Some(NeuronId { id: 1 })
    );
    assert_eq!(
        index.get_neuron_id_by_account_id(&account_id_2),
        Some(NeuronId { id: 2 })
    );
}

#[test]
fn index_num_entries() {
    let mut index = NeuronAccountIdIndex::new(VectorMemory::default());
    let account_id = AccountIdentifier::from_slice(&[1u8; 28]).unwrap();

    assert_eq!(index.num_entries(), 0);

    assert!(
        index
            .add_neuron_account_id(NeuronId { id: 1 }, account_id)
            .is_ok()
    );

    assert_eq!(index.num_entries(), 1);
}
