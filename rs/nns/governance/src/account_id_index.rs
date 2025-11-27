use crate::{
    pb::v1::{GovernanceError, governance_error::ErrorType},
    storage::validate_stable_btree_map,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::{Memory, StableBTreeMap};
use icp_ledger::AccountIdentifier;

/// An Index mapping an AccountIdentifier on the ICP Ledger to a NeuronId. The
/// This AccountIdentifier is the ICP Ledger Account that "backs" a Neuron's
/// stake.  
pub struct NeuronAccountIdIndex<M: Memory> {
    account_id_to_id: StableBTreeMap<[u8; 28], u64, M>,
}

impl<M: Memory> NeuronAccountIdIndex<M> {
    pub fn new(memory: M) -> Self {
        Self {
            account_id_to_id: StableBTreeMap::init(memory),
        }
    }

    pub fn num_entries(&self) -> usize {
        self.account_id_to_id.len() as usize
    }

    pub fn add_neuron_account_id(
        &mut self,
        neuron_id: NeuronId,
        account_id: AccountIdentifier,
    ) -> Result<(), GovernanceError> {
        let previous_neuron_id = self.account_id_to_id.insert(account_id.hash, neuron_id.id);
        match previous_neuron_id {
            None => Ok(()),
            Some(previous_neuron_id) => {
                self.account_id_to_id
                    .insert(account_id.hash, previous_neuron_id);
                Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("AccountIdentifier {account_id:?} already exists in the index"),
                ))
            }
        }
    }

    pub fn remove_neuron_account_id(
        &mut self,
        neuron_id: NeuronId,
        account_identifier: AccountIdentifier,
    ) -> Result<(), GovernanceError> {
        let previous_neuron_id = self.account_id_to_id.remove(&account_identifier.hash);

        match previous_neuron_id {
            Some(previous_neuron_id) => {
                if previous_neuron_id == neuron_id.id {
                    Ok(())
                } else {
                    self.account_id_to_id
                        .insert(account_identifier.hash, previous_neuron_id);
                    Err(GovernanceError::new_with_message(
                        ErrorType::PreconditionFailed,
                        format!(
                            "AccountIdentifier ({account_identifier}) exists in the index with a different neuron id {previous_neuron_id}"
                        ),
                    ))
                }
            }
            None => Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("AccountIdentifier ({account_identifier}) already absent in the index"),
            )),
        }
    }

    /// Finds the neuron id by subaccount if it exists.
    pub fn get_neuron_id_by_account_id(&self, account_id: &AccountIdentifier) -> Option<NeuronId> {
        self.account_id_to_id
            .get(&account_id.hash)
            .map(|id| NeuronId { id })
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    pub fn validate(&self) {
        validate_stable_btree_map(&self.account_id_to_id);
    }
}

#[cfg(test)]
mod tests;
