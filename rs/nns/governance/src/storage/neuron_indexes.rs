#![allow(unused)] // TODO(NNS1-2409): Re-enable once we add code to migrate indexes.

use crate::{
    known_neuron_index::{AddKnownNeuronError, KnownNeuronIndex},
    pb::v1::Neuron,
    storage::Signed32,
    subaccount_index::NeuronSubaccountIndex,
};

use ic_base_types::PrincipalId;
use ic_nervous_system_governance::index::{
    neuron_following::{add_neuron_followees, StableNeuronFollowingIndex},
    neuron_principal::{add_neuron_id_principal_ids, StableNeuronPrincipalIndex},
};
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::VectorMemory;
use icp_ledger::Subaccount;

// Because many arguments are needed to construct a StableNeuronIndexes,
// there is no natural argument order that StableNeuronIndexes::new would be able to
// follow. Therefore, constructing a StableNeuronIndexes is done like so:
//
//     let stable_neuron_indexes = neurons::StableNeuronIndexesBuilder {
//         subaccount_index: new_memory(...),
//         principal_index: etc,
//         ...
//     }
//     .build()
pub(crate) struct StableNeuronIndexesBuilder<Memory> {
    pub subaccount: Memory,
    pub principal: Memory,
    pub following: Memory,
    pub known_neuron: Memory,
}

impl<Memory> StableNeuronIndexesBuilder<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    pub fn build(self) -> StableNeuronIndexes<Memory> {
        let Self {
            subaccount,
            principal,
            following,
            known_neuron,
        } = self;

        StableNeuronIndexes {
            subaccount: NeuronSubaccountIndex::new(subaccount),
            principal: StableNeuronPrincipalIndex::new(principal),
            following: StableNeuronFollowingIndex::new(following),
            known_neuron: KnownNeuronIndex::new(known_neuron),
        }
    }
}

/// Neuron indexes based on stable storage.
pub(crate) struct StableNeuronIndexes<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    subaccount: NeuronSubaccountIndex<Memory>,
    principal: StableNeuronPrincipalIndex<u64, Memory>,
    following: StableNeuronFollowingIndex<u64, Signed32, Memory>,
    known_neuron: KnownNeuronIndex<Memory>,
}

impl<Memory> StableNeuronIndexes<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    /// Adds a neuron into indexes, and returns error whether anything is unexpected (e.g. conflicts with
    /// existing data).
    /// Even when we have error for some indexes, we will keep updating other indexes since there is not
    /// a good way to recover from the errors, and the correctness of the indexes need to depend on the
    /// NeuronStore to call them correctly.
    pub fn add_neuron(&mut self, neuron: &Neuron) -> Result<(), String> {
        let neuron_id = neuron.id.expect("Neuron must have an id");
        let mut defects = vec![];

        let existing_topic_followee_pairs = add_neuron_followees(
            &mut self.following,
            &neuron_id.id,
            neuron
                .topic_followee_pairs()
                .iter()
                .map(|(topic, followee)| (Signed32::from(*topic as i32), followee.id))
                .collect(),
        );
        if !existing_topic_followee_pairs.is_empty() {
            defects.push(format!(
                "Topic-followee pairs {:?} already exists for neuron {}",
                existing_topic_followee_pairs, neuron_id.id
            ))
        }

        let existing_principal_ids = add_neuron_id_principal_ids(
            &mut self.principal,
            &neuron_id.id,
            neuron.principal_ids_with_special_permissions(),
        );
        if !existing_principal_ids.is_empty() {
            defects.push(format!(
                "Principals {:?} already exists for neuron {}",
                existing_principal_ids, neuron_id.id
            ));
        }

        if let Some(known_neuron_data) = neuron.known_neuron_data.as_ref() {
            self.known_neuron
                .add_known_neuron(&known_neuron_data.name, neuron_id)
                .map_err(|add_known_neuron_error| match add_known_neuron_error {
                    AddKnownNeuronError::AlreadyExists => defects.push(format!(
                        "Failed to add neuron {} to known neuron index because the known \
                        neuron name {} already exists",
                        neuron_id.id, known_neuron_data.name
                    )),
                    AddKnownNeuronError::ExceedsSizeLimit => defects.push(format!(
                        "Failed to add neuron {} to known neuron index because the known \
                        neuron name {} exceeds size limit",
                        neuron_id.id, known_neuron_data.name
                    )),
                });
        }

        neuron
            .subaccount()
            .and_then(|subaccount| {
                self.subaccount
                    .add_neuron_subaccount(neuron_id, &subaccount)
            })
            .map_err(|error| {
                defects.push(error.error_message);
            });

        if defects.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Adding neuron {} to stable storage indexes failed because of {}",
                neuron_id.id,
                defects.join("\n -")
            ))
        }
    }

    // It's OK to expose read-only access to all the indexes.
    pub fn subaccount(&self) -> &NeuronSubaccountIndex<Memory> {
        &self.subaccount
    }

    pub fn principal(&self) -> &StableNeuronPrincipalIndex<u64, Memory> {
        &self.principal
    }

    pub fn following(&self) -> &StableNeuronFollowingIndex<u64, Signed32, Memory> {
        &self.following
    }

    pub fn known_neuron(&self) -> &KnownNeuronIndex<Memory> {
        &self.known_neuron
    }
}

pub(crate) fn new_heap_based() -> StableNeuronIndexes<VectorMemory> {
    StableNeuronIndexesBuilder {
        subaccount: VectorMemory::default(),
        principal: VectorMemory::default(),
        following: VectorMemory::default(),
        known_neuron: VectorMemory::default(),
    }
    .build()
}

#[cfg(test)]
mod tests;
