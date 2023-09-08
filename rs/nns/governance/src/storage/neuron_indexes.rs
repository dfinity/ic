#![allow(unused)] // TODO(NNS1-2409): Re-enable once we add code to migrate indexes.

use crate::{
    known_neuron_index::{AddKnownNeuronError, KnownNeuronIndex},
    neuron_store::NeuronStoreError,
    pb::v1::Neuron,
    storage::Signed32,
    subaccount_index::NeuronSubaccountIndex,
};

use ic_base_types::PrincipalId;
use ic_nervous_system_governance::index::{
    neuron_following::{add_neuron_followees, StableNeuronFollowingIndex},
    neuron_principal::{add_neuron_id_principal_ids, StableNeuronPrincipalIndex},
};
use ic_stable_structures::VectorMemory;
use icp_ledger::Subaccount;
use std::fmt::{Display, Formatter};

type NeuronId = u64;
type Topic = Signed32;

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
    principal: StableNeuronPrincipalIndex<NeuronId, Memory>,
    following: StableNeuronFollowingIndex<NeuronId, Topic, Memory>,
    known_neuron: KnownNeuronIndex<Memory>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CorruptedNeuronIndexes {
    neuron_id: NeuronId,
    indexes: Vec<NeuronIndexDefect>,
}

impl Display for CorruptedNeuronIndexes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let index_defect_reasons: String = self
            .indexes
            .iter()
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "Neuron indexes for neuron {} are corrupted: {}",
            self.neuron_id, index_defect_reasons
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum NeuronIndexDefect {
    Subaccount { reason: String },
    Principal { reason: String },
    Following { reason: String },
    KnownNeuron { reason: String },
}

impl Display for NeuronIndexDefect {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Subaccount { reason } => {
                write!(f, "Neuron subaccount index is corrupted: {}", reason)
            }
            Self::Principal { reason } => {
                write!(f, "Neuron principal index is corrupted: {}", reason)
            }
            Self::Following { reason } => {
                write!(f, "Neuron following index is corrupted: {}", reason)
            }
            Self::KnownNeuron { reason } => {
                write!(f, "Known neuron index is corrupted: {}", reason)
            }
        }
    }
}

/// A common interface for neuron indexes for updating them in a unified way.
trait NeuronIndex {
    /// Adds a neuron into indexes. An error signals something might be wrong with the indexes. The
    /// second time the exact same neuron gets added should have no effect (other than returning an
    /// error).
    fn add_neuron(&mut self, new_neuron: &Neuron) -> Result<(), NeuronIndexDefect>;
}

impl<Memory> NeuronIndex for NeuronSubaccountIndex<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    fn add_neuron(&mut self, new_neuron: &Neuron) -> Result<(), NeuronIndexDefect> {
        // StableNeuronIndexes::add_neuron checks neuron id before calling this method.
        new_neuron
            .subaccount()
            .and_then(|subaccount| {
                self.add_neuron_subaccount(
                    new_neuron.id.expect("Neuron must have an id"),
                    &subaccount,
                )
            })
            .map_err(|error| NeuronIndexDefect::Subaccount {
                reason: error.error_message,
            })
    }
}

impl<Memory> NeuronIndex for StableNeuronPrincipalIndex<u64, Memory>
where
    Memory: ic_stable_structures::Memory,
{
    fn add_neuron(&mut self, new_neuron: &Neuron) -> Result<(), NeuronIndexDefect> {
        // StableNeuronIndexes::add_neuron checks neuron id before calling this method.
        let neuron_id = new_neuron.id.expect("Neuron must have an id").id;
        let existing_principal_ids = add_neuron_id_principal_ids(
            self,
            &neuron_id,
            new_neuron.principal_ids_with_special_permissions(),
        );
        if existing_principal_ids.is_empty() {
            Ok(())
        } else {
            Err(NeuronIndexDefect::Principal {
                reason: format!(
                    "Principals {:?} already exists for neuron {}",
                    existing_principal_ids, neuron_id
                ),
            })
        }
    }
}

impl<Memory> NeuronIndex for StableNeuronFollowingIndex<u64, Signed32, Memory>
where
    Memory: ic_stable_structures::Memory,
{
    fn add_neuron(&mut self, new_neuron: &Neuron) -> Result<(), NeuronIndexDefect> {
        // StableNeuronIndexes::add_neuron checks neuron id before calling this method.
        let neuron_id = new_neuron.id.expect("Neuron must have an id").id;
        let existing_topic_followee_pairs = add_neuron_followees(
            self,
            &neuron_id,
            new_neuron
                .topic_followee_pairs()
                .iter()
                .map(|(topic, followee)| (Signed32::from(*topic as i32), followee.id))
                .collect(),
        );
        if existing_topic_followee_pairs.is_empty() {
            Ok(())
        } else {
            Err(NeuronIndexDefect::Following {
                reason: format!(
                    "Topic-followee pairs {:?} already exists for neuron {}",
                    existing_topic_followee_pairs, neuron_id
                ),
            })
        }
    }
}

impl<Memory> NeuronIndex for KnownNeuronIndex<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    fn add_neuron(&mut self, new_neuron: &Neuron) -> Result<(), NeuronIndexDefect> {
        let known_neuron_name = match new_neuron.known_neuron_data.as_ref() {
            Some(known_neuron_data) => &known_neuron_data.name,
            // This is fine. Only some (a small number) of Neurons are known.
            None => return Ok(()),
        };
        // StableNeuronIndexes::add_neuron checks neuron id before calling this method.
        let neuron_id = new_neuron.id.expect("Neuron must have an id");

        self.add_known_neuron(known_neuron_name, neuron_id)
            .map_err(|add_known_neuron_error| match add_known_neuron_error {
                // It's caller's responsibility to make sure the known neuron name is within the
                // size limit.
                AddKnownNeuronError::AlreadyExists => NeuronIndexDefect::KnownNeuron {
                    reason: format!(
                        "Failed to add neuron {} to known neuron index because the known \
                        neuron name {} already exists",
                        neuron_id.id, known_neuron_name
                    ),
                },
                AddKnownNeuronError::ExceedsSizeLimit => NeuronIndexDefect::KnownNeuron {
                    reason: format!(
                        "Failed to add neuron {} to known neuron index because the known \
                        neuron name {} exceeds size limit",
                        neuron_id.id, known_neuron_name
                    ),
                },
            })
    }
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
    pub fn add_neuron(&mut self, new_neuron: &Neuron) -> Result<(), NeuronStoreError> {
        let neuron_id = new_neuron.id.ok_or(NeuronStoreError::NeuronIdIsNone)?;
        let mut defects = vec![];

        for index in self.indexes_mut() {
            let defect = index.add_neuron(new_neuron).err();
            defects.extend(defect);
        }

        if defects.is_empty() {
            Ok(())
        } else {
            Err(NeuronStoreError::CorruptedNeuronIndexes(
                CorruptedNeuronIndexes {
                    neuron_id: neuron_id.id,
                    indexes: defects,
                },
            ))
        }
    }

    fn indexes_mut(&mut self) -> Vec<&mut dyn NeuronIndex> {
        vec![
            &mut self.subaccount,
            &mut self.principal,
            &mut self.following,
            &mut self.known_neuron,
        ]
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
