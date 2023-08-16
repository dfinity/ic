#![allow(unused)] // TODO(NNS1-2443): Re-enable clippy once we start actually using this code.

use crate::pb::v1::{
    governance_error::ErrorType, neuron::Followees, BallotInfo, GovernanceError, KnownNeuronData,
    Neuron, NeuronStakeTransfer,
};
use bytes::Buf;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::{BoundedStorable, StableBTreeMap, Storable, VectorMemory};
use prost::Message;
use std::{borrow::Cow, collections::HashMap};

// Because many arguments are needed to construct a StableNeuronStore, there is
// no natural argument order that StableNeuronStore::new would be able to
// follow. Therefore, constructing a StableNeuronStore is done like so:
//
//     let stable_neurons_store = neurons::StableNeuronStoreBuilder {
//         main: new_memory(...),
//         hot_keys: etc,
//         ...
//     }
//     .build()
pub(crate) struct StableNeuronStoreBuilder<Memory> {
    pub main: Memory,

    // Collections
    pub hot_keys: Memory,
    pub followees: Memory,
    pub recent_ballots: Memory,

    // Singletons
    pub known_neuron_data: Memory,
    pub transfer: Memory,
}

impl<Memory> StableNeuronStoreBuilder<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    pub fn build(self) -> StableNeuronStore<Memory> {
        let Self {
            main,

            // TODO(NNS1-2484): Use these.
            // Collections
            hot_keys: _,
            followees: _,
            recent_ballots: _,

            // TODO(NNS1-2485): Use these.
            // Singletons
            known_neuron_data: _,
            transfer: _,
        } = self;

        StableNeuronStore {
            main: StableBTreeMap::init(main),
        }
    }
}

pub(crate) struct StableNeuronStore<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    main: StableBTreeMap<u64, Neuron, Memory>,
    // TODO(NNS1-2484): Implement.
    // hot_keys: StableBTreeMap<, , Memory>,
    // followees: StableBTreeMap<, , Memory>,
    // recent_ballots: StableBTreeMap<, , Memory>,

    // TODO(NNS1-2485): Implement
    // known_neuron_data: StableBTreeMap<, , Memory>,
    // transfer: StableBTreeMap<, , Memory>,
}

/// A collection of `Neuron`s, backed by some `ic_stable_structure::Memory`s.
///
/// Like any good collection/database, this supports the essential CRUD
/// operations via the following methods:
///
///   create(Neuron)
///   read(NeuronId)
///   update(Neuron)
///   delete(NeuronId)
///
/// Notice that when an element is passed (i.e. a Neuron) is passed (create and
/// update), it is consumed, just like with Vec::push, or BTreeMap::insert.
///
/// Notice that all of these return Result<X, GovernanceError>, where X is ()
/// for mutations, and Neuron for read.
///
/// Additionall, there is upsert, which updates or inserts, depending on whether
/// an entry with the same ID already exists. You can think of this as insert,
/// but clobbering is allowed.
///
/// Several `Memory`s are used instead of just oneñ, because the size of
/// serialized Neurons varies significantly, which leads to inefficient use of
/// space by ic_stable_structures. In other words, the point of breaking out
/// into multiple `Memory`s is space efficiency. OTOH, this is probably less
/// efficient in terms of time/processing. The caller need not be concerned with
/// the details of how the `Memory`s are used; they simply need to make sure to
/// pass them consistently from one canister upgrade to the next (i.e. do pass a
/// `Memory` for main, when previously, it was passed for hot_keys). Currently,
/// they are working on removing encoding size restrictions, but that might not
/// land soon enough for us. That would probably obviate all of this.
impl<Memory> StableNeuronStore<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    /// Adds a new entry.
    ///
    /// However, if the id is already in use, returns Err.
    pub fn create(&mut self, mut neuron: Neuron) -> Result<(), GovernanceError> {
        let neuron_id = Self::id_or_err(&neuron)?;

        #[allow(unused)] // TODO(NNS1-2484, NNS1-2485): Re-enable clippy.
        let DecomposedNeuron {
            main: neuron,

            // TODO(NNS1-2484): Use these.
            hot_keys,
            followees,
            recent_ballots,

            // TODO(NNS1-2485): Use these.
            known_neuron_data,
            transfer,
        } = DecomposedNeuron::from(neuron);

        // Try to insert into main.
        let previous_neuron = self.main.insert(neuron_id, neuron);

        // Make sure that we did not clobber an existing entry just now.
        match previous_neuron {
            // Phew! Now, we can safely proceed.
            None => (),

            // Yikes! We just clobbered an existing entry! Abort!
            Some(previous_neuron) => {
                // Restore the original entry.
                self.main.insert(neuron_id, previous_neuron);

                // Return Err indicating that ID is already in use.
                return Err(GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!("Neuron ID already in use: {}", neuron_id),
                ));
            }
        }

        // TODO(NNS1-2484, NNS1-2485): Implement.

        Ok(())
    }

    /// Retrieves an existing entry.
    pub fn read(&self, neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
        let neuron_id = neuron_id.id;

        let abridged_neuron = self
            .main
            .get(&neuron_id)
            // Deal with no entry by blaming it on the caller.
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!("Unable to find neuron with ID {}", neuron_id),
                )
            })?;

        // TODO(NNS1-2484, NNS1-2485): Implement.

        Ok(abridged_neuron)
    }

    /// Changes an existing entry.
    ///
    /// If the entry does not already exist, returns a NotFound Err.
    pub fn update(&mut self, mut neuron: Neuron) -> Result<(), GovernanceError> {
        let neuron_id = Self::id_or_err(&neuron)?;

        #[allow(unused)] // TODO(NNS1-2484, NNS1-2485): Re-enable clippy.
        let DecomposedNeuron {
            main: neuron,

            // TODO(NNS1-2484): Use these.
            hot_keys,
            followees,
            recent_ballots,

            // TODO(NNS1-2485): Use these.
            known_neuron_data,
            transfer,
        } = DecomposedNeuron::from(neuron);

        // Try to insert into main.
        let previous_neuron = self.main.insert(
            neuron_id,
            // clone is done here, because we might later use neuron in an error
            // message. This should be not a big performance hit, because this
            // is an abridged neuron.
            neuron.clone(),
        );

        // Make sure that we changed an existing entry, not created a new entry.
        let _previous_neuron = previous_neuron.ok_or_else(|| {
            // Yikes! There was no entry before. Abort!

            // First, clean up.
            self.main.remove(&neuron_id);

            GovernanceError::new_with_message(
                ErrorType::NotFound,
                format!(
                    "Tried to update an existing Neuron in stable memory, \
                         but there was none: {:#?}",
                    neuron,
                ),
            )
        })?;

        // TODO(NNS1-2484, NNS1-2485): Implement.

        Ok(())
    }

    /// Removes an existing element.
    ///
    /// Returns Err if not found (and no changes are made, of course).
    pub fn delete(&mut self, neuron_id: NeuronId) -> Result<(), GovernanceError> {
        let neuron_id = neuron_id.id;

        let deleted_neuron = self.main.remove(&neuron_id);

        match deleted_neuron {
            Some(_deleted_neuron) => (),
            None => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!(
                        "Tried to delete Neuron from stable storage by ID, \
                         but ID not found: {}",
                        neuron_id,
                    ),
                ));
            }
        }

        // TODO(NNS1-2484, NNS1-2485): Implement.

        Ok(())
    }

    /// Inserts or updates, depending on whether an entry (with the same ID) is
    /// already present.
    ///
    /// Like insert, but if there is already an entry, it gets clobbered.
    ///
    /// This is useful when "writing through"/mirroring mutations on a heap
    /// Neuron.
    ///
    /// Currently, the only way this can return Err is if there is an internal
    /// bug, which the caller cannot possibly compensate for.
    pub fn upsert(&mut self, neuron: Neuron) -> Result<(), GovernanceError> {
        let neuron_id = Self::id_or_err(&neuron)?;

        #[allow(unused)] // TODO(NNS1-2484, NNS1-2485): Re-enable clippy.
        let DecomposedNeuron {
            main: neuron,

            // TODO(NNS1-2484): Use these.
            hot_keys,
            followees,
            recent_ballots,

            // TODO(NNS1-2485): Use these.
            known_neuron_data,
            transfer,
        } = DecomposedNeuron::from(neuron);

        let _previous_neuron = self.main.insert(
            neuron_id,
            // clone is done here, because we might later use neuron in an error
            // message. This should be not a big performance hit, because this
            // is an abridged neuron.
            neuron.clone(),
        );

        // TODO(NNS1-2484, NNS1-2485): Implement.

        Ok(())
    }

    // Misc Private Helper(s)
    // ----------------------

    /// Pulls out u64 id from a Neuron.
    fn id_or_err(neuron: &Neuron) -> Result<u64, GovernanceError> {
        neuron
            .id
            .as_ref()
            // Unwrap id, converting it from NeuronId to simple u64, suitable
            // for use in StableBTreeMap key.
            .map(|neuron_id| neuron_id.id)
            // Handle id field not set.
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("Tried to store a Neuron, but it lacks an id: {:#?}", neuron),
                )
            })
    }
}

pub(crate) fn new_heap_based() -> StableNeuronStore<VectorMemory> {
    StableNeuronStoreBuilder {
        main: VectorMemory::default(),

        // Collections
        hot_keys: VectorMemory::default(),
        followees: VectorMemory::default(),
        recent_ballots: VectorMemory::default(),

        // Singletons
        known_neuron_data: VectorMemory::default(),
        transfer: VectorMemory::default(),
    }
    .build()
}

// Make Neuron Suitable for ic_stable_structures
// ---------------------------------------------

// TODO(NNS1-2486): AbridgedNeuron.
impl Storable for Neuron {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..])
            // Convert from Result to Self. (Unfortunately, it seems that
            // panic is unavoid able in the case of Err.)
            .expect("Unable to deserialize Neuron.")
    }
}

impl BoundedStorable for Neuron {
    const IS_FIXED_SIZE: bool = false;

    // How this number was chosen: we constructed the largest abridged Neuron
    // possible, and found that its serialized size was 190 bytes. This is 2x
    // that, which seems to strike a good balance between comfortable room for
    // growth vs. excessive wasted space.
    const MAX_SIZE: u32 = 380;
}

// Private Helpers
// ---------------

/// Breaks out "fat" fields from a Neuron.
///
/// Used like so:
///
///     let DecomposedNeuron {
///         main: abridged_neuron,
///
///         hot_keys,
///         followees,
///         recent_ballots,
///
///         known_neuron_data,
///         transfer,
///     } = DecomposedNeuron::from(full_neuron);
///
/// Of course, a similar effect can be achieved "manually" by calling
/// std::mem::take on each of the auxiliary fields, but that is error prone,
/// because it is very easy forget to take one of the auxilliary fields. By
/// sticking to this, such mistakes can be avoided.
///
/// Notice that full_neuron in the above example gets consumed. It is "replaced"
/// with abridged_neuron.
struct DecomposedNeuron {
    // TODO(2486): AbridgedNeuron.
    main: Neuron,

    // TODO(NNS1-2484): Use these.
    // Collections
    hot_keys: Vec<PrincipalId>,
    followees: HashMap</* topic ID */ i32, Followees>,
    recent_ballots: Vec<BallotInfo>,

    // TODO(NNS1-2485): Use these.
    // Singletons
    known_neuron_data: Option<KnownNeuronData>,
    transfer: Option<NeuronStakeTransfer>,
}

impl From<Neuron> for DecomposedNeuron {
    fn from(mut source: Neuron) -> Self {
        let hot_keys = std::mem::take(&mut source.hot_keys);
        let followees = std::mem::take(&mut source.followees);
        let recent_ballots = std::mem::take(&mut source.recent_ballots);

        let known_neuron_data = std::mem::take(&mut source.known_neuron_data);
        let transfer = std::mem::take(&mut source.transfer);

        let main = source; // Just a local re-name.

        Self {
            main,

            // Collections
            hot_keys,
            followees,
            recent_ballots,

            // Singletons
            known_neuron_data,
            transfer,
        }
    }
}

#[cfg(test)]
mod neurons_tests;
