#![allow(unused)] // TODO(NNS1-2443): Re-enable clippy once we start actually using this code.

use crate::pb::v1::{governance_error::ErrorType, GovernanceError, Neuron};
use bytes::Buf;
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::{BoundedStorable, StableBTreeMap, Storable, VectorMemory};
use prost::Message;
use std::borrow::Cow;

// Because many arguments are needed to construct a Store, there is no natural
// argument order that Store::new would be able to follow. Therefore,
// constructing a Store is done like so:
//
// ```
// let neurons_store: neurons::Store = neurons::StoreBuilder {
//     main: new_memory(...),
//     hot_keys: etc,
//     ...
// }
// .build()
// ```
pub(crate) struct StoreBuilder<Memory> {
    pub main: Memory,

    // Collections
    pub hot_keys: Memory,
    pub followees: Memory,
    pub recent_ballots: Memory,

    // Singletons
    pub known_neuron_data: Memory,
    pub transfer: Memory,
}

impl<Memory> StoreBuilder<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    pub fn build(self) -> Store<Memory> {
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

        Store {
            main: StableBTreeMap::init(main),
        }
    }
}

pub(crate) struct Store<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    main: StableBTreeMap<u64, Neuron, Memory>,
}

impl<Memory> Store<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    pub fn create(&mut self, mut neuron: Neuron) -> Result<(), GovernanceError> {
        // Key.
        let neuron_id = match neuron.id.as_ref() {
            None => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    format!("Tried to store a Neuron, but it lacks an id: {:#?}", neuron),
                ))
            }
            Some(neuron_id) => neuron_id.id,
        };

        // TODO(NNS1-2484): Use these.
        let _hot_keys = std::mem::take(&mut neuron.hot_keys);
        let _followees = std::mem::take(&mut neuron.followees);
        let _recent_ballots = std::mem::take(&mut neuron.recent_ballots);

        // TODO(NNS1-2485): Use these.
        let _known_neuron_data = std::mem::take(&mut neuron.known_neuron_data);
        let _transfer = std::mem::take(&mut neuron.transfer);

        // Try to insert into main.
        let previous_neuron = self.main.insert(neuron_id, neuron);
        let previous_neuron = match previous_neuron {
            None => return Ok(()),
            Some(previous_neuron) => previous_neuron,
        };

        // The previous step clobbered an existing Neuron. Here, we restore the
        // original Neuron..
        self.main.insert(neuron_id, previous_neuron);

        // Return Err indicating that ID is already in use.
        Err(GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!("Neuron ID already in use: {}", neuron_id),
        ))
    }

    pub fn read(&self, neuron_id: NeuronId) -> Result<Neuron, GovernanceError> {
        let neuron_id = neuron_id.id;

        self.main
            .get(&neuron_id)
            // Deal with no entry by blaming it on the caller.
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::NotFound,
                    format!("Unable to find neuron with ID {}", neuron_id),
                )
            })
    }

    // TODO(2488): pub fn update(neuron: Neuron)    -> Result<Neuron, GovernanceError> { todo!() }
    // TODO(2488): pub fn delete(neuron_id: NeuronId)    -> Result<Neuron, GovernanceError> { todo!() }

    // TODO(NNS1-2488): upsert: If not present, create ("insert"). If present,
    // update. Use of this seems like an anti-pattern, but there may be some
    // valid use cases...
}

pub(crate) fn new_heap_based() -> Store<VectorMemory> {
    StoreBuilder {
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

// TODO(2486): AbridgedNeuron.
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

#[cfg(test)]
mod neurons_tests;
