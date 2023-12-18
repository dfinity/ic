use crate::{
    neuron_store::NeuronStoreError,
    pb::v1::{neuron::Followees, BallotInfo, KnownNeuronData, Neuron, NeuronStakeTransfer, Topic},
};
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_stable_structures::{BoundedStorable, StableBTreeMap, Storable};
use itertools::Itertools;
use lazy_static::lazy_static;
use maplit::hashmap;
use prost::Message;
use std::{
    borrow::Cow,
    collections::{BTreeMap as HeapBTreeMap, BTreeSet as HeapBTreeSet, HashMap},
    ops::RangeBounds,
};

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
    pub recent_ballots: Memory,
    pub followees: Memory,

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

            // Collections
            hot_keys,
            recent_ballots,
            followees,

            // Singletons
            known_neuron_data,
            transfer,
        } = self;

        StableNeuronStore {
            main: StableBTreeMap::init(main),

            // Collections
            hot_keys_map: StableBTreeMap::init(hot_keys),
            followees_map: StableBTreeMap::init(followees),
            recent_ballots_map: StableBTreeMap::init(recent_ballots),

            // Singletons
            known_neuron_data_map: StableBTreeMap::init(known_neuron_data),
            transfer_map: StableBTreeMap::init(transfer),
        }
    }
}

pub(crate) struct StableNeuronStore<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    main: StableBTreeMap<NeuronId, Neuron, Memory>,

    // Collections
    hot_keys_map: StableBTreeMap<(NeuronId, /* index */ u64), PrincipalId, Memory>,
    recent_ballots_map: StableBTreeMap<(NeuronId, /* index */ u64), BallotInfo, Memory>,
    followees_map: StableBTreeMap<FolloweesKey, NeuronId, Memory>,

    // Singletons
    known_neuron_data_map: StableBTreeMap<NeuronId, KnownNeuronData, Memory>,
    transfer_map: StableBTreeMap<NeuronId, NeuronStakeTransfer, Memory>,
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
/// Notice that when an element is passed (i.e. a Neuron to create and update),
/// it is consumed, just like with Vec::push, or BTreeMap::insert.
///
/// Notice that all of these return Result<X, NeuronStoreError>, where X is ()
/// for mutations, and Neuron for read.
///
/// Additionally, there is upsert, which updates or inserts, depending on whether
/// an entry with the same ID already exists. You can think of this as insert,
/// but clobbering is allowed.
///
/// Several `Memory`s are used instead of just one, because the size of
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
    pub fn create(&mut self, neuron: Neuron) -> Result<(), NeuronStoreError> {
        let neuron_id = Self::id_or_err(&neuron)?;

        let DecomposedNeuron {
            main: neuron,

            hot_keys,
            recent_ballots,
            followees,

            known_neuron_data,
            transfer,
        } = DecomposedNeuron::from(neuron);

        validate_recent_ballots(&recent_ballots)?;

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
                return Err(NeuronStoreError::NeuronAlreadyExists(neuron_id));
            }
        }

        // Auxiliary Data
        // --------------

        update_repeated_field(neuron_id, hot_keys, &mut self.hot_keys_map);
        update_repeated_field(neuron_id, recent_ballots, &mut self.recent_ballots_map);
        self.update_followees(neuron_id, followees);

        update_singleton_field(
            neuron_id,
            known_neuron_data,
            &mut self.known_neuron_data_map,
        );
        update_singleton_field(neuron_id, transfer, &mut self.transfer_map);

        Ok(())
    }

    /// Retrieves an existing entry.
    pub fn read(&self, neuron_id: NeuronId) -> Result<Neuron, NeuronStoreError> {
        let main_neuron_part = self
            .main
            .get(&neuron_id)
            // Deal with no entry by blaming it on the caller.
            .ok_or_else(|| NeuronStoreError::not_found(neuron_id))?;

        Ok(self.reconstitute_neuron(main_neuron_part))
    }

    /// Changes an existing entry.
    ///
    /// If the entry does not already exist, returns a NotFound Err.
    pub fn update(&mut self, neuron: Neuron) -> Result<(), NeuronStoreError> {
        let neuron_id = Self::id_or_err(&neuron)?;

        let DecomposedNeuron {
            // The original neuron is consumed near the end of this
            // statement. This abridged one takes its place.
            main: neuron,

            hot_keys,
            recent_ballots,
            followees,

            known_neuron_data,
            transfer,
        } = DecomposedNeuron::from(neuron);

        validate_recent_ballots(&recent_ballots)?;

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

            NeuronStoreError::not_found(neuron_id)
        })?;

        // Auxiliary Data
        // --------------

        update_repeated_field(neuron_id, hot_keys, &mut self.hot_keys_map);
        update_repeated_field(neuron_id, recent_ballots, &mut self.recent_ballots_map);
        self.update_followees(neuron_id, followees);

        update_singleton_field(
            neuron_id,
            known_neuron_data,
            &mut self.known_neuron_data_map,
        );
        update_singleton_field(neuron_id, transfer, &mut self.transfer_map);

        Ok(())
    }

    /// Removes an existing element.
    ///
    /// Returns Err if not found (and no changes are made, of course).
    pub fn delete(&mut self, neuron_id: NeuronId) -> Result<(), NeuronStoreError> {
        let deleted_neuron = self.main.remove(&neuron_id);

        match deleted_neuron {
            Some(_deleted_neuron) => (),
            None => {
                return Err(NeuronStoreError::not_found(neuron_id));
            }
        }

        // Auxiliary Data
        // --------------
        update_repeated_field(neuron_id, vec![], &mut self.hot_keys_map);
        update_repeated_field(neuron_id, vec![], &mut self.recent_ballots_map);
        self.update_followees(neuron_id, hashmap![]);

        update_singleton_field(neuron_id, None, &mut self.known_neuron_data_map);
        update_singleton_field(neuron_id, None, &mut self.transfer_map);

        Ok(())
    }

    pub fn contains(&self, neuron_id: NeuronId) -> bool {
        self.main.contains_key(&neuron_id)
    }

    pub fn len(&self) -> usize {
        // We can't possibly have usize::MAX neurons, but we casting it in a saturating way anyway.
        self.main.len().min(usize::MAX as u64) as usize
    }

    #[allow(dead_code)] // TODO(NNS1-2416): Re-enable clippy once we start actually using this code.
    pub fn is_empty(&self) -> bool {
        self.main.is_empty()
    }

    /// Returns the next neuron_id equal to or higher than the provided neuron_id
    pub fn range_neurons<R>(&self, range: R) -> impl Iterator<Item = Neuron> + '_
    where
        R: RangeBounds<NeuronId>,
    {
        self.main
            .range(range)
            .map(|(_neuron_id, neuron)| self.reconstitute_neuron(neuron))
    }

    /// Returns the next NeuronId and Neuron equal to or higher than the provided neuron_id. This
    /// method differs from `range_neurons` in that it does not reconstitute the neuron or read
    /// any attributes from other stable memory collections.
    // TODO[NNS1-2784] - remove method after index has been built
    pub fn range_neurons_map<R>(&self, range: R) -> impl Iterator<Item = (NeuronId, Neuron)> + '_
    where
        R: RangeBounds<NeuronId>,
    {
        self.main.range(range)
    }

    /// Returns the number of entries for some of the storage sections.
    pub fn lens(&self) -> NeuronStorageLens {
        NeuronStorageLens {
            hot_keys: self.hot_keys_map.len(),
            followees: self.followees_map.len(),
            known_neuron_data: self.known_neuron_data_map.len(),
        }
    }

    /// Internal function to take what's in the main map and fill in the remaining data from
    /// the other stable storage maps.
    fn reconstitute_neuron(&self, main_neuron_part: Neuron) -> Neuron {
        let neuron_id = main_neuron_part.id.unwrap();
        let hot_keys = read_repeated_field(neuron_id, &self.hot_keys_map);
        let recent_ballots = read_repeated_field(neuron_id, &self.recent_ballots_map);
        let followees = self.read_followees(neuron_id);

        let known_neuron_data = self.known_neuron_data_map.get(&neuron_id);
        let transfer = self.transfer_map.get(&neuron_id);

        DecomposedNeuron {
            main: main_neuron_part,

            hot_keys,
            recent_ballots,
            followees,

            known_neuron_data,
            transfer,
        }
        .reconstitute()
    }

    // Misc Private Helper(s)
    // ----------------------

    fn read_followees(&self, follower_id: NeuronId) -> HashMap</* topic ID */ i32, Followees> {
        // Read from stable memory.
        let first = FolloweesKey {
            follower_id,
            ..FolloweesKey::MIN
        };
        let last = FolloweesKey {
            follower_id,
            ..FolloweesKey::MAX
        };
        let range = self.followees_map.range(first..=last);

        range
            // create groups for topics
            .group_by(|(followees_key, _followee_id)| followees_key.topic)
            .into_iter()
            // convert (Topic, group) into (i32, followees)
            .map(|(topic, group)| {
                // FolloweesKey::index represents the followee's index within the followees list for
                // a specific follower and topic. We have strong guarantee that StableBTreeMap's
                // range() returns followee entries with ascending `FolloweesKey::index` (because
                // the Ord implementation of FolloweesKey), and the current implementation of
                // `group_by()` preserves the order of the elements within groups. Therefore
                // `sorted_by_key()` below is technically not needed. However, the
                // `Itertools::group_by` documentation does not specify whether it actually preserves
                // the order. For this reason we choose to still sort by `FolloweesKey::index`,
                // instead of relying on an undefined behavior.
                let followees = group
                    .sorted_by_key(|(followees_key, _)| followees_key.index)
                    .map(|(_, followee_id)| followee_id)
                    .collect::<Vec<_>>();

                (i32::from(topic), Followees { followees })
            })
            .collect()
    }

    fn update_followees(
        &mut self,
        follower_id: NeuronId,
        new_followees: HashMap</* topic ID */ i32, Followees>,
    ) {
        // This will replace whatever was there before (if anything). As
        // elsewhere, "new" does not mean "additional".
        let new_entries =
            new_followees
                .into_iter()
                .flat_map(|(topic, followees)| {
                    let topic = Topic::try_from(topic).expect("Invalid topic");
                    followees.followees.into_iter().enumerate().map(
                        move // Take ownership of topic.
                        |(index, followee_id)| {
                            let index = index as u64;

                            let key = FolloweesKey {
                                follower_id,
                                topic,
                                index,
                            };

                            (key, followee_id)
                        },
                    )
                })
                .collect();

        let range = {
            let first = FolloweesKey {
                follower_id,
                ..FolloweesKey::MIN
            };
            let last = FolloweesKey {
                follower_id,
                ..FolloweesKey::MAX
            };

            first..=last
        };

        update_range(new_entries, range, &mut self.followees_map);
    }

    /// Pulls out NeuronId from a Neuron.
    fn id_or_err(neuron: &Neuron) -> Result<NeuronId, NeuronStoreError> {
        neuron
            .id
            // Handle id field not set.
            .ok_or(NeuronStoreError::NeuronIdIsNone)
    }
}

/// Number of entries for each section of the neuron storage. Only the ones needed are defined.
pub struct NeuronStorageLens {
    pub hot_keys: u64,
    pub followees: u64,
    pub known_neuron_data: u64,
}

#[cfg(test)]
use ic_stable_structures::VectorMemory;

#[cfg(test)]
pub(crate) fn new_heap_based() -> StableNeuronStore<VectorMemory> {
    StableNeuronStoreBuilder {
        main: VectorMemory::default(),

        // Collections
        hot_keys: VectorMemory::default(),
        recent_ballots: VectorMemory::default(),
        followees: VectorMemory::default(),

        // Singletons
        known_neuron_data: VectorMemory::default(),
        transfer: VectorMemory::default(),
    }
    .build()
}

// impl BoundedStorable for $ProtoMessage
// ======================================

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

impl Storable for BallotInfo {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize Neuron.")
    }
}
impl BoundedStorable for BallotInfo {
    const IS_FIXED_SIZE: bool = false;

    // How this number was chosen: Similar to how MAX_SIZE was chosen for Neuron.
    const MAX_SIZE: u32 = 48;
}

impl Storable for KnownNeuronData {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize Neuron.")
    }
}
impl BoundedStorable for KnownNeuronData {
    const IS_FIXED_SIZE: bool = false;

    // How this number was chosen: Similar to how MAX_SIZE was chosen for Neuron.
    const MAX_SIZE: u32 = 6412;
}

impl Storable for NeuronStakeTransfer {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize Neuron.")
    }
}
impl BoundedStorable for NeuronStakeTransfer {
    const IS_FIXED_SIZE: bool = false;

    // How this number was chosen: Similar to how MAX_SIZE was chosen for Neuron.
    const MAX_SIZE: u32 = 290;
}

// Private Helpers
// ===============

// This is copied from candid/src. Seems like their definition should be public,
// but it's not. Seems to be an oversight.
const PRINCIPAL_MAX_LENGTH_IN_BYTES: usize = 29;

// For range scanning.
lazy_static! {
    static ref MIN_PRINCIPAL_ID: PrincipalId =
        PrincipalId(Principal::try_from(vec![]).expect("Unable to construct MIN_PRINCIPAL_ID."));
    static ref MAX_PRINCIPAL_ID: PrincipalId = PrincipalId(
        Principal::try_from(vec![0xFF_u8; PRINCIPAL_MAX_LENGTH_IN_BYTES])
            .expect("Unable to construct MAX_PRINCIPAL_ID.")
    );
}

/// Breaks out "fat" fields from a Neuron.
///
/// Used like so:
///
///     let DecomposedNeuron {
///         main: abridged_neuron,
///
///         hot_keys,
///         recent_ballots,
///         followees,
///
///         known_neuron_data,
///         transfer,
///     } = DecomposedNeuron::from(full_neuron);
///
/// Of course, a similar effect can be achieved "manually" by calling
/// std::mem::take on each of the auxiliary fields, but that is error prone,
/// because it is very easy to forget to take one of the auxiliary fields. By
/// sticking to this, such mistakes can be avoided.
///
/// Notice that full_neuron in the above example gets consumed. It is "replaced"
/// with abridged_neuron.
struct DecomposedNeuron {
    // TODO(2486): AbridgedNeuron.
    main: Neuron,

    // Collections
    hot_keys: Vec<PrincipalId>,
    recent_ballots: Vec<BallotInfo>,
    followees: HashMap</* topic ID */ i32, Followees>,

    // Singletons
    known_neuron_data: Option<KnownNeuronData>,
    transfer: Option<NeuronStakeTransfer>,
}

impl From<Neuron> for DecomposedNeuron {
    fn from(mut source: Neuron) -> Self {
        let hot_keys = std::mem::take(&mut source.hot_keys);
        let recent_ballots = std::mem::take(&mut source.recent_ballots);
        let followees = std::mem::take(&mut source.followees);

        let known_neuron_data = std::mem::take(&mut source.known_neuron_data);
        let transfer = std::mem::take(&mut source.transfer);

        let main = source; // Just a local re-name.

        Self {
            main,

            // Collections
            hot_keys,
            recent_ballots,
            followees,

            // Singletons
            known_neuron_data,
            transfer,
        }
    }
}

impl DecomposedNeuron {
    fn reconstitute(self) -> Neuron {
        let Self {
            main,

            hot_keys,
            recent_ballots,
            followees,

            known_neuron_data,
            transfer,
        } = self;

        Neuron {
            hot_keys,
            recent_ballots,
            followees,

            known_neuron_data,
            transfer,
            ..main
        }
    }
}

/// Replaces values in a StableBTreeMap corresponding to a repeated field in a Neuron.
///
/// E.g. hot_keys, recent_ballots.
fn update_repeated_field<Element, Memory>(
    neuron_id: NeuronId,
    new_elements: Vec<Element>,
    map: &mut StableBTreeMap<(NeuronId, /* index */ u64), Element, Memory>,
) where
    Element: BoundedStorable,
    Memory: ic_stable_structures::Memory,
{
    let new_entries = new_elements
        .into_iter()
        .enumerate()
        .map(|(index, element)| {
            let key = (neuron_id, index as u64);
            (key, element)
        })
        .collect();

    let range = {
        let first = (neuron_id, u64::MIN);
        let last = (neuron_id, u64::MAX);
        first..=last
    };

    update_range(new_entries, range, map)
}

/// Replaces the contents of map where keys are in range with new_entries.
// TODO(NNS1-2513): To avoid the caller passing an incorrect range (e.g. too
// small, or to big), derive range from NeuronId.
fn update_range<Key, Value, Memory>(
    new_entries: HeapBTreeMap<Key, Value>,
    range: impl RangeBounds<Key>,
    map: &mut StableBTreeMap<Key, Value, Memory>,
) where
    Key: BoundedStorable + Ord + Clone,
    Value: BoundedStorable,
    Memory: ic_stable_structures::Memory,
{
    let new_keys = new_entries.keys().cloned().collect::<HeapBTreeSet<Key>>();

    for (new_key, new_value) in new_entries {
        map.insert(new_key, new_value);
    }

    let obsolete_keys = map
        .range(range)
        .filter(|(key, _value)| !new_keys.contains(key))
        .map(|(key, _value)| key)
        .collect::<Vec<_>>();

    for obsolete_key in obsolete_keys {
        map.remove(&obsolete_key);
    }
}

fn update_singleton_field<Element, Memory>(
    neuron_id: NeuronId,
    element: Option<Element>,
    map: &mut StableBTreeMap<NeuronId, Element, Memory>,
) where
    Element: BoundedStorable,
    Memory: ic_stable_structures::Memory,
{
    match element {
        None => map.remove(&neuron_id),
        Some(element) => map.insert(neuron_id, element),
    };
}

fn read_repeated_field<Element, Memory>(
    neuron_id: NeuronId,
    map: &StableBTreeMap<(NeuronId, /* index */ u64), Element, Memory>,
) -> Vec<Element>
where
    Element: BoundedStorable,
    Memory: ic_stable_structures::Memory,
{
    let first = (neuron_id, u64::MIN);
    let last = (neuron_id, u64::MAX);

    map.range(first..=last).map(|(_key, value)| value).collect()
}

/// Basically, this just means that all elements have a proper ProposalId,
/// because that's what StableNeuronStore needs.
fn validate_recent_ballots(recent_ballots: &[BallotInfo]) -> Result<(), NeuronStoreError> {
    let mut defects = vec![];

    for (i, ballot_info) in recent_ballots.iter().enumerate() {
        let has_proposal_id = ballot_info.proposal_id.is_some();
        if !has_proposal_id {
            defects.push(i);
        }
    }

    if defects.is_empty() {
        return Ok(());
    }

    Err(NeuronStoreError::InvalidData {
        reason: format!(
            "Some elements in Neuron.recent_ballots are invalid: {:?}",
            defects
        ),
    })
}

// StableBTreeMap Compound Keys
// ----------------------------
//
// TODO(NNS1-2506): Stop using primitive types for key components (e.g. u64 ->
// NeuronId). Of course, that does not distinguish between follower and
// followee. We can push this idea even further by having separate FollowerId
// and FolloweeId types, but that might be overkill.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FolloweesKey {
    follower_id: NeuronId,
    topic: Topic,
    index: u64,
}
type FolloweesKeyEquivalentTuple = (NeuronId, (Topic, u64));
impl FolloweesKey {
    const MIN: Self = Self {
        follower_id: NeuronId::MIN,
        topic: Topic::MIN,
        index: u64::MIN,
    };
    const MAX: Self = Self {
        follower_id: NeuronId::MAX,
        topic: Topic::MAX,
        index: u64::MAX,
    };
}
impl Storable for FolloweesKey {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let Self {
            follower_id,
            topic,
            index,
        } = *self;
        let tuple: FolloweesKeyEquivalentTuple = (follower_id, (topic, index));
        let bytes: Vec<u8> = tuple.to_bytes().to_vec();
        Cow::from(bytes)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        let (follower_id, (topic, index)) = FolloweesKeyEquivalentTuple::from_bytes(bytes);

        Self {
            follower_id,
            topic,
            index,
        }
    }
}
impl BoundedStorable for FolloweesKey {
    const IS_FIXED_SIZE: bool = FolloweesKeyEquivalentTuple::IS_FIXED_SIZE;
    const MAX_SIZE: u32 = FolloweesKeyEquivalentTuple::MAX_SIZE;
}

#[cfg(test)]
mod neurons_tests;
