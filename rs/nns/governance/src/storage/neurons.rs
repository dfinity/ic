use crate::{
    neuron::{DecomposedNeuron, Neuron},
    neuron_store::NeuronStoreError,
    pb::v1::{
        AbridgedNeuron, BallotInfo, Followees, KnownNeuronData, MaturityDisbursement,
        NeuronStakeTransfer, Topic,
    },
    storage::validate_stable_btree_map,
};
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_stable_structures::{StableBTreeMap, Storable, storable::Bound};
use itertools::Itertools;
use maplit::hashmap;
use prost::Message;
use std::{
    borrow::Cow,
    collections::{BTreeMap as HeapBTreeMap, HashMap, btree_map::Entry},
    iter::Peekable,
    ops::{Bound as RangeBound, RangeBounds},
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
    pub maturity_disbursements: Memory,

    // Singletons
    pub known_neuron_data: Memory,
    pub transfer: Memory,
}

/// A section of a neuron represents a part of neuron that can potentially be large, and when a
/// neuron is read, the caller can specify which sections of the neuron they want to read.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) struct NeuronSections {
    pub hot_keys: bool,
    pub recent_ballots: bool,
    pub followees: bool,
    pub maturity_disbursements: bool,
    pub known_neuron_data: bool,
    pub transfer: bool,
}

impl NeuronSections {
    pub const NONE: Self = Self {
        hot_keys: false,
        recent_ballots: false,
        followees: false,
        maturity_disbursements: false,
        known_neuron_data: false,
        transfer: false,
    };

    pub const ALL: Self = Self {
        hot_keys: true,
        recent_ballots: true,
        followees: true,
        maturity_disbursements: true,
        known_neuron_data: true,
        transfer: true,
    };
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
            maturity_disbursements,

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
            maturity_disbursements_map: StableBTreeMap::init(maturity_disbursements),

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
    main: StableBTreeMap<NeuronId, AbridgedNeuron, Memory>,

    // Collections
    hot_keys_map: StableBTreeMap<(NeuronId, /* index */ u64), Principal, Memory>,
    recent_ballots_map: StableBTreeMap<(NeuronId, /* index */ u64), BallotInfo, Memory>,
    followees_map: StableBTreeMap<FolloweesKey, NeuronId, Memory>,
    maturity_disbursements_map:
        StableBTreeMap<(NeuronId, /* index */ u64), MaturityDisbursement, Memory>,

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
///   read(NeuronId, NeuronSections)
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
/// When a Neuron is read, the caller can specify which sections of the Neuron
/// they want to read. This is done by passing a `NeuronSections` to the read
/// method. When reading a neuron for modification, all sections should be read by
/// passing `NeuronSections::all()`.
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
        let DecomposedNeuron {
            id: neuron_id,
            main: neuron,

            hot_keys,
            recent_ballots,
            followees,
            maturity_disbursements_in_progress,

            known_neuron_data,
            transfer,
        } = DecomposedNeuron::try_from(neuron)?;

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

        update_repeated_field(
            neuron_id,
            hot_keys
                .iter()
                .map(|principal_id| Principal::from(*principal_id))
                .collect(),
            &mut self.hot_keys_map,
        );
        update_repeated_field(neuron_id, recent_ballots, &mut self.recent_ballots_map);
        self.update_followees(neuron_id, followees);
        update_repeated_field(
            neuron_id,
            maturity_disbursements_in_progress,
            &mut self.maturity_disbursements_map,
        );

        update_singleton_field(
            neuron_id,
            known_neuron_data,
            &mut self.known_neuron_data_map,
        );
        update_singleton_field(neuron_id, transfer, &mut self.transfer_map);

        Ok(())
    }

    /// Reads an existing entry given the ID and the sections to read.
    pub fn read(
        &self,
        neuron_id: NeuronId,
        sections: NeuronSections,
    ) -> Result<Neuron, NeuronStoreError> {
        let main_neuron_part = self
            .main
            .get(&neuron_id)
            // Deal with no entry by blaming it on the caller.
            .ok_or_else(|| NeuronStoreError::not_found(neuron_id))?;

        Ok(self.reconstitute_neuron(neuron_id, main_neuron_part, sections))
    }

    pub fn register_recent_neuron_ballot(
        &mut self,
        neuron_id: NeuronId,
        topic: Topic,
        proposal_id: ProposalId,
        vote: Vote,
    ) -> Result<(), NeuronStoreError> {
        if topic == Topic::ExchangeRate {
            return Ok(());
        }

        let main_neuron_part = self
            .main
            .get(&neuron_id)
            // Deal with no entry by blaming it on the caller.
            .ok_or_else(|| NeuronStoreError::not_found(neuron_id))?;

        let recent_entry_index = main_neuron_part.recent_ballots_next_entry_index;

        let next_entry_index = if let Some(recent_entry_index) = recent_entry_index {
            recent_entry_index as usize
        } else {
            let mut ballots = read_repeated_field(neuron_id, &self.recent_ballots_map);
            ballots.reverse();
            let next_entry = ballots.len() % MAX_NEURON_RECENT_BALLOTS;
            update_repeated_field(neuron_id, ballots, &mut self.recent_ballots_map);
            next_entry
        };
        // We cannot error after this, or we risk creating some chaos with the ordering
        // of the ballots b/c of the migration code above.

        let ballot_info = BallotInfo {
            proposal_id: Some(proposal_id),
            vote: vote as i32,
        };

        insert_element_in_repeated_field(
            neuron_id,
            next_entry_index as u64,
            ballot_info,
            &mut self.recent_ballots_map,
        );

        // update the main part now
        let mut main_neuron_part = main_neuron_part;
        main_neuron_part.recent_ballots_next_entry_index =
            Some(((next_entry_index + 1) % MAX_NEURON_RECENT_BALLOTS) as u32);
        self.main.insert(neuron_id, main_neuron_part);

        Ok(())
    }

    /// Updates the main part of an existing neuron.
    pub fn with_main_part_mut<R>(
        &mut self,
        neuron_id: NeuronId,
        f: impl FnOnce(&mut AbridgedNeuron) -> R,
    ) -> Result<R, NeuronStoreError> {
        let mut main_neuron_part = self
            .main
            .get(&neuron_id)
            // Deal with no entry by blaming it on the caller.
            .ok_or_else(|| NeuronStoreError::not_found(neuron_id))?;

        let result = f(&mut main_neuron_part);
        self.main.insert(neuron_id, main_neuron_part);

        Ok(result)
    }

    /// Changes an existing entry.
    ///
    /// If the entry does not already exist, returns a NotFound Err.
    pub fn update(
        &mut self,
        old_neuron: &Neuron,
        new_neuron: Neuron,
    ) -> Result<(), NeuronStoreError> {
        let DecomposedNeuron {
            // The original neuron is consumed near the end of this
            // statement. This abridged one takes its place.
            id: neuron_id,
            main: neuron,

            hot_keys,
            recent_ballots,
            followees,
            maturity_disbursements_in_progress,

            known_neuron_data,
            transfer,
        } = DecomposedNeuron::try_from(new_neuron)?;

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

        if hot_keys != old_neuron.hot_keys {
            update_repeated_field(
                neuron_id,
                hot_keys
                    .iter()
                    .map(|principal_id| Principal::from(*principal_id))
                    .collect(),
                &mut self.hot_keys_map,
            );
        }
        if recent_ballots != old_neuron.recent_ballots {
            update_repeated_field(neuron_id, recent_ballots, &mut self.recent_ballots_map);
        }
        if followees != old_neuron.followees {
            self.update_followees(neuron_id, followees);
        }
        if maturity_disbursements_in_progress != old_neuron.maturity_disbursements_in_progress {
            update_repeated_field(
                neuron_id,
                maturity_disbursements_in_progress,
                &mut self.maturity_disbursements_map,
            );
        }

        if known_neuron_data.as_ref() != old_neuron.known_neuron_data() {
            update_singleton_field(
                neuron_id,
                known_neuron_data,
                &mut self.known_neuron_data_map,
            );
        }
        if transfer != old_neuron.transfer {
            update_singleton_field(neuron_id, transfer, &mut self.transfer_map);
        }

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

    pub fn range_neurons<R>(&self, range: R) -> impl Iterator<Item = Neuron> + '_
    where
        R: RangeBounds<NeuronId> + Clone,
    {
        self.range_neurons_sections(range, NeuronSections::ALL)
    }

    /// Returns the next neuron_id equal to or higher than the provided neuron_id
    pub fn range_neurons_sections<R>(
        &self,
        range: R,
        sections: NeuronSections,
    ) -> impl Iterator<Item = Neuron> + '_
    where
        R: RangeBounds<NeuronId> + Clone,
    {
        let (start, end) = get_range_boundaries(range.clone());

        // We want our ranges for sub iterators to include start and end
        let hotkeys_range = (start, u64::MIN)..=(end, u64::MAX);
        let ballots_range = (start, u64::MIN)..=(end, u64::MAX);
        let maturity_disbursements_range = (start, u64::MIN)..=(end, u64::MAX);

        let followees_range = FolloweesKey {
            follower_id: start,
            ..FolloweesKey::MIN
        }..=FolloweesKey {
            follower_id: end,
            ..FolloweesKey::MAX
        };

        // Instead of randomly accessing each map (which is expensive for StableBTreeMaps), we
        // use a range query on each map, and iterate all of the ranges at the same time.  This
        // uses 40% less instructions compared to just iterating on the top level range, and
        // accessing the other maps for each neuron_id.
        // This is only possible because EVERY range begins with NeuronId, so that their ordering
        // is the same in respect to the main range's neurons.

        let main_range = self.main.range(range.clone());
        let mut hot_keys_iter = self.hot_keys_map.range(hotkeys_range).peekable();
        let mut recent_ballots_iter = self.recent_ballots_map.range(ballots_range).peekable();
        let mut followees_iter = self.followees_map.range(followees_range).peekable();
        let mut maturity_disbursements_iter = self
            .maturity_disbursements_map
            .range(maturity_disbursements_range)
            .peekable();
        let mut known_neuron_data_iter = self.known_neuron_data_map.range(range.clone()).peekable();
        let mut transfer_iter = self.transfer_map.range(range).peekable();

        main_range.map(move |(main_neuron_id, abridged_neuron)| {
            // We'll collect data from all relevant maps for this neuron_id

            let hot_keys = if sections.hot_keys {
                collect_values_for_neuron_from_peekable_range(
                    &mut hot_keys_iter,
                    main_neuron_id,
                    |((neuron_id, _), _)| *neuron_id,
                    |((_, _), principal)| PrincipalId::from(principal),
                )
            } else {
                vec![]
            };

            let ballots = if sections.recent_ballots {
                collect_values_for_neuron_from_peekable_range(
                    &mut recent_ballots_iter,
                    main_neuron_id,
                    |((neuron_id, _), _)| *neuron_id,
                    |((_, _), ballot_info)| ballot_info,
                )
            } else {
                vec![]
            };

            let followees = if sections.followees {
                collect_values_for_neuron_from_peekable_range(
                    &mut followees_iter,
                    main_neuron_id,
                    |(followees_key, _)| followees_key.follower_id,
                    |x| x,
                )
            } else {
                vec![]
            };

            let maturity_disbursements_in_progress = if sections.maturity_disbursements {
                collect_values_for_neuron_from_peekable_range(
                    &mut maturity_disbursements_iter,
                    main_neuron_id,
                    |((neuron_id, _), _)| *neuron_id,
                    |((_, _), maturity_disbursement)| maturity_disbursement,
                )
            } else {
                vec![]
            };

            let current_known_neuron_data = if sections.known_neuron_data {
                collect_values_for_neuron_from_peekable_range(
                    &mut known_neuron_data_iter,
                    main_neuron_id,
                    |(neuron_id, _)| *neuron_id,
                    |(_, known_neuron_data)| known_neuron_data,
                )
                .pop()
            } else {
                None
            };

            let current_transfer = if sections.transfer {
                collect_values_for_neuron_from_peekable_range(
                    &mut transfer_iter,
                    main_neuron_id,
                    |(neuron_id, _)| *neuron_id,
                    |(_, transfer)| transfer,
                )
                .pop()
            } else {
                None
            };

            Neuron::from(DecomposedNeuron {
                id: main_neuron_id,
                main: abridged_neuron,
                hot_keys,
                recent_ballots: ballots,
                followees: self.reconstitute_followees_from_range(followees.into_iter()),
                maturity_disbursements_in_progress,
                known_neuron_data: current_known_neuron_data,
                transfer: current_transfer,
            })
        })
    }

    /// Returns the number of entries for some of the storage sections.
    pub fn lens(&self) -> NeuronStorageLens {
        NeuronStorageLens {
            hot_keys: self.hot_keys_map.len(),
            followees: self.followees_map.len(),
            known_neuron_data: self.known_neuron_data_map.len(),
            maturity_disbursements: self.maturity_disbursements_map.len(),
        }
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    pub fn validate(&self) {
        validate_stable_btree_map(&self.main);
        validate_stable_btree_map(&self.hot_keys_map);
        validate_stable_btree_map(&self.recent_ballots_map);
        validate_stable_btree_map(&self.followees_map);
        validate_stable_btree_map(&self.maturity_disbursements_map);
        validate_stable_btree_map(&self.known_neuron_data_map);
        validate_stable_btree_map(&self.transfer_map);
    }

    /// Internal function to take what's in the main map and fill in the remaining data from
    /// the other stable storage maps.
    fn reconstitute_neuron(
        &self,
        neuron_id: NeuronId,
        main_neuron_part: AbridgedNeuron,
        sections: NeuronSections,
    ) -> Neuron {
        let hot_keys = if sections.hot_keys {
            read_repeated_field(neuron_id, &self.hot_keys_map)
        } else {
            Vec::new()
        };
        let recent_ballots = if sections.recent_ballots {
            read_repeated_field(neuron_id, &self.recent_ballots_map)
        } else {
            Vec::new()
        };
        let followees = if sections.followees {
            self.read_followees(neuron_id)
        } else {
            HashMap::new()
        };
        let maturity_disbursements = if sections.maturity_disbursements {
            read_repeated_field(neuron_id, &self.maturity_disbursements_map)
        } else {
            Vec::new()
        };

        let known_neuron_data = if sections.known_neuron_data {
            self.known_neuron_data_map.get(&neuron_id)
        } else {
            None
        };
        let transfer = if sections.transfer {
            self.transfer_map.get(&neuron_id)
        } else {
            None
        };

        let decomposed = DecomposedNeuron {
            id: neuron_id,
            main: main_neuron_part,

            hot_keys: hot_keys
                .iter()
                .map(|principal| PrincipalId::from(*principal))
                .collect(),
            recent_ballots,
            followees,
            maturity_disbursements_in_progress: maturity_disbursements,

            known_neuron_data,
            transfer,
        };

        Neuron::from(decomposed)
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

        self.reconstitute_followees_from_range(range)
    }

    fn reconstitute_followees_from_range(
        &self,
        range: impl Iterator<Item = (FolloweesKey, NeuronId)>,
    ) -> HashMap</* topic ID */ i32, Followees> {
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

    pub fn is_known_neuron(&self, neuron_id: NeuronId) -> bool {
        self.known_neuron_data_map.contains_key(&neuron_id)
    }
}

/// Number of entries for each section of the neuron storage. Only the ones needed are defined.
pub struct NeuronStorageLens {
    pub hot_keys: u64,
    pub followees: u64,
    pub known_neuron_data: u64,
    pub maturity_disbursements: u64,
}

use crate::{governance::MAX_NEURON_RECENT_BALLOTS, pb::v1::Vote};
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
        maturity_disbursements: VectorMemory::default(),

        // Singletons
        known_neuron_data: VectorMemory::default(),
        transfer: VectorMemory::default(),
    }
    .build()
}

// impl Storable for $ProtoMessage
// ======================================

impl Storable for AbridgedNeuron {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..])
            // Convert from Result to Self. (Unfortunately, it seems that
            // panic is unavoid able in the case of Err.)
            .expect("Unable to deserialize Neuron.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for BallotInfo {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize Neuron.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for MaturityDisbursement {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize Neuron.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for KnownNeuronData {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize Neuron.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for NeuronStakeTransfer {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize Neuron.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

// Private Helpers
// ===============

fn get_range_boundaries<R>(range_bound: R) -> (NeuronId, NeuronId)
where
    R: RangeBounds<NeuronId>,
{
    let start = match range_bound.start_bound() {
        RangeBound::Included(start) => *start,
        RangeBound::Excluded(start) => *start,
        RangeBound::Unbounded => NeuronId::MIN,
    };
    let end = match range_bound.end_bound() {
        RangeBound::Included(end) => *end,
        RangeBound::Excluded(end) => *end,
        RangeBound::Unbounded => NeuronId::MAX,
    };

    (start, end)
}

/// Skips until extract_neuron_id(item) == target_neuron_id, then maps corresponding items through
/// extract_value and returns the result as a vector.
fn collect_values_for_neuron_from_peekable_range<Iter, T, R, FNeuronId, FValue>(
    iter: &mut Peekable<Iter>,
    target_neuron_id: NeuronId,
    extract_neuron_id: FNeuronId,
    extract_value: FValue,
) -> Vec<R>
where
    Iter: Iterator<Item = T>,
    FNeuronId: Fn(&T) -> NeuronId,
    FValue: Fn(T) -> R,
{
    let mut result = vec![];

    while let Some(item) = iter.peek() {
        let neuron_id = extract_neuron_id(item);
        if neuron_id > target_neuron_id {
            break;
        }
        let item = iter
            .next()
            .expect("Peek had a value, but next did not!  This should be impossible.");

        if neuron_id == target_neuron_id {
            result.push(extract_value(item));
        }
    }

    result
}

/// Replaces values in a StableBTreeMap corresponding to a repeated field in a Neuron.
///
/// E.g. hot_keys, recent_ballots.
fn update_repeated_field<Element, Memory>(
    neuron_id: NeuronId,
    new_elements: Vec<Element>,
    map: &mut StableBTreeMap<(NeuronId, /* index */ u64), Element, Memory>,
) where
    Element: Storable + PartialEq,
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

fn insert_element_in_repeated_field<Element, Memory>(
    neuron_id: NeuronId,
    index: u64,
    element: Element,
    map: &mut StableBTreeMap<(NeuronId, /* index */ u64), Element, Memory>,
) where
    Element: Storable + PartialEq,
    Memory: ic_stable_structures::Memory,
{
    let key = (neuron_id, index);
    map.insert(key, element);
}

/// Replaces the contents of map where keys are in range with new_entries.
// TODO(NNS1-2513): To avoid the caller passing an incorrect range (e.g. too
// small, or to big), derive range from NeuronId.
fn update_range<Key, Value, Memory>(
    mut new_entries: HeapBTreeMap<Key, Value>,
    range: impl RangeBounds<Key>,
    map: &mut StableBTreeMap<Key, Value, Memory>,
) where
    Key: Storable + Ord + Clone,
    Value: Storable + PartialEq,
    Memory: ic_stable_structures::Memory,
{
    let mut to_remove = vec![];
    for (key, value) in map.range(range) {
        match new_entries.entry(key.clone()) {
            // If our new entries do not include a key in existing, we remove it from existing.
            Entry::Vacant(_) => {
                to_remove.push(key);
            }
            Entry::Occupied(entry) => {
                // If our new entries have the same value as what exists, we do not want to insert
                // it, but instead remove it from the list of new entries, since it's present.
                if *entry.get() == value {
                    entry.remove();
                }
            }
        };
    }

    for (new_key, new_value) in new_entries {
        map.insert(new_key, new_value);
    }

    for obsolete_key in to_remove {
        map.remove(&obsolete_key);
    }
}

fn update_singleton_field<Element, Memory>(
    neuron_id: NeuronId,
    element: Option<Element>,
    map: &mut StableBTreeMap<NeuronId, Element, Memory>,
) where
    Element: Storable,
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
    Element: Storable,
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
        reason: format!("Some elements in Neuron.recent_ballots are invalid: {defects:?}"),
    })
}

// StableBTreeMap Compound Keys
// ----------------------------

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
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

    const BOUND: Bound = <FolloweesKeyEquivalentTuple as Storable>::BOUND;
}

#[cfg(test)]
mod neurons_tests;
