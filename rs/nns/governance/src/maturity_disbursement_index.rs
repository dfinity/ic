use std::collections::BTreeSet;

use crate::storage::validate_stable_btree_map;

use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_stable_structures::{Memory, StableBTreeMap};

type TimestampSeconds = u64;
type NeuronId = u64;

/// An index which stores (finalization_timestamp, neuron_id) pairs for maturity disbursement
/// events. Used for quickly looking up the next finalization timestamp.
pub struct MaturityDisbursementIndex<M: Memory> {
    // Conceptually, it is possible to use StableMinHeap here. However, `impl NeuronIndex`  requires
    // the index to be able to remove any entries associated with a neuron, which is a bit
    // restrictive since we don't expect any disbursement to be removed. On the other hand, using
    // StableBTreeMap achieves similar performance.
    finalization_timestamp_neuron_id_to_null: StableBTreeMap<(TimestampSeconds, NeuronId), (), M>,
}

impl<M: Memory> MaturityDisbursementIndex<M> {
    pub fn new(memory: M) -> Self {
        Self {
            finalization_timestamp_neuron_id_to_null: StableBTreeMap::init(memory),
        }
    }

    pub fn num_entries(&self) -> usize {
        self.finalization_timestamp_neuron_id_to_null.len() as usize
    }

    pub fn contains_entry(
        &self,
        neuron_id: NeuronId,
        finalization_timestamp: TimestampSeconds,
    ) -> bool {
        self.finalization_timestamp_neuron_id_to_null
            .contains_key(&(finalization_timestamp, neuron_id))
    }

    /// Adds (finalization_timestamp, neuron_id) pairs to the index, returns a list of timestamps
    /// that are not added because of clobbering.
    pub fn add_neuron_id_finalization_timestamps(
        &mut self,
        neuron_id: NeuronId,
        finalization_timestamps: BTreeSet<TimestampSeconds>,
    ) -> Vec<TimestampSeconds> {
        let mut already_present_timestamps = Vec::new();
        for finalization_timestamp in finalization_timestamps {
            let already_present = self
                .finalization_timestamp_neuron_id_to_null
                .insert((finalization_timestamp, neuron_id), ())
                .is_some();
            if already_present {
                already_present_timestamps.push(finalization_timestamp);
            }
        }
        already_present_timestamps
    }

    /// Removes (finalization_timestamp, neuron_id) pairs from the index, returns a list of
    /// timestamps that are not removed because of non-existence.
    pub fn remove_neuron_id_finalization_timestamps(
        &mut self,
        neuron_id: NeuronId,
        finalization_timestamps: BTreeSet<TimestampSeconds>,
    ) -> Vec<TimestampSeconds> {
        let mut already_absent_timestamps = Vec::new();
        for finalization_timestamp in finalization_timestamps {
            let already_absent = self
                .finalization_timestamp_neuron_id_to_null
                .remove(&(finalization_timestamp, neuron_id))
                .is_none();
            if already_absent {
                already_absent_timestamps.push(finalization_timestamp);
            }
        }
        already_absent_timestamps
    }

    /// Returns the neuron ids that are ready for maturity disbursement.
    pub fn get_neuron_ids_ready_to_finalize(
        &self,
        now_seconds: TimestampSeconds,
    ) -> BTreeSet<NeuronId> {
        let max_key = (now_seconds, u64::MAX);
        self.finalization_timestamp_neuron_id_to_null
            .range(..=max_key)
            .map(|((_, neuron_id), _)| neuron_id)
            .collect()
    }

    /// Returns the next entry of the index.
    pub fn get_next_entry(&self) -> Option<(TimestampSeconds, NeuronIdProto)> {
        self.finalization_timestamp_neuron_id_to_null
            .first_key_value()
            .map(|((finalization_timestamp, neuron_id), _)| {
                (finalization_timestamp, NeuronIdProto::from_u64(neuron_id))
            })
    }

    /// Validates that some of the data in stable storage can be read, in order to prevent broken
    /// schema. Should only be called in post_upgrade.
    pub fn validate(&self) {
        validate_stable_btree_map(&self.finalization_timestamp_neuron_id_to_null);
    }
}
