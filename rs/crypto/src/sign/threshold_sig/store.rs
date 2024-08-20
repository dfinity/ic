use super::*;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use std::collections::VecDeque;

#[cfg(test)]
mod tests;

/// A store for data required to verify threshold signatures.
///
/// The data that can be stored comprises
/// * the `CspPublicCoefficients` for a particular DKG instance,
/// * the `NodeIndex`es of the nodes participating in a DKG instance,
/// * the `CspThresholdPublicKey`s of the nodes participating in a DKG instance,
///
/// where the DKG instance is identified by a `NiDkgId`.
pub trait ThresholdSigDataStore {
    /// Inserts both public coefficients and indices for a given `dkg_id` into
    /// the store.
    ///
    /// If entries for the public coefficients and/or the indices already exist
    /// for the DKG instance with the given `dkg_id`, these entries will be
    /// overwritten. The indices map is replaced entirely in case it was set
    /// before.
    fn insert_transcript_data(
        &mut self,
        dkg_id: NiDkgId,
        public_coefficients: CspPublicCoefficients,
        indices: BTreeMap<NodeId, NodeIndex>,
    );

    /// Inserts an individual public key for a given `dkg_id` and a given
    /// `node_id` into the store.
    ///
    /// If an individual public key already exists for the DKG instance
    /// with the given `dkg_id`, this key will be overwritten.
    fn insert_individual_public_key(
        &mut self,
        dkg_id: NiDkgId,
        node_id: NodeId,
        individual_public_key: CspThresholdSigPublicKey,
    );

    /// Returns the transcript data for the node_id if it has been loaded.
    fn transcript_data(&self, dkg_id: NiDkgId) -> Option<&TranscriptData>;

    /// Returns a reference to the individual public key of the node with ID
    /// `node_id` for the given `dkg_id`.
    fn individual_public_key(
        &self,
        dkg_id: NiDkgId,
        node_id: NodeId,
    ) -> Option<&CspThresholdSigPublicKey>;
}

#[derive(Clone)]
pub struct TranscriptData {
    public_coeffs: CspPublicCoefficients,
    indices: BTreeMap<NodeId, NodeIndex>,
}

impl TranscriptData {
    /// Returns a reference to the public coefficients.
    pub fn public_coefficients(&self) -> &CspPublicCoefficients {
        &self.public_coeffs
    }

    /// Returns a reference to the index of the node with ID `node_id`.
    pub fn index(&self, node_id: NodeId) -> Option<&NodeIndex> {
        self.indices.get(&node_id)
    }
}

/// Threshold signature data store that limits the number of DKG IDs
/// for which data is kept.
///
/// If after insertion of data (i.e., public coefficients and indices, or an
/// individual public key) the number of DKG IDs for which the store contains
/// data exceeds the maximum size, the data associated with the DKG ID for which
/// data was inserted _first_ is removed, that is, DKG IDs are purged in
/// insertion order.
///
/// The maximum number of threshold signature data stored per tag is defined by
/// `CAPACITY_PER_TAG`. For the moment there are two tags, `LowThreshold` and `HighThreshold`,
/// meaning that the total capacity of the threshold signature data store is `2 * CAPACITY_PER_TAG`.
pub struct ThresholdSigDataStoreImpl {
    store: BTreeMap<NiDkgId, ThresholdSigData>,
    max_num_of_dkg_ids_per_tag: usize,
    // VecDeque used as queue: `push_back` to add, `pop_front` to remove
    low_threshold_dkg_id_insertion_order: VecDeque<NiDkgId>,
    high_threshold_dkg_id_insertion_order: VecDeque<NiDkgId>,
}

#[derive(Default)]
struct ThresholdSigData {
    transcript_data: Option<TranscriptData>,
    public_keys: Option<BTreeMap<NodeId, CspThresholdSigPublicKey>>,
}

impl Default for ThresholdSigDataStoreImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl ThresholdSigDataStoreImpl {
    pub const CAPACITY_PER_TAG: usize = 9;

    /// Creates a new store with a default maximum size per tag.
    pub fn new() -> Self {
        Self::new_with_max_size(Self::CAPACITY_PER_TAG)
    }

    /// Creates a new store that keeps the data for the
    /// given maximum number of DKG IDs per tag.
    ///
    /// # Panics
    /// If `max_num_of_dkg_ids_per_tag` is smaller than 1.
    fn new_with_max_size(max_num_of_dkg_ids_per_tag: usize) -> Self {
        assert!(
            max_num_of_dkg_ids_per_tag >= 1,
            "The maximum size per tag must be at least 1"
        );
        ThresholdSigDataStoreImpl {
            store: BTreeMap::new(),
            max_num_of_dkg_ids_per_tag,
            low_threshold_dkg_id_insertion_order: VecDeque::with_capacity(
                max_num_of_dkg_ids_per_tag,
            ),
            high_threshold_dkg_id_insertion_order: VecDeque::with_capacity(
                max_num_of_dkg_ids_per_tag,
            ),
        }
    }

    #[allow(clippy::map_entry)]
    fn entry_for(&mut self, dkg_id: NiDkgId) -> &mut ThresholdSigData {
        if !self.store.contains_key(&dkg_id) {
            self.store.insert(dkg_id, ThresholdSigData::default());
            match dkg_id.dkg_tag {
                NiDkgTag::LowThreshold => {
                    self.low_threshold_dkg_id_insertion_order.push_back(dkg_id);
                }
                NiDkgTag::HighThreshold => {
                    self.high_threshold_dkg_id_insertion_order.push_back(dkg_id);
                }
            }
        }
        self.store
            .get_mut(&dkg_id)
            .expect("Missing dkg id from store")
    }

    fn purge_entry_for_oldest_dkg_id_if_necessary(&mut self, tag: NiDkgTag) {
        let dkg_id_insertion_order = match tag {
            NiDkgTag::LowThreshold => &mut self.low_threshold_dkg_id_insertion_order,
            NiDkgTag::HighThreshold => &mut self.high_threshold_dkg_id_insertion_order,
        };
        if dkg_id_insertion_order.len() > self.max_num_of_dkg_ids_per_tag {
            let oldest_dkg_id = dkg_id_insertion_order
                .pop_front()
                .expect("dkg store unexpectedly empty");
            self.store.remove(&oldest_dkg_id);
        }
    }

    fn assert_length_invariant(&self) {
        assert_eq!(
            self.store.len(),
            self.low_threshold_dkg_id_insertion_order.len()
                + self.high_threshold_dkg_id_insertion_order.len(),
            "The combined length of the queues maintaining DKG ID insertion order must be the \
            same as that of the map containing the DKG ID data."
        );
    }
}

impl ThresholdSigDataStore for ThresholdSigDataStoreImpl {
    fn insert_transcript_data(
        &mut self,
        dkg_id: NiDkgId,
        public_coefficients: CspPublicCoefficients,
        indices: BTreeMap<NodeId, NodeIndex>,
    ) {
        let data = self.entry_for(dkg_id);
        data.transcript_data = Some(TranscriptData {
            public_coeffs: public_coefficients,
            indices,
        });

        self.purge_entry_for_oldest_dkg_id_if_necessary(dkg_id.dkg_tag);
        self.assert_length_invariant();
    }

    fn insert_individual_public_key(
        &mut self,
        dkg_id: NiDkgId,
        node_id: NodeId,
        public_key: CspThresholdSigPublicKey,
    ) {
        self.entry_for(dkg_id)
            .public_keys
            .get_or_insert_with(BTreeMap::new)
            .insert(node_id, public_key);

        self.purge_entry_for_oldest_dkg_id_if_necessary(dkg_id.dkg_tag);
        self.assert_length_invariant();
    }

    fn transcript_data(&self, dkg_id: NiDkgId) -> Option<&TranscriptData> {
        self.store
            .get(&dkg_id)
            .and_then(|data| data.transcript_data.as_ref())
    }

    fn individual_public_key(
        &self,
        dkg_id: NiDkgId,
        node_id: NodeId,
    ) -> Option<&CspThresholdSigPublicKey> {
        self.store.get(&dkg_id).and_then(|data| {
            data.public_keys
                .as_ref()
                .and_then(|public_key_map| public_key_map.get(&node_id))
        })
    }
}
