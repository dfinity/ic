use super::*;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgMasterPublicKeyId};
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
        dkg_id: &NiDkgId,
        public_coefficients: CspPublicCoefficients,
        indices: BTreeMap<NodeId, NodeIndex>,
        registry_version: RegistryVersion,
    );

    /// Inserts an individual public key for a given `dkg_id` and a given
    /// `node_id` into the store.
    ///
    /// If an individual public key already exists for the DKG instance
    /// with the given `dkg_id`, this key will be overwritten.
    fn insert_individual_public_key(
        &mut self,
        dkg_id: &NiDkgId,
        node_id: NodeId,
        individual_public_key: CspThresholdSigPublicKey,
    );

    /// Returns the transcript data for the node_id if it has been loaded.
    fn transcript_data(&self, dkg_id: &NiDkgId) -> Option<&TranscriptData>;

    /// Returns a reference to the individual public key of the node with ID
    /// `node_id` for the given `dkg_id`.
    fn individual_public_key(
        &self,
        dkg_id: &NiDkgId,
        node_id: NodeId,
    ) -> Option<&CspThresholdSigPublicKey>;
}

#[derive(Clone)]
pub struct TranscriptData {
    public_coeffs: CspPublicCoefficients,
    indices: BTreeMap<NodeId, NodeIndex>,
    registry_version: RegistryVersion,
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

    /// Returns a reference to the registry version.
    /////////////////////////////////////////
    // TODO(CRP-2599): remove allow(unused) once this method is used
    #[allow(unused)]
    pub fn registry_version(&self) -> RegistryVersion {
        self.registry_version
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
/// The maximum number of threshold signature data stored per tag or key is defined by
/// `CAPACITY_PER_TAG_OR_KEY`. For the moment there are three tags:
/// * `LowThreshold`
/// * `HighThreshold`
/// * `HighThresholdForKey(NiDkgMasterPublicKeyId)`
///
/// and the total capacity of the threshold signature data store is
/// `2*CAPACITY_PER_TAG_OR_KEY + K*CAPACITY_PER_TAG_OR_KEY` where `K` is
/// the number of different `NiDkgMasterPublicKeyId`s that are stored on the
/// subnet. In production, currently at most 3 keys are stored per subnet
/// (1 ECDSA key, 2 Schnorr keys).
pub struct ThresholdSigDataStoreImpl {
    store: BTreeMap<NiDkgId, ThresholdSigData>,
    max_num_of_dkg_ids_per_tag_or_key: usize,
    // VecDeque used as queue: `push_back` to add, `pop_front` to remove
    low_threshold_dkg_id_insertion_order: VecDeque<NiDkgId>,
    high_threshold_dkg_id_insertion_order: VecDeque<NiDkgId>,
    high_threshold_for_key_dkg_id_insertion_order:
        BTreeMap<NiDkgMasterPublicKeyId, VecDeque<NiDkgId>>,
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

const _SHOULD_HAVE_CAPACITY_GREATER_ZERO: () = assert!(
    ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY > 0,
    "Capacity per tag or key must be at least 1"
);
const _SHOULD_HAVE_CAPACITY_OF_NINE: () = assert!(
    ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY == 9,
    "Capacity per tag or key must be 9"
);

impl ThresholdSigDataStoreImpl {
    pub const CAPACITY_PER_TAG_OR_KEY: usize = 9;

    /// Creates a new store with a default capacity per tag or key.
    pub fn new() -> Self {
        ThresholdSigDataStoreImpl {
            store: BTreeMap::new(),
            max_num_of_dkg_ids_per_tag_or_key: Self::CAPACITY_PER_TAG_OR_KEY,
            low_threshold_dkg_id_insertion_order: VecDeque::with_capacity(
                Self::CAPACITY_PER_TAG_OR_KEY,
            ),
            high_threshold_dkg_id_insertion_order: VecDeque::with_capacity(
                Self::CAPACITY_PER_TAG_OR_KEY,
            ),
            high_threshold_for_key_dkg_id_insertion_order: BTreeMap::new(),
        }
    }

    #[allow(clippy::map_entry)]
    fn entry_for(&mut self, dkg_id: &NiDkgId) -> &mut ThresholdSigData {
        if !self.store.contains_key(dkg_id) {
            self.store
                .insert(dkg_id.clone(), ThresholdSigData::default());
            match &dkg_id.dkg_tag {
                NiDkgTag::LowThreshold => {
                    self.low_threshold_dkg_id_insertion_order
                        .push_back(dkg_id.clone());
                }
                NiDkgTag::HighThreshold => {
                    self.high_threshold_dkg_id_insertion_order
                        .push_back(dkg_id.clone());
                }
                NiDkgTag::HighThresholdForKey(master_public_key_id) => {
                    match self
                        .high_threshold_for_key_dkg_id_insertion_order
                        .get_mut(master_public_key_id)
                    {
                        Some(insertion_order) => insertion_order.push_back(dkg_id.clone()),
                        None => {
                            let mut buf =
                                VecDeque::with_capacity(self.max_num_of_dkg_ids_per_tag_or_key);
                            buf.push_back(dkg_id.clone());
                            self.high_threshold_for_key_dkg_id_insertion_order
                                .insert(master_public_key_id.clone(), buf);
                        }
                    }
                }
            }
        }
        self.store
            .get_mut(dkg_id)
            .expect("Missing dkg id from store")
    }

    fn purge_entry_for_oldest_dkg_id_if_necessary(&mut self, tag: &NiDkgTag) {
        let dkg_id_insertion_order = match tag {
            NiDkgTag::LowThreshold => Some(&mut self.low_threshold_dkg_id_insertion_order),
            NiDkgTag::HighThreshold => Some(&mut self.high_threshold_dkg_id_insertion_order),
            NiDkgTag::HighThresholdForKey(master_public_key_id) => self
                .high_threshold_for_key_dkg_id_insertion_order
                .get_mut(master_public_key_id),
        };
        if let Some(insertion_order) = dkg_id_insertion_order
            && insertion_order.len() > self.max_num_of_dkg_ids_per_tag_or_key
        {
            let oldest_dkg_id = insertion_order
                .pop_front()
                .expect("dkg store unexpectedly empty");
            self.store.remove(&oldest_dkg_id);
        }
    }

    fn assert_length_invariant(&self) {
        let high_threshold_for_key_id_dkg_id_insertion_order_len: usize = self
            .high_threshold_for_key_dkg_id_insertion_order
            .values()
            .map(|v| v.len())
            .sum();
        assert_eq!(
            self.store.len(),
            self.low_threshold_dkg_id_insertion_order.len()
                + self.high_threshold_dkg_id_insertion_order.len()
                + high_threshold_for_key_id_dkg_id_insertion_order_len,
            "ThresholdSigDataStore length invariant violated"
        );
    }
}

impl ThresholdSigDataStore for ThresholdSigDataStoreImpl {
    fn insert_transcript_data(
        &mut self,
        dkg_id: &NiDkgId,
        public_coefficients: CspPublicCoefficients,
        indices: BTreeMap<NodeId, NodeIndex>,
        registry_version: RegistryVersion,
    ) {
        let data = self.entry_for(dkg_id);
        data.transcript_data = Some(TranscriptData {
            public_coeffs: public_coefficients,
            indices,
            registry_version,
        });

        self.purge_entry_for_oldest_dkg_id_if_necessary(&dkg_id.dkg_tag);
        self.assert_length_invariant();
    }

    fn insert_individual_public_key(
        &mut self,
        dkg_id: &NiDkgId,
        node_id: NodeId,
        public_key: CspThresholdSigPublicKey,
    ) {
        self.entry_for(dkg_id)
            .public_keys
            .get_or_insert_with(BTreeMap::new)
            .insert(node_id, public_key);

        self.purge_entry_for_oldest_dkg_id_if_necessary(&dkg_id.dkg_tag);
        self.assert_length_invariant();
    }

    fn transcript_data(&self, dkg_id: &NiDkgId) -> Option<&TranscriptData> {
        self.store
            .get(dkg_id)
            .and_then(|data| data.transcript_data.as_ref())
    }

    fn individual_public_key(
        &self,
        dkg_id: &NiDkgId,
        node_id: NodeId,
    ) -> Option<&CspThresholdSigPublicKey> {
        self.store.get(dkg_id).and_then(|data| {
            data.public_keys
                .as_ref()
                .and_then(|public_key_map| public_key_map.get(&node_id))
        })
    }
}
