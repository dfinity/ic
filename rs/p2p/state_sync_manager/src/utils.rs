use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use ic_logger::{ReplicaLogger, info};
use ic_protobuf::{p2p::v1 as pb, proxy::ProxyDecodeError};
use ic_types::NodeId;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, btree_map::Entry},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Advert {
    pub(crate) id: StateSyncArtifactId,
    pub(crate) partial_state: Option<XorDistance>,
}

impl From<Advert> for pb::Advert {
    fn from(advert: Advert) -> Self {
        pb::Advert {
            id: Some(advert.id.into()),
            partial_state: advert
                .partial_state
                .map(|partial_state| partial_state.0.into()),
        }
    }
}

impl TryFrom<pb::Advert> for Advert {
    type Error = ProxyDecodeError;

    fn try_from(advert: pb::Advert) -> Result<Self, Self::Error> {
        Ok(Advert {
            id: advert
                .id
                .map(StateSyncArtifactId::from)
                .ok_or(ProxyDecodeError::MissingField("id"))?,
            partial_state: match advert.partial_state {
                Some(partial_state) => Some(
                    <[u8; 32]>::try_from(partial_state)
                        .map(XorDistance)
                        .map_err(|partial_state| ProxyDecodeError::InvalidDigestLength {
                            expected: 32,
                            actual: partial_state.len(),
                        })?,
                ),
                None => None,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct XorDistance([u8; 32]);

impl XorDistance {
    pub(crate) fn new(
        peer_id: NodeId,
        artifact_id: StateSyncArtifactId,
        chunk_id: ChunkId,
    ) -> Self {
        let mut lhs_hash: [u8; 32] = Sha256::digest(peer_id.get().to_vec()).into();

        let mut rhs_hash = Sha256::new();
        rhs_hash.update(artifact_id.height.get().to_be_bytes());
        rhs_hash.update(artifact_id.hash.0);
        rhs_hash.update(chunk_id.get().to_be_bytes());
        let rhs_hash: [u8; 32] = rhs_hash.finalize().into();

        lhs_hash
            .iter_mut()
            .zip(rhs_hash.iter())
            .for_each(|(lhs, rhs)| *lhs ^= rhs);

        Self(lhs_hash)
    }
}

pub(crate) struct ChunksToDownload(
    RefCell<BTreeMap<XorDistance, (ChunkId, bool)>>,
    ReplicaLogger,
);

impl ChunksToDownload {
    pub(crate) fn new(log: &ReplicaLogger) -> Self {
        Self(RefCell::new(BTreeMap::new()), log.clone())
    }

    // Add chunks to the chunks to download list
    pub(crate) fn add_chunks(
        &self,
        node_id: NodeId,
        artifact_id: StateSyncArtifactId,
        chunks: impl Iterator<Item = ChunkId>,
    ) -> usize {
        let mut added = 0;
        for chunk in chunks {
            let xor_distance = XorDistance::new(node_id, artifact_id.clone(), chunk);

            if let Entry::Vacant(entry) = self.0.borrow_mut().entry(xor_distance) {
                entry.insert((chunk, false));
                added += 1;
            } else {
                info!(self.1, "STATE_SYNC: Attempt to double insert a chunk");
            }
        }

        added
    }

    pub(crate) fn next_chunk_to_download(&self) -> Option<ChunkId> {
        let mut chunks = self.0.borrow_mut();

        let next_chunk = chunks
            .iter_mut()
            .find(|(_, (_, downloading))| !downloading)?;

        next_chunk.1.1 = true;
        Some(next_chunk.1.0)
    }

    pub(crate) fn next_chunk_to_download_with_lookahead<F>(
        &self,
        lookahead: usize,
        check_fn: F,
    ) -> Option<(NodeId, ChunkId)>
    where
        F: Fn(ChunkId) -> Option<NodeId>,
    {
        let mut chunks = self.0.borrow_mut();

        let (next_chunk, peer) = chunks
            .iter_mut()
            .take(lookahead)
            .filter(|(_, (_, downloading))| !downloading)
            .filter_map(|chunk| check_fn(chunk.1.0).map(|peer| (chunk, peer)))
            .next()?;

        next_chunk.1.1 = true;
        Some((peer, next_chunk.1.0))
    }

    pub(crate) fn download_finished(&self, chunk_id: ChunkId) {
        let mut chunks = self.0.borrow_mut();
        if let Some(key) = chunks.iter().find(|(_, (chunk, _))| *chunk == chunk_id) {
            let key = key.0.clone();
            chunks.remove(&key);
        }
    }

    pub(crate) fn download_failed(&self, chunk_id: ChunkId) {
        if let Some(next_chunk) = self
            .0
            .borrow_mut()
            .iter_mut()
            .find(|(_, (chunk, _))| chunk == &chunk_id)
        {
            next_chunk.1.1 = false;
        }
    }

    pub(crate) fn next_xor_distance(&self) -> Option<XorDistance> {
        self.0
            .borrow()
            .first_key_value()
            .map(|(key, _)| key.clone())
    }

    pub(crate) fn num_entries(&self) -> usize {
        self.0.borrow().len()
    }
}

pub(crate) struct PeerState {
    num_downloads: usize,
    partial_state: Option<XorDistance>,
}

impl PeerState {
    pub(crate) fn new(partial_state: Option<XorDistance>) -> Self {
        Self {
            num_downloads: 0,
            partial_state,
        }
    }

    pub(crate) fn register_download(&mut self) {
        self.num_downloads += 1;
    }

    pub(crate) fn deregister_download(&mut self) {
        // We do a saturating sub here because it can happen (in rare cases) that a peer that just joined this sync
        // was previously removed from the sync and still had outstanding downloads. As a consequence there is the possibiliy
        // of an underflow. In the case where we close old download task while having active downloads we might start to
        // undercount active downloads for this peer but this is acceptable since everything will be reset anyway every
        self.num_downloads = self.num_downloads.saturating_sub(1);
    }

    pub(crate) fn active_downloads(&self) -> usize {
        self.num_downloads
    }

    pub(crate) fn update_partial_state(&mut self, partial_state: XorDistance) {
        match self.partial_state {
            Some(ref mut old_partial_state) => {
                if &partial_state > old_partial_state {
                    *old_partial_state = partial_state
                }
            }
            None => self.partial_state = Some(partial_state),
        }
    }

    pub(crate) fn is_chunk_served(
        &self,
        peer_id: NodeId,
        artifact_id: StateSyncArtifactId,
        chunk_id: ChunkId,
    ) -> bool {
        match &self.partial_state {
            Some(partial_state) => {
                let distance = XorDistance::new(peer_id, artifact_id, chunk_id);
                distance < *partial_state
            }
            None => true,
        }
    }
}

// TODO: Test XorMetric ordering
// TODO: Test Advert round trip
// TODO: Test malformed advert parsing
