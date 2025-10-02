use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use ic_logger::{ReplicaLogger, info};
use ic_protobuf::{p2p::v1 as pb, proxy::ProxyDecodeError};
use ic_types::NodeId;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, btree_map::Entry};

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
                .map(|id| StateSyncArtifactId::from(id))
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
        let mut lhs_hash: [u8; 32] = Sha256::digest(peer_id.get().to_vec()).try_into().unwrap();

        let mut rhs_hash = Sha256::new();
        rhs_hash.update(artifact_id.height.get().to_be_bytes());
        rhs_hash.update(artifact_id.hash.0);
        rhs_hash.update(chunk_id.get().to_be_bytes());
        let rhs_hash: [u8; 32] = rhs_hash.finalize().try_into().unwrap();

        lhs_hash
            .iter_mut()
            .zip(rhs_hash.iter())
            .for_each(|(lhs, rhs)| *lhs ^= rhs);

        Self(lhs_hash)
    }
}

pub(crate) struct ChunksToDownload(BTreeMap<XorDistance, (ChunkId, bool)>, ReplicaLogger);

impl ChunksToDownload {
    pub(crate) fn new(log: &ReplicaLogger) -> Self {
        Self(BTreeMap::new(), log.clone())
    }

    // Add chunks to the chunks to download list
    pub(crate) fn add_chunks(
        &mut self,
        node_id: NodeId,
        artifact_id: StateSyncArtifactId,
        chunks: impl Iterator<Item = ChunkId>,
    ) -> usize {
        let mut added = 0;
        for chunk in chunks {
            let xor_distance = XorDistance::new(node_id, artifact_id.clone(), chunk);

            if let Entry::Vacant(entry) = self.0.entry(xor_distance) {
                entry.insert((chunk, false));
                added += 1;
            } else {
                info!(self.1, "STATE_SYNC: Attempt to double insert a chunk");
            }
        }

        added
    }

    pub(crate) fn next_chunk_to_download(&mut self) -> Option<ChunkId> {
        let next_chunk = self
            .0
            .iter_mut()
            .find(|(_, (_, downloading))| *downloading == false)?;

        next_chunk.1.1 = true;
        Some(next_chunk.1.0.clone())
    }

    pub(crate) fn download_finished(&mut self, chunk_id: ChunkId) {
        if let Some(key) = self.0.iter().find(|(_, (chunk, _))| *chunk == chunk_id) {
            let key = key.0.clone();
            self.0.remove(&key);
        }
    }

    pub(crate) fn download_failed(&mut self, chunk_id: ChunkId) {
        if let Some(next_chunk) = self.0.iter_mut().find(|(_, (chunk, _))| chunk == &chunk_id) {
            next_chunk.1.1 = false;
        }
    }

    pub(crate) fn next_xor_distance(&self) -> Option<XorDistance> {
        self.0.first_key_value().map(|(key, _)| key.clone())
    }

    pub(crate) fn num_entries(&self) -> usize {
        self.0.len()
    }
}

// TODO: Test XorMetric ordering
// TODO: Test Advert round trip
// TODO: Test malformed advert parsing
