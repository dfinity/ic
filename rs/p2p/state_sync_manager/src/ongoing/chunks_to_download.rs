use crate::utils::XorDistance;
use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use ic_logger::{ReplicaLogger, info};
use ic_types::NodeId;
use std::collections::{BTreeMap, btree_map::Entry};

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
            .find(|(_, (_, downloading))| !downloading)?;

        next_chunk.1.1 = true;
        Some(next_chunk.1.0)
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
