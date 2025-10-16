use crate::utils::XorDistance;
use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use ic_logger::{ReplicaLogger, info};
use ic_types::NodeId;
use std::collections::{BTreeMap, btree_map::Entry};

/// Maintains a list of chunks that are still be downloaded
pub(crate) struct ChunksToDownload {
    own_node_id: NodeId,
    artifact_id: StateSyncArtifactId,
    chunks: BTreeMap<XorDistance, ChunkToDownload>,
    log: ReplicaLogger,
}

impl ChunksToDownload {
    pub(crate) fn new(
        own_node_id: NodeId,
        artifact_id: StateSyncArtifactId,
        log: &ReplicaLogger,
    ) -> Self {
        Self {
            own_node_id,
            artifact_id,
            chunks: BTreeMap::new(),
            log: log.clone(),
        }
    }

    // Add chunks to the chunks to download list
    pub(crate) fn add_chunks(&mut self, chunks: impl Iterator<Item = ChunkId>) -> usize {
        let mut added = 0;
        for chunk_id in chunks {
            let xor_distance =
                XorDistance::new(self.own_node_id, self.artifact_id.clone(), chunk_id);

            if let Entry::Vacant(entry) = self.chunks.entry(xor_distance) {
                entry.insert(ChunkToDownload {
                    id: chunk_id,
                    downloading: false,
                });
                added += 1;
            } else {
                info!(self.log, "STATE_SYNC: Attempt to double insert a chunk");
            }
        }

        added
    }

    /// Pick the next chunk to download
    pub(crate) fn next_chunk_to_download(&mut self) -> Option<ChunkId> {
        let (_, next_chunk) = self
            .chunks
            .iter_mut()
            .find(|(_, chunk)| !chunk.downloading)?;

        next_chunk.downloading = true;
        Some(next_chunk.id)
    }

    /// Register a chunk as being downloaded
    pub(crate) fn download_finished(&mut self, chunk_id: ChunkId) {
        let xor_distance = XorDistance::new(self.own_node_id, self.artifact_id.clone(), chunk_id);
        self.chunks.remove(&xor_distance);
    }

    /// Register a chunk download as failed, i.e. requeue the chunk
    pub(crate) fn download_failed(&mut self, chunk_id: ChunkId) {
        let xor_distance = XorDistance::new(self.own_node_id, self.artifact_id.clone(), chunk_id);
        self.chunks
            .entry(xor_distance)
            .and_modify(|chunk| chunk.downloading = false);
    }

    pub(crate) fn next_xor_distance(&self) -> Option<XorDistance> {
        self.chunks.first_key_value().map(|(key, _)| key.clone())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

struct ChunkToDownload {
    id: ChunkId,
    downloading: bool,
}
