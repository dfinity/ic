use crate::utils::XorDistance;
use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use ic_logger::{ReplicaLogger, info};
use ic_types::NodeId;
use std::collections::{BTreeMap, btree_map::Entry};

/// Maintains a list of chunks that are still be downloaded
pub(crate) struct ChunksToDownload {
    log: ReplicaLogger,
    chunks: BTreeMap<XorDistance, ChunkToDownload>,
}

impl ChunksToDownload {
    pub(crate) fn new(log: &ReplicaLogger) -> Self {
        Self {
            log: log.clone(),
            chunks: BTreeMap::new(),
        }
    }

    // Add chunks to the chunks to download list
    pub(crate) fn add_chunks(
        &mut self,
        node_id: NodeId,
        artifact_id: StateSyncArtifactId,
        chunks: impl Iterator<Item = ChunkId>,
    ) -> usize {
        let mut added = 0;
        for chunk_id in chunks {
            let xor_distance = XorDistance::new(node_id, artifact_id.clone(), chunk_id);

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

    pub(crate) fn next_chunk_to_download(&mut self) -> Option<ChunkId> {
        let (_, next_chunk) = self
            .chunks
            .iter_mut()
            .find(|(_, chunk)| !chunk.downloading)?;

        next_chunk.downloading = true;
        Some(next_chunk.id)
    }

    pub(crate) fn download_finished(&mut self, chunk_id: ChunkId) {
        if let Some((key, _)) = self.chunks.iter().find(|(_, chunk)| chunk.id == chunk_id) {
            let key = key.clone();
            self.chunks.remove(&key);
        }
    }

    pub(crate) fn download_failed(&mut self, chunk_id: ChunkId) {
        if let Some((_, failed_chunk)) = self
            .chunks
            .iter_mut()
            .find(|(_, chunk)| chunk.id == chunk_id)
        {
            failed_chunk.downloading = false;
        }
    }

    pub(crate) fn next_xor_distance(&self) -> Option<XorDistance> {
        self.chunks.first_key_value().map(|(key, _)| key.clone())
    }

    pub(crate) fn num_entries(&self) -> usize {
        self.chunks.len()
    }
}

struct ChunkToDownload {
    id: ChunkId,
    downloading: bool,
}
