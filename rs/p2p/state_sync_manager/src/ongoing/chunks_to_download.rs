use ic_base_types::NodeId;
use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use std::collections::VecDeque;

/// Maintains a list of chunks that are still be downloaded
pub(crate) struct ChunksToDownload {
    chunks: VecDeque<ChunkId>,
}

impl ChunksToDownload {
    pub(crate) fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
        }
    }

    // Add chunks to the chunks to download list
    pub(crate) fn add_chunks(&mut self, chunks: impl Iterator<Item = ChunkId>) -> usize {
        let mut added = 0;
        for chunk_id in chunks {
            self.chunks.push_back(chunk_id);
            added += 1;
        }

        added
    }

    /// Pick the next chunk to download
    pub(crate) fn next_chunk_to_download(&mut self) -> Option<ChunkId> {
        self.chunks.pop_front()
    }

    /// Register a chunk download as failed, i.e. requeue the chunk
    pub(crate) fn download_failed(&mut self, chunk_id: ChunkId) {
        self.chunks.push_front(chunk_id);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}
