use ic_interfaces::p2p::state_sync::ChunkId;

/// Maintains a list of chunks that still need to be downloaded
pub(crate) struct ChunksToDownload {
    chunks: Vec<ChunkId>,
}

impl ChunksToDownload {
    pub(crate) fn new() -> Self {
        Self { chunks: vec![] }
    }

    /// Add chunks to the chunks to download list
    pub(crate) fn add_chunks(&mut self, chunks: impl Iterator<Item = ChunkId>) -> usize {
        let initial_len = self.chunks.len();
        self.chunks.extend(chunks);
        self.chunks.len() - initial_len
    }

    /// Pick the next chunk to download
    pub(crate) fn next_chunk_to_download(&mut self) -> Option<ChunkId> {
        self.chunks.pop()
    }

    /// Register a chunk download as failed, i.e. requeue the chunk
    pub(crate) fn download_failed(&mut self, chunk_id: ChunkId) {
        self.chunks.push(chunk_id);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}
