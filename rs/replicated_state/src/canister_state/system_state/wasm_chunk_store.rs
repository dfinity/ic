use std::{collections::BTreeMap, sync::Arc};

use ic_protobuf::{proxy::ProxyDecodeError, state::canister_state_bits::v1 as pb};
use ic_types::NumPages;

use crate::{page_map::PageAllocatorFileDescriptor, PageMap};

pub type WasmChunkHash = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChunkInfo {
    /// Corresponds to an index in the list of chunks. The starting byte in the
    /// `PageMap` can be calculated by multiplying the index by the fixed size of
    /// each chunk.
    index: u64,

    /// Each chunk takes up a fixed amount of space in the `PageMap`, but the actual
    /// length of the chunk may be smaller.
    length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmChunkStore {
    data: PageMap,
    metadata: WasmChunkStoreMetadata,
}

impl WasmChunkStore {
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self {
            data: PageMap::new(fd_factory),
            metadata: WasmChunkStoreMetadata::default(),
        }
    }

    /// Creates a new `WasmChunkStore` that will use the temp file system for
    /// allocating new pages.
    pub fn new_for_testing() -> Self {
        Self {
            data: PageMap::new_for_testing(),
            metadata: WasmChunkStoreMetadata::default(),
        }
    }

    pub fn page_map(&self) -> &PageMap {
        &self.data
    }

    pub fn page_map_mut(&mut self) -> &mut PageMap {
        &mut self.data
    }

    pub fn metadata(&self) -> &WasmChunkStoreMetadata {
        &self.metadata
    }

    pub(crate) fn from_checkpoint(data: PageMap, metadata: WasmChunkStoreMetadata) -> Self {
        Self { data, metadata }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WasmChunkStoreMetadata {
    /// Maps each chunk to its chunk index and length.
    chunks: BTreeMap<WasmChunkHash, ChunkInfo>,
    /// Total size of the data in the chunk store.
    size: NumPages,
}

impl From<&WasmChunkStoreMetadata> for pb::WasmChunkStoreMetadata {
    fn from(item: &WasmChunkStoreMetadata) -> Self {
        let chunks = item
            .chunks
            .iter()
            .map(|(hash, ChunkInfo { index, length })| pb::WasmChunkData {
                hash: hash.to_vec(),
                index: *index,
                length: *length,
            })
            .collect::<Vec<_>>();
        let size = item.size.get();
        pb::WasmChunkStoreMetadata { chunks, size }
    }
}

impl TryFrom<pb::WasmChunkStoreMetadata> for WasmChunkStoreMetadata {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::WasmChunkStoreMetadata) -> Result<Self, Self::Error> {
        let mut chunks = BTreeMap::new();
        for chunk in value.chunks {
            let hash: [u8; 32] =
                chunk
                    .hash
                    .try_into()
                    .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                        typ: "[u8; 32]",
                        err: format!("Failed to convert vector to fixed size arrary: {:?}", e),
                    })?;
            chunks.insert(
                hash,
                ChunkInfo {
                    index: chunk.index,
                    length: chunk.length,
                },
            );
        }

        let size = value.size.into();
        Ok(Self { chunks, size })
    }
}
