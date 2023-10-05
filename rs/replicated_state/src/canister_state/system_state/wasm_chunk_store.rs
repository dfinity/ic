use std::{collections::BTreeMap, sync::Arc};

use ic_protobuf::{proxy::ProxyDecodeError, state::canister_state_bits::v1 as pb};
use ic_sys::{PageBytes, PageIndex, PAGE_SIZE};
use ic_types::{NumBytes, NumPages};

use crate::{page_map::PageAllocatorFileDescriptor, PageMap};

const PAGES_PER_CHUNK: u64 = 256;
const CHUNK_SIZE: u64 = PAGES_PER_CHUNK * (PAGE_SIZE as u64);

#[test]
fn check_chunk_size() {
    assert_eq!(1024 * 1024, CHUNK_SIZE);
}

pub type WasmChunkHash = [u8; 32];

pub fn chunk_size() -> NumBytes {
    NumBytes::from(CHUNK_SIZE)
}

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

    pub fn memory_usage(&self) -> NumBytes {
        NumBytes::from(self.metadata.size.get() * PAGE_SIZE as u64)
    }

    pub fn get_chunk_data(&self, chunk_hash: &[u8; 32]) -> Option<impl Iterator<Item = &[u8]>> {
        self.metadata
            .chunks
            .get(chunk_hash)
            .map(|ChunkInfo { index, length }| {
                let start_page = Self::page_index(*index).get();
                let end_page = start_page + PAGES_PER_CHUNK;
                (start_page..end_page).scan(*length, |bytes_remaining, page_index| {
                    if *bytes_remaining == 0 {
                        return None;
                    }
                    let bytes_read = std::cmp::min(*bytes_remaining, PAGE_SIZE as u64);
                    *bytes_remaining -= bytes_read;
                    Some(&self.data.get_page(PageIndex::from(page_index))[..bytes_read as usize])
                })
            })
    }

    pub fn insert_chunk(&mut self, chunk: &[u8]) -> Result<[u8; 32], String> {
        if chunk.len() > CHUNK_SIZE as usize {
            return Err(
                format! {"Wasm chunk size {} exceeds the maximum chunk size of {}", chunk.len(), CHUNK_SIZE},
            );
        }

        let hash = ic_crypto_sha2::Sha256::hash(chunk);

        let index = self.metadata.chunks.len() as u64;
        let start_page = Self::page_index(index);

        let mut pages = chunk.chunks(PAGE_SIZE);
        let last_page = pages.next_back().unwrap_or_default();

        // The last page in the chunk may be less than `PAGE_SIZE`, so we need
        // to copy the contents into an array that is long enough.
        let mut temp_last_page = [0; PAGE_SIZE];
        temp_last_page[..last_page.len()].copy_from_slice(last_page);

        let mut pages_to_insert: Vec<_> = pages
            .enumerate()
            .map(|(page_count, contents)| {
                let page_bytes = <&[u8] as TryInto<&PageBytes>>::try_into(contents).unwrap();
                (
                    PageIndex::from(start_page.get() + page_count as u64),
                    page_bytes,
                )
            })
            .collect();
        pages_to_insert.push((
            PageIndex::from(start_page.get() + pages_to_insert.len() as u64),
            &temp_last_page,
        ));

        self.metadata.size += NumPages::from(PAGES_PER_CHUNK);
        self.data.update(&pages_to_insert);
        self.metadata.chunks.insert(
            hash,
            ChunkInfo {
                index,
                length: chunk.len() as u64,
            },
        );

        Ok(hash)
    }

    pub(crate) fn from_checkpoint(data: PageMap, metadata: WasmChunkStoreMetadata) -> Self {
        Self { data, metadata }
    }

    fn page_index(chunk_index: u64) -> PageIndex {
        (chunk_index * PAGES_PER_CHUNK).into()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn get_chunk_as_vec(store: &WasmChunkStore, hash: WasmChunkHash) -> Vec<u8> {
        store
            .get_chunk_data(&hash)
            .unwrap()
            .fold(vec![], |mut result, page| {
                result.extend_from_slice(page);
                result
            })
    }

    #[test]
    fn store_and_retrieve_chunk() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = [1, 2, 3].repeat(10_000);
        let hash = store.insert_chunk(&contents).unwrap();
        let round_trip_contents = get_chunk_as_vec(&store, hash);
        assert_eq!(contents, round_trip_contents);
    }

    #[test]
    fn store_and_retrieve_empty_chunk() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![];
        let hash = store.insert_chunk(&contents).unwrap();
        let round_trip_contents = get_chunk_as_vec(&store, hash);
        assert_eq!(contents, round_trip_contents);
    }

    #[test]
    fn error_when_chunk_exceeds_size_limit() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; 1024 * 1024 + 1];
        let result = store.insert_chunk(&contents);
        assert_eq!(
            result,
            Err("Wasm chunk size 1048577 exceeds the maximum chunk size of 1048576".to_string())
        );
    }

    #[test]
    fn can_insert_and_retrieve_multiple_chunks() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents1 = vec![0xab; 1024];
        let hash1 = store.insert_chunk(&contents1).unwrap();
        let contents2 = vec![0x41; 1024];
        let hash2 = store.insert_chunk(&contents2).unwrap();

        let round_trip_contents1 = get_chunk_as_vec(&store, hash1);
        assert_eq!(contents1, round_trip_contents1);

        let round_trip_contents2 = get_chunk_as_vec(&store, hash2);
        assert_eq!(contents2, round_trip_contents2);
    }
}
