use std::{collections::BTreeMap, sync::Arc};

use ic_protobuf::{proxy::ProxyDecodeError, state::canister_state_bits::v1 as pb};
use ic_sys::{PageBytes, PageIndex, PAGE_SIZE};
use ic_types::{NumBytes, NumOsPages};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;

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

#[derive(Clone, Eq, PartialEq, Debug)]
struct ChunkInfo {
    /// Corresponds to an index in the list of chunks. The starting byte in the
    /// `PageMap` can be calculated by multiplying the index by the fixed size of
    /// each chunk.
    index: u64,

    /// Each chunk takes up a fixed amount of space in the `PageMap`, but the actual
    /// length of the chunk may be smaller.
    length: u64,
}

/// Uploaded chunks which can be assembled to create a Wasm module.
/// It is cheap to clone because the data is stored in a [`PageMap`].
#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct WasmChunkStore {
    #[validate_eq(Ignore)]
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

    pub fn keys(&self) -> impl Iterator<Item = &WasmChunkHash> {
        self.metadata.chunks.keys()
    }

    pub fn get_chunk_data(
        &self,
        chunk_hash: &WasmChunkHash,
    ) -> Option<impl Iterator<Item = &[u8]>> {
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

    /// Check all conditions for inserting this chunk are satisfied.  Invariant:
    /// If this returns [`Ok`], then [`Self::insert_chunk`] is guaranteed to
    /// succeed.
    pub fn can_insert_chunk(&self, max_size: NumBytes, chunk: &[u8]) -> Result<(), String> {
        if chunk.len() > CHUNK_SIZE as usize {
            return Err(format!(
                "Wasm chunk size {} exceeds the maximum chunk size of {}",
                chunk.len(),
                CHUNK_SIZE
            ));
        }
        if self.metadata.chunks.len() as u64 * CHUNK_SIZE >= max_size.get() {
            return Err(format!(
                "Wasm chunk store has already reached maximum capacity of {} bytes",
                max_size
            ));
        }
        Ok(())
    }

    pub fn insert_chunk(&mut self, max_size: NumBytes, chunk: &[u8]) -> Result<[u8; 32], String> {
        let hash = ic_crypto_sha2::Sha256::hash(chunk);

        // No changes needed if we already have the chunk
        if self.metadata.chunks.contains_key(&hash) {
            return Ok(hash);
        }

        self.can_insert_chunk(max_size, chunk)?;

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

        self.metadata.size += NumOsPages::from(PAGES_PER_CHUNK);
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

    pub fn from_checkpoint(data: PageMap, metadata: WasmChunkStoreMetadata) -> Self {
        Self { data, metadata }
    }

    fn page_index(chunk_index: u64) -> PageIndex {
        (chunk_index * PAGES_PER_CHUNK).into()
    }

    pub(crate) fn heap_delta(&self) -> NumBytes {
        NumBytes::from((self.data.num_delta_pages() * PAGE_SIZE) as u64)
    }
}

/// Mapping from chunk hash to location in the store. It is cheap to clone
/// because the size is limited to 100 entries.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct WasmChunkStoreMetadata {
    /// Maps each chunk to its chunk index and length.
    chunks: BTreeMap<WasmChunkHash, ChunkInfo>,
    /// Total size of the data in the chunk store.
    size: NumOsPages,
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
    use assert_matches::assert_matches;
    use ic_config::embedders::Config;

    fn get_chunk_as_vec(store: &WasmChunkStore, hash: WasmChunkHash) -> Vec<u8> {
        store
            .get_chunk_data(&hash)
            .unwrap()
            .fold(vec![], |mut result, page| {
                result.extend_from_slice(page);
                result
            })
    }

    // In order to make the metadata cheap to clone, we should ensure that the size
    // of the Map is limited to a small number of entries.
    #[test]
    fn wasm_chunk_store_cheap_clone() {
        assert!(Config::default().wasm_max_size / CHUNK_SIZE <= 100.into());
    }

    fn default_max_size() -> NumBytes {
        Config::default().wasm_max_size
    }

    #[test]
    fn store_and_retrieve_chunk() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = [1, 2, 3].repeat(10_000);
        let hash = store.insert_chunk(default_max_size(), &contents).unwrap();
        let round_trip_contents = get_chunk_as_vec(&store, hash);
        assert_eq!(contents, round_trip_contents);
    }

    #[test]
    fn store_and_retrieve_empty_chunk() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![];
        let hash = store.insert_chunk(default_max_size(), &contents).unwrap();
        let round_trip_contents = get_chunk_as_vec(&store, hash);
        assert_eq!(contents, round_trip_contents);
    }

    #[test]
    fn error_when_chunk_exceeds_size_limit() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; chunk_size().get() as usize + 1];
        let result = store.insert_chunk(default_max_size(), &contents);
        assert_eq!(
            result,
            Err("Wasm chunk size 1048577 exceeds the maximum chunk size of 1048576".to_string())
        );
    }

    #[test]
    fn can_insert_chunk_up_to_max_size() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; chunk_size().get() as usize];
        let result = store.insert_chunk(default_max_size(), &contents);
        assert_matches!(result, Ok(_));
    }

    #[test]
    fn can_insert_and_retrieve_multiple_chunks() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents1 = vec![0xab; 1024];
        let hash1 = store.insert_chunk(default_max_size(), &contents1).unwrap();
        let contents2 = vec![0x41; 1024];
        let hash2 = store.insert_chunk(default_max_size(), &contents2).unwrap();

        let round_trip_contents1 = get_chunk_as_vec(&store, hash1);
        assert_eq!(contents1, round_trip_contents1);

        let round_trip_contents2 = get_chunk_as_vec(&store, hash2);
        assert_eq!(contents2, round_trip_contents2);
    }

    fn two_chunk_max_size() -> NumBytes {
        NumBytes::from(2 * CHUNK_SIZE)
    }

    #[test]
    fn cant_grow_beyond_max_size() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; 1024];
        let _hash = store.insert_chunk(two_chunk_max_size(), &contents).unwrap();
        let contents = vec![0xbc; 1024];
        let _hash = store.insert_chunk(two_chunk_max_size(), &contents).unwrap();
        let contents = vec![0xcd; 1024];
        store
            .insert_chunk(two_chunk_max_size(), &contents)
            .unwrap_err();
    }

    #[test]
    fn inserting_same_chunk_doesnt_increase_size() {
        // Store only has space for two chunks
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; 1024];

        // We can insert the same chunk many times because it doesn't take up
        // new space in the store since it is already present.
        let _hash = store.insert_chunk(two_chunk_max_size(), &contents).unwrap();
        let _hash = store.insert_chunk(two_chunk_max_size(), &contents).unwrap();
        let _hash = store.insert_chunk(two_chunk_max_size(), &contents).unwrap();
        let _hash = store.insert_chunk(two_chunk_max_size(), &contents).unwrap();
    }

    #[test]
    fn inserting_existing_chunk_succeeds_when_full() {
        // Store only has space for two chunks
        let mut store = WasmChunkStore::new_for_testing();

        // We can insert the same chunk many times because it doesn't take up
        // new space in the store since it is already present.
        let _hash = store
            .insert_chunk(two_chunk_max_size(), &[0xab; 10])
            .unwrap();
        let _hash = store
            .insert_chunk(two_chunk_max_size(), &[0xcd; 10])
            .unwrap();
        // Store is now full, but inserting the same chunk again succeeds.
        let _hash = store
            .insert_chunk(two_chunk_max_size(), &[0xab; 10])
            .unwrap();
    }

    mod proptest_tests {
        use super::*;
        use proptest::collection::vec as prop_vec;
        use proptest::prelude::*;

        const MB: usize = 1024 * 1024;
        const MAX_SIZE: NumBytes = NumBytes::new(20 * MB as u64);

        proptest! {
            #[test]
            // Try chunks 2x as big as the size limit.
            // If all inserts below the size limit succeeded, we'd expect 50 *
            // .5 MiB = 25 MiB total. So set the max size below that to
            // evenutally hit the size limit.
            fn insert_result_matches_can_insert(vecs in prop_vec((any::<u8>(), 0..2 * MB), 100)) {
                let mut store = WasmChunkStore::new_for_testing();
                for (byte, length) in vecs {
                    let chunk = vec![byte; length];
                    let check = store.can_insert_chunk(MAX_SIZE, &chunk);
                    let hash = store.insert_chunk(MAX_SIZE, &chunk);
                    if hash.is_ok() {
                        assert_eq!(check, Ok(()));
                    } else {
                        assert_eq!(check.unwrap_err(), hash.unwrap_err());
                    }
                }
            }
        }
    }
}
