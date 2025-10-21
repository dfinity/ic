use std::{collections::BTreeMap, sync::Arc};

use ic_sys::{PAGE_SIZE, PageBytes, PageIndex};
use ic_types::{NumBytes, NumOsPages};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;

use crate::{PageMap, page_map::PageAllocatorFileDescriptor};

pub mod proto;

/// This is the _maximum_ chunk size. A chunk may take up as little space as
/// a single OS page. However, the cycles cost of maintaining a chunk in the
/// store is that of the maximum chunk size. Also, the capacity calculation
/// of the chunk store assumes every chunk is maximal, so that the number of
/// entries in the chunk store is limited to a small number, i.e.,
/// 'max_chunk_store_capacity' / CHUNK_SIZE = 100 entries.
pub const CHUNK_SIZE: u64 = 1024 * 1024;
/// Depends on the OS, because OS pages have different sizes.
const PAGES_PER_CHUNK: u64 = CHUNK_SIZE / (PAGE_SIZE as u64);

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

/// Struct wrapping a validated chunk with its hash to be inserted into the chunk store.
#[derive(Debug)]
pub struct ValidatedChunk {
    chunk: Vec<u8>,
    hash: WasmChunkHash,
}

impl ValidatedChunk {
    pub fn hash(&self) -> WasmChunkHash {
        self.hash
    }
}

/// The result of validating a chunk before it is inserted into the chunk store:
/// - the chunk is validated and supposed to be inserted later (after further checks, e.g., subnet available memory);
/// - the chunk already exists (its hash is returned to be included in the management canister call response);
/// - a validation error.
#[derive(Debug)]
pub enum ChunkValidationResult {
    Insert(ValidatedChunk),
    AlreadyExists(WasmChunkHash),
    ValidationError(String),
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
    ) -> Option<impl Iterator<Item = &[u8]> + use<'_>> {
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

    /// Returns the complete chunk as a single vector.
    ///
    /// Use `get_chunk_data` for paginated access.
    pub fn get_chunk_complete(&self, chunk_hash: &WasmChunkHash) -> Option<Vec<u8>> {
        self.get_chunk_data(chunk_hash).map(|pages| {
            pages.fold(vec![], |mut bytes, page| {
                bytes.extend_from_slice(page);
                bytes
            })
        })
    }

    /// Check all conditions for inserting this chunk are satisfied.
    pub fn can_insert_chunk(&self, max_size: NumBytes, chunk: Vec<u8>) -> ChunkValidationResult {
        let hash = ic_crypto_sha2::Sha256::hash(&chunk);
        if self.metadata.chunks.contains_key(&hash) {
            ChunkValidationResult::AlreadyExists(hash)
        } else if chunk.len() > CHUNK_SIZE as usize {
            ChunkValidationResult::ValidationError(format!(
                "Wasm chunk size {} exceeds the maximum chunk size of {}",
                chunk.len(),
                CHUNK_SIZE
            ))
        } else if self.metadata.chunks.len() as u64 * CHUNK_SIZE >= max_size.get() {
            ChunkValidationResult::ValidationError(format!(
                "Wasm chunk store has already reached maximum capacity of {} bytes or the maximum number of entries, {}",
                max_size,
                max_size.get() / CHUNK_SIZE
            ))
        } else {
            ChunkValidationResult::Insert(ValidatedChunk { chunk, hash })
        }
    }

    pub fn insert_chunk(&mut self, validated_chunk: ValidatedChunk) {
        let index = self.metadata.chunks.len() as u64;
        let start_page = Self::page_index(index);

        let mut pages = validated_chunk.chunk.chunks(PAGE_SIZE);
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
            validated_chunk.hash,
            ChunkInfo {
                index,
                length: validated_chunk.chunk.len() as u64,
            },
        );
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
/// This is because in the size calculation, every chunk is assumed to be
/// of maximal size (even if the user submitted smaller chunks).
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct WasmChunkStoreMetadata {
    /// Maps each chunk to its chunk index and length.
    chunks: BTreeMap<WasmChunkHash, ChunkInfo>,
    /// Total size of the data in the chunk store.
    size: NumOsPages,
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn insert_chunk(
        store: &mut WasmChunkStore,
        max_size: NumBytes,
        chunk: Vec<u8>,
    ) -> WasmChunkHash {
        let validated_chunk = match store.can_insert_chunk(max_size, chunk) {
            ChunkValidationResult::Insert(validated_chunk) => validated_chunk,
            res => panic!("Unexpected chunk validation result: {res:?}"),
        };
        let hash = validated_chunk.hash;
        store.insert_chunk(validated_chunk);
        hash
    }

    #[test]
    fn store_and_retrieve_chunk() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = [1, 2, 3].repeat(10_000);
        let hash = insert_chunk(&mut store, default_max_size(), contents.clone());
        let round_trip_contents = get_chunk_as_vec(&store, hash);
        assert_eq!(contents, round_trip_contents);
    }

    #[test]
    fn store_and_retrieve_empty_chunk() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![];
        let hash = insert_chunk(&mut store, default_max_size(), contents.clone());
        let round_trip_contents = get_chunk_as_vec(&store, hash);
        assert_eq!(contents, round_trip_contents);
    }

    #[test]
    fn error_when_chunk_exceeds_size_limit() {
        let store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; chunk_size().get() as usize + 1];
        let result = store.can_insert_chunk(default_max_size(), contents);
        match result {
            ChunkValidationResult::ValidationError(err) => assert_eq!(
                err,
                "Wasm chunk size 1048577 exceeds the maximum chunk size of 1048576".to_string()
            ),
            res => panic!("Unexpected chunk validation result: {res:?}"),
        };
    }

    #[test]
    fn can_insert_chunk_up_to_max_size() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; chunk_size().get() as usize];
        insert_chunk(&mut store, default_max_size(), contents);
    }

    #[test]
    fn can_insert_and_retrieve_multiple_chunks() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents1 = vec![0xab; 1024];
        let hash1 = insert_chunk(&mut store, default_max_size(), contents1.clone());
        let contents2 = vec![0x41; 1024];
        let hash2 = insert_chunk(&mut store, default_max_size(), contents2.clone());

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
        insert_chunk(&mut store, two_chunk_max_size(), contents);
        let contents = vec![0xbc; 1024];
        insert_chunk(&mut store, two_chunk_max_size(), contents);
        let contents = vec![0xcd; 1024];
        let result = store.can_insert_chunk(two_chunk_max_size(), contents);
        assert!(matches!(result, ChunkValidationResult::ValidationError(_)));
    }

    #[test]
    fn contains_chunk() {
        let mut store = WasmChunkStore::new_for_testing();
        let contents = vec![0xab; 1024];

        let hash = insert_chunk(&mut store, default_max_size(), contents.clone());
        match store.can_insert_chunk(default_max_size(), contents) {
            ChunkValidationResult::AlreadyExists(hash_from_validation) => {
                assert_eq!(hash_from_validation, hash)
            }
            res => panic!("Unexpected chunk validation result: {res:?}"),
        }
    }
}
