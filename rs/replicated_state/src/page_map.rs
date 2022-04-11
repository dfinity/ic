mod checkpoint;
pub mod int_map;
mod page_allocator;

use checkpoint::Checkpoint;
pub use checkpoint::{CheckpointSerialization, MappingSerialization};
use ic_sys::PageBytes;
pub use ic_sys::{PageIndex, PAGE_SIZE};
use ic_utils::deterministic_operations::deterministic_copy_from_slice;
pub use page_allocator::{
    allocated_pages_count, PageAllocatorSerialization, PageDeltaSerialization, PageSerialization,
};
// Exported publicly for benchmarking.
pub use page_allocator::{DefaultPageAllocatorImpl, HeapBasedPageAllocator, PageAllocatorInner};
// NOTE: We use a persistent map to make snapshotting of a PageMap a cheap
// operation. This allows us to simplify canister state management: we can
// simply have a copy of the whole PageMap in every canister snapshot.
use ic_types::Height;
use int_map::IntMap;
use libc::off_t;
use page_allocator::{Page, PageAllocator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::ops::Range;
use std::os::unix::io::RawFd;
use std::path::Path;

/// `PageDelta` represents a changeset of the module heap.
#[derive(Clone, Default, Debug)]
struct PageDelta(IntMap<Page>);

impl PageDelta {
    /// Gets content of the page at the specified index.
    ///
    /// The given `page_allocator` must be the same as the one used for
    /// allocating pages in this `PageDelta`. It serves as a witness that
    /// the contents of the page is still valid.
    fn get_page(&self, page_index: PageIndex) -> Option<&PageBytes> {
        self.0.get(page_index.get()).map(|p| p.contents())
    }

    /// Returns a reference to the page at the specified index.
    fn get_page_ref(&self, page_index: PageIndex) -> Option<&Page> {
        self.0.get(page_index.get())
    }

    /// Gets an inclusive range of pages that contains the given page.
    fn bounds(&self, page_index: PageIndex) -> (Option<PageIndex>, Option<PageIndex>) {
        let (lower, upper) = self.0.bounds(page_index.get());
        (lower.map(PageIndex::new), upper.map(PageIndex::new))
    }

    /// Modifies this delta in-place by applying all the entries in `rhs` to it.
    fn update(&mut self, rhs: PageDelta) {
        self.0 = rhs.0.union(std::mem::take(&mut self.0));
    }

    /// Enumerates all the pages in this delta.
    fn iter(&self) -> impl Iterator<Item = (PageIndex, &'_ Page)> {
        self.0.iter().map(|(idx, page)| (PageIndex::new(idx), page))
    }

    /// Applies this delta to the specified file.
    /// Precondition: `file` is seekable and writeable.
    fn apply_to_file(&self, file: &mut File, path: &Path) -> Result<(), PersistenceError> {
        use std::io::{Seek, SeekFrom};

        for (index, page) in self.iter() {
            let offset = index.get() * PAGE_SIZE as u64;
            file.seek(SeekFrom::Start(offset as u64)).map_err(|err| {
                PersistenceError::FileSystemError {
                    path: path.display().to_string(),
                    context: format!("Failed to seek to {}", offset),
                    internal_error: err.to_string(),
                }
            })?;
            let mut contents = page.contents() as &[u8];
            std::io::copy(&mut contents, file).map_err(|err| {
                PersistenceError::FileSystemError {
                    path: path.display().to_string(),
                    context: format!("Failed to copy page #{}", index),
                    internal_error: err.to_string(),
                }
            })?;
        }
        Ok(())
    }

    /// Persists this delta to the specified destination.
    fn persist(&self, dst: &Path) -> Result<(), PersistenceError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(dst)
            .map_err(|err| PersistenceError::FileSystemError {
                path: dst.display().to_string(),
                context: "Failed to open file".to_string(),
                internal_error: err.to_string(),
            })?;
        self.apply_to_file(&mut file, dst)?;
        Ok(())
    }

    /// Persists this delta to the specified destination and flushes it.
    fn persist_and_sync(&self, dst: &Path) -> Result<(), PersistenceError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(dst)
            .map_err(|err| PersistenceError::FileSystemError {
                path: dst.display().to_string(),
                context: "Failed to open file".to_string(),
                internal_error: err.to_string(),
            })?;
        self.apply_to_file(&mut file, dst)?;
        file.sync_all()
            .map_err(|err| PersistenceError::FileSystemError {
                path: dst.display().to_string(),
                context: "Failed to sync file".to_string(),
                internal_error: err.to_string(),
            })?;
        Ok(())
    }

    /// Returns true if the page delta contains no pages.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<I> From<I> for PageDelta
where
    I: IntoIterator<Item = (PageIndex, Page)>,
{
    fn from(delta: I) -> Self {
        Self(delta.into_iter().map(|(i, p)| (i.get(), p)).collect())
    }
}

/// Errors that can happen when one saves or loads a PageMap.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PersistenceError {
    /// I/O error while interacting with the filesystem.
    FileSystemError {
        path: String,
        context: String,
        internal_error: String,
    },
    /// Error trying to memory map a file.
    MmapError {
        path: String,
        len: usize,
        internal_error: String,
    },
    /// File is not a multiple of the page size.
    InvalidHeapFile {
        path: String,
        file_size: usize,
        page_size: usize,
    },
    /// (Slice) size is not equal to page size.
    BadPageSize { expected: usize, actual: usize },
}

impl PersistenceError {
    pub fn is_invalid_heap_file(&self) -> bool {
        matches!(self, PersistenceError::InvalidHeapFile { .. })
    }
}

impl std::error::Error for PersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceError::FileSystemError {
                path,
                context,
                internal_error,
            } => {
                write!(
                    f,
                    "File system error for file {}: {} {}",
                    path, context, internal_error
                )
            }
            PersistenceError::MmapError { path, len, .. } => {
                write!(f, "Failed to memory map file {} of length {}", path, len)
            }
            PersistenceError::InvalidHeapFile {
                path,
                file_size,
                page_size,
            } => write!(
                f,
                "Size of heap file {} is {}, which is not a multiple of the page size {}",
                path, file_size, page_size
            ),
            PersistenceError::BadPageSize { expected, actual } => write!(
                f,
                "Bad slice size: expected {}, actual {}",
                expected, actual
            ),
        }
    }
}

/// A wrapper around the raw file descriptor to be used for memory mapping the
/// file into the Wasm heap while executing a canister.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileDescriptor {
    pub fd: RawFd,
}

/// A type alias for a raw offset within a file. It is not wrapped in a struct
/// to simplify arithmetic operations.
pub type FileOffset = off_t;

/// The result of the `get_memory_region(page_index)` function. It specifies the
/// largest contiguous page range that contains the given page such that all
/// pages share the same backing store. There are three possible cases:
/// - The page is not in the current `PageMap` and it is zero initialized.
/// - The page maps to the checkpoint file.
/// - The page is in the page delta of the current `PageMap`. In this case the
///   range is a singleton and its contents need to be copied out.
pub enum MemoryRegion<'a> {
    Zeros(Range<PageIndex>),
    BackedByFile(Range<PageIndex>, FileDescriptor),
    BackedByPage(&'a PageBytes),
}

/// PageMap is a data structure that represents an image of a canister virtual
/// memory.  The memory is viewed as a collection of _pages_. `PageMap` uses
/// 4KiB host OS pages to track the heap contents, not 64KiB Wasm pages.
///
/// The map only contains the "modified prefix" of the heap.  Modified prefix is
/// the minimal continuous range of the memory pages a canister ever written
/// data to.  E.g., if a canister only issued XXX.load instructions to addresses
/// belonging to pages {0, 1, 5, 100}, its modified prefix is the content of
/// pages [0,100], and the length of the modified prefix in pages is 101.
///
/// If a canister Wasm module requested more memory (say, 200 pages) but never
/// accessed it, it won't be explicitly stored in the `PageMap`.
///
/// `PageMap` is designed to be cheap to copy so that heap can be easily
/// versioned.
#[derive(Clone, Default)]
pub struct PageMap {
    /// The checkpoint that is used for all the pages that can not be found in
    /// the `page_delta`.
    checkpoint: Checkpoint,

    /// The height of the checkpoint that backs the page map.
    pub base_height: Option<Height>,

    /// The map containing pages overriding pages from the `checkpoint`.
    /// We need these pages to be able to reconstruct the full heap.
    /// It is reset when `strip_all_deltas()` method is called.
    page_delta: PageDelta,

    /// The map containing deltas accumulated since the beginning of the
    /// execution round.  It is reset when `strip_round_delta()` or
    /// `strip_all_deltas()` methods are called.
    ///
    /// Invariant: round_delta ⊆ page_delta
    round_delta: PageDelta,

    /// The allocator for PageDelta pages.
    /// It is reset when `strip_all_deltas()` method is called.
    page_allocator: PageAllocator,
}

impl PageMap {
    /// Creates a new page map that always returns zeroed pages.
    pub fn new() -> Self {
        // Ensure that the hardcoded constant matches the OS page size.
        assert_eq!(ic_sys::sysconf_page_size(), PAGE_SIZE);
        Default::default()
    }

    /// Creates a page map backed by the provided heap file.
    ///
    /// Note that the file is assumed to be read-only.
    pub fn open(heap_file: &Path, base_height: Option<Height>) -> Result<Self, PersistenceError> {
        let checkpoint = Checkpoint::open(heap_file)?;
        Ok(Self {
            checkpoint,
            base_height,
            page_delta: Default::default(),
            round_delta: Default::default(),
            page_allocator: Default::default(),
        })
    }

    /// Returns a serialization-friendly representation of the page-map.
    pub fn serialize(&self) -> PageMapSerialization {
        PageMapSerialization {
            checkpoint: self.checkpoint.serialize(),
            base_height: self.base_height,
            page_delta: self
                .page_allocator
                .serialize_page_delta(self.page_delta.iter()),
            round_delta: self
                .page_allocator
                .serialize_page_delta(self.round_delta.iter()),
            page_allocator: self.page_allocator.serialize(),
        }
    }

    /// Creates a page-map from the given serialization-friendly representation.
    pub fn deserialize(page_map: PageMapSerialization) -> Result<Self, PersistenceError> {
        let checkpoint = Checkpoint::deserialize(page_map.checkpoint)?;
        let page_allocator = PageAllocator::deserialize(page_map.page_allocator);
        let page_delta =
            PageDelta::from(page_allocator.deserialize_page_delta(page_map.page_delta));
        let round_delta =
            PageDelta::from(page_allocator.deserialize_page_delta(page_map.round_delta));
        Ok(Self {
            checkpoint,
            base_height: page_map.base_height,
            page_delta,
            round_delta,
            page_allocator,
        })
    }

    /// Returns a serialization-friendly representation of the page allocator.
    pub fn serialize_allocator(&self) -> PageAllocatorSerialization {
        self.page_allocator.serialize()
    }

    /// Creates and sets the page allocator from the given
    /// serialization-friendly representation.
    pub fn deserialize_allocator(&mut self, page_allocator: PageAllocatorSerialization) {
        self.page_allocator = PageAllocator::deserialize(page_allocator);
    }

    /// Returns a serialization-friendly representation of the page delta.
    pub fn serialize_delta(&self, pages: &[PageIndex]) -> PageDeltaSerialization {
        self.page_allocator.serialize_page_delta(
            pages
                .iter()
                .map(|index| (*index, self.page_delta.get_page_ref(*index).unwrap())),
        )
    }

    /// Creates and applies the page delta from the given serialization-friendly
    /// representation.
    pub fn deserialize_delta(&mut self, page_delta: PageDeltaSerialization) {
        let page_delta = self.page_allocator.deserialize_page_delta(page_delta);
        self.apply(page_delta);
    }

    /// Modifies this page map by adding the given dirty pages to it.
    /// Returns a list of dirty page indicies and an indication of whether the
    /// page allocator was created or not, which is used for synchronization
    /// with the sandbox process.
    pub fn update(&mut self, pages: &[(PageIndex, &PageBytes)]) -> Vec<PageIndex> {
        let page_delta = self.page_allocator.allocate(pages);
        self.apply(page_delta);
        pages.iter().map(|(index, _)| *index).collect()
    }

    /// Persists the heap delta contained in this page map to the specified
    /// destination.
    pub fn persist_delta(&self, dst: &Path) -> Result<(), PersistenceError> {
        self.page_delta.persist(dst)
    }

    /// Persists the heap delta contained in this page map to the specified
    /// destination and fsync the file to disk.
    pub fn persist_and_sync_delta(&self, dst: &Path) -> Result<(), PersistenceError> {
        self.page_delta.persist_and_sync(dst)
    }

    /// Persists the round delta contained in this page map to the specified
    /// destination.
    pub fn persist_round_delta(&self, dst: &Path) -> Result<(), PersistenceError> {
        self.round_delta.persist(dst)
    }

    /// Returns the iterator over host pages managed by this `PageMap`.
    pub fn host_pages_iter(&self) -> impl Iterator<Item = (PageIndex, &PageBytes)> + '_ {
        (0..self.num_host_pages()).map(move |i| {
            let idx = PageIndex::from(i as u64);
            (idx, self.get_page(idx))
        })
    }

    /// Returns the page with the specified `page_index`.
    pub fn get_page(&self, page_index: PageIndex) -> &PageBytes {
        match self.page_delta.get_page(page_index) {
            Some(page) => page,
            None => self.checkpoint.get_page(page_index),
        }
    }

    /// Returns the largest contiguous range of pages that contains the given
    /// page such that all pages share the same backing store.
    pub fn get_memory_region(&self, page_index: PageIndex) -> MemoryRegion {
        match self.page_delta.get_page(page_index) {
            Some(page) => MemoryRegion::BackedByPage(page),
            None => {
                let (start, end) = self.page_delta.bounds(page_index);
                let start = match start {
                    None => PageIndex::new(0),
                    Some(start) => {
                        // Here `start` is a page in `page_delta`. We need to skip that page to
                        // get to the start of the checkpoint region that contains `page_index`.
                        PageIndex::new(start.get() + 1)
                    }
                };
                let end = match end {
                    None => PageIndex::new(u64::MAX),
                    Some(end) => {
                        // Here `end` is a page in `page_delta`. Since we will use it as the end of
                        // half-open `Range`, so we can take it as is without decrementing.
                        end
                    }
                };
                let range = Range { start, end };
                assert!(range.contains(&page_index));
                self.checkpoint.get_memory_region(page_index, range)
            }
        }
    }

    /// Returns the whole checkpoint memory region.
    pub fn get_checkpoint_memory_region(&self) -> MemoryRegion {
        let start = PageIndex::new(0);
        let end = PageIndex::new(u64::MAX);
        self.checkpoint
            .get_memory_region(start, Range { start, end })
    }

    /// Removes the page delta from this page map.
    pub fn strip_all_deltas(&mut self) {
        // Ensure that all pages are dropped before we drop the page allocator.
        // This is not necessary for correctness in the current implementation,
        // because page destructors are currently trivial. Nevertheless, it is
        // a good property to maintain.
        {
            std::mem::take(&mut self.page_delta);
            std::mem::take(&mut self.round_delta);
        }
        std::mem::take(&mut self.page_allocator);
    }

    /// Removes the round delta from this page map.
    pub fn strip_round_delta(&mut self) {
        std::mem::take(&mut self.round_delta);
    }

    pub fn get_page_delta_indices(&self) -> Vec<PageIndex> {
        self.page_delta.iter().map(|(index, _)| index).collect()
    }

    /// Returns the length of the modified prefix in host pages.
    ///
    /// Also, the following property holds:
    ///
    /// ```text
    /// ∀ n . n ≥ self.num_host_pages() ⇒ self.get_page(n) = ZERO_PAGE
    /// ```
    pub fn num_host_pages(&self) -> usize {
        let pages_in_checkpoint = self.checkpoint.num_pages();

        pages_in_checkpoint.max(
            self.page_delta
                .iter()
                .map(|(k, _v)| (k.get() + 1) as usize)
                .max()
                .unwrap_or(pages_in_checkpoint),
        )
    }

    /// Switches the checkpoint file of the current page map to the one provided
    /// by the given page map. Page deltas of both page maps must be empty.
    pub fn switch_to_checkpoint(&mut self, checkpointed_page_map: &PageMap) {
        self.checkpoint = checkpointed_page_map.checkpoint.clone();
        // Also copy the base height to reflect the height of the new checkpoint.
        self.base_height = checkpointed_page_map.base_height;
        assert!(self.page_delta.is_empty());
        assert!(self.round_delta.is_empty());
        assert!(checkpointed_page_map.page_delta.is_empty());
        assert!(checkpointed_page_map.round_delta.is_empty());
        // Keep the page allocators of the states disjoint.
    }

    // Modifies this page map by applying the given page delta to it.
    fn apply<I>(&mut self, delta: I)
    where
        I: IntoIterator<Item = (PageIndex, Page)>,
    {
        let delta = PageDelta::from(delta);
        // Delta is a persistent data structure and is cheap to clone.
        self.page_delta.update(delta.clone());
        self.round_delta.update(delta)
    }
}

impl From<&[u8]> for PageMap {
    fn from(bytes: &[u8]) -> Self {
        let mut buf = Buffer::new(PageMap::default());
        buf.write(bytes, 0);
        let mut page_map = PageMap::default();
        page_map.update(&buf.dirty_pages().collect::<Vec<_>>());
        page_map
    }
}

/// Buffer provides a file-like interface to a PageMap.
pub struct Buffer {
    page_map: PageMap,
    /// The map containing pages modified by the caller since this buffer was
    /// created. These pages can be modified in-place by the write method.
    ///
    /// Note: using a hash map here is beneficial for performance and doesn't
    /// affect determinism because the state machine has no way of observing the
    /// order of the keys in this map (or even inside of PageDelta for that
    /// matter).
    dirty_pages: HashMap<PageIndex, PageBytes>,
}

impl Buffer {
    /// Constructs a new buffer backed by the specified page map.
    pub fn new(page_map: PageMap) -> Self {
        Self {
            page_map,
            dirty_pages: HashMap::new(),
        }
    }

    /// Reads the contents of this buffer at the specified offset into the
    /// specified destination buffer.
    pub fn read(&self, mut dst: &mut [u8], mut offset: usize) {
        let page_size = PAGE_SIZE;

        while !dst.is_empty() {
            let page = PageIndex::new((offset / page_size) as u64);
            let offset_into_page = offset % page_size;
            let page_len = dst.len().min(page_size - offset_into_page);

            let page_contents = match self.dirty_pages.get(&page) {
                Some(bytes) => bytes,
                None => self.page_map.get_page(page),
            };
            deterministic_copy_from_slice(
                &mut dst[0..page_len],
                &page_contents[offset_into_page..offset_into_page + page_len],
            );

            offset += page_len;
            let n = dst.len();
            dst = &mut dst[page_len..n];
        }
    }

    /// Overwrites the contents of this buffer at the specified offset with the
    /// contents of the source buffer.
    pub fn write(&mut self, mut src: &[u8], mut offset: usize) {
        let page_size = PAGE_SIZE;

        while !src.is_empty() {
            let page = PageIndex::new((offset / page_size) as u64);
            let offset_into_page = offset % page_size;
            let page_len = src.len().min(page_size - offset_into_page);

            let dirty_page = self
                .dirty_pages
                .entry(page)
                .or_insert(*self.page_map.get_page(page));
            deterministic_copy_from_slice(
                &mut dirty_page[offset_into_page..offset_into_page + page_len],
                &src[0..page_len],
            );

            offset += page_len;
            src = &src[page_len..src.len()];
        }
    }

    pub fn dirty_pages(&self) -> impl Iterator<Item = (PageIndex, &PageBytes)> {
        self.dirty_pages.iter().map(|(i, p)| (*i, p))
    }

    pub fn into_page_map(&self) -> PageMap {
        let mut page_map = self.page_map.clone();
        page_map.update(&self.dirty_pages().collect::<Vec<_>>());
        page_map
    }
}

// We have to implement the equality by hand because the derived one
// is not correct: two page maps can be equal even if their
// checkpoints and deltas not equal. Example:
//
// `(C={(0, X), (1, Y)}, Δ={(1, Z)}) = (C={(0, X), (1, Z)}, Δ=∅)`
//
// So we compare the total number of pages and equality of each page
// instead.
impl PartialEq for PageMap {
    fn eq(&self, rhs: &PageMap) -> bool {
        if self.num_host_pages() != rhs.num_host_pages() {
            return false;
        }

        self.host_pages_iter().eq(rhs.host_pages_iter())
    }
}
impl Eq for PageMap {}

impl std::fmt::Debug for PageMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.num_host_pages();
        write!(f, "{{")?;
        (0..n)
            .map(|i| {
                let idx = PageIndex::from(i as u64);
                ic_utils::rle::display(self.get_page(idx))
            })
            .try_for_each(|s| write!(f, "[{:?}]", s))?;
        write!(f, "}}")
    }
}

/// Serialization-friendly representation of `PageMap`.
///
/// It contains sufficient information to reconstruct `PageMap`
/// in another process. Note that canister sandboxing does not
/// need `round_delta`, but the field is kept for consistency here.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PageMapSerialization {
    pub checkpoint: CheckpointSerialization,
    pub base_height: Option<Height>,
    pub page_delta: PageDeltaSerialization,
    pub round_delta: PageDeltaSerialization,
    pub page_allocator: PageAllocatorSerialization,
}

#[cfg(test)]
mod tests;
