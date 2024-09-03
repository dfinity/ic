mod checkpoint;
pub mod int_map;
mod page_allocator;
pub mod storage;
pub mod test_utils;

use bit_vec::BitVec;
pub use checkpoint::{CheckpointSerialization, MappingSerialization};
use ic_config::flag_status::FlagStatus;
use ic_config::state_manager::LsmtConfig;
use ic_metrics::buckets::{decimal_buckets, linear_buckets};
use ic_metrics::MetricsRegistry;
use ic_sys::{fs::write_all_vectored, PageBytes};
pub use ic_sys::{PageIndex, PAGE_SIZE};
use ic_utils::deterministic_operations::deterministic_copy_from_slice;
pub use page_allocator::{
    allocated_pages_count, PageAllocator, PageAllocatorRegistry, PageAllocatorSerialization,
    PageDeltaSerialization, PageSerialization,
};
pub use storage::{
    BaseFileSerialization, MergeCandidate, OverlayFileSerialization, Shard, StorageLayout,
    StorageResult, StorageSerialization, MAX_NUMBER_OF_FILES,
};
use storage::{OverlayFile, OverlayVersion, Storage};

use ic_types::{Height, NumOsPages, MAX_STABLE_MEMORY_IN_BYTES};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use int_map::{Bounds, IntMap};
use libc::off_t;
use page_allocator::Page;
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::ops::Range;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Arc;

// When persisting data we expand dirty pages to an aligned bucket of given size.
const WRITE_BUCKET_PAGES: u64 = 16;

const LABEL_OP: &str = "op";
const LABEL_TYPE: &str = "type";
const LABEL_OP_FLUSH: &str = "flush";
const LABEL_OP_MERGE: &str = "merge";
const LABEL_TYPE_PAGE_DATA: &str = "data";
const LABEL_TYPE_INDEX: &str = "index";

#[derive(Clone)]
pub struct StorageMetrics {
    /// How many bytes are written as part of storage operations, broken down by data vs index and merge vs flush.
    write_bytes: IntCounterVec,
    /// Timings of how long it takes to write overlay files.
    write_duration: HistogramVec,
    /// Number of overlays not written because they would have been empty.
    empty_delta_writes: IntCounter,
    /// For each merge, amount of input files we merged.
    num_merged_files: Histogram,
    /// The number of files in a shard before merging.
    num_files_by_shard: Histogram,
    /// The storage overhead of a shard before merging.
    storage_overhead_by_shard: Histogram,
}

impl StorageMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        let write_bytes = metrics_registry.int_counter_vec(
            "storage_layer_write_bytes",
            "Number of bytes written to disk, broken down by data vs index and merge vs flush.",
            &[LABEL_OP, LABEL_TYPE],
        );

        for op in &[LABEL_OP_FLUSH, LABEL_OP_MERGE] {
            for tp in &[LABEL_TYPE_PAGE_DATA, LABEL_TYPE_INDEX] {
                write_bytes.with_label_values(&[*op, *tp]);
            }
        }

        let write_duration = metrics_registry.histogram_vec(
            "storage_layer_write_duration_seconds",
            "Duration of write operation ('flush', 'merge').",
            // 100µs, 200µs, 500µs, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, …, 100s, 200s, 500s
            decimal_buckets(-4, 2),
            &[LABEL_OP],
        );

        for tp in &[LABEL_OP_FLUSH, LABEL_OP_MERGE] {
            write_duration.with_label_values(&[*tp]);
        }

        let empty_delta_writes = metrics_registry.int_counter(
            "storage_layer_empty_delta_writes",
            "The number of PageMaps that did not receive any deltas since the last write attempt.",
        );

        let num_merged_files = metrics_registry.histogram(
            "storage_layer_num_merged_files",
            "For each merge, number of input files we merged.",
            linear_buckets(0.0, 1.0, 20),
        );

        let num_files_by_shard = metrics_registry.histogram(
            "storage_layer_merge_num_files_by_shard",
            "Number of files per PageMap shard before merging.",
            linear_buckets(0.0, 1.0, 20),
        );

        let storage_overhead_by_shard = metrics_registry.histogram(
            "storage_layer_merge_storage_overhead_by_shard",
            "Storage overhead per PageMap shard before merging.",
            // Extra resolution in the 1 - 1.25 range.
            vec![
                0.5, 0.75, 1.0, 1.05, 1.1, 1.15, 1.2, 1.25, 1.3, 1.5, 1.75, 2.0, 2.25, 2.5, 3.0,
                3.5, 4.0, 4.5, 5.0, 6.0, 7.0,
            ],
        );

        Self {
            write_bytes,
            write_duration,
            empty_delta_writes,
            num_merged_files,
            num_files_by_shard,
            storage_overhead_by_shard,
        }
    }
}

struct WriteBuffer<'a> {
    content: Vec<&'a [u8]>,
    start_index: PageIndex,
}

impl<'a> WriteBuffer<'a> {
    fn apply_to_file(&mut self, file: &mut File, path: &Path) -> Result<(), PersistenceError> {
        use std::io::{Seek, SeekFrom};

        let offset = self.start_index.get() * PAGE_SIZE as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: format!("Failed to seek to {}", offset),
                internal_error: err.to_string(),
            })?;

        write_all_vectored(file, &self.content).map_err(|err| {
            PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: format!(
                    "Failed to copy page range #{}..{}",
                    self.start_index,
                    self.start_index.get() + self.content.len() as u64
                ),
                internal_error: err.to_string(),
            }
        })?;

        Ok(())
    }
}

/// `PageDelta` represents a changeset of the module heap.
///
/// NOTE: We use a persistent map to make snapshotting of a PageMap a cheap
/// operation. This allows us to simplify canister state management: we can
/// simply have a copy of the whole PageMap in every canister snapshot.
#[derive(Clone, Debug, Default)]
pub(crate) struct PageDelta(IntMap<Page>);

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

    /// Returns (lower, upper), where:
    /// - lower is the largest index/page smaller or equal to the given page index.
    /// - upper is the smallest index/page larger or equal to the given page index.
    fn bounds(&self, page_index: PageIndex) -> Bounds<PageIndex, Page> {
        let (lower, upper) = self.0.bounds(page_index.get());
        let map_index = |(k, v)| (PageIndex::new(k), v);
        (lower.map(map_index), upper.map(map_index))
    }

    /// Modifies this delta in-place by applying all the entries in `rhs` to it.
    fn update(&mut self, rhs: PageDelta) {
        self.0 = rhs.0.union(std::mem::take(&mut self.0));
    }

    /// Enumerates all the pages in this delta.
    fn iter(&self) -> impl Iterator<Item = (PageIndex, &'_ Page)> {
        self.0.iter().map(|(idx, page)| (PageIndex::new(idx), page))
    }

    /// Returns true if the page delta contains no pages.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the largest page index in the page delta.
    /// If the page delta is empty, then it returns `None`.
    fn max_page_index(&self) -> Option<PageIndex> {
        self.0.max_key().map(PageIndex::from)
    }

    /// Returns the number of pages in the page delta.
    fn len(&self) -> usize {
        self.0.len()
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
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
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
    /// Overlay data is broken.
    InvalidOverlay { path: String, message: String },
    /// (Slice) size is not equal to page size.
    BadPageSize { expected: usize, actual: usize },
    /// Some overlay file has a larger version number than the replica supports
    VersionMismatch {
        path: String,
        file_version: u32,
        supported: OverlayVersion,
    },
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
            PersistenceError::InvalidOverlay { path, message } => {
                write!(f, "Overlay file {} is broken: {}", path, message)
            }
            PersistenceError::BadPageSize { expected, actual } => write!(
                f,
                "Bad slice size: expected {}, actual {}",
                expected, actual
            ),
            PersistenceError::VersionMismatch {
                path,
                file_version,
                supported,
            } => write!(
                f,
                "Unsupported overlay version for {}: file version {}, max supported {:?}",
                path, file_version, supported,
            ),
        }
    }
}

/// A wrapper around the raw file descriptor to be used for memory mapping the
/// file into the Wasm heap while executing a canister.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct FileDescriptor {
    pub fd: RawFd,
}

/// A type alias for a raw offset within a file. It is not wrapped in a struct
/// to simplify arithmetic operations.
pub type FileOffset = off_t;

/// The result of the get_memory_instructions() function.
/// Contains sequence of `instructions` for either a range that can be memory mapped, or a data
/// that can be copied. The total range covered is given by `range`.
/// The ranges in `instructions` can overlap. To correctly apply the instructions they have to be applied
/// in order.
/// The vector can be empty, in which case nothing needs to be done.
/// Note: For an entry in `instructions` of the form `(range, Data(bytes))`, the lengths of range and bytes
/// will be consistent. For an entry of the form `(range, MemoryMap(fd, offset))` the length
/// of the memory map can be inferred from `range`.
#[derive(PartialEq, Debug)]
pub struct MemoryInstructions<'a> {
    pub range: Range<PageIndex>,
    pub instructions: Vec<MemoryInstruction<'a>>,
}

/// A single memory instruction for a range, see `MemoryInstructions`.
pub type MemoryInstruction<'a> = (Range<PageIndex>, MemoryMapOrData<'a>);

/// Description of range of pages.
/// See also `MemoryInstructions`.
#[derive(PartialEq, Debug)]
pub enum MemoryMapOrData<'a> {
    MemoryMap(FileDescriptor, usize),
    Data(&'a [u8]),
}

impl<'a> MemoryInstructions<'a> {
    // Filters and cuts any instructions that do not fall into `new_range`.
    pub fn restrict_to_range(&mut self, new_range: &Range<PageIndex>) {
        self.range = PageIndex::new(std::cmp::max(self.range.start.get(), new_range.start.get()))
            ..PageIndex::new(std::cmp::min(self.range.end.get(), new_range.end.get()));
        let instructions = std::mem::take(&mut self.instructions);
        self.instructions = instructions
            .into_iter()
            .filter_map(|(range, instruction)| {
                if range.end.get() <= self.range.start.get()
                    || range.start.get() >= self.range.end.get()
                {
                    // The entire instruction is outside of `new_range` and can be dropped.
                    None
                } else {
                    // Cut off from the left.
                    let (range, instruction) = if range.start.get() < self.range.start.get() {
                        let shift = (self.range.start.get() - range.start.get()) as usize;
                        let range = self.range.start..range.end;
                        match instruction {
                            MemoryMapOrData::MemoryMap(fd, offset) => (
                                range,
                                MemoryMapOrData::MemoryMap(fd, offset + shift * PAGE_SIZE),
                            ),
                            MemoryMapOrData::Data(data) => {
                                (range, MemoryMapOrData::Data(&data[(shift * PAGE_SIZE)..]))
                            }
                        }
                    } else {
                        (range, instruction)
                    };

                    // Cut off from the right.
                    let (range, instruction) = if range.end.get() > self.range.end.get() {
                        let shift = (range.end.get() - self.range.end.get()) as usize;
                        let range = range.start..self.range.end;
                        match instruction {
                            MemoryMapOrData::MemoryMap(fd, offset) => {
                                (range, MemoryMapOrData::MemoryMap(fd, offset))
                            }
                            MemoryMapOrData::Data(data) => {
                                debug_assert!(data.len() > shift * PAGE_SIZE);
                                (
                                    range,
                                    MemoryMapOrData::Data(
                                        &data[..(data.len() - shift * PAGE_SIZE)],
                                    ),
                                )
                            }
                        }
                    } else {
                        (range, instruction)
                    };

                    Some((range, instruction))
                }
            })
            .collect();
    }
}

/// `PageMap` is a data structure that represents an image of a canister virtual
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
#[derive(Clone, ValidateEq)]
pub struct PageMap {
    /// The checkpoint that is used for all the pages that can not be found in
    /// the `page_delta`.
    #[validate_eq(Ignore)]
    storage: Storage,

    /// The height of the checkpoint that backs the page map.
    #[validate_eq(Ignore)]
    pub base_height: Option<Height>,

    /// The map containing pages overriding pages from `storage`.
    /// We need these pages to be able to reconstruct the full heap.
    /// It is reset when `strip_all_deltas()` method is called.
    #[validate_eq(Ignore)]
    page_delta: PageDelta,

    /// The map containing deltas accumulated since the last flush to disk.
    /// It is reset when `strip_unflushed_delta()` or `strip_all_deltas()` methods are called.
    ///
    /// Invariant: unflushed_delta ⊆ page_delta
    #[validate_eq(Ignore)]
    unflushed_delta: PageDelta,

    #[validate_eq(Ignore)]
    has_stripped_unflushed_deltas: bool,

    /// The allocator for PageDelta pages.
    /// It is reset when `strip_all_deltas()` method is called.
    #[validate_eq(Ignore)]
    page_allocator: PageAllocator,
}

impl PageMap {
    /// Creates a new page map that always returns zeroed pages.
    /// The allocator of this page map is backed by the file descriptor
    /// the page map is instantiated with.
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self {
            storage: Default::default(),
            base_height: Default::default(),
            page_delta: Default::default(),
            unflushed_delta: Default::default(),
            has_stripped_unflushed_deltas: false,
            page_allocator: PageAllocator::new(fd_factory),
        }
    }

    /// Creates a new page map for testing purposes.
    pub fn new_for_testing() -> Self {
        Self {
            storage: Default::default(),
            base_height: Default::default(),
            page_delta: Default::default(),
            unflushed_delta: Default::default(),
            has_stripped_unflushed_deltas: false,
            page_allocator: PageAllocator::new_for_testing(),
        }
    }

    /// Creates a page map backed by the provided heap file.
    ///
    /// Note that the file is assumed to be read-only.
    pub fn open(
        storage_layout: &dyn StorageLayout,
        base_height: Height,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    ) -> Result<Self, PersistenceError> {
        Ok(Self {
            storage: Storage::load(storage_layout)?,
            base_height: Some(base_height),
            page_delta: Default::default(),
            unflushed_delta: Default::default(),
            has_stripped_unflushed_deltas: false,
            page_allocator: PageAllocator::new(fd_factory),
        })
    }

    /// Returns a serialization-friendly representation of the page-map.
    pub fn serialize(&self) -> PageMapSerialization {
        PageMapSerialization {
            storage: self.storage.serialize(),
            base_height: self.base_height,
            page_delta: self
                .page_allocator
                .serialize_page_delta(self.page_delta.iter()),
            unflushed_delta: self
                .page_allocator
                .serialize_page_delta(self.unflushed_delta.iter()),
            has_stripped_unflushed_deltas: self.has_stripped_unflushed_deltas,
            page_allocator: self.page_allocator.serialize(),
        }
    }

    /// Creates a page-map from the given serialization-friendly representation.
    /// The page allocator registry is needed to deduplicate page allocators
    /// such that each page allocator is deserialized at most once. Otherwise,
    /// two page allocators may share the same backing file and corrupt each
    /// other's data.
    pub fn deserialize(
        page_map: PageMapSerialization,
        registry: &PageAllocatorRegistry,
    ) -> Result<Self, PersistenceError> {
        let storage = Storage::deserialize(page_map.storage)?;
        let page_allocator = PageAllocator::deserialize(page_map.page_allocator, registry);
        let page_delta =
            PageDelta::from(page_allocator.deserialize_page_delta(page_map.page_delta));
        let unflushed_delta =
            PageDelta::from(page_allocator.deserialize_page_delta(page_map.unflushed_delta));
        Ok(Self {
            storage,
            base_height: page_map.base_height,
            page_delta,
            unflushed_delta,
            has_stripped_unflushed_deltas: page_map.has_stripped_unflushed_deltas,
            page_allocator,
        })
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
    /// Returns a list of dirty page indices and an indication of whether the
    /// page allocator was created or not, which is used for synchronization
    /// with the sandbox process.
    pub fn update(&mut self, pages: &[(PageIndex, &PageBytes)]) -> Vec<PageIndex> {
        let page_delta = self.page_allocator.allocate(pages);
        self.apply(page_delta);
        pages.iter().map(|(index, _)| *index).collect()
    }

    /// Persists the heap delta contained in this page map to the specified
    /// destination.
    pub fn persist_delta(
        &self,
        storage_layout: &dyn StorageLayout,
        height: Height,
        lsmt_config: &LsmtConfig,
        metrics: &StorageMetrics,
    ) -> Result<(), PersistenceError> {
        match lsmt_config.lsmt_status {
            FlagStatus::Disabled => self.persist_to_file(&self.page_delta, &storage_layout.base()),
            FlagStatus::Enabled => self.persist_to_overlay(
                &self.page_delta,
                storage_layout,
                height,
                lsmt_config,
                metrics,
            ),
        }
    }

    /// Persists the unflushed delta contained in this page map to the specified
    /// destination.
    pub fn persist_unflushed_delta(
        &self,
        storage_layout: &dyn StorageLayout,
        height: Height,
        lsmt_config: &LsmtConfig,
        metrics: &StorageMetrics,
    ) -> Result<(), PersistenceError> {
        match lsmt_config.lsmt_status {
            FlagStatus::Disabled => {
                self.persist_to_file(&self.unflushed_delta, &storage_layout.base())
            }
            FlagStatus::Enabled => self.persist_to_overlay(
                &self.unflushed_delta,
                storage_layout,
                height,
                lsmt_config,
                metrics,
            ),
        }
    }

    fn persist_to_overlay(
        &self,
        page_delta: &PageDelta,
        storage_layout: &dyn StorageLayout,
        height: Height,
        lsmt_config: &LsmtConfig,
        metrics: &StorageMetrics,
    ) -> Result<(), PersistenceError> {
        if !page_delta.is_empty() {
            OverlayFile::write(page_delta, storage_layout, height, lsmt_config, metrics)
        } else {
            metrics.empty_delta_writes.inc();
            Ok(())
        }
    }

    /// Returns the iterator over host pages managed by this `PageMap`.
    pub fn host_pages_iter(&self) -> impl Iterator<Item = (PageIndex, &PageBytes)> + '_ {
        (0..self.num_host_pages()).map(move |i| {
            let idx = PageIndex::from(i as u64);
            (idx, self.get_page(idx))
        })
    }

    /// Returns the iterator over delta pages in this `PageMap`
    pub fn delta_pages_iter(&self) -> impl Iterator<Item = (PageIndex, &PageBytes)> + '_ {
        self.page_delta
            .iter()
            .map(|(index, page)| (index, page.contents()))
    }

    /// Returns the page with the specified `page_index`.
    pub fn get_page(&self, page_index: PageIndex) -> &PageBytes {
        match self.page_delta.get_page(page_index) {
            Some(page) => page,
            None => self.storage.get_page(page_index),
        }
    }

    /// Returns a sequence of instructions on how to prepare a memory region. It always returns instructions for at least `min_range`,
    /// but the range can be as large as `max_range`. The result only extends past `min_range`, if it does not require any extra instructions
    /// to do so.
    /// Assumptions:
    ///       * `min_range` ⊆ `max_range`
    ///       * The entire memory has already been initialized according to `get_base_memory_instructions`
    ///       * MemoryInstructions are applied in the correct order, see description of `MemoryInstructions`
    /// Guarantees:
    ///       * `min_range` ⊆ result.range ⊆ `max_range`
    ///       * For any page in result.range, reading that page from the memory region is equal to calling
    ///         `get_page(page)`.
    pub fn get_memory_instructions(
        &self,
        min_range: Range<PageIndex>,
        max_range: Range<PageIndex>,
    ) -> MemoryInstructions {
        debug_assert!(min_range.start >= max_range.start && min_range.end <= max_range.end);

        let mut delta_instructions = Vec::new();

        // Grow result_range to the right.
        // If `include` is false, stop just short of the next delta page, otherwise include it into instructions.
        fn grow_right<'a>(
            page_delta: &'a PageDelta,
            instructions: &mut Vec<MemoryInstruction<'a>>,
            result_range: &mut Range<PageIndex>,
            max_range: &Range<PageIndex>,
            include: bool,
        ) {
            debug_assert!(result_range.end <= max_range.end);
            if result_range.end < max_range.end {
                let (_, upper_bound) = page_delta.bounds(result_range.end);
                match upper_bound {
                    Some((key, page)) if key < max_range.end => {
                        if include {
                            let end = PageIndex::new(key.get() + 1);
                            instructions.push((key..end, MemoryMapOrData::Data(page.contents())));
                            result_range.end = end;
                        } else {
                            result_range.end = key;
                        }
                    }
                    _ => result_range.end = max_range.end,
                }
            }
        }

        // Grow result_range to the left.
        // If `include` is false, stop just short of the next delta page, otherwise include it into instructions.
        // Never grows past `max_range`.
        fn grow_left<'a>(
            page_delta: &'a PageDelta,
            instructions: &mut Vec<MemoryInstruction<'a>>,
            result_range: &mut Range<PageIndex>,
            max_range: &Range<PageIndex>,
            include: bool,
        ) {
            debug_assert!(result_range.start >= max_range.start);
            if result_range.start > max_range.start {
                debug_assert!(result_range.start.get() > 0);
                let (lower_bound, _) =
                    page_delta.bounds(PageIndex::new(result_range.start.get() - 1));
                match lower_bound {
                    Some((key, page)) if key >= max_range.start => {
                        let end = PageIndex::new(key.get() + 1);
                        if include {
                            instructions.push((key..end, MemoryMapOrData::Data(page.contents())));
                            result_range.start = key;
                        } else {
                            result_range.start = end;
                        }
                    }
                    _ => result_range.start = max_range.start,
                }
            }
        }

        let mut result_range = min_range.start..min_range.start;

        // Find all deltas in min_range
        while result_range != min_range {
            grow_right(
                &self.page_delta,
                &mut delta_instructions,
                &mut result_range,
                &min_range, // Only grow to min_range in the first step.
                true,
            );
        }

        // Grow `result_range` to the edge of the next deltas, but do not include them.
        grow_left(
            &self.page_delta,
            &mut delta_instructions,
            &mut result_range,
            &max_range,
            false,
        );
        grow_right(
            &self.page_delta,
            &mut delta_instructions,
            &mut result_range,
            &max_range,
            false,
        );

        let mut filter = BitVec::from_elem(
            (result_range.end.get() - result_range.start.get()) as usize,
            false,
        );
        for (delta, _) in &delta_instructions {
            filter.set(
                (delta.start.get() - result_range.start.get()) as usize,
                true,
            );
        }

        let mut storage_instructions = self
            .storage
            .get_memory_instructions(result_range.clone(), &mut filter)
            .instructions;
        storage_instructions.extend(delta_instructions);

        // Find left and right cutoff point to have no instructions fully outside of `min_range`.
        let mut cut_left = result_range.start;
        for instruction in &storage_instructions {
            // We explicitly do not consider instructions that start within `min_range`,
            // and end outside, as they do not add additional instructions.
            if instruction.0.end.get() > cut_left.get()
                && instruction.0.end.get() <= min_range.start.get()
            {
                cut_left = instruction.0.end;
            }
        }
        let mut cut_right = result_range.end;
        for instruction in &storage_instructions {
            if instruction.0.start.get() < cut_right.get()
                && instruction.0.start.get() >= min_range.end.get()
            {
                cut_right = instruction.0.start;
            }
        }

        let result_range = cut_left..cut_right;

        let mut result = MemoryInstructions {
            range: result_range.clone(),
            instructions: storage_instructions,
        };

        result.restrict_to_range(&result_range);
        result
    }

    /// Returns how to memory map the base layer of this PageMap
    /// These instructions are generally cheap and are supposed to be used to initialize a memory region.
    /// The intention is that the instructions from this function are applied first and only once. The more expensive
    /// instructions from `get_memory_instructions(range)` are then applied on top.
    pub fn get_base_memory_instructions(&self) -> MemoryInstructions {
        self.storage.get_base_memory_instructions()
    }

    /// Removes the page delta from this page map.
    pub fn strip_all_deltas(&mut self, fd_factory: Arc<dyn PageAllocatorFileDescriptor>) {
        // Ensure that all pages are dropped before we drop the page allocator.
        // This is not necessary for correctness in the current implementation,
        // because page destructors are currently trivial. Nevertheless, it is
        // a good property to maintain.
        {
            std::mem::take(&mut self.page_delta);
            std::mem::take(&mut self.unflushed_delta);
        }
        self.page_allocator = PageAllocator::new(Arc::clone(&fd_factory));
    }

    /// Removes the unflushed delta from this page map.
    pub fn strip_unflushed_delta(&mut self) {
        self.has_stripped_unflushed_deltas = true;

        std::mem::take(&mut self.unflushed_delta);
    }

    pub fn get_page_delta_indices(&self) -> Vec<PageIndex> {
        self.page_delta.iter().map(|(index, _)| index).collect()
    }

    /// Whether there are any page deltas
    pub fn page_delta_is_empty(&self) -> bool {
        self.page_delta.is_empty()
    }

    /// Whether there are any unflushed deltas
    pub fn unflushed_delta_is_empty(&self) -> bool {
        self.unflushed_delta.is_empty()
    }

    /// Whether strip_unflushed_deltas has been called before
    pub fn has_stripped_unflushed_deltas(&self) -> bool {
        self.has_stripped_unflushed_deltas
    }

    /// Returns the length of the modified prefix in host pages.
    ///
    /// Also, the following property holds:
    ///
    /// ```text
    /// ∀ n . n ≥ self.num_host_pages() ⇒ self.get_page(n) = ZERO_PAGE
    /// ```
    pub fn num_host_pages(&self) -> usize {
        let pages_in_checkpoint = self.storage.num_logical_pages();
        pages_in_checkpoint.max(
            self.page_delta
                .max_page_index()
                .map(|i| i.get() + 1)
                .unwrap_or(0) as usize,
        )
    }

    /// Switches the checkpoint file of the current page map to the one provided
    /// by the given page map. Page deltas of both page maps must be empty.
    pub fn switch_to_checkpoint(&mut self, checkpointed_page_map: &PageMap) {
        self.storage = checkpointed_page_map.storage.clone();
        // Also copy the base height to reflect the height of the new checkpoint.
        self.base_height = checkpointed_page_map.base_height;
        assert!(self.page_delta.is_empty());
        assert!(self.unflushed_delta.is_empty());
        assert!(checkpointed_page_map.page_delta.is_empty());
        assert!(checkpointed_page_map.unflushed_delta.is_empty());
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
        self.unflushed_delta.update(delta)
    }

    /// Persists the given delta to the specified destination.
    fn persist_to_file(&self, page_delta: &PageDelta, dst: &Path) -> Result<(), PersistenceError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(dst)
            .map_err(|err| PersistenceError::FileSystemError {
                path: dst.display().to_string(),
                context: "Failed to open file".to_string(),
                internal_error: err.to_string(),
            })?;
        self.apply_delta_to_file(&mut file, page_delta, dst)?;
        Ok(())
    }

    /// Applies the given delta to the specified file.
    /// Precondition: `file` is seekable and writeable.
    fn apply_delta_to_file(
        &self,
        file: &mut File,
        page_delta: &PageDelta,
        path: &Path,
    ) -> Result<(), PersistenceError> {
        // Empty delta
        if page_delta.max_page_index().is_none() {
            return Ok(());
        }

        let mut last_applied_index: Option<PageIndex> = None;
        let num_host_pages = self.num_host_pages() as u64;
        for (index, _) in page_delta.iter() {
            debug_assert!(self.page_delta.0.get(index.get()).is_some());
            assert!(index < num_host_pages.into());

            if last_applied_index.is_some() && last_applied_index.unwrap() >= index {
                continue;
            }

            let bucket_start_index =
                PageIndex::from((index.get() / WRITE_BUCKET_PAGES) * WRITE_BUCKET_PAGES);
            let mut buffer = WriteBuffer {
                content: vec![],
                start_index: bucket_start_index,
            };
            for i in 0..WRITE_BUCKET_PAGES {
                let index_to_apply = PageIndex::from(bucket_start_index.get() + i);
                // We don't expand past the end of file to make bucketing transparent.
                if index_to_apply.get() < num_host_pages {
                    let content = self.get_page(index_to_apply);
                    buffer.content.push(content);
                    last_applied_index = Some(index_to_apply);
                }
            }
            buffer.apply_to_file(file, path)?;
        }

        Ok(())
    }

    /// Returns the number of delta pages included in this PageMap.
    pub fn num_delta_pages(&self) -> usize {
        self.page_delta.len()
    }
}

impl From<&[u8]> for PageMap {
    fn from(bytes: &[u8]) -> Self {
        let mut buf = Buffer::new(PageMap::new_for_testing());
        buf.write(bytes, 0);
        let mut page_map = PageMap::new_for_testing();
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
                .or_insert_with(|| *self.page_map.get_page(page));
            deterministic_copy_from_slice(
                &mut dirty_page[offset_into_page..offset_into_page + page_len],
                &src[0..page_len],
            );

            offset += page_len;
            src = &src[page_len..src.len()];
        }
    }

    /// Determines the number of dirty pages that would be created by a write at
    /// the given offset with the given size. This does not guarantee that the
    /// write will succeed.
    ///
    /// This function assumes the write doesn't extend beyond the maximum stable
    /// memory size (in which case the memory would fail anyway).
    pub fn dirty_pages_from_write(&self, offset: u64, size: u64) -> NumOsPages {
        if size == 0 {
            return NumOsPages::from(0);
        }
        let first_page = offset / (PAGE_SIZE as u64);
        let last_page = offset
            .saturating_add(size - 1)
            .min(MAX_STABLE_MEMORY_IN_BYTES)
            / (PAGE_SIZE as u64);
        let dirty_page_count = (first_page..=last_page)
            .filter(|p| !self.dirty_pages.contains_key(&PageIndex::new(*p)))
            .count();
        NumOsPages::new(dirty_page_count as u64)
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
/// need `unflushed_delta`, but the field is kept for consistency here.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct PageMapSerialization {
    pub storage: StorageSerialization,
    pub base_height: Option<Height>,
    pub page_delta: PageDeltaSerialization,
    pub unflushed_delta: PageDeltaSerialization,
    pub has_stripped_unflushed_deltas: bool,
    pub page_allocator: PageAllocatorSerialization,
}

/// Interface for generating unique file descriptors
/// that back the mmap-based page allocators instantiated by PageMaps
pub trait PageAllocatorFileDescriptor: Send + Sync + std::fmt::Debug {
    fn get_fd(&self) -> RawFd;
}

/// Simple implementation that can instantiate give file descriptors to temp file system
#[derive(Copy, Clone, Debug)]
pub struct TestPageAllocatorFileDescriptorImpl;

impl PageAllocatorFileDescriptor for TestPageAllocatorFileDescriptorImpl {
    fn get_fd(&self) -> RawFd {
        use std::os::unix::io::IntoRawFd;
        match tempfile::tempfile() {
            Ok(file) => file.into_raw_fd(),
            Err(err) => {
                panic!(
                    "TempPageAllocatorFileDescriptorImpl failed to create the backing file {}",
                    err
                )
            }
        }
    }
}

impl TestPageAllocatorFileDescriptorImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TestPageAllocatorFileDescriptorImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
