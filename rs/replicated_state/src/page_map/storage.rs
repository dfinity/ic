//! The storage module contains functionality to read and write PageMap files as they are
//! represented on disk, without any parts of a PageMap which are purely represented in memory.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::{Deref, DerefMut, Range},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use crate::page_map::{
    CheckpointSerialization, LABEL_OP_FLUSH, LABEL_OP_MERGE, LABEL_TYPE_INDEX,
    LABEL_TYPE_PAGE_DATA, MappingSerialization, MemoryInstruction, MemoryInstructions,
    MemoryMapOrData, PageDelta, PersistenceError, StorageMetrics,
    checkpoint::{Checkpoint, Mapping, ZEROED_PAGE},
};

use bit_vec::BitVec;
use ic_config::state_manager::LsmtConfig;
use ic_sys::{PAGE_SIZE, PageBytes, PageIndex};
use ic_types::Height;
use itertools::{Itertools, izip};
use phantom_newtype::{AmountOf, Id};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use strum_macros::{EnumCount, EnumIter};

/// The (soft) maximum of the number of overlay files.
/// There is no limit on the number of overlays while reading,
/// but we target this number with merges.
pub const MAX_NUMBER_OF_FILES: usize = 7;

/// For `get_memory_instructions`, any range with a size of up to that number
/// of pages will be copied, and larger ranges will be memory mapped instead.
const MAX_COPY_MEMORY_INSTRUCTION: u64 = 10;

/// The overlay version used for newly written overlays.
const CURRENT_OVERLAY_VERSION: OverlayVersion = OverlayVersion::V0;

/// The maximum supported overlay version for reading.
const MAX_SUPPORTED_OVERLAY_VERSION: OverlayVersion = OverlayVersion::V0;

/// Buffer size, in bytes, for writing data to disk.
const BUF_SIZE: usize = 16 * 1024 * 1024;

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    Deserialize,
    EnumCount,
    EnumIter,
    Serialize,
)]
pub enum OverlayVersion {
    /// The overlay file consists of 3 sections (from back to front):
    /// 1. Version: A single 32 bit little-endian unsigned integer containg the OverlayVersion.
    /// 2. Size: A 64 bit little-endian unsigned integer containing the number of pages in the overlay
    ///    file.
    /// 3. Index: Description of the pages contained in this Overlay. The index
    ///    is encoded as a series of contiguous ranges. For each range we
    ///    encode two numbers as 64 bit little-endian unsigned integers:
    ///
    ///    1. The `PageIndex` of the first page in the range.
    ///    2. The `PageIndex` past the last page in the range
    ///    3. The `FileIndex` (offset in PAGE_SIZE blocks) of the first page in the range.
    ///
    /// 4. Data: The data of any number of 4KB pages concatenated.
    ///
    /// Example: An overlay containing pages 5,6, and 10
    ///          [Data5][Data6][Data10]       [[5,7,0][10,11,2]]         [3]                 [0]
    ///              Data (3*4 KB)          Index (2*3*8 bytes)    Size (8 bytes)    Version (4 bytes)
    ///
    /// We can read the version and size based on offset from the end of the file, then knowing the
    /// data size we can parse the index.
    ///
    /// Note that the version, size and index are at the end, so that data pages are aligned with the page
    /// size, which is required to mmap them.
    V0 = 0,
}

/// Number of bytes to store the OverlayVersion.
const VERSION_NUM_BYTES: usize = 4;

/// Number of bytes storing the number of pages contained in an overlay file.
const SIZE_NUM_BYTES: usize = 8;

/// Number of bytes storing a range in an overlay file.
const PAGE_INDEX_RANGE_NUM_BYTES: usize = 24;

impl std::convert::TryFrom<u32> for OverlayVersion {
    type Error = ();

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        use strum::IntoEnumIterator;
        OverlayVersion::iter().nth(n as usize).ok_or(())
    }
}

/// BaseFile contains the oldest version of the data. As it has no underlaying layers, we can just
/// mmap all of it during loading.
#[derive(Clone)]
enum BaseFile {
    /// A base file simply contains pages from PageIndex(0) to PageIndex(n) for some n.
    /// The `Checkpoint` handles the full range of page indices, returning zeroes for pages > n.
    Base(Checkpoint),
    /// Overlay files optimized for fast mmapping, i.e. containing a single range.
    Overlay(Vec<OverlayFile>),
}

impl Default for BaseFile {
    fn default() -> Self {
        BaseFile::Base(Checkpoint::default())
    }
}

impl BaseFile {
    fn serialize(&self) -> BaseFileSerialization {
        match self {
            BaseFile::Base(base) => BaseFileSerialization::Base(base.serialize()),
            BaseFile::Overlay(overlay) => {
                BaseFileSerialization::Overlay(overlay.iter().map(|o| o.serialize()).collect())
            }
        }
    }
    pub fn deserialize(serialized: BaseFileSerialization) -> Result<Self, PersistenceError> {
        Ok(match serialized {
            BaseFileSerialization::Base(base) => BaseFile::Base(Checkpoint::deserialize(base)?),
            BaseFileSerialization::Overlay(overlays) => BaseFile::Overlay(
                overlays
                    .into_iter()
                    .map(OverlayFile::deserialize)
                    .collect::<Result<Vec<OverlayFile>, _>>()?,
            ),
        })
    }
}

/// Representation of PageMap files on disk after loading.
///
/// A `PageMap` is represented by at most one base file, and an arbitrarily high stack of overlay files,
/// sorted from oldest to newest.
///
/// For any page that appears in multiple overlay files, its contents are read
/// from the newest overlay containing the page.
/// The contents of pages that appear in no overlay file are read from `base`.
///
/// DO NOT IMPLEMENT CLONE TO ELIMINATE DOUBLE INITIALIZATION IN `Storage`
#[derive(Default)]
pub(crate) struct StorageImpl {
    /// The lowest level data we mmap during loading.
    base: BaseFile,
    /// Stack of overlay files, newest file last.
    overlays: Vec<OverlayFile>,
}

/// Validate that the overlay files are loadable.
pub fn validate(storage_layout: &dyn StorageLayout) -> Result<(), PersistenceError> {
    StorageImpl::load(storage_layout)?;
    Ok(())
}

/// Lazy loaded representation of `StorageImpl` (see above).
/// The `storage_layout` points to the files on disk, which are loaded at the first access.
/// The loaded `StorageImpl` is never modified or unloaded till `drop`, meaning we don't read
/// `storage_layout` ever again.
/// If `storage_layout` is `None` during load we construct `StorageLayout` with the default
/// constructor.
#[derive(Clone, Default)]
pub(crate) struct Storage {
    storage_layout: Arc<Mutex<Option<Box<dyn StorageLayout + Send + Sync>>>>,
    storage_impl: Arc<OnceLock<StorageImpl>>,
}

impl Storage {
    fn init_or_die(&self) -> &StorageImpl {
        self.storage_impl.get_or_init(|| {
            match std::mem::take(
                self.storage_layout
                    .lock()
                    .expect("Failed to lock storage_layout")
                    .deref_mut(),
            ) {
                None => Default::default(),
                Some(storage_layout) => StorageImpl::load(storage_layout.deref())
                    .expect("Failed to load storage layout"),
            }
        })
    }

    /// Whether the `storage_impl` is already loaded.
    pub fn is_loaded(&self) -> bool {
        self.storage_impl.get().is_some()
    }

    /// Create `Storage`.
    pub fn lazy_load(
        storage_layout: Box<dyn StorageLayout + Send + Sync>,
    ) -> Result<Self, PersistenceError> {
        Ok(Storage {
            storage_layout: Arc::new(Mutex::new(Some(storage_layout))),
            storage_impl: OnceLock::default().into(),
        })
    }

    pub fn get_page(&self, page_index: PageIndex) -> &PageBytes {
        self.init_or_die().get_page(page_index)
    }

    pub fn get_base_memory_instructions(&self) -> MemoryInstructions<'_> {
        self.init_or_die().get_base_memory_instructions()
    }

    pub fn get_memory_instructions(
        &self,
        range: Range<PageIndex>,
        filter: &mut BitVec,
    ) -> MemoryInstructions<'_> {
        self.init_or_die().get_memory_instructions(range, filter)
    }

    pub fn num_logical_pages(&self) -> usize {
        self.init_or_die().num_logical_pages()
    }

    pub fn serialize(&self) -> StorageSerialization {
        self.init_or_die().serialize()
    }

    pub fn deserialize(serialized_storage: StorageSerialization) -> Result<Self, PersistenceError> {
        let storage_impl = OnceLock::new();
        let _ = storage_impl.set(StorageImpl::deserialize(serialized_storage)?);
        Ok(Self {
            storage_layout: Arc::new(Mutex::new(None)),
            storage_impl: storage_impl.into(),
        })
    }
}

impl StorageImpl {
    pub fn load(storage_layout: &dyn StorageLayout) -> Result<Self, PersistenceError> {
        // For each shard, the oldest (i.e. lowest height) overlay belongs to `BaseFile` if it
        // consists of a single range.
        let base_file = storage_layout.base();
        let base_path = if base_file.exists() {
            Some(base_file)
        } else {
            None
        };
        let overlay_paths = storage_layout.existing_overlays().map_err(|err| {
            PersistenceError::FileSystemError {
                path: "".to_string(),
                context: "Failed to get overlays".to_string(),
                internal_error: err.to_string(),
            }
        })?;
        let mut shards_with_overlays = BTreeSet::<Shard>::new();
        let mut range_by_shard = BTreeMap::<Shard, Range<PageIndex>>::new();
        let mut base_overlays = Vec::<OverlayFile>::new();
        let mut overlays = Vec::<OverlayFile>::new();
        for path in overlay_paths.iter() {
            let overlay = OverlayFile::load(path)?;
            let start_page_index = overlay
                .index_iter()
                .next()
                .expect("Verified overlay cannot be empty")
                .start_page;
            let last_page_index = PageIndex::new(overlay.end_logical_pages() as u64);
            let shard = storage_layout.overlay_shard(path).unwrap();
            range_by_shard
                .entry(shard)
                .and_modify(|ref mut range| {
                    range.start = std::cmp::min(range.start, start_page_index);
                    range.end = std::cmp::max(range.end, last_page_index);
                })
                .or_insert(start_page_index..last_page_index);
            // For each shard the lowest height version is a base, if it can be loaded fast.
            // It can be mmapped fast if it contains a single range, hence one mmap.
            if base_path.is_none()
                && !shards_with_overlays.contains(&shard)
                && overlay.index_iter().count() == 1
            {
                base_overlays.push(overlay);
            } else {
                overlays.push(overlay);
            }
            shards_with_overlays.insert(shard);
        }
        for prev_next in range_by_shard.values().collect::<Vec<_>>().windows(2) {
            if prev_next[0].end > prev_next[1].start {
                return Err(PersistenceError::InvalidOverlay {
                    path: overlay_paths[0].display().to_string(),
                    message: "Overlapping sharding".to_string(),
                });
            }
        }

        let base = match base_path.as_deref().map(Checkpoint::open).transpose()? {
            Some(base) => {
                assert!(base_overlays.is_empty());
                BaseFile::Base(base)
            }
            _ => BaseFile::Overlay(base_overlays),
        };

        Ok(Self { base, overlays })
    }

    pub fn get_page(&self, page_index: PageIndex) -> &PageBytes {
        let from_overlays = self
            .overlays
            .iter()
            .rev()
            .find_map(|overlay| overlay.get_page(page_index));
        match from_overlays {
            Some(bytes) => bytes,
            None => match &self.base {
                BaseFile::Base(base) => base.get_page(page_index),
                BaseFile::Overlay(overlays) => overlays
                    .iter()
                    .find_map(|overlay| overlay.get_page(page_index))
                    .unwrap_or(&ZEROED_PAGE),
            },
        }
    }

    /// For base overlays and regular base we pre-mmap all data in constructor.
    pub fn get_base_memory_instructions(&self) -> MemoryInstructions<'_> {
        match &self.base {
            BaseFile::Base(base) => base.get_memory_instructions(),
            BaseFile::Overlay(overlays) => MemoryInstructions {
                range: PageIndex::from(0)..PageIndex::from(u64::MAX),
                instructions: overlays
                    .iter()
                    .flat_map(|o| o.get_base_memory_instructions().instructions)
                    .collect(),
            },
        }
    }

    /// Memory instructions from the overlays for a range of indices.
    /// `filter` is a bit vector of which pages in `range` can be ignored (filter[0] refers to range.start).
    /// The filter mechanism is intended so that we don't unnecessarily copy data from lower layers if
    /// higher layers simply overwrite it with later memory instructions.
    /// We expect `filter` to mark all pages with page deltas.
    pub(crate) fn get_memory_instructions(
        &self,
        range: Range<PageIndex>,
        filter: &mut BitVec,
    ) -> MemoryInstructions<'_> {
        let mut result = Vec::<MemoryInstruction>::new();

        for overlay in self.overlays.iter().rev() {
            // The order within the same overlay doesn't matter as they are nonoverlapping.
            result.append(&mut overlay.get_memory_instructions(range.clone(), filter));
        }

        // We reverse so that instructions from earlier layers appear earlier.
        // If multiple overlays contain instructions for the same page, the newest overlay's
        // data will end up in the buffer after applying the instructions in order.
        result.reverse();
        MemoryInstructions {
            range,
            instructions: result,
        }
    }

    /// Number of (logical) pages contained in this `Storage`.
    pub(crate) fn num_logical_pages(&self) -> usize {
        let base = match &self.base {
            BaseFile::Base(base) => base.num_pages(),
            BaseFile::Overlay(overlays) => overlays
                .iter()
                .map(|o| o.end_logical_pages())
                .max()
                .unwrap_or(0),
        };
        let overlays = self
            .overlays
            .iter()
            .map(|overlay| overlay.end_logical_pages())
            .max()
            .unwrap_or(0);
        base.max(overlays)
    }

    pub fn serialize(&self) -> StorageSerialization {
        StorageSerialization {
            base: self.base.serialize(),
            overlays: self.overlays.iter().map(|o| o.serialize()).collect(),
        }
    }

    pub fn deserialize(serialized_storage: StorageSerialization) -> Result<Self, PersistenceError> {
        Ok(Self {
            base: BaseFile::deserialize(serialized_storage.base)?,
            overlays: serialized_storage
                .overlays
                .into_iter()
                .map(OverlayFile::deserialize)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

/// A single overlay file describing a not necessarily exhaustive set of pages.
#[derive(Clone)]
pub struct OverlayFile {
    /// A memory map of the entire file.
    /// Invariant: `mapping` satisfies `check_correctness(&mapping)`.
    mapping: Arc<Mapping>,
}

impl OverlayFile {
    fn iter(&self) -> impl Iterator<Item = (PageIndex, &[u8])> {
        self.index_iter()
            .flat_map(
                |PageIndexRange {
                     start_page,
                     end_page,
                     start_file_index,
                 }| {
                    (start_page.get()..end_page.get()).map(move |index| {
                        (
                            PageIndex::new(index),
                            FileIndex::new(start_file_index.get() + index - start_page.get()),
                        )
                    })
                },
            )
            .map(|(index, offset)| {
                let page = get_page_in_mapping(&self.mapping, offset);
                // In a validated mapping, all file_indices from the index are within range.
                assert!(page.is_some());
                (index, page.unwrap().as_slice())
            })
    }

    /// Get the page at `page_index`.
    /// Returns `None` for pages not contained in this overlay.
    fn get_page(&self, page_index: PageIndex) -> Option<&PageBytes> {
        let position = self.get_file_index(page_index)?;
        get_page_in_mapping(&self.mapping, position)
    }

    /// Write a new overlay to the destination specified by `storage_layout` containing
    /// all pages from `delta`.
    /// The resulting overlay may consist of multiple shards.
    pub(crate) fn write(
        delta: &PageDelta,
        storage_layout: &dyn StorageLayout,
        height: Height,
        lsmt_config: &LsmtConfig,
        metrics: &StorageMetrics,
    ) -> Result<(), PersistenceError> {
        let _timer = metrics
            .write_duration
            .with_label_values(&[LABEL_OP_FLUSH])
            .start_timer();
        if delta.max_page_index().is_none() {
            return Ok(());
        }
        let max_index = delta.max_page_index().unwrap().get();
        let num_shards = num_shards(max_index + 1, lsmt_config);
        let mut page_data: Vec<Vec<&[u8]>> = vec![Vec::new(); num_shards as usize];
        let mut page_indices: Vec<Vec<PageIndex>> = vec![Vec::new(); num_shards as usize];

        for (index, data) in delta.iter() {
            let shard = index.get() / lsmt_config.shard_num_pages;
            page_data[shard as usize].push(data.contents());
            page_indices[shard as usize].push(*index);
        }

        for shard in 0..num_shards {
            write_overlay(
                &page_data[shard as usize],
                &page_indices[shard as usize],
                &storage_layout.overlay(height, Shard::new(shard)),
                metrics,
                LABEL_OP_FLUSH,
            )?
        }
        Ok(())
    }

    /// Load an overlay file from `path`.
    /// Returns an error if disk operations fail or the file does not have the format of an
    /// overlay file.
    pub fn load(path: &Path) -> Result<Self, PersistenceError> {
        let file = OpenOptions::new().read(true).open(path).map_err(|err| {
            PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Failed to open file".to_string(),
                internal_error: err.to_string(),
            }
        })?;
        let metadata = file
            .metadata()
            .map_err(|err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Failed to retrieve file metadata".to_string(),
                internal_error: err.to_string(),
            })?;
        let mapping = Mapping::new(file, metadata.len() as usize, Some(path))?.ok_or(
            PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: "Empty mapping for overlay's page_data; zero num_pages?".to_string(),
            },
        )?;

        check_mapping_correctness(&mapping, path)?;

        Ok(Self {
            mapping: Arc::new(mapping),
        })
    }

    /// Serialize the loaded overlay file for communication with sandboxes.
    pub fn serialize(&self) -> OverlayFileSerialization {
        OverlayFileSerialization {
            mapping: self.mapping.serialize(),
        }
    }

    /// Deserializes the loaded overlay file. For use by sandbox processes.
    pub fn deserialize(
        serialized_overlay: OverlayFileSerialization,
    ) -> Result<Self, PersistenceError> {
        let mapping = Mapping::deserialize(serialized_overlay.mapping)?.ok_or(
            PersistenceError::InvalidOverlay {
                path: "none".to_string(),
                message:
                    "Empty mapping for deserialized overlay's page_data during; zero num_pages?"
                        .to_string(),
            },
        )?;

        Ok(Self {
            mapping: Arc::new(mapping),
        })
    }

    /// Number of pages in this overlay file containing data.
    #[allow(dead_code)]
    pub fn num_pages(&self) -> usize {
        num_pages(&self.mapping)
    }

    /// The index as a slice.
    fn index_slice(&self) -> &[[[u8; 8]; 3]] {
        index_slice(&self.mapping)
    }

    /// The number of logical pages covered by this overlay file, i.e. the largest `PageIndex`
    /// contained + 1.
    fn end_logical_pages(&self) -> usize {
        PageIndexRange::from(self.index_slice().iter().last().unwrap())
            .end_page
            .get() as usize
    }

    /// For base overlays we mmap all content in constructor.
    fn get_base_memory_instructions(&self) -> MemoryInstructions<'_> {
        assert_eq!(self.index_iter().count(), 1);
        let page_index_range = self.index_iter().next().unwrap();
        MemoryInstructions {
            range: 0.into()..u64::MAX.into(),
            instructions: vec![(
                page_index_range.start_page..page_index_range.end_page,
                MemoryMapOrData::MemoryMap(
                    self.mapping.file_descriptor().clone(),
                    page_index_range.start_file_index.get() as usize,
                ),
            )],
        }
    }

    /// Get page index ranges overlapping with input `range`; clamp all fields of `PageIndexRange`
    /// if the overlap is partial.
    /// E.g. if the Index is [{2, 20, 0}, {25, 26, 18}, {30, 40, 19}] and `range` is (4, 31) return
    /// an iterator over     [{4, 20, 2}, {25, 26, 18}, {30, 31, 19}]
    fn get_overlapping_page_ranges(
        &self,
        range: Range<PageIndex>,
    ) -> impl Iterator<Item = PageIndexRange> + '_ {
        let slice = self.index_slice();
        // `range.start` cannot be contained in any index range before this index, no need to iterate over them.
        let start_slice_index =
            slice.partition_point(|probe| PageIndexRange::from(probe).end_page <= range.start);

        let range_end = range.end;
        (start_slice_index..slice.len())
            .map(|slice_index| PageIndexRange::from(&slice[slice_index]))
            .take_while(move |page_index_range| page_index_range.start_page < range_end)
            .map(move |page_index_range| {
                // Return intersection of `range` and `page_index_range`.
                let clamped_range = PageIndex::new(std::cmp::max(
                    page_index_range.start_page.get(),
                    range.start.get(),
                ))
                    ..PageIndex::new(std::cmp::min(
                        page_index_range.end_page.get(),
                        range.end.get(),
                    ));
                PageIndexRange {
                    start_page: clamped_range.start,
                    end_page: clamped_range.end,
                    start_file_index: FileIndex::from(
                        page_index_range.start_file_index.get() + clamped_range.start.get()
                            - page_index_range.start_page.get(),
                    ),
                }
            })
    }

    /// Get memory instructions for all pages in `range`.
    ///
    /// Page indices marked true in `filter` are omitted from the result where convenient.
    /// `filter` is modified to set all pages indices returned in the result to true.
    ///
    /// Also see `Storage::get_memory_instructions`.
    ///
    /// The algorithm is as follows:
    ///     1. Do a binary search in the index to find `range.start`.
    ///     2. Iterate over all `PageIndexRange`s until we reach `range.end`.
    ///     3. For each `PageIndexRange`
    ///        * If it contains many pages (> `MAX_COPY_MEMORY_INSTRUCTIONS`) not covered by `filter`,
    ///          include a memory instruction to mmap the entire `PageIndexRange`
    ///        * Otherwise include memory instructions to copy each page to covered by `filter`.
    fn get_memory_instructions(
        &self,
        range: Range<PageIndex>,
        filter: &mut BitVec,
    ) -> Vec<MemoryInstruction<'_>> {
        let mut result = Vec::<MemoryInstruction>::new();

        for page_index_range in self.get_overlapping_page_ranges(range.clone()) {
            // Count how many pages are not covered yet by `filter`.
            let range_start = range.start.get();
            let needed_pages = page_index_range
                .iter_page_indices()
                .filter(|page| {
                    !filter
                        .get(page.get() as usize - range_start as usize)
                        .expect("Page index is out of bound")
                })
                .count() as u64;

            if needed_pages > MAX_COPY_MEMORY_INSTRUCTION {
                // If we need many pages from the `page_index_range`, we mmap the entire range.
                let offset = page_index_range.start_file_index.get() as usize * PAGE_SIZE;
                result.push((
                    page_index_range.start_page..page_index_range.end_page,
                    MemoryMapOrData::MemoryMap(self.mapping.file_descriptor().clone(), offset),
                ));
            } else if needed_pages > 0 {
                // We copy the needed pages individually.
                for (page_index, file_index) in page_index_range.iter_page_and_file_indices() {
                    let filter_index = page_index.get() - range.start.get();
                    if filter
                        .get(filter_index as usize)
                        .expect("Page index is out of bound")
                    {
                        continue;
                    }
                    let page = get_page_in_mapping(&self.mapping, file_index);
                    // In a valid overlay file the file index is within range.
                    debug_assert!(page.is_some());
                    result.push((
                        page_index..PageIndex::new(page_index.get() + 1),
                        MemoryMapOrData::Data(page.unwrap()),
                    ));
                }
            }

            // Mark all new pages in `filter`.
            for page_index in page_index_range.iter_page_indices() {
                filter.set(page_index.get() as usize - range.start.get() as usize, true);
            }
        }
        result
    }

    /// The overlay version contained in the file.
    #[allow(dead_code)]
    fn version(&self) -> OverlayVersion {
        let result = try_version(&self.mapping);

        // We verify that this unwrap succeeds while loading the overlay.
        debug_assert!(result.is_ok());

        result.unwrap()
    }

    /// If `index` is present in this overlay, returns its `FileIndex`.
    fn get_file_index(&self, index: PageIndex) -> Option<FileIndex> {
        let slice = self.index_slice();
        slice
            .binary_search_by(|probe| {
                let probe = PageIndexRange::from(probe);
                if probe.start_page > index {
                    Ordering::Greater
                } else if probe.end_page <= index {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .map_or(None, |loc| {
                let index = PageIndexRange::from(&slice[loc]).file_index(index);
                debug_assert!(index.is_some());
                index
            })
    }

    /// Iterate over all ranges in the index.
    pub fn index_iter(&self) -> impl Iterator<Item = PageIndexRange> + '_ {
        self.index_slice().iter().map(PageIndexRange::from)
    }
}

impl std::fmt::Debug for OverlayFile {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_list().entries(self.index_iter()).finish()
    }
}

/// The index portion of the file as a slice of pairs of numbers, each describing
/// a range of pages.
/// See `OverlayVersion` for an explanation of how the index is structured.
fn index_slice(mapping: &Mapping) -> &[[[u8; 8]; 3]] {
    let full_slice = mapping.as_slice();
    let start = num_pages(mapping) * PAGE_SIZE;
    let end = full_slice.len() - VERSION_NUM_BYTES - SIZE_NUM_BYTES;

    let (prefix, slice, suffix) = unsafe { full_slice[start..end].align_to::<[[u8; 8]; 3]>() };
    // Prefix would be non-empty if the address wasn't u64-aligned, but mmap is always page-aligned.
    assert!(prefix.is_empty());
    // Suffix would be non-empty if the length (in bytes) isn't a multiple of 8*3, which would be a
    // bug in the loading step.
    assert!(suffix.is_empty());

    slice
}

/// Returns the page at `index`. None if `index` is too large.
fn get_page_in_mapping(mapping: &Mapping, index: FileIndex) -> Option<&PageBytes> {
    if index.get() < num_pages(mapping) as u64 {
        Some(mapping.get_page(PageIndex::new(index.get())))
    } else {
        None
    }
}

/// The version according to the mapping.
/// If the number in the file does not correspond with an enum value of `OverlayVersion`,
/// returns the raw number instead.
fn try_version(mapping: &Mapping) -> Result<OverlayVersion, u32> {
    let slice = mapping.as_slice();
    let le_bytes: [u8; VERSION_NUM_BYTES] = slice[(slice.len() - VERSION_NUM_BYTES)..]
        .try_into()
        .unwrap();
    let raw_version = u32::from_le_bytes(le_bytes);
    OverlayVersion::try_from(raw_version).map_err(|_| raw_version)
}

/// Number of pages in this overlay file containing data.
fn num_pages(mapping: &Mapping) -> usize {
    let slice = mapping.as_slice();

    // This condition is checked during loading before we first call this function.
    assert!(slice.len() >= VERSION_NUM_BYTES + SIZE_NUM_BYTES);
    let le_bytes: [u8; SIZE_NUM_BYTES] = slice
        [(slice.len() - VERSION_NUM_BYTES - SIZE_NUM_BYTES)..(slice.len() - VERSION_NUM_BYTES)]
        .try_into()
        .unwrap();
    u64::from_le_bytes(le_bytes) as usize
}

/// Check that the overlay mapping is valid.
///
/// 1) The index is present and less than the maximum supported version.
/// 2) The number of pages is present and consistent with the index.
///
/// For the index, check that all the ranges:
/// 1) Have positive length.
/// 2) Are backed by data within the [0; self.num_pages) interval in the overlay file.
/// 3) Don't overlap.
/// 4) Are not back-to-back, e.g. [2..4][4..9].
///
/// We should always check correctness before constructing an `OverlayFile`.
fn check_mapping_correctness(mapping: &Mapping, path: &Path) -> Result<(), PersistenceError> {
    if mapping.as_slice().len() < VERSION_NUM_BYTES {
        return Err(PersistenceError::InvalidOverlay {
            path: path.display().to_string(),
            message: "No version provided in overlay file".to_string(),
        });
    } else if mapping.as_slice().len() < VERSION_NUM_BYTES + SIZE_NUM_BYTES {
        return Err(PersistenceError::InvalidOverlay {
            path: path.display().to_string(),
            message: "No num_pages provided in overlay file".to_string(),
        });
    } else if mapping.as_slice().len()
        <= VERSION_NUM_BYTES + SIZE_NUM_BYTES + num_pages(mapping) * PAGE_SIZE
    {
        return Err(PersistenceError::InvalidOverlay {
            path: path.display().to_string(),
            message: "No index provided in overlay file".to_string(),
        });
    }

    // Safety: Cannot underflow as we would return an error above.
    let index_length = mapping.as_slice().len()
        - num_pages(mapping) * PAGE_SIZE
        - VERSION_NUM_BYTES
        - SIZE_NUM_BYTES;
    if !index_length.is_multiple_of(PAGE_INDEX_RANGE_NUM_BYTES) {
        return Err(PersistenceError::InvalidOverlay {
            path: path.display().to_string(),
            message: "Invalid index length".to_string(),
        });
    }

    match try_version(mapping) {
        Ok(v) if v <= MAX_SUPPORTED_OVERLAY_VERSION => (),
        Ok(v) => {
            return Err(PersistenceError::VersionMismatch {
                path: path.display().to_string(),
                file_version: v as u32,
                supported: MAX_SUPPORTED_OVERLAY_VERSION,
            });
        }
        Err(v) => {
            return Err(PersistenceError::VersionMismatch {
                path: path.display().to_string(),
                file_version: v,
                supported: MAX_SUPPORTED_OVERLAY_VERSION,
            });
        }
    };

    let slice = index_slice(mapping);
    // The first range should start at file_index 0
    if !slice.is_empty() {
        let entry = PageIndexRange::from(&slice[0]);
        if entry.start_file_index != FileIndex::from(0) {
            return Err(PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: format!(
                    "Broken overlay file: First PageIndexRange ({entry:?}) does not start at file_index 0",
                ),
            });
        }
    }
    for i in 0..slice.len() {
        let next_file_index = if i == slice.len() - 1 {
            FileIndex::from(num_pages(mapping) as u64)
        } else {
            PageIndexRange::from(&slice[i + 1]).start_file_index
        };
        let next_page_index = if i == slice.len() - 1 {
            None
        } else {
            Some(PageIndexRange::from(&slice[i + 1]).start_page)
        };
        let entry = PageIndexRange::from(&slice[i]);
        let has_error = if entry.start_file_index >= next_file_index
            || entry.end_page.get() - entry.start_page.get()
                != next_file_index.get() - entry.start_file_index.get()
        {
            true
        } else if let Some(next_page_index) = next_page_index {
            if next_page_index <= entry.start_page {
                true
            } else {
                let file_index_delta = next_file_index.get() - entry.start_file_index.get();
                let max_page_index_delta = next_page_index.get() - entry.start_page.get();
                // if file_index_delta == max_page_index_delta we have back to back ranges,
                // e.g. [0..2], [2..3]
                file_index_delta >= max_page_index_delta
            }
        } else {
            false
        };
        if has_error {
            return Err(PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: format!(
                    "Broken overlay file: PageIndexRange[{}], entry: {:?}, next_file_index: {}, \
                         next_page_index: {:?}, num_pages: {}",
                    i,
                    entry,
                    next_file_index,
                    next_page_index,
                    num_pages(mapping)
                ),
            });
        }
    }
    Ok(())
}

/// Too large files are hard to write within one checkpoint interval, so we split them into multiple
/// shards. E.g. if we need 400 GiB stable memory, we can write it as 8x50GiB files.
/// If a certain range has no data, we don't create the shard. E.g. if the 400GiB file shaded by
/// 50GiB only contains the last page, we would have only the shard number 7.
pub struct ShardTag {}
pub type Shard = AmountOf<ShardTag, u64>;
pub type StorageResult<T> = Result<T, Box<dyn std::error::Error + Send>>;

/// Provide information from `StateLayout` about paths of a specific `PageMap`.
pub trait StorageLayout {
    /// Base file path.
    fn base(&self) -> PathBuf;

    /// Path for overlay of given height.
    fn overlay(&self, height: Height, shard: Shard) -> PathBuf;

    /// All existing overlay files.
    fn existing_overlays(&self) -> StorageResult<Vec<PathBuf>>;

    /// Get the height of an existing overlay path.
    fn overlay_height(&self, overlay: &Path) -> StorageResult<Height>;

    /// Get the shard of an existing overlay path.
    fn overlay_shard(&self, overlay: &Path) -> StorageResult<Shard>;
}

impl dyn StorageLayout + '_ {
    pub fn storage_size_bytes(&self) -> StorageResult<u64> {
        let mut result = 0;
        for path in self.existing_files()? {
            result += std::fs::metadata(&path)
                .map_err(|err: _| {
                    Box::new(PersistenceError::FileSystemError {
                        path: path.display().to_string(),
                        context: format!("Failed get existing file length: {}", path.display()),
                        internal_error: err.to_string(),
                    }) as Box<dyn std::error::Error + Send>
                })?
                .len();
        }
        Ok(result)
    }

    /// Number of pages required to load the PageMap into memory.
    /// Implementation ignores the zero pages that we don't load, so it's the index of last page + 1.
    pub fn memory_size_pages(&self) -> StorageResult<usize> {
        let mut result = 0;
        if let Some(base) = self.existing_base() {
            result = (std::fs::metadata(&base)
                .map_err(|err: _| {
                    Box::new(PersistenceError::FileSystemError {
                        path: base.display().to_string(),
                        context: format!("Failed get existing file length: {}", base.display()),
                        internal_error: err.to_string(),
                    }) as Box<dyn std::error::Error + Send>
                })?
                .len() as usize)
                / PAGE_SIZE;
        }
        for overlay in self.existing_overlays()? {
            result = std::cmp::max(result, Self::num_overlay_logical_pages(&overlay)?);
        }
        Ok(result)
    }
    fn existing_base(&self) -> Option<PathBuf> {
        if self.base().exists() {
            Some(self.base().to_path_buf())
        } else {
            None
        }
    }

    // Base if any; then overlays old to new.
    fn existing_files(&self) -> StorageResult<Vec<PathBuf>> {
        Ok(self
            .existing_base()
            .into_iter()
            .chain(self.existing_overlays()?)
            .collect())
    }

    // Base if any; then relevant overlays old to new.
    fn existing_files_with_shard(&self, shard: Shard) -> StorageResult<Vec<PathBuf>> {
        let mut result: Vec<_> = self.existing_base().into_iter().collect();
        for overlay in self.existing_overlays()?.into_iter() {
            if self.overlay_shard(&overlay)? == shard {
                result.push(overlay)
            }
        }
        Ok(result)
    }

    // Read the number of memory pages from overlay.
    // Basically it's the index of the last page, which we read based on the offset from the end of
    // the file plus some error handling.
    fn num_overlay_logical_pages(overlay: &Path) -> StorageResult<usize> {
        let to_storage_err = |err: std::io::Error| -> Box<dyn std::error::Error + Send> {
            Box::new(PersistenceError::FileSystemError {
                path: overlay.display().to_string(),
                context: "Failed to get number of memory pages".to_string(),
                internal_error: err.to_string(),
            }) as Box<dyn std::error::Error + Send>
        };

        let mut file = OpenOptions::new()
            .read(true)
            .open(overlay)
            .map_err(to_storage_err)?;

        let mut version_buf = [0u8; VERSION_NUM_BYTES];
        file.seek(SeekFrom::End(-(VERSION_NUM_BYTES as i64)))
            .map_err(to_storage_err)?;
        file.read_exact(&mut version_buf).map_err(to_storage_err)?;
        static_assertions::const_assert_eq!(MAX_SUPPORTED_OVERLAY_VERSION as u32, 0);
        let version = u32::from_le_bytes(version_buf);
        if version > MAX_SUPPORTED_OVERLAY_VERSION as u32 {
            return Err(Box::new(PersistenceError::VersionMismatch {
                path: overlay.display().to_string(),
                file_version: version,
                supported: MAX_SUPPORTED_OVERLAY_VERSION,
            }) as Box<dyn std::error::Error + Send>);
        }

        let mut last_page_index_range_buf = [[0u8; 8]; 3];
        file.seek(SeekFrom::End(
            -((VERSION_NUM_BYTES + SIZE_NUM_BYTES + PAGE_INDEX_RANGE_NUM_BYTES) as i64),
        ))
        .map_err(to_storage_err)?;
        file.read_exact(last_page_index_range_buf.as_flattened_mut())
            .map_err(to_storage_err)?;
        let last_page_index_range = PageIndexRange::from(&last_page_index_range_buf);
        Ok(last_page_index_range.end_page.get() as usize)
    }
}

/// Whether to merge into a base file or an overlay.
#[derive(Clone, Eq, PartialEq, Debug)]
enum MergeDestination {
    /// Serialize as a base file.
    BaseFile(PathBuf),
    /// Serialize and split into shards of specified length. The `shard_paths` provide paths for each
    /// possible shard from 0 to `num_shards(page_map_size, shard_num_pages)`.
    MultiShardOverlay {
        shard_paths: Vec<PathBuf>,
        shard_num_pages: u64,
    },
    /// Serialize as a single overlay file.
    SingleShardOverlay(PathBuf),
}

/// `MergeCandidate` shows which files to merge into a single `PageMap`.
#[derive(Clone, Debug)]
pub struct MergeCandidate {
    /// Overlay files to merge.
    overlays: Vec<PathBuf>,
    /// Base to merge if any.
    base: Option<PathBuf>,
    /// File to create. The format is based on `MergeDestination` variant, either `Base` or
    /// `Overlay`.
    /// We merge all the data from `overlays` and `base` into it, and remove old files.
    dst: MergeDestination,
    /// Range of pages covered by this MergeCandidate.
    start_page: PageIndex,
    end_page: PageIndex,

    /// Number of overlays for this shard. Can be larger then `overlays.len() + base.len()` for a
    /// parital merge.
    num_files_before: u64,
    /// Size of shards related to this merge on disk. For a partial merge larger than
    /// `input_size_bytes`.
    storage_size_bytes_before: u64,
    /// Size of input files, i.e. size to read from disk during merge.
    input_size_bytes: u64,
}

/// Number of shards to serialize `num_pages` worth of data.
fn num_shards(num_pages: u64, lsmt_config: &LsmtConfig) -> u64 {
    num_pages / lsmt_config.shard_num_pages
        + if num_pages.is_multiple_of(lsmt_config.shard_num_pages) {
            0
        } else {
            1
        }
}

impl MergeCandidate {
    /// Size of page map covered by all the input files related to the shard; total size of
    /// page_map for `split_to_shards`
    pub fn page_map_size_bytes(&self) -> u64 {
        (self.end_page.get() - self.start_page.get()) * PAGE_SIZE as u64
    }

    /// Size of all the input files related to the shard.
    pub fn storage_size_bytes_before(&self) -> u64 {
        self.storage_size_bytes_before
    }

    /// Number of all the input files related to the shard.
    pub fn num_files_before(&self) -> u64 {
        self.num_files_before
    }

    /// Estimate for the shard size on disk after the merge.
    pub fn storage_size_bytes_after(&self) -> u64 {
        if self.is_full_merge() {
            // For a full merge we just serialize data to a single file.
            // We ignore index and version size here.
            self.page_map_size_bytes()
        } else {
            // For a partial merge all the overlays may have non-overlapping pages, in which case
            // we don't save any space.
            self.storage_size_bytes_before
        }
    }

    /// Estimate of disk write needed to apply the merge.
    pub fn write_size_bytes(&self) -> u64 {
        if self.is_full_merge() {
            // For a full merge we expand missing pages with zeroes, so we write all the pages.
            self.page_map_size_bytes()
        } else {
            // For a partial merge we don't expand with zeroes. If pages in input overlays don't
            // overlap we write all of them; there can be at most `page_map_size_bytes()` worth of
            // non-overlapping pages.
            std::cmp::min(self.page_map_size_bytes(), self.input_size_bytes)
        }
    }

    /// Is it a full merge down to the ground level.
    pub fn is_full_merge(&self) -> bool {
        self.num_files_before as usize == self.base.iter().len() + self.overlays.iter().len()
    }

    /// Create a `MergeCandidate` for the given overlays and base. The `MergeCandidate` has as dst
    /// either `dst_base` or `dst_overlay` depending on if we decided to make a partial (overlay) or a
    /// full (base) merge.
    /// If we apply the `MergeCandidate`, we must have up to `MAX_NUMBER_OF_FILES` files, forming a
    /// pyramid, each file size being greater or equal to sum of newer files on top, with the base file
    /// having to be 4 times the size of the newer files on top. For example:
    ///     Overlay_3   |x|
    ///     Overlay_2   |xx|
    ///     Overlay_1   |xxxxxx|
    ///     Base        |xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
    pub fn new(
        layout: &dyn StorageLayout,
        height: Height,
        num_pages: u64,
        lsmt_config: &LsmtConfig,
        metrics: &StorageMetrics,
    ) -> StorageResult<Vec<MergeCandidate>> {
        if layout.base().exists() && num_pages > lsmt_config.shard_num_pages {
            Self::split_to_shards(layout, height, num_pages, lsmt_config)
        } else {
            Self::merge_by_shard(layout, height, num_pages, lsmt_config, metrics)
        }
    }

    /// Merge all overlays to a single base file.
    pub fn merge_to_base(
        layout: &dyn StorageLayout,
        num_pages: u64,
    ) -> StorageResult<Option<MergeCandidate>> {
        let existing_overlays = layout.existing_overlays()?;
        let base_path = layout.base();
        if existing_overlays.is_empty() {
            Ok(None)
        } else {
            let storage_size = layout.storage_size_bytes()?;
            Ok(Some(MergeCandidate {
                overlays: existing_overlays.to_vec(),
                base: if base_path.exists() {
                    Some(base_path.clone())
                } else {
                    None
                },
                dst: MergeDestination::BaseFile(base_path),
                start_page: PageIndex::new(0),
                end_page: PageIndex::new(num_pages),
                num_files_before: layout.existing_files()?.len() as u64,
                storage_size_bytes_before: storage_size,
                input_size_bytes: storage_size,
            }))
        }
    }

    /// Merge data from `overlays` and `base` into `dst` and remove the input files.
    pub fn apply(&self, metrics: &StorageMetrics) -> Result<(), PersistenceError> {
        let _timer = metrics
            .write_duration
            .with_label_values(&[LABEL_OP_MERGE])
            .start_timer();
        let base: Option<Checkpoint> = match self.base {
            None => None,
            Some(ref path) => {
                let checkpoint = Checkpoint::open(path)?;
                std::fs::remove_file(path).map_err(|io_err| PersistenceError::FileSystemError {
                    path: path.display().to_string(),
                    context: "Could not remove base file before merge".to_string(),
                    internal_error: io_err.to_string(),
                })?;
                Some(checkpoint)
            }
        };

        let num_merged_files = self.overlays.len() + base.iter().count();
        metrics.num_merged_files.observe(num_merged_files as f64);

        let overlays: Vec<OverlayFile> = self
            .overlays
            .iter()
            .map(|path| OverlayFile::load(path))
            .collect::<Result<Vec<_>, PersistenceError>>()?;
        for path in &self.overlays {
            std::fs::remove_file(path).map_err(|io_err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Could not remove overlay file before merge".to_string(),
                internal_error: io_err.to_string(),
            })?;
        }
        let pages_with_indices = Self::merge_data(&base, &overlays);

        let (num_output_shards, shard_num_pages) = match &self.dst {
            MergeDestination::MultiShardOverlay {
                shard_paths,
                shard_num_pages,
            } => (shard_paths.len(), *shard_num_pages),
            MergeDestination::BaseFile(_) => (1, u64::MAX),
            MergeDestination::SingleShardOverlay(_) => (1, u64::MAX),
        };
        let mut page_data: Vec<Vec<&[u8]>> = vec![Vec::new(); num_output_shards];
        let mut page_indices: Vec<Vec<PageIndex>> = vec![Vec::new(); num_output_shards];
        // Group sorted `merged_iterator` by `page_index`. Elements within group are sorted by
        // priority; we need only the first element of each group.
        for (index, data) in pages_with_indices.into_iter() {
            assert!(index >= self.start_page);
            assert!(index < self.end_page);
            let shard = if num_output_shards > 1 {
                index.get() as usize / shard_num_pages as usize
            } else {
                0
            };
            page_indices[shard].push(index);
            page_data[shard].push(data);
        }

        match &self.dst {
            MergeDestination::MultiShardOverlay { shard_paths, .. } => {
                assert!(shard_paths.len() >= num_output_shards);
                for (page_indices, page_data, path) in
                    izip!(page_indices.into_iter(), page_data.into_iter(), shard_paths)
                {
                    let (page_data, page_indices) = if self.is_full_merge() {
                        expand_with_zeroes(&page_data, &page_indices, ExpandBeforeStart::No)
                    } else {
                        (page_data, page_indices)
                    };
                    write_overlay(&page_data, &page_indices, path, metrics, LABEL_OP_MERGE)?
                }
                Ok(())
            }
            MergeDestination::SingleShardOverlay(path) => {
                let (page_data, page_indices) = if self.is_full_merge() {
                    expand_with_zeroes(&page_data[0], &page_indices[0], ExpandBeforeStart::No)
                } else {
                    (page_data[0].clone(), page_indices[0].clone())
                };
                write_overlay(&page_data, &page_indices, path, metrics, LABEL_OP_MERGE)
            }
            MergeDestination::BaseFile(path) => write_base(
                &page_data[0],
                &page_indices[0],
                path,
                metrics,
                LABEL_OP_MERGE,
            ),
        }
    }

    /// Take all the data, merge and split into shards.
    fn split_to_shards(
        layout: &dyn StorageLayout,
        height: Height,
        num_pages: u64,
        lsmt_config: &LsmtConfig,
    ) -> StorageResult<Vec<MergeCandidate>> {
        let dst_overlays: Vec<_> = (0..num_shards(num_pages, lsmt_config))
            .map(|shard| layout.overlay(height, Shard::new(shard)).to_path_buf())
            .collect();
        debug_assert!(
            dst_overlays.len()
                >= layout
                    .existing_overlays()?
                    .iter()
                    .map(|p| layout.overlay_shard(p).unwrap().get() + 1)
                    .max()
                    .unwrap_or(0) as usize
        );

        let base = if layout.base().exists() {
            Some(layout.base().to_path_buf())
        } else {
            None
        };
        let storage_size = layout.storage_size_bytes()?;
        Ok(vec![MergeCandidate {
            overlays: layout.existing_overlays()?,
            base,
            dst: MergeDestination::MultiShardOverlay {
                shard_paths: dst_overlays,
                shard_num_pages: lsmt_config.shard_num_pages,
            },
            start_page: PageIndex::new(0),
            end_page: PageIndex::new(num_pages),
            num_files_before: layout.existing_files()?.len() as u64,
            storage_size_bytes_before: storage_size,
            input_size_bytes: storage_size,
        }])
    }

    /// Merge each shard individually. If whole pagemap fits into a single shard, also handle base
    /// as belonging to the zero shard; crash if base is shared by multiple shards.
    fn merge_by_shard(
        layout: &dyn StorageLayout,
        height: Height,
        num_pages: u64,
        lsmt_config: &LsmtConfig,
        metrics: &StorageMetrics,
    ) -> StorageResult<Vec<MergeCandidate>> {
        let existing_base = layout.existing_base();

        let mut result = Vec::new();
        let num_shards = num_shards(num_pages, lsmt_config);
        if existing_base.is_none() {
            debug_assert_eq!(
                num_shards,
                layout
                    .existing_overlays()?
                    .iter()
                    .map(|p| layout.overlay_shard(p).unwrap().get() + 1)
                    .max()
                    .unwrap_or(0)
            );
        } else {
            assert!(num_shards <= 1);
        }
        for shard in 0..num_shards {
            let shard = Shard::new(shard);

            let start_page = PageIndex::new(shard.get() * lsmt_config.shard_num_pages);
            let end_page =
                PageIndex::new(num_pages.min((shard.get() + 1) * lsmt_config.shard_num_pages));

            let existing_files = layout.existing_files_with_shard(shard)?;
            let file_lengths: Vec<u64> = existing_files
                .iter()
                .map(|path| {
                    Ok(std::fs::metadata(path)
                        .map_err(|err: _| {
                            Box::new(PersistenceError::FileSystemError {
                                path: path.display().to_string(),
                                context: format!(
                                    "Failed get existing file length: {}",
                                    path.display()
                                ),
                                internal_error: err.to_string(),
                            }) as Box<dyn std::error::Error + Send>
                        })?
                        .len())
                })
                .collect::<StorageResult<_>>()?;
            let existing_overlays = &existing_files[existing_base.iter().len()..];

            metrics
                .num_files_by_shard
                .observe(existing_files.len() as f64);

            if end_page.get() > start_page.get() {
                metrics.storage_overhead_by_shard.observe(
                    file_lengths.iter().sum::<u64>() as f64
                        / ((end_page.get() - start_page.get()) * PAGE_SIZE as u64) as f64,
                );
            }

            let Some(num_files_to_merge) = Self::num_files_to_merge(&file_lengths) else {
                continue;
            };
            let input_size_bytes = file_lengths.iter().rev().take(num_files_to_merge).sum();

            // If we merge all including base, `num_files_to_merge` is larger than the length of
            // `existing_overlays`, `saturating_sub` returns zero, and we merge all overlays without
            // skipping.
            let overlays: Vec<PathBuf> = existing_overlays
                .iter()
                .skip(existing_overlays.len().saturating_sub(num_files_to_merge))
                .cloned()
                .collect();

            // Merge all existing files and put all the data into a single base file.
            // Otherwise we create an overlay file.
            let base = if num_files_to_merge == file_lengths.len() {
                existing_base.clone()
            } else {
                None
            };
            result.push(MergeCandidate {
                overlays,
                base,
                dst: MergeDestination::SingleShardOverlay(layout.overlay(height, shard)),
                start_page,
                end_page,
                num_files_before: existing_files.len() as u64,
                storage_size_bytes_before: file_lengths.iter().sum(),
                input_size_bytes,
            })
        }
        Ok(result)
    }

    fn merge_data<'a>(
        existing_base: &'a Option<Checkpoint>,
        existing: &'a [OverlayFile],
    ) -> Vec<(PageIndex, &'a [u8])> {
        struct PageWithPriority<'a> {
            // Page index in the `PageMap`.
            page_index: PageIndex,
            page_data: &'a [u8],
            // Given the same `page_index`, we chose the data with the lowest priority to write.
            priority: usize,
        }

        let iterators_with_priority: Vec<Box<dyn Iterator<Item = PageWithPriority>>> = existing
            .iter()
            .rev()
            .enumerate()
            .map(|(priority, overlay)| {
                Box::new(
                    overlay
                        .iter()
                        .map(move |(page_index, page_data)| PageWithPriority {
                            page_index,
                            page_data,
                            priority,
                        }),
                ) as Box<dyn Iterator<Item = PageWithPriority>>
            })
            .chain(existing_base.as_ref().map(|checkpoint| {
                Box::new((0..checkpoint.num_pages()).map(move |index| {
                    let page_index = PageIndex::new(index as u64);
                    PageWithPriority {
                        page_index,
                        page_data: checkpoint.get_page(page_index).as_slice(),
                        priority: existing.len(),
                    }
                })) as Box<dyn Iterator<Item = PageWithPriority>>
            }))
            .collect();

        // Sort all iterators by `(page_index, priority)`. All sub-iterators in `iterators_with_priority`
        // are sorted by `page_index` and have the same priority. So all the sub-iterators are sorted
        // and the `merged_iterators` as well.
        let merged_iterator = iterators_with_priority
            .into_iter()
            .kmerge_by(|a, b| (a.page_index, a.priority) < (b.page_index, b.priority));

        // Group sorted `merged_iterator` by `page_index`. Elements within group are sorted by
        // priority; we need only the first element of each group.
        merged_iterator
            .group_by(|page_with_priority| page_with_priority.page_index)
            .into_iter()
            .map(move |(_, mut group)| {
                let page_with_priority = group
                    .next()
                    .expect("group_by is expected to create non-empty groups");
                (page_with_priority.page_index, page_with_priority.page_data)
            })
            .collect()
    }

    /// Number of files to merge to achieve the `MergeCandidate` criteria.
    /// The criteria is that each file has to be larger than the sum of the sizes of the newer files,
    /// with the base file having to be at least 4 times as large as the sum of the overlays.
    /// Also see the `MergeCandidate::new` documentation.
    /// If no merge is required, return `None`.
    fn num_files_to_merge(existing_lengths: &[u64]) -> Option<usize> {
        let mut merge_to_get_pyramid = 0;
        let mut sum = 0;
        for (i, len) in existing_lengths.iter().rev().enumerate() {
            let factor = if i == existing_lengths.len() - 1 {
                4
            } else {
                1
            };
            if sum * factor > *len {
                merge_to_get_pyramid = i + 1;
            }
            sum += len;
        }

        let result = std::cmp::max(
            merge_to_get_pyramid,
            // +1 because merge is going to create a file.
            (existing_lengths.len() + 1).saturating_sub(MAX_NUMBER_OF_FILES),
        );
        assert!(result <= existing_lengths.len());
        if result <= 1 { None } else { Some(result) }
    }
}

struct FileIndexTag;
/// Physical position of a page in an overlay file (smallest `PageIndex` has `FileIndex` 0, second smallest
/// has `FileIndex` 1).
type FileIndex = Id<FileIndexTag, u64>;

/// A representation of a range of `PageIndex` backed by an overlay file.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PageIndexRange {
    /// Start of the range in the `PageMap`, i.e. where to mmap to.
    start_page: PageIndex,
    /// End of the range in the `PageMap`.
    end_page: PageIndex,
    /// Offset of the range in the overlay file.
    start_file_index: FileIndex,
}

impl PageIndexRange {
    /// A `PageIndexRange` as it is serialized in the overlay file.
    fn bytes(&self) -> [u8; PAGE_INDEX_RANGE_NUM_BYTES] {
        let start = self.start_page.get().to_le_bytes();
        let end = self.end_page.get().to_le_bytes();
        let file_index = self.start_file_index.get().to_le_bytes();
        let mut result = [0; 24];
        result[..8].copy_from_slice(&start);
        result[8..16].copy_from_slice(&end);
        result[16..].copy_from_slice(&file_index);
        result
    }

    /// If a page is covered by this `PageIndexRange`, returns its `FileIndex`
    /// in the the overlay file.
    fn file_index(&self, index: PageIndex) -> Option<FileIndex> {
        if index < self.start_page || index >= self.end_page {
            None
        } else {
            Some(FileIndex::from(
                self.start_file_index.get() + index.get() - self.start_page.get(),
            ))
        }
    }

    fn iter_page_indices(&self) -> impl Iterator<Item = PageIndex> + '_ {
        (self.start_page.get()..self.end_page.get()).map(PageIndex::from)
    }

    fn iter_page_and_file_indices(&self) -> impl Iterator<Item = (PageIndex, FileIndex)> + '_ {
        (self.start_page.get()..self.end_page.get()).map(|i| {
            (
                PageIndex::from(i),
                FileIndex::from(i - self.start_page.get() + self.start_file_index.get()),
            )
        })
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.end_page.get() - self.start_page.get()
    }
}

impl From<&[[u8; 8]; 3]> for PageIndexRange {
    fn from(source: &[[u8; 8]; 3]) -> Self {
        let start_page = u64::from_le_bytes(source[0]).into();
        let end_page = u64::from_le_bytes(source[1]).into();
        let start_file_index = u64::from_le_bytes(source[2]).into();

        Self {
            start_page,
            end_page,
            start_file_index,
        }
    }
}

/// Convert a sorted list of `PageIndex` to a sorted list of `PageIndexRange`, combining
/// adjacent `PageIndex` to a single range.
fn group_pages_into_ranges(page_indices: &[PageIndex]) -> Vec<PageIndexRange> {
    page_indices
        .iter()
        .enumerate()
        // (element value) - (element index) stay the same for consecutive groups,
        // but differs for different groups.
        .group_by(|(i, page_index)| (page_index.get() as i64) - (*i as i64))
        .into_iter()
        .map(|(_, mut group)| {
            // Here we have all the original page indices enumerated and grouped into consecutive groups.
            // Each `group` is made of `(u64, PageIndex)` tuples, the u64 stands for index in the input
            // `page_indices`.
            let (start_file_index, start_page) = group.next().unwrap();
            let len = 1 + group.count(); // +1 because we already consumed one element of the iterator above.
            PageIndexRange {
                start_page: *start_page,
                end_page: PageIndex::from(start_page.get() + len as u64),
                start_file_index: FileIndex::from(start_file_index as u64),
            }
        })
        .collect()
}

/// Create a new file to write `PageMap` data to. Because we write asynchonously with execution we
/// open file with `O_DIRECT | O_DSYNC`, otherwise it tends to cause lock congestion in Qemu.
fn create_file_for_write(path: &Path) -> Result<File, PersistenceError> {
    let mut open_options = OpenOptions::new();
    open_options.write(true).create_new(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options
            .custom_flags(libc::O_DIRECT)
            .custom_flags(libc::O_DSYNC);
    }
    open_options
        .open(path)
        .map_err(|err| PersistenceError::FileSystemError {
            path: path.display().to_string(),
            context: "Failed to open file".to_string(),
            internal_error: err.to_string(),
        })
}

enum ExpandBeforeStart {
    Yes,
    No,
}

/// Expand gaps between ranges with zeroes, and also [0; start) if `expand_before_start` is YES.
fn expand_with_zeroes<'a>(
    pages: &[&'a [u8]],
    indices: &[PageIndex],
    expand_before_start: ExpandBeforeStart,
) -> (Vec<&'a [u8]>, Vec<PageIndex>) {
    if indices.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let start = match expand_before_start {
        ExpandBeforeStart::Yes => 0,
        ExpandBeforeStart::No => indices[0].get() as usize,
    };

    let mut result_pages = vec![
        &ZEROED_PAGE as &PageBytes as &[u8];
        (indices.last().unwrap().get() as usize - start) + 1
    ];
    let result_indices: Vec<_> = (start..indices.last().unwrap().get() as usize + 1)
        .map(|i| PageIndex::from(i as u64))
        .collect();
    assert_eq!(pages.len(), indices.len());
    for (page, index) in pages.iter().zip(indices) {
        result_pages[index.get() as usize - start] = page;
    }
    assert_eq!(result_pages.len(), result_indices.len());
    (result_pages, result_indices)
}

/// Write all the pages into their corresponding indices as a base file (dense storage).
fn write_base(
    pages: &[&[u8]],
    indices: &[PageIndex],
    path: &Path,
    metrics: &StorageMetrics,
    op_label: &str, // `LABEL_OP_FLUSH` or `LABEL_OP_MERGE`.
) -> Result<(), PersistenceError> {
    assert_eq!(pages.len(), indices.len());
    if pages.is_empty() {
        return Ok(());
    }
    let mut file = create_file_for_write(path)?;
    let (pages, _) = expand_with_zeroes(pages, indices, ExpandBeforeStart::Yes);

    write_pages(&mut file, &pages).map_err(|err| PersistenceError::FileSystemError {
        path: path.display().to_string(),
        context: format!("Failed to write base file {}", path.display()),
        internal_error: err.to_string(),
    })?;
    metrics
        .write_bytes
        .with_label_values(&[op_label, LABEL_TYPE_PAGE_DATA])
        .inc_by((pages.len() * PAGE_SIZE) as u64);
    Ok(())
}

/// Helper function to write the data section of an overlay file.
fn write_pages(file: &mut File, data: &Vec<&[u8]>) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    for page in data {
        if buf.len() + page.len() > BUF_SIZE {
            file.write_all(&buf)?;
            buf.clear();
        }
        buf.extend(*page);
    }
    file.write_all(&buf)?;
    Ok(())
}

/// Write an overlay file to `path`.
fn write_overlay(
    pages: &Vec<&[u8]>,
    indices: &[PageIndex],
    path: &Path,
    metrics: &StorageMetrics,
    op_label: &str, // `LABEL_OP_FLUSH` or `LABEL_OP_MERGE`
) -> Result<(), PersistenceError> {
    if pages.is_empty() {
        return Ok(());
    }
    let ranges_serialized = group_pages_into_ranges(indices)
        .into_iter()
        .map(|range| range.bytes())
        .fold(
            Vec::with_capacity(PAGE_INDEX_RANGE_NUM_BYTES * indices.len()),
            |mut data, slice| {
                data.extend(slice);
                data
            },
        );

    let mut file = create_file_for_write(path)?;

    write_pages(&mut file, pages).map_err(|err| PersistenceError::FileSystemError {
        path: path.display().to_string(),
        context: format!("Failed to write overlay file {}", path.display()),
        internal_error: err.to_string(),
    })?;

    file.write_all(&ranges_serialized)
        .map_err(|err| PersistenceError::FileSystemError {
            path: path.display().to_string(),
            context: format!("Failed to write overlay file {}", path.display()),
            internal_error: err.to_string(),
        })?;

    file.write_all(&(pages.len() as u64).to_le_bytes())
        .map_err(|err| PersistenceError::FileSystemError {
            path: path.display().to_string(),
            context: format!("Failed to write overlay file {}", path.display()),
            internal_error: err.to_string(),
        })?;

    file.write_all(&(CURRENT_OVERLAY_VERSION as u32).to_le_bytes())
        .map_err(|err| PersistenceError::FileSystemError {
            path: path.display().to_string(),
            context: format!("Failed to write overlay file {}", path.display()),
            internal_error: err.to_string(),
        })?;

    // Mark the file as readonly.
    let metadata = path
        .metadata()
        .map_err(|err| PersistenceError::FileSystemError {
            path: path.display().to_string(),
            context: format!("Failed to write overlay file {}", path.display()),
            internal_error: err.to_string(),
        })?;
    let mut permissions = metadata.permissions();
    if !permissions.readonly() {
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions).map_err(|err| {
            PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: format!("Failed to write overlay file {}", path.display()),
                internal_error: err.to_string(),
            }
        })?;
    }

    let data_size = pages.len() * PAGE_SIZE;
    let index_size = ranges_serialized.len() + 8;

    metrics
        .write_bytes
        .with_label_values(&[op_label, LABEL_TYPE_INDEX])
        .inc_by(index_size as u64);
    metrics
        .write_bytes
        .with_label_values(&[op_label, LABEL_TYPE_PAGE_DATA])
        .inc_by(data_size as u64);
    Ok(())
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum BaseFileSerialization {
    Base(CheckpointSerialization),
    Overlay(Vec<OverlayFileSerialization>),
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct StorageSerialization {
    pub base: BaseFileSerialization,
    pub overlays: Vec<OverlayFileSerialization>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OverlayFileSerialization {
    pub mapping: MappingSerialization,
}

#[cfg(any(test, feature = "fuzzing_code"))]
pub mod tests;
