//! The storage module contains functionality to read and write PageMap files as they are
//! represented on disk, without any parts of a PageMap which are purely represented in memory.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Range,
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::page_map::{
    checkpoint::{Checkpoint, Mapping, ZEROED_PAGE},
    CheckpointSerialization, FileDescriptor, FileOffset, MappingSerialization, MemoryInstruction,
    MemoryInstructions, MemoryMapOrData, PageDelta, PersistDestination, PersistenceError,
    StorageMetrics, LABEL_OP_FLUSH, LABEL_OP_MERGE, LABEL_TYPE_INDEX, LABEL_TYPE_PAGE_DATA,
};

use bit_vec::BitVec;
use ic_sys::{mmap::ScopedMmap, PageBytes, PageIndex, PAGE_SIZE};
use ic_types::Height;
use itertools::Itertools;
use phantom_newtype::Id;
use serde::{Deserialize, Serialize};
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
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumCount,
    EnumIter,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum OverlayVersion {
    /// The overlay file consists of 3 sections (from back to front):
    /// 1. Version: A single 32 bit little-endian unsigned integer containg the OverlayVersion.
    /// 2. Size: A 64 bit little-endian unsigned integer containing the number of pages in the overlay
    ///          file.
    /// 3. Index: Description of the pages contained in this Overlay. The index
    ///           is encoded as a series of contiguous ranges. For each range we
    ///           encode two numbers as 64 bit little-endian unsigned integers:
    ///
    ///           1. The `PageIndex` of the first page in the range.
    ///           2. The `FileIndex` (offset in PAGE_SIZE blocks) of the first page in the range.
    ///
    /// 4. Data: The data of any number of 4KB pages concatenated.
    ///
    /// Example: An overlay containing pages 5,6, and 10
    ///          [Data5][Data6][Data10]       [[5,0][10,2]]         [3]                 [0]
    ///              Data (3*4 KB)          Index (4*8 bytes)  Size (8 bytes)    Version (4 bytes)
    ///
    /// In this example, we can infer that the first range has length 2, as the first range starts
    /// at file index 0, and the second range starts at file index 2. Similarly, the second range has
    /// length 1 as the range starts at file index 2, and the total number of pages is 3.
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
const INDEX_ENTRY_NUM_BYTES: usize = 16;

impl std::convert::TryFrom<u32> for OverlayVersion {
    type Error = ();

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        use strum::IntoEnumIterator;
        OverlayVersion::iter().nth(n as usize).ok_or(())
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
#[derive(Default, Clone)]
pub(crate) struct Storage {
    /// A base file simply contains pages from PageIndex(0) to PageIndex(n) for some n.
    /// The `Checkpoint` handles the full range of page indices, returning zeroes for pages > n.
    base: Checkpoint,
    /// Stack of overlay files, newest file last.
    overlays: Vec<OverlayFile>,
}

impl Storage {
    pub fn load(
        base_path: Option<&Path>,
        overlay_paths: &[PathBuf],
    ) -> Result<Self, PersistenceError> {
        let overlays: Vec<OverlayFile> = overlay_paths
            .iter()
            .map(|path| OverlayFile::load(path))
            .collect::<Result<Vec<_>, _>>()?;

        let base = if let Some(path) = base_path {
            Checkpoint::open(path)?
        } else {
            Checkpoint::empty()
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
            None => self.base.get_page(page_index),
        }
    }

    pub fn get_base_memory_instructions(&self) -> MemoryInstructions {
        self.base.get_memory_instructions()
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
    ) -> MemoryInstructions {
        let mut result = Vec::<MemoryInstruction>::new();

        for overlay in self.overlays.iter().rev() {
            // The order within the same overlay doesn't matter as they are nonoverlapping.
            result.append(
                &mut overlay
                    .get_memory_instructions(range.clone(), filter)
                    .instructions,
            );
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
        let base = self.base.num_pages();
        let overlays = self
            .overlays
            .iter()
            .map(|overlay| overlay.num_logical_pages())
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
            base: Checkpoint::deserialize(serialized_storage.base)?,
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
pub(crate) struct OverlayFile {
    /// Mapping containing the data section of the overlay file.
    mapping: Arc<Mapping>,
    /// The index section of the overlay file.
    index: Arc<OverlayIndices>,
    /// Version of the format.
    version: OverlayVersion,
}

impl OverlayFile {
    fn iter(&self) -> impl Iterator<Item = (PageIndex, &[u8])> {
        self.index
            .iter()
            .flat_map(
                |PageIndexRange {
                     start_page,
                     end_page,
                     start_file_index,
                 }| {
                    (start_page.get()..end_page.get()).map(move |index| {
                        (
                            PageIndex::new(index),
                            PageIndex::new(start_file_index.get() + index - start_page.get()),
                        )
                    })
                },
            )
            .map(|(index, offset)| (index, self.mapping.get_page(offset).as_slice()))
    }

    /// Get the page at `page_index`.
    /// Returns `None` for pages not contained in this overlay.
    fn get_page(&self, page_index: PageIndex) -> Option<&PageBytes> {
        let position = self.index.get_file_index(page_index)?;
        // For Mapping PageIndex and FileIndex mean the same thing.
        Some(self.mapping.get_page(PageIndex::from(position.get())))
    }

    /// Write a new overlay file to `path` containing all pages from `delta`.
    pub(crate) fn write(
        delta: &PageDelta,
        path: &Path,
        metrics: &StorageMetrics,
    ) -> Result<(), PersistenceError> {
        let _timer = metrics
            .write_duration
            .with_label_values(&[LABEL_OP_FLUSH])
            .start_timer();
        let max_size = delta.num_pages();
        let mut page_data: Vec<&[u8]> = Vec::with_capacity(max_size);
        let mut page_indices: Vec<PageIndex> = Vec::with_capacity(max_size);

        for (index, data) in delta.iter() {
            page_data.push(data.contents());
            page_indices.push(index);
        }

        write_overlay(&page_data, &page_indices, path, metrics, LABEL_OP_FLUSH)
    }

    /// Load an overlay file from `path`.
    /// Returns an error if disk operations fail or the file does not have the format of an
    /// overlay file.
    pub fn load(path: &Path) -> Result<Self, PersistenceError> {
        let mut file = OpenOptions::new().read(true).open(path).map_err(|err| {
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

        if metadata.len() < VERSION_NUM_BYTES as u64 {
            return Err(PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: "No version provided in overlay file".to_string(),
            });
        }
        file.seek(SeekFrom::End(-(VERSION_NUM_BYTES as i64)))
            .map_err(|err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Failed to seek for version".to_string(),
                internal_error: err.to_string(),
            })?;
        let mut buf: [u8; VERSION_NUM_BYTES] = [0; VERSION_NUM_BYTES];
        file.read_exact(&mut buf)
            .map_err(|err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Failed to read version".to_string(),
                internal_error: err.to_string(),
            })?;
        let raw_version = u32::from_le_bytes(buf);

        let version = match OverlayVersion::try_from(raw_version) {
            Ok(v) if v <= MAX_SUPPORTED_OVERLAY_VERSION => v,
            _ => {
                return Err(PersistenceError::VersionMismatch {
                    path: path.display().to_string(),
                    file_version: raw_version,
                    supported: MAX_SUPPORTED_OVERLAY_VERSION,
                });
            }
        };

        let version_and_size_num_bytes = VERSION_NUM_BYTES + SIZE_NUM_BYTES;

        if metadata.len() < version_and_size_num_bytes as u64 {
            return Err(PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: "No num_pages provided in overlay file".to_string(),
            });
        }
        file.seek(SeekFrom::End(-(version_and_size_num_bytes as i64)))
            .map_err(|err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Failed to seek for num_pages".to_string(),
                internal_error: err.to_string(),
            })?;
        let mut buf: [u8; SIZE_NUM_BYTES] = [0; SIZE_NUM_BYTES];
        file.read_exact(&mut buf)
            .map_err(|err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Failed to read num_pages".to_string(),
                internal_error: err.to_string(),
            })?;
        let num_pages = u64::from_le_bytes(buf);

        let data_len = (num_pages as usize).checked_mul(PAGE_SIZE).ok_or_else(|| {
            PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: format!("Overflow with number of pages: {}", num_pages),
            }
        })?;
        let data_version_size_num_bytes = data_len
            .checked_add(version_and_size_num_bytes)
            .ok_or_else(|| PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: format!("Overflow with number of pages: {}", num_pages),
            })?;
        if (metadata.len() as usize) <= data_version_size_num_bytes {
            return Err(PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: "No place for index in overlay file".to_string(),
            });
        }

        let file_clone = file
            .try_clone()
            .map_err(|err| PersistenceError::FileSystemError {
                path: path.display().to_string(),
                context: "Failed to clone file for mapping".to_string(),
                internal_error: err.to_string(),
            })?;
        let mapping =
            Mapping::new(file, data_len, Some(path))?.ok_or(PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: "Empty mapping for overlay's page_data; zero num_pages?".to_string(),
            })?;

        let index_len = metadata.len() as usize - data_len - version_and_size_num_bytes;
        let index_offset =
            i64::try_from(data_len).map_err(|e| PersistenceError::InvalidOverlay {
                path: path.display().to_string(),
                message: format!("Overflow with cutoff: {}", e),
            })?;

        let index = OverlayIndices::new(file_clone, index_len, index_offset, num_pages)?;
        index.check_correctness(path)?;

        Ok(Self {
            mapping: Arc::new(mapping),
            index: Arc::new(index),
            version,
        })
    }

    /// Serialize the loaded overlay file for communication with sandboxes.
    pub fn serialize(&self) -> OverlayFileSerialization {
        OverlayFileSerialization {
            mapping: self.mapping.serialize(),
            index: self.index.serialize(),
            version: self.version,
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
        let index = OverlayIndices::deserialize(serialized_overlay.index)?;
        Ok(Self {
            mapping: Arc::new(mapping),
            index: Arc::new(index),
            version: serialized_overlay.version,
        })
    }

    /// Number of pages in this overlay file containing data.
    fn num_pages(&self) -> usize {
        self.index.num_pages as usize
    }

    /// The number of logical pages covered by this overlay file, i.e. the largest `PageIndex`
    /// contained + 1.
    fn num_logical_pages(&self) -> usize {
        let slice = self.index.as_slice();
        let last_range = index_range(slice, slice.len() - 1, self.num_pages() as u64);
        last_range.end_page.get() as usize
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
    ) -> MemoryInstructions {
        let slice = self.index.as_slice();
        let binary_search =
            slice.binary_search_by(|probe| IndexEntry::from(probe).start_page.cmp(&range.start));
        // `range.start` cannot be contained in any index range before this index, no need to iterate over them.
        let start_slice_index = match binary_search {
            Ok(loc) => loc,
            Err(0) => 0,
            Err(loc) => loc - 1,
        };

        let mut result = Vec::<MemoryInstruction>::new();

        for slice_index in start_slice_index..slice.len() {
            let page_index_range = index_range(slice, slice_index, self.num_pages() as u64);
            if page_index_range.start_page >= range.end {
                // Any later `PageIndexRange` in `slice` won't intersect with `range` anymore.
                break;
            }
            // This condition can be false if `range.start` is not contained in the overlay.
            // In this case `range.start` would be between the `start_slice_index` and `start_slice_index + 1`.
            if page_index_range.end_page > range.start {
                // `clamped_range` is the intersection of `range` and `page_index_range`.
                let clamped_range = PageIndex::new(std::cmp::max(
                    page_index_range.start_page.get(),
                    range.start.get(),
                ))
                    ..PageIndex::new(std::cmp::min(
                        page_index_range.end_page.get(),
                        range.end.get(),
                    ));
                let shifted_range = (clamped_range.start.get() - range.start.get())
                    ..(clamped_range.end.get() - range.start.get());

                // Count how many pages from `shifted_range` are not covered yet by `filter`.
                let needed_pages = shifted_range
                    .clone()
                    .filter(|page| {
                        !filter
                            .get(*page as usize)
                            .expect("Page index in shifted_range is out of bound")
                    })
                    .count() as u64;

                if needed_pages > MAX_COPY_MEMORY_INSTRUCTION {
                    // If we need many pages from the `page_index_range`, we mmap the entire range.
                    let offset =
                        (page_index_range.start_file_index.get() + clamped_range.start.get()
                            - page_index_range.start_page.get()) as usize
                            * PAGE_SIZE;
                    result.push((
                        clamped_range,
                        MemoryMapOrData::MemoryMap(self.mapping.file_descriptor().clone(), offset),
                    ));
                } else if needed_pages > 0 {
                    // We copy the needed pages individually.
                    for page_index in clamped_range.start.get()..clamped_range.end.get() {
                        let shifted_index = page_index - range.start.get();
                        if !filter
                            .get(shifted_index as usize)
                            .expect("Page index in shifted_range is out of bound")
                        {
                            let file_index = page_index_range.start_file_index.get() + page_index
                                - page_index_range.start_page.get();
                            let page = self.mapping.get_page(PageIndex::new(file_index));
                            result.push((
                                PageIndex::new(page_index)..PageIndex::new(page_index + 1),
                                MemoryMapOrData::Data(page),
                            ));
                        }
                    }
                }

                // Mark all new pages in `filter`.
                for page in shifted_range {
                    filter.set(page as usize, true);
                }
            }
        }

        MemoryInstructions {
            range,
            instructions: result,
        }
    }
}

/// Provide information from `StateLayout` about paths of a specific `PageMap`.
pub trait StorageLayout {
    /// Base file path.
    fn base(&self) -> PathBuf;

    /// Path for overlay of given height.
    fn overlay(&self, height: Height) -> PathBuf;

    /// All existing overlay files.
    fn existing_overlays(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>>;
}

/// `MergeCandidate` shows which files to merge into a single `PageMap`.
#[derive(Clone, Debug)]
pub struct MergeCandidate {
    /// Overlay files to merge.
    overlays: Vec<PathBuf>,
    /// Base to merge if any.
    base: Option<PathBuf>,
    /// File to create. The format is based on `PersistDestination` variant, either `Base` or
    /// `Overlay`.
    /// We merge all the data from `overlays` and `base` into it, and remove old files.
    dst: PersistDestination,
}

impl MergeCandidate {
    /// Create a `MergeCandidate` for the given overlays and base. The `MergeCandidate` has as dst
    /// either `dst_base` or `dst_overlay` depending on if we decided to make a partial (overlay) or a
    /// full (base) merge.
    /// If we apply the `MergeCandidate`, we must have up to `MAX_NUMBER_OF_FILES` files, forming a
    /// pyramid, each file size being greater or equal to sum of newer files on top. For example:
    ///     Overlay_3   |x|
    ///     Overlay_2   |xx|
    ///     Overlay_1   |xxxxxx|
    ///     Base        |xxxxxxxxxxxxxxxxxxxxxxxxxxxx|
    pub fn new(
        layout: &dyn StorageLayout,
        height: Height,
    ) -> Result<Option<MergeCandidate>, Box<dyn std::error::Error>> {
        let existing_base = if layout.base().exists() {
            Some(layout.base().to_path_buf())
        } else {
            None
        };

        let existing_overlays = layout.existing_overlays()?;
        // base if any; then overlays old to new.
        let existing_files = existing_base.iter().chain(existing_overlays.iter());

        let file_lengths: Vec<usize> = existing_files
            .map(|path| {
                Ok(std::fs::metadata(path)
                    .map_err(|err: _| PersistenceError::FileSystemError {
                        path: path.display().to_string(),
                        context: format!("Failed get existing file length: {}", path.display()),
                        internal_error: err.to_string(),
                    })?
                    .len() as usize)
            })
            .collect::<Result<_, PersistenceError>>()?;

        let Some(num_files_to_merge) = Self::num_files_to_merge(&file_lengths) else {
            return Ok(None);
        };

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
        let merge_all = num_files_to_merge == file_lengths.len();
        let base = if merge_all {
            existing_base.clone()
        } else {
            None
        };

        let dst = if merge_all {
            PersistDestination::BaseFile(layout.base().to_path_buf())
        } else {
            PersistDestination::OverlayFile(layout.overlay(height).to_path_buf())
        };

        Ok(Some(MergeCandidate {
            overlays,
            base,
            dst,
        }))
    }

    pub fn full_merge(
        layout: &dyn StorageLayout,
    ) -> Result<Option<MergeCandidate>, Box<dyn std::error::Error>> {
        let existing_overlays = layout.existing_overlays()?;
        let base_path = layout.base();
        if existing_overlays.is_empty() {
            Ok(None)
        } else {
            Ok(Some(MergeCandidate {
                overlays: existing_overlays.to_vec(),
                base: if base_path.exists() {
                    Some(base_path.clone())
                } else {
                    None
                },
                dst: PersistDestination::BaseFile(base_path),
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
        Self::merge_impl(&self.dst, base, &overlays, metrics)
    }

    pub fn is_full_merge(&self) -> bool {
        matches!(self.dst, PersistDestination::BaseFile(..))
    }

    pub fn input_size_bytes(&self) -> Result<u64, PersistenceError> {
        let mut sum = 0;
        for f in self.base.iter().chain(self.overlays.iter()) {
            match std::fs::metadata(f) {
                Err(err) => {
                    return Err(PersistenceError::FileSystemError {
                        path: f.display().to_string(),
                        context: "Failed to retrieve file metadata".to_string(),
                        internal_error: err.to_string(),
                    })
                }
                Ok(metadata) => sum += metadata.len(),
            }
        }
        Ok(sum)
    }

    fn merge_impl(
        dst: &PersistDestination,
        existing_base: Option<Checkpoint>,
        existing: &[OverlayFile],
        metrics: &StorageMetrics,
    ) -> Result<(), PersistenceError> {
        let max_size = existing.iter().map(|f| f.num_pages()).sum::<usize>()
            + existing_base.as_ref().map_or(0, |base| base.num_pages());
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
                Box::new((0..checkpoint.num_pages()).map(|index| {
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
        let mut pages_data: Vec<&[u8]> = Vec::with_capacity(max_size);
        let mut pages_indices: Vec<PageIndex> = Vec::with_capacity(max_size);
        // Group sorted `merged_iterator` by `page_index`. Elements within group are sorted by
        // priority; we need only the first element of each group.
        for (_, mut group) in
            &merged_iterator.group_by(|page_with_priority| page_with_priority.page_index)
        {
            let page_with_priority = group
                .next()
                .expect("group_by is expected to create non-empty groups");
            pages_data.push(page_with_priority.page_data);
            pages_indices.push(page_with_priority.page_index);
        }

        match dst {
            PersistDestination::OverlayFile(path) => {
                write_overlay(&pages_data, &pages_indices, path, metrics, LABEL_OP_MERGE)
            }
            PersistDestination::BaseFile(path) => {
                write_base(&pages_data, &pages_indices, path, metrics, LABEL_OP_MERGE)
            }
        }
    }

    /// Number of files to merge to achieve the `MergeCandidate` criteria (see `MergeCandidate::new`
    /// documentation).
    /// If no merge is required, return `None`.
    fn num_files_to_merge(existing_lengths: &[usize]) -> Option<usize> {
        let mut merge_to_get_pyramid = 0;
        let mut sum = 0;
        for (i, len) in existing_lengths.iter().rev().enumerate() {
            if sum > *len {
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
        if result <= 1 {
            None
        } else {
            Some(result)
        }
    }
}

/// A struct describing the index section of an overlay file.
struct OverlayIndices {
    /// A memory map of the index section of the file.
    mmap: ScopedMmap,
    /// The opened file for the index.
    file: File,
    /// Where in the file the index starts.
    offset: i64,
    /// Total number of pages contained in the index.
    num_pages: u64,
}

impl OverlayIndices {
    /// The index as a slice of pairs of numbers, each describing a range of pages.
    /// See `OverlayVersion` for an explanation of how the index is structured.
    fn as_slice(&self) -> &[[[u8; 8]; 2]] {
        let (prefix, slice, suffix) = unsafe { self.mmap.as_slice().align_to::<[[u8; 8]; 2]>() };
        // Prefix would be non-empty if the address wasn't u64-aligned, but mmap is always page-aligned.
        assert!(prefix.is_empty());
        // Suffix would be non-empty if the length (in bytes) isn't a multiple of 8*3, which would be a
        // bug in the loading step.
        assert!(suffix.is_empty());

        slice
    }

    /// If `index` is present in this overlay, returns its `FileIndex`.
    fn get_file_index(&self, index: PageIndex) -> Option<FileIndex> {
        let slice = self.as_slice();
        let result = slice.binary_search_by(|probe| IndexEntry::from(probe).start_page.cmp(&index));

        match result {
            Ok(loc) => Some(IndexEntry::from(&slice[loc]).start_file_index),
            Err(0) => None,
            Err(loc) => {
                let entry: IndexEntry = (&slice[loc - 1]).into();
                let next_file_index = if loc < slice.len() {
                    IndexEntry::from(&slice[loc]).start_file_index
                } else {
                    FileIndex::from(self.num_pages)
                };
                let range = PageIndexRange::new(&entry, next_file_index);
                range.file_index(index)
            }
        }
    }

    /// Iterate over all ranges.
    fn iter(&self) -> impl Iterator<Item = PageIndexRange> + '_ {
        let slice = self.as_slice();
        (0..slice.len()).map(|i| index_range(slice, i, self.num_pages))
    }

    /// Open the `OverlayIndices` in the given file at the right offset.
    fn new(file: File, len: usize, offset: i64, num_pages: u64) -> Result<Self, PersistenceError> {
        assert!(len > 0);
        let mmap =
            ScopedMmap::from_readonly_file_with_offset(&file, len, offset).map_err(|err| {
                let path = format!("/proc/self/fd/{}", file.as_raw_fd());
                PersistenceError::MmapError {
                    path,
                    len,
                    internal_error: err.to_string(),
                }
            })?;
        Ok(Self {
            file,
            mmap,
            offset,
            num_pages,
        })
    }

    /// Check that all the ranges:
    ///   1) Have positive length.
    ///   2) Are backed by data within the [0; self.num_pages) interval in the overlay file.
    ///   3) Don't overlap.
    ///   4) Are not back-to-back, e.g. [2..4][4..9].
    ///
    ///   We don't check for gaps in the page data, e.g. pages in file that are not covered by any
    ///   range.
    fn check_correctness(&self, path: &Path) -> Result<(), PersistenceError> {
        let slice = self.as_slice();
        for i in 0..slice.len() {
            let next_file_index = if i == slice.len() - 1 {
                FileIndex::from(self.num_pages)
            } else {
                IndexEntry::from(&slice[i + 1]).start_file_index
            };
            let next_page_index = if i == slice.len() - 1 {
                None
            } else {
                Some(IndexEntry::from(&slice[i + 1]).start_page)
            };
            let entry = IndexEntry::from(&slice[i]);
            let has_error = if entry.start_file_index >= next_file_index {
                true
            } else if let Some(next_page_index) = next_page_index {
                if next_page_index <= entry.start_page {
                    true
                } else {
                    let file_index_delta = next_file_index.get() - entry.start_file_index.get();
                    let max_page_index_delta = next_page_index.get() - entry.start_page.get();
                    // if length_in_file == max_length_in_mmap we have back to back ranges,
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
                        "Broken overlay file: IndexEntry[{}], entry: {:?}, next_file_index: {}, \
                        next_page_index: {:?}",
                        i, entry, next_file_index, next_page_index
                    ),
                });
            }
        }
        Ok(())
    }

    fn serialize(&self) -> OverlayIndicesSerialization {
        OverlayIndicesSerialization {
            file_descriptor: FileDescriptor {
                fd: self.file.as_raw_fd(),
            },
            index_len: self.mmap.len() as FileOffset,
            offset: self.offset,
            num_pages: self.num_pages,
        }
    }

    fn deserialize(
        serialized_index: OverlayIndicesSerialization,
    ) -> Result<Self, PersistenceError> {
        let file = unsafe { File::from_raw_fd(serialized_index.file_descriptor.fd) };
        Self::new(
            file,
            serialized_index.index_len as usize,
            serialized_index.offset,
            serialized_index.num_pages,
        )
    }
}

/// Construct a `PageIndexRange` for the range at `index`.
/// In the slice the information is stored in a fairly compressed format. An `PageIndexRange` is more convenient
/// to work with.
fn index_range(slice: &[[[u8; 8]; 2]], index: usize, num_pages: u64) -> PageIndexRange {
    PageIndexRange::new(
        &IndexEntry::from(&slice[index]),
        if index + 1 < slice.len() {
            FileIndex::from(IndexEntry::from(&slice[index + 1]).start_file_index)
        } else {
            FileIndex::from(num_pages)
        },
    )
}

struct FileIndexTag;
/// Physical position of a page in an overlay file (smallest `PageIndex` has `FileIndex` 0, second smallest
/// has `FileIndex` 1).
type FileIndex = Id<FileIndexTag, u64>;

/// The two numbers we store for each range in the overlay file.
#[derive(Copy, Clone, Debug)]
struct IndexEntry {
    /// Page index in the mmap.
    start_page: PageIndex,
    /// Offset in the file measured in `PAGE_SIZE` blocks.
    start_file_index: FileIndex,
}

impl From<&[[u8; 8]; 2]> for IndexEntry {
    fn from(source: &[[u8; 8]; 2]) -> Self {
        let start_page = u64::from_le_bytes(source[0]).into();
        let start_file_index = u64::from_le_bytes(source[1]).into();

        Self {
            start_page,
            start_file_index,
        }
    }
}

impl From<&PageIndexRange> for IndexEntry {
    fn from(source: &PageIndexRange) -> Self {
        Self {
            start_page: source.start_page,
            start_file_index: source.start_file_index,
        }
    }
}

impl IndexEntry {
    /// A `PageIndexRange` as it is serialized in the overlay file.
    fn bytes(&self) -> [u8; INDEX_ENTRY_NUM_BYTES] {
        let start = self.start_page.get().to_le_bytes();
        let file_index = self.start_file_index.get().to_le_bytes();
        let mut result = [0; 16];
        result[..8].copy_from_slice(&start);
        result[8..].copy_from_slice(&file_index);
        result
    }
}

/// A representation of a range of `PageIndex` that is intended to be easier to use
/// than the raw representation in the file.
#[derive(Copy, Clone, Debug)]
struct PageIndexRange {
    /// Start of the range in the `PageMap`, i.e. where to mmap to.
    start_page: PageIndex,
    /// End of the range in the `PageMap`.
    end_page: PageIndex,
    /// Offset of the range in the overlay file.
    start_file_index: FileIndex,
}

impl PageIndexRange {
    /// Construct a `PageIndexRange` for a single `IndexEntry` and the relevant information
    /// from the next `IndexEntry`.
    fn new(entry: &IndexEntry, next_file_index: FileIndex) -> Self {
        debug_assert!(next_file_index > entry.start_file_index);
        Self {
            start_page: entry.start_page,
            end_page: PageIndex::from(
                next_file_index.get() - entry.start_file_index.get() + entry.start_page.get(),
            ),
            start_file_index: entry.start_file_index,
        }
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
}

/// Convert a sorted list of `PageIndex` to a sorted list of `PageIndexRange`, combining
/// adjacent `PageIndex` to a single range.
fn group_pages_into_ranges(page_indices: &[PageIndex]) -> Vec<IndexEntry> {
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
            IndexEntry {
                start_page: *start_page,
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

fn expand_with_zeroes<'a>(pages: &[&'a [u8]], indices: &[PageIndex]) -> Vec<&'a [u8]> {
    if indices.is_empty() {
        return Vec::new();
    }

    let mut result =
        vec![&ZEROED_PAGE as &PageBytes as &[u8]; indices.last().unwrap().get() as usize + 1];
    assert_eq!(pages.len(), indices.len());
    for (page, index) in pages.iter().zip(indices) {
        result[index.get() as usize] = page;
    }
    result
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
    let pages = expand_with_zeroes(pages, indices);
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
    let ranges_serialized = group_pages_into_ranges(indices)
        .into_iter()
        .map(|range| range.bytes())
        .fold(
            Vec::with_capacity(INDEX_ENTRY_NUM_BYTES * indices.len()),
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageSerialization {
    pub base: CheckpointSerialization,
    pub overlays: Vec<OverlayFileSerialization>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OverlayIndicesSerialization {
    pub file_descriptor: FileDescriptor,
    pub index_len: FileOffset,
    offset: i64,
    num_pages: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OverlayFileSerialization {
    pub mapping: MappingSerialization,
    pub index: OverlayIndicesSerialization,
    pub version: OverlayVersion,
}

#[cfg(test)]
mod tests;
