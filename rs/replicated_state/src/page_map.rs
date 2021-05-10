mod checkpoint;
pub mod int_map;

use checkpoint::Checkpoint;
pub use ic_sys::PAGE_SIZE;
// NOTE: We use a persistent map to make snapshotting of a PageMap a cheap
// operation. This allows us to simplify canister state management: we can
// simply have a copy of the whole PageMap in every canister snapshot.
use int_map::IntMap;
use phantom_newtype::Id;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

static ALLOCATED_PAGES: PageCounter = PageCounter::new();

struct PageCounter(AtomicUsize);

impl PageCounter {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }
    fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
    fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct PageIndexTag;
/// 0-based index of the _host_ virtual memory page (i.e. not Wasm
/// memory page).
pub type PageIndex = Id<PageIndexTag, u64>;

#[derive(PartialEq, Eq, Clone, Debug)]
struct Page(Box<[u8]>);

impl Page {
    fn new(contents: &[u8]) -> Self {
        ALLOCATED_PAGES.inc();
        Self(contents.to_vec().into_boxed_slice())
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        ALLOCATED_PAGES.dec();
    }
}

/// Tracked page is ref-counted immutable memory page.
#[derive(Clone, Debug)]
pub struct TrackedPage(Arc<Page>);

impl TrackedPage {
    /// Returns the contents of the page. The length of the slice is
    /// always equal to the page size.
    ///
    /// Use `page.contents().as_ptr()` to get a pointer to the
    /// beginning of the page.
    pub fn contents(&self) -> &[u8] {
        &*(self.0).0
    }
}

impl TryFrom<&[u8]> for TrackedPage {
    type Error = PersistenceError;
    fn try_from(contents: &[u8]) -> Result<TrackedPage, PersistenceError> {
        if contents.len() != *PAGE_SIZE {
            Err(PersistenceError::BadPageSize {
                expected: *PAGE_SIZE,
                actual: contents.len(),
            })
        } else {
            Ok(Self(Arc::new(Page::new(contents))))
        }
    }
}

/// `PageDelta` represents a changeset of the module heap.
#[derive(Clone, Default, Debug)]
pub struct PageDelta(IntMap<TrackedPage>);

impl PageDelta {
    /// Returns true if the delta doesn't contain any pages.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of pages in the delta.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Gets content of the page at the specified index.
    pub fn get_page(&self, page_index: PageIndex) -> Option<&[u8]> {
        self.0.get(page_index.get()).map(|p| p.contents())
    }

    /// Modifies this delta in-place by applying all the entries in `rhs` to it.
    pub fn update(&mut self, rhs: PageDelta) {
        self.0 = rhs.0.union(std::mem::take(&mut self.0));
    }

    /// Unions two page deltas into a single delta.
    /// If both deltas contain a page with the same number, the page contained
    /// in `self` wins, i.e.
    /// `extend([(N, X)], [(N, Y), (M, Z)]) = [(N, X), (M, Z)]`
    pub fn extend(self, rhs: PageDelta) -> Self {
        Self(self.0.union(rhs.0))
    }

    /// Enumerates all the pages in this delta.
    pub fn iter(&self) -> impl Iterator<Item = (PageIndex, &'_ TrackedPage)> {
        self.0.iter().map(|(idx, page)| (PageIndex::new(idx), page))
    }

    /// Applies this delta to the specified file.
    ///
    /// Precondition: `file` is seekable and writeable.
    fn apply_to_file(&self, file: &mut File, path: &Path) -> Result<(), PersistenceError> {
        use std::io::{Seek, SeekFrom};

        for (index, page) in self.iter() {
            let offset = index.get() * *PAGE_SIZE as u64;
            file.seek(SeekFrom::Start(offset as u64)).map_err(|err| {
                PersistenceError::FileSystemError {
                    path: path.display().to_string(),
                    context: format!("Failed to seek to {}", offset),
                    internal_error: err.to_string(),
                }
            })?;
            let mut contents = page.contents();
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
    pub fn persist(&self, dst: &Path) -> Result<(), PersistenceError> {
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
    pub fn persist_and_flush(&self, dst: &Path) -> Result<(), PersistenceError> {
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
                context: "Failed to flush".to_string(),
                internal_error: err.to_string(),
            })?;
        Ok(())
    }
}

impl From<&[(PageIndex, &[u8])]> for PageDelta {
    fn from(pages: &[(PageIndex, &[u8])]) -> Self {
        let dirty_pages: Vec<_> = pages.iter().map(|x| x.1).collect();
        let tracked_pages = allocate_pages(dirty_pages.as_slice());

        Self(
            pages
                .iter()
                .cloned()
                .zip(tracked_pages.into_iter())
                .map(|((num, _), tracked_page)| (num.get(), tracked_page))
                .collect(),
        )
    }
}

/// Makes tracked copies of the provided _pages_.  The pages will be
/// automatically deallocated when they go out of scope.
pub fn allocate_pages(pages: &[&[u8]]) -> Vec<TrackedPage> {
    pages
        .iter()
        .map(|page_slice| TrackedPage::try_from(*page_slice).unwrap())
        .collect()
}

/// Returns the total number of tracked pages allocated at the moment.
pub fn allocated_pages_count() -> usize {
    ALLOCATED_PAGES.get()
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
        match self {
            PersistenceError::InvalidHeapFile { .. } => true,
            _ => false,
        }
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
            PersistenceError::FileSystemError { path, context, .. } => {
                write!(f, "File system error for file {}: {}", path, context)
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

    /// The map containing pages overriding pages from the `checkpoint`.
    /// We need these pages to be able to reconstruct the full heap.
    page_delta: PageDelta,

    /// The map containing deltas accumulated since the beginning of
    /// the execution round.  This delta is reset when
    /// `take_round_delta()` method is called.
    ///
    /// Invariant: round_delta ⊆ page_delta
    round_delta: PageDelta,
}

impl PageMap {
    /// Creates a new page map that always returns zeroed pages.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a page map backed by the provided heap file.
    ///
    /// Note that the file is assumed to be read-only.
    pub fn open(heap_file: &Path) -> Result<Self, PersistenceError> {
        let checkpoint = Checkpoint::open(heap_file)?;
        Ok(Self {
            checkpoint,
            page_delta: Default::default(),
            round_delta: Default::default(),
        })
    }

    /// Modifies this page map by appending the given delta to it.
    pub fn update(&mut self, delta: PageDelta) {
        // Delta is a persistent data structure and is cheap to clone.
        self.page_delta.update(delta.clone());
        self.round_delta.update(delta)
    }

    /// Returns true if this page map has pages stored only in memory.
    pub fn has_deltas(&self) -> bool {
        !self.page_delta.is_empty()
    }

    /// Persists the heap delta contained in this page map to the specified
    /// destination.
    pub fn persist_delta(&self, dst: &Path) -> Result<(), PersistenceError> {
        self.page_delta.persist(dst)
    }

    /// Persists the heap delta contained in this page map to the specified
    /// destination and flushes it to disk.
    pub fn persist_and_flush_delta(&self, dst: &Path) -> Result<(), PersistenceError> {
        self.page_delta.persist_and_flush(dst)
    }

    /// Extracts the delta accumulated since the beginning of the execution
    /// round.
    pub fn take_round_delta(&mut self) -> PageDelta {
        std::mem::take(&mut self.round_delta)
    }

    /// Returns the iterator over host pages managed by this `PageMap`.
    pub fn host_pages_iter(&self) -> impl Iterator<Item = (PageIndex, &[u8])> + '_ {
        (0..self.num_host_pages()).map(move |i| {
            let idx = PageIndex::from(i as u64);
            (idx, self.get_page(idx))
        })
    }

    /// Returns the page with the specified `page_index`.
    pub fn get_page(&self, page_index: PageIndex) -> &[u8] {
        match self.page_delta.get_page(page_index) {
            Some(page) => page,
            None => self.checkpoint.get_page(page_index),
        }
    }

    /// Removes the page delta from this page map.
    pub fn strip_delta(&mut self) -> PageDelta {
        std::mem::take(&mut self.page_delta)
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
}

impl From<&[u8]> for PageMap {
    fn from(bytes: &[u8]) -> Self {
        let mut buf = Buffer::new(PageMap::default());
        buf.write(bytes, 0);
        buf.into_page_map()
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
    dirty_pages: HashMap<PageIndex, TrackedPage>,
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
        let page_size = *PAGE_SIZE;

        while !dst.is_empty() {
            let page = PageIndex::new((offset / page_size) as u64);
            let offset_into_page = offset % page_size;
            let page_len = dst.len().min(page_size - offset_into_page);

            let page_contents = match self.dirty_pages.get(&page) {
                Some(p) => p.contents(),
                None => self.page_map.get_page(page),
            };
            dst[0..page_len]
                .copy_from_slice(&page_contents[offset_into_page..offset_into_page + page_len]);

            offset += page_len;
            let n = dst.len();
            dst = &mut dst[page_len..n];
        }
    }

    /// Overwrites the contents of this buffer at the specified offset with the
    /// contents of the source buffer.
    pub fn write(&mut self, mut src: &[u8], mut offset: usize) {
        use std::collections::hash_map::Entry;

        let page_size = *PAGE_SIZE;

        while !src.is_empty() {
            let page = PageIndex::new((offset / page_size) as u64);
            let offset_into_page = offset % page_size;
            let page_len = src.len().min(page_size - offset_into_page);

            match self.dirty_pages.entry(page) {
                Entry::Occupied(mut dirty_page) => {
                    Arc::make_mut(&mut dirty_page.get_mut().0).0
                        [offset_into_page..offset_into_page + page_len]
                        .copy_from_slice(&src[0..page_len]);
                }
                Entry::Vacant(page_slot) => {
                    let new_page = page_slot
                        .insert(TrackedPage::try_from(self.page_map.get_page(page)).unwrap());

                    Arc::make_mut(&mut new_page.0).0[offset_into_page..offset_into_page + page_len]
                        .copy_from_slice(&src[0..page_len]);
                }
            }

            offset += page_len;
            src = &src[page_len..src.len()];
        }
    }

    /// Consumes this buffer and converts it back into a page map.
    ///
    /// Complexity: O(dirtied pages)
    pub fn into_page_map(mut self) -> PageMap {
        let delta: IntMap<_> = self
            .dirty_pages
            .into_iter()
            .map(|(n, p)| (n.get(), p))
            .collect();
        self.page_map.update(PageDelta(delta));
        self.page_map
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

#[cfg(test)]
mod tests;
