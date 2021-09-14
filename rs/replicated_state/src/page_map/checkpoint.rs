use crate::page_map::{FileDescriptor, MemoryRegion, PageIndex, PersistenceError};
use ic_sys::{mmap::ScopedMmap, PAGE_SIZE};
use lazy_static::lazy_static;
use std::fs::{File, OpenOptions};
use std::ops::Range;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Arc;

lazy_static! {
    static ref ZEROED_PAGE: Vec<u8> = vec![0; *PAGE_SIZE];
}

/// Checkpoint represents a full snapshot of the heap of a single Wasm
/// module.
///
/// Conceptually it's an immutable byte array backed by a file and
/// aligned to a page boundary.
#[derive(Clone)]
pub(crate) struct Checkpoint {
    mapping: Option<Arc<Mapping>>,
}

struct Mapping {
    mmap: ScopedMmap,
    _file: File, // It is not used but it keeps the `file_descriptor` alive.
    file_descriptor: RawFd,
}

impl Mapping {
    fn new(path: &Path) -> Result<Option<Mapping>, PersistenceError> {
        let file = OpenOptions::new().read(true).open(&path).map_err(|err| {
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

        let len = metadata.len() as usize;
        if len % *PAGE_SIZE != 0 {
            return Err(PersistenceError::InvalidHeapFile {
                path: path.display().to_string(),
                file_size: len,
                page_size: *PAGE_SIZE,
            });
        }

        if len == 0 {
            // It's illegal to mmap an empty region, so the checkpoint
            // will act as an empty mapping if the file size is zero.
            Ok(None)
        } else {
            let mmap = ScopedMmap::from_readonly_file(&file, len).map_err(|err| {
                PersistenceError::MmapError {
                    path: path.display().to_string(),
                    len,
                    internal_error: err.to_string(),
                }
            })?;
            let fd = file.as_raw_fd();
            Ok(Some(Mapping {
                _file: file,
                file_descriptor: fd,
                mmap,
            }))
        }
    }

    fn get_page(&self, page_index: PageIndex) -> &[u8] {
        let num_pages = self.mmap.len() / *PAGE_SIZE;
        if page_index.get() < num_pages as u64 {
            let offset = (page_index.get() as usize * *PAGE_SIZE) as isize;
            unsafe { std::slice::from_raw_parts(self.mmap.addr().offset(offset), *PAGE_SIZE) }
        } else {
            &ZEROED_PAGE[..]
        }
    }

    /// See the comments of `PageMap::get_memory_region()`.
    pub fn get_memory_region(
        &self,
        page_index: PageIndex,
        page_range: Range<PageIndex>,
    ) -> MemoryRegion {
        let num_pages = (self.mmap.len() / *PAGE_SIZE) as u64;
        if page_index.get() >= num_pages {
            MemoryRegion::Zeros(Range {
                start: PageIndex::new(num_pages),
                end: page_range.end,
            })
        } else {
            MemoryRegion::BackedByFile(
                Range {
                    start: page_range.start,
                    end: PageIndex::new(std::cmp::min(num_pages, page_range.end.get())),
                },
                FileDescriptor {
                    fd: self.file_descriptor,
                },
            )
        }
    }

    pub fn num_pages(&self) -> usize {
        self.mmap.len() / *PAGE_SIZE
    }
}

impl Checkpoint {
    /// Returns an empty checkpoint, not backed by any file. It serves
    /// zeroed pages.
    pub fn empty() -> Checkpoint {
        Checkpoint { mapping: None }
    }

    /// Opens an existing heap file located at the specified path.
    pub fn open(path: &Path) -> Result<Checkpoint, PersistenceError> {
        Mapping::new(path).map(|mapping| Checkpoint {
            mapping: mapping.map(Arc::new),
        })
    }

    /// Returns the page with the specified `page_number`.
    pub fn get_page(&self, page_index: PageIndex) -> &[u8] {
        match self.mapping {
            Some(ref mapping) => mapping.get_page(page_index),
            None => &ZEROED_PAGE,
        }
    }

    /// See the comments of `PageMap::get_memory_region()`.
    pub fn get_memory_region(
        &self,
        page_index: PageIndex,
        page_range: Range<PageIndex>,
    ) -> MemoryRegion {
        assert!(page_range.contains(&page_index));
        match self.mapping {
            Some(ref mapping) => mapping.get_memory_region(page_index, page_range),
            None => MemoryRegion::Zeros(page_range),
        }
    }

    /// Returns the max number of (possibly) non-zero pages in this
    /// checkpoint.
    pub fn num_pages(&self) -> usize {
        match self.mapping {
            Some(ref mapping) => mapping.num_pages(),
            None => 0,
        }
    }
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self::empty()
    }
}
