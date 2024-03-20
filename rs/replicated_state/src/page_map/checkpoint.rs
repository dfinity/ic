use crate::page_map::{
    FileDescriptor, FileOffset, MemoryInstructions, MemoryMapOrData, PageIndex, PersistenceError,
};
use ic_sys::{mmap::ScopedMmap, PAGE_SIZE};
use ic_sys::{page_bytes_from_ptr, PageBytes};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::FromRawFd;
use std::path::Path;
use std::sync::Arc;

lazy_static! {
    pub(crate) static ref ZEROED_PAGE: Box<PageBytes> = Box::new([0; PAGE_SIZE]);
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

/// A memory map of a (section of a) file containing pages of size `PAGE_SIZE`.
/// The memory map is read-only and most functions are helper functions to read pages.
pub(crate) struct Mapping {
    mmap: ScopedMmap,
    _file: File, // It is not used but it keeps the `file_descriptor` alive.
    file_descriptor: FileDescriptor,
}

impl Mapping {
    pub(crate) fn new(
        file: File,
        len: usize,
        path: Option<&Path>,
    ) -> Result<Option<Mapping>, PersistenceError> {
        if len == 0 {
            // It's illegal to mmap an empty region, so the checkpoint
            // will act as an empty mapping if the file size is zero.
            Ok(None)
        } else {
            let mmap = ScopedMmap::from_readonly_file(&file, len).map_err(|err| {
                let path = match path {
                    Some(path) => path.display().to_string(),
                    None => format!("/proc/self/fd/{}", file.as_raw_fd()),
                };
                PersistenceError::MmapError {
                    path,
                    len,
                    internal_error: err.to_string(),
                }
            })?;
            let fd = file.as_raw_fd();
            Ok(Some(Mapping {
                _file: file,
                file_descriptor: FileDescriptor { fd },
                mmap,
            }))
        }
    }

    fn open(path: &Path) -> Result<Option<Mapping>, PersistenceError> {
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

        let len = metadata.len() as usize;
        if len % PAGE_SIZE != 0 {
            return Err(PersistenceError::InvalidHeapFile {
                path: path.display().to_string(),
                file_size: len,
                page_size: PAGE_SIZE,
            });
        }
        Self::new(file, len, Some(path))
    }

    /// Returns a serialization-friendly representation of `Mapping`.
    pub(crate) fn serialize(&self) -> MappingSerialization {
        MappingSerialization {
            file_descriptor: self.file_descriptor.clone(),
            file_len: self.mmap.len() as FileOffset,
        }
    }

    /// Creates `Mapping` from the given serialization-friendly representation.
    pub(crate) fn deserialize(
        serialized_mapping: MappingSerialization,
    ) -> Result<Option<Mapping>, PersistenceError> {
        // SAFETY: the file descriptor is valid because `serialized_mapping` is
        // guaranteed to be valid as a precondition.
        let file = unsafe { File::from_raw_fd(serialized_mapping.file_descriptor.fd) };
        Mapping::new(file, serialized_mapping.file_len as usize, None)
    }

    /// Returns the `PageBytes` read from bytes `[PAGE_SIZE * page_index..PAGE_SIZE * (page_index + 1))`
    pub(crate) fn get_page(&self, page_index: PageIndex) -> &PageBytes {
        let num_pages = self.mmap.len() / PAGE_SIZE;
        if page_index.get() < num_pages as u64 {
            let page_start = (page_index.get() as usize * PAGE_SIZE) as isize;
            // SAFETY: The memory from `page_start` to `page_start + PAGE_SIZE` is mapped
            // and will remain valid for the lifetime of `self`. The memory is read-only
            // and does not have any mutable references to it.
            unsafe { page_bytes_from_ptr(self, self.mmap.addr().offset(page_start)) }
        } else {
            &ZEROED_PAGE
        }
    }

    /// The entire mmap as a slice of bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.mmap.as_slice()
    }

    /// See the comments of `PageMap::get_checkpoint_memory_instructions()`.
    pub fn get_memory_instructions(&self) -> MemoryInstructions {
        let num_pages = (self.mmap.len() / PAGE_SIZE) as u64;

        MemoryInstructions {
            range: PageIndex::new(0)..PageIndex::new(u64::MAX),
            instructions: vec![(
                PageIndex::new(0)..PageIndex::new(num_pages),
                MemoryMapOrData::MemoryMap(self.file_descriptor.clone(), 0),
            )],
        }
    }

    pub(crate) fn file_descriptor(&self) -> &FileDescriptor {
        &self.file_descriptor
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
        Mapping::open(path).map(|mapping| Checkpoint {
            mapping: mapping.map(Arc::new),
        })
    }

    /// Returns a serialization-friendly representation of `Checkpoint`.
    pub fn serialize(&self) -> CheckpointSerialization {
        CheckpointSerialization {
            mapping: self.mapping.as_ref().map(|mapping| mapping.serialize()),
        }
    }

    /// Creates `Checkpoint` from the given serialization-friendly
    /// representation.
    pub fn deserialize(
        serialized_checkpoint: CheckpointSerialization,
    ) -> Result<Checkpoint, PersistenceError> {
        let mapping = match serialized_checkpoint.mapping {
            None => None,
            Some(mapping) => Mapping::deserialize(mapping)?,
        };
        Ok(Checkpoint {
            mapping: mapping.map(Arc::new),
        })
    }

    /// Returns the page with the specified `page_number`.
    pub fn get_page(&self, page_index: PageIndex) -> &PageBytes {
        match self.mapping {
            Some(ref mapping) => mapping.get_page(page_index),
            None => &ZEROED_PAGE,
        }
    }

    /// See the comments of `PageMap::get_checkpoint_memory_instructions()`.
    pub fn get_memory_instructions(&self) -> MemoryInstructions {
        self.mapping.as_ref().map_or(
            MemoryInstructions {
                range: PageIndex::new(0)..PageIndex::new(u64::MAX),
                instructions: vec![],
            },
            |mapping| mapping.get_memory_instructions(),
        )
    }

    /// Returns the max number of (possibly) non-zero pages in this
    /// checkpoint.
    pub fn num_pages(&self) -> usize {
        match self.mapping {
            Some(ref mapping) => mapping.as_slice().len() / PAGE_SIZE,
            None => 0,
        }
    }
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self::empty()
    }
}

/// Serialization-friendly representation of `Mapping`.
///
/// It contains sufficient information to reconstruct `Mapping`
/// in another process.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MappingSerialization {
    pub file_descriptor: FileDescriptor,
    pub file_len: FileOffset,
}

/// Serialization-friendly representation of `Checkpoint`.
///
/// It contains sufficient information to reconstruct `Checkpoint`
/// in another process.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CheckpointSerialization {
    pub mapping: Option<MappingSerialization>,
}
