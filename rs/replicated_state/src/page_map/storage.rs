/*
 The storage module contains functionality to read and write PageMap files as they are
 represented on disk, without any parts of a PageMap which are purely represented in memory.
*/

use ic_sys::{PageBytes, PageIndex};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::page_map::{
    checkpoint::{Checkpoint, CheckpointSerialization},
    MemoryInstructions, PersistenceError,
};

/// Representation of PageMap files on disk after loading.
///
/// A PageMap is currently represented by a single file, but will be represented by
/// a collection of files in the future.
#[derive(Default, Clone)]
pub(crate) struct Storage {
    base: Checkpoint,
}

impl Storage {
    pub fn load(
        base_path: Option<&Path>,
        overlay_paths: &[PathBuf],
    ) -> Result<Self, PersistenceError> {
        // TODO(IC-1306): Load overlay files
        assert!(overlay_paths.is_empty());

        let base = if let Some(path) = base_path {
            Checkpoint::open(path)?
        } else {
            Checkpoint::empty()
        };

        Ok(Self { base })
    }

    pub fn get_page(&self, page_index: PageIndex) -> &PageBytes {
        // TODO(IC-1306): Get page from overlays
        self.base.get_page(page_index)
    }

    pub fn get_base_memory_instructions(&self) -> MemoryInstructions {
        self.base.get_memory_instructions()
    }

    pub fn num_host_pages(&self) -> usize {
        // TODO(IC-1306): Consider pages in overlays
        self.base.num_pages()
    }

    pub fn serialize(&self) -> StorageSerialization {
        StorageSerialization {
            base: self.base.serialize(),
        }
    }

    pub fn deserialize(serialized_storage: StorageSerialization) -> Result<Self, PersistenceError> {
        Ok(Self {
            base: Checkpoint::deserialize(serialized_storage.base)?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageSerialization {
    pub base: CheckpointSerialization,
    // TODO (IC-1396): Serialize overlays
}
