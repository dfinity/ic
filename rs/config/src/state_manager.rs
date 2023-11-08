use crate::flag_status::FlagStatus;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub state_root: PathBuf,
    /// A feature flag that enables/disables the file backed memory allocator.
    #[serde(default = "file_backed_memory_allocator_default")]
    pub file_backed_memory_allocator: FlagStatus,
    /// A feature flag that enables/disables the log structure merge tree based storage
    #[serde(default = "lsmt_storage_default")]
    pub lsmt_storage: FlagStatus,
}

impl Config {
    pub fn new(state_root: PathBuf) -> Self {
        Self {
            state_root,
            file_backed_memory_allocator: file_backed_memory_allocator_default(),
            lsmt_storage: lsmt_storage_default(),
        }
    }

    pub fn state_root(&self) -> PathBuf {
        self.state_root.clone()
    }

    // The page_deltas directory stores files backing the file
    // allocator and is a child of the state directory.
    pub fn page_deltas_dirname(&self) -> String {
        "page_deltas".to_string()
    }
}

fn file_backed_memory_allocator_default() -> FlagStatus {
    FlagStatus::Enabled
}

pub fn lsmt_storage_default() -> FlagStatus {
    FlagStatus::Disabled
}
