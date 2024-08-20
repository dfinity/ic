use crate::flag_status::FlagStatus;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LsmtConfig {
    /// Whether LSMT is enabled or not.
    pub lsmt_status: FlagStatus,
    /// Number of pages per shard in sharded overlays; u64::MAX if unlimited.
    pub shard_num_pages: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub state_root: PathBuf,
    /// A feature flag that enables/disables the file backed memory allocator.
    #[serde(default = "file_backed_memory_allocator_default")]
    pub file_backed_memory_allocator: FlagStatus,
    /// A config for LSMT storage.
    #[serde(default = "lsmt_config_default")]
    pub lsmt_config: LsmtConfig,
}

impl Config {
    pub fn new(state_root: PathBuf) -> Self {
        Self {
            state_root,
            file_backed_memory_allocator: file_backed_memory_allocator_default(),
            lsmt_config: lsmt_config_default(),
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
    FlagStatus::Disabled
}

pub fn lsmt_config_default() -> LsmtConfig {
    LsmtConfig {
        lsmt_status: FlagStatus::Enabled,
        // 40GiB
        // DO NOT CHANGE after LSMT is enabled, as it would crash the new replica trying to merge
        // old data.
        shard_num_pages: 10 * 1024 * 1024,
    }
}
