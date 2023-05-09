use crate::flag_status::FlagStatus;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    state_root: PathBuf,
    /// A feature flag that enables/disables the file backed memory allocator.
    #[serde(default = "file_backed_memory_allocator_default")]
    pub file_backed_memory_allocator: FlagStatus,
}

impl Config {
    pub fn new(state_root: PathBuf) -> Self {
        Self {
            state_root,
            file_backed_memory_allocator: FlagStatus::Disabled,
        }
    }

    pub fn state_root(&self) -> PathBuf {
        self.state_root.clone()
    }
}

fn file_backed_memory_allocator_default() -> FlagStatus {
    FlagStatus::Enabled
}
