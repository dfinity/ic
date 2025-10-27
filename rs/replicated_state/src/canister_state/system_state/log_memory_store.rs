use crate::{PageMap, page_map::PageAllocatorFileDescriptor};
use ic_types::CanisterLog;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::sync::Arc;

#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct LogMemoryStore {
    #[validate_eq(Ignore)]
    pub data: PageMap,
}

impl LogMemoryStore {
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self {
            data: PageMap::new(fd_factory),
        }
    }

    /// Creates a new `LogMemoryStore` that will use the temp file system for
    /// allocating new pages.
    pub fn new_for_testing() -> Self {
        Self {
            data: PageMap::new_for_testing(),
        }
    }

    pub fn from_checkpoint(data: PageMap) -> Self {
        Self { data }
    }

    pub fn page_map(&self) -> &PageMap {
        &self.data
    }

    pub fn page_map_mut(&mut self) -> &mut PageMap {
        &mut self.data
    }

    pub fn clear(&mut self) {
        // TODO.
    }

    pub fn capacity(&self) -> usize {
        0 // TODO.
    }

    pub fn used_space(&self) -> usize {
        0 // TODO.
    }

    pub fn next_id(&self) -> u64 {
        0 // TODO.
    }

    pub fn records(&self, filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        vec![] // TODO.
    }

    pub fn append_delta_log(&mut self, _delta_log: &mut CanisterLog) {
        // TODO: preserve record sizes, advance next_idx, append records.
    }

    fn push_delta_log_size(&mut self, size: usize) {
        // TODO.
    }

    pub fn take_delta_log_sizes(&mut self) -> Vec<usize> {
        vec![] // TODO.
    }
}
