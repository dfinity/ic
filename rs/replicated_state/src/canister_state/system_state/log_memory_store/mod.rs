#![allow(dead_code)] // TODO: don't forget to cleanup.

pub(crate) mod header;
pub(crate) mod index_table;
pub(crate) mod log_record;
pub(crate) mod memory;
pub(crate) mod ring_buffer;
pub(crate) mod struct_io;

use crate::page_map::{PageAllocatorFileDescriptor, PageMap};
use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};
use ic_types::CanisterLog;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::VecDeque;
use std::sync::Arc;

/// Upper bound on how many delta log sizes is retained.
/// Prevents unbounded growth of `delta_log_sizes`.
const DELTA_LOG_SIZES_CAP: usize = 100;

#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct LogMemoryStore {
    #[validate_eq(Ignore)]
    pub data: PageMap,

    /// (!) No need to preserve across checkpoints.
    /// Tracks the size of each delta log appended during a round.
    /// Multiple logs can be appended in one round (e.g. heartbeat, timers, or message executions).
    /// The collected sizes are used to expose per-round memory usage metrics
    /// and the record is cleared at the end of the round.
    delta_log_sizes: VecDeque<usize>,
}

impl LogMemoryStore {
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self::new_inner(PageMap::new(fd_factory))
    }

    /// Creates a new `LogMemoryStore` that will use the temp file system for allocating new pages.
    pub fn new_for_testing() -> Self {
        Self::new_inner(PageMap::new_for_testing())
    }

    pub fn new_inner(page_map: PageMap) -> Self {
        // TODO: implement initialization logic.
        let tmp_data = page_map.clone();
        Self {
            data: tmp_data,
            delta_log_sizes: VecDeque::new(),
        }
    }

    pub fn from_checkpoint(data: PageMap) -> Self {
        Self {
            data,
            delta_log_sizes: VecDeque::new(),
        }
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
        // TODO.
        0
    }

    pub fn used_space(&self) -> usize {
        // TODO.
        0
    }

    /// Returns true if the canister log buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.used_space() == 0
    }

    pub fn next_id(&self) -> u64 {
        // TODO.
        0
    }

    pub fn append_delta_log(&mut self, delta_log: &mut CanisterLog) {
        // Record the size of the appended delta log for metrics.
        self.push_delta_log_size(delta_log.used_space());

        // TODO: implement appending logic.
    }

    /// Records the size of the appended delta log.
    fn push_delta_log_size(&mut self, size: usize) {
        if self.delta_log_sizes.len() >= DELTA_LOG_SIZES_CAP {
            self.delta_log_sizes.pop_front();
        }
        self.delta_log_sizes.push_back(size);
    }

    /// Atomically snapshot and clear the per-round delta_log sizes — use at end of round.
    pub fn take_delta_log_sizes(&mut self) -> Vec<usize> {
        self.delta_log_sizes.drain(..).collect()
    }

    pub fn records(&self, _filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        vec![] // TODO.
    }
}
