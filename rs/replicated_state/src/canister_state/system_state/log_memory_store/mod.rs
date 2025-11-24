pub(crate) mod header;
pub(crate) mod index_table;
pub(crate) mod log_record;
pub(crate) mod memory;
pub(crate) mod ring_buffer;
pub(crate) mod struct_io;

use crate::canister_state::system_state::log_memory_store::{
    memory::MemorySize, ring_buffer::RingBuffer,
};
use crate::page_map::{PageAllocatorFileDescriptor, PageMap};
use ic_management_canister_types_private::{
    CanisterLogRecord, FetchCanisterLogsFilter, FetchCanisterLogsRange,
};
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
    pub page_map: PageMap,

    // ring_buffer: RingBuffer, // cached reference to the inner ring buffer of the
    // page_map: PageMap,
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

    pub fn from_checkpoint(page_map: PageMap) -> Self {
        Self::new_inner(page_map)
    }

    pub fn new_inner(page_map: PageMap) -> Self {
        Self {
            page_map,
            delta_log_sizes: VecDeque::new(),
        }
    }

    pub fn page_map(&self) -> &PageMap {
        &self.page_map
    }

    pub fn page_map_mut(&mut self) -> &mut PageMap {
        &mut self.page_map
    }

    fn ring_buffer(&self) -> RingBuffer {
        let data_capacity = MemorySize::new(10_000_000); // TODO: populate it properly
        RingBuffer::init(self.page_map.clone(), data_capacity)
    }

    /// Set the ring buffer capacity — preserves existing records by collecting and re-appending them.
    pub fn set_capacity(&mut self, new_capacity: u64) {
        // TODO: PageMap cannot be shrunk today; reducing capacity does not free allocated pages
        // (practical ring buffer max currently ~55 MB). Future improvement: allocate a new PageMap
        // with the desired capacity, refeed records, then drop the old map or provide a `PageMap::shrink` API.
        let old = self.ring_buffer();
        if old.capacity() == new_capacity {
            return;
        }

        // `old.records(...)` may return results in batches, so iterate until all available records are collected.
        let mut records = Vec::new();
        let mut idx = 0;
        while idx < old.next_id() {
            let batch = old.records(Some(FetchCanisterLogsFilter::ByIdx(
                FetchCanisterLogsRange {
                    start: idx,
                    end: u64::MAX,
                },
            )));
            if batch.is_empty() {
                break;
            }
            idx = batch.last().unwrap().idx + 1;
            records.extend(batch);
        }

        // Recreate ring buffer with new capacity and restore records.
        let mut new = RingBuffer::new(old.to_page_map(), MemorySize::new(new_capacity));
        new.append_log(records);
        self.page_map = new.to_page_map();
    }

    pub fn next_id(&self) -> u64 {
        self.ring_buffer().next_id()
    }

    pub fn records(&self, filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        self.ring_buffer().records(filter)
    }

    pub fn append_delta_log(&mut self, delta_log: &mut CanisterLog) {
        // Record the size of the appended delta log for metrics.
        self.push_delta_log_size(delta_log.used_space());

        let mut ring_buffer = self.ring_buffer();
        ring_buffer.append_log(
            delta_log
                .records_mut()
                .iter_mut()
                .map(std::mem::take)
                .collect(),
        );
        self.page_map = ring_buffer.to_page_map();
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
}

/*
bazel test //rs/replicated_state:replicated_state_test \
  --test_output=streamed \
  --test_arg=--nocapture \
  --test_arg=log_memory_store
*/
