mod header;
mod index_table;
mod log_record;
mod memory;
mod ring_buffer;
mod struct_io;

use crate::canister_state::system_state::log_memory_store::{
    header::Header,
    memory::MemorySize,
    ring_buffer::{DATA_CAPACITY_MIN, HEADER_SIZE, RingBuffer, VIRTUAL_PAGE_SIZE},
};
use crate::page_map::{PageAllocatorFileDescriptor, PageMap};
use ic_config::flag_status::FlagStatus;
use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};
use ic_types::CanisterLog;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::VecDeque;
use std::sync::Arc;

/// Upper bound on stored delta-log sizes used for metrics.
/// Limits memory growth, 10k covers expected per-round
/// number of messages per canister (and so delta log appends).
const DELTA_LOG_SIZES_CAP: usize = 10_000;
use std::sync::OnceLock;

#[derive(Debug, ValidateEq)]
pub struct LogMemoryStore {
    feature_flag: FlagStatus,

    #[validate_eq(Ignore)]
    maybe_page_map: Option<PageMap>,

    /// (!) No need to preserve across checkpoints.
    /// Tracks the size of each delta log appended during a round.
    /// Multiple logs can be appended in one round (e.g. heartbeat, timers, or message executions).
    /// The collected sizes are used to expose per-round memory usage metrics
    /// and the record is cleared at the end of the round.
    #[validate_eq(Ignore)]
    delta_log_sizes: VecDeque<usize>,

    /// Caches the ring buffer header to avoid expensive reads from the `PageMap`.
    #[validate_eq(Ignore)]
    header_cache: OnceLock<Option<Header>>,
}

impl LogMemoryStore {
    /// Creates a new uninitialized store with an empty ring buffer.
    ///
    /// The store technically exists but has 0 capacity and is considered "uninitialized".
    /// Any attempts to append logs will be silently ignored until the store is
    /// explicitly resized to a non-zero capacity.
    pub fn new(feature_flag: FlagStatus) -> Self {
        Self::new_inner(feature_flag, None)
    }

    /// Creates a new store from a checkpoint.
    pub fn from_checkpoint(feature_flag: FlagStatus, page_map: PageMap) -> Self {
        Self::new_inner(feature_flag, Some(page_map))
    }

    fn new_inner(feature_flag: FlagStatus, maybe_page_map: Option<PageMap>) -> Self {
        Self {
            feature_flag,
            maybe_page_map,
            delta_log_sizes: VecDeque::new(),
            header_cache: OnceLock::new(),
        }
    }

    pub fn maybe_page_map(&self) -> Option<&PageMap> {
        self.maybe_page_map.as_ref()
    }

    pub fn maybe_page_map_mut(&mut self) -> Option<&mut PageMap> {
        self.header_cache = OnceLock::new();
        self.maybe_page_map.as_mut()
    }

    /// Clears the canister log records without deallocating the ring buffer.
    pub fn clear(&mut self) {
        if let Some(mut ring_buffer) = self.load_ring_buffer() {
            ring_buffer.clear();
            self.maybe_page_map = Some(ring_buffer.to_page_map());
            self.header_cache = OnceLock::from(Some(ring_buffer.get_header()));
        } else {
            self.header_cache = OnceLock::new();
        }
    }

    /// Deallocates underlying memory.
    pub fn deallocate(&mut self) {
        self.maybe_page_map = None;
        self.header_cache = OnceLock::new();
    }

    /// Loads the ring buffer from the page map.
    fn load_ring_buffer(&self) -> Option<RingBuffer> {
        self.maybe_page_map
            .clone()
            .and_then(RingBuffer::load_checked)
    }

    /// Returns the ring buffer header.
    fn get_header(&self) -> Option<Header> {
        *self
            .header_cache
            .get_or_init(|| self.load_ring_buffer().map(|rb| rb.get_header()))
    }

    /// Returns actual memory usage of the ring buffer.
    pub fn memory_usage(&self) -> usize {
        self.total_virtual_memory_usage()
    }

    /// Returns the total virtual memory usage of the ring buffer.
    ///
    /// Includes header, index table and data region.
    /// It is 'virtual' because it is not alligned to actual OS page size.
    pub fn total_virtual_memory_usage(&self) -> usize {
        self.get_header()
            .map(|h| {
                (HEADER_SIZE.get()
                    + h.index_table_pages as u64 * VIRTUAL_PAGE_SIZE as u64
                    + h.data_capacity.get()) as usize
            })
            .unwrap_or(0)
    }

    /// Returns the data capacity of the ring buffer.
    pub fn byte_capacity(&self) -> usize {
        self.get_header()
            .map(|h| h.data_capacity.get() as usize)
            .unwrap_or(0)
    }

    /// Resizes the ring buffer to the specified limit, preserving existing records.
    ///
    /// This method enforces a minimum safe capacity and performs no operation if the
    /// effective capacity has not changed.
    pub fn resize(&mut self, limit: usize, fd_factory: Arc<dyn PageAllocatorFileDescriptor>) {
        self.resize_impl(limit, || PageMap::new(fd_factory))
    }

    #[cfg(test)]
    fn resize_for_testing(&mut self, limit: usize) {
        self.resize_impl(limit, PageMap::new_for_testing)
    }

    fn resize_impl(&mut self, limit: usize, create_page_map: impl FnOnce() -> PageMap) {
        if self.feature_flag == FlagStatus::Disabled {
            self.deallocate();
            return;
        }
        if limit == 0 {
            self.deallocate();
            return;
        }
        let target_limit = limit.max(DATA_CAPACITY_MIN);
        let current_capacity = self.get_header().map(|h| h.data_capacity.get() as usize);
        if current_capacity == Some(target_limit) {
            return; // Only resize if the capacity actually changes.
        }

        // Determine the PageMap strategy and create a new ring buffer.
        let page_map = match current_capacity {
            // Downsizing: New map to ensure we free old physical pages.
            Some(curr) if target_limit < curr => create_page_map(),
            // Upsizing or First-time init: Reuse existing or create new.
            _ => self.maybe_page_map.clone().unwrap_or(create_page_map()),
        };
        let mut new_buffer = RingBuffer::new(page_map, MemorySize::new(target_limit as u64));

        // Migrate records.
        if let Some(old_buffer) = self.load_ring_buffer() {
            new_buffer.append_log_iter(old_buffer.iter());
        }

        // Update of the state.
        self.maybe_page_map = Some(new_buffer.to_page_map());
        self.header_cache = OnceLock::from(Some(new_buffer.get_header()));
    }

    /// Returns the next log record `idx`.
    pub fn next_idx(&self) -> u64 {
        self.get_header().map(|h| h.next_idx).unwrap_or(0)
    }

    /// Returns true if the ring buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes_used() == 0
    }

    fn bytes_used(&self) -> usize {
        self.get_header()
            .map(|h| h.data_size.get() as usize)
            .unwrap_or(0)
    }

    /// Returns the canister log records, optionally filtered.
    pub fn records(&self, filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        self.load_ring_buffer()
            .map(|rb| rb.records(filter))
            .unwrap_or_default()
    }

    /// Appends a delta log to the ring buffer if it exists.
    pub fn append_delta_log(&mut self, delta_log: &mut CanisterLog) {
        if self.feature_flag == FlagStatus::Disabled {
            self.deallocate();
            return;
        }
        if delta_log.is_empty() {
            return; // Don't append if delta is empty.
        }
        let Some(mut ring_buffer) = self.load_ring_buffer() else {
            return; // No ring buffer exists.
        };
        // Record the size of the appended delta log for metrics.
        self.push_delta_log_size(delta_log.bytes_used());
        // Append the delta records and persist the ring buffer.
        ring_buffer.append_log(delta_log.records_mut().drain(..).collect());
        self.maybe_page_map = Some(ring_buffer.to_page_map());
        self.header_cache = OnceLock::from(Some(ring_buffer.get_header()));
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

impl Default for LogMemoryStore {
    fn default() -> Self {
        Self::new(FlagStatus::Disabled)
    }
}

impl Clone for LogMemoryStore {
    fn clone(&self) -> Self {
        Self {
            feature_flag: self.feature_flag,
            // PageMap is a persistent data structure, so clone is cheap and creates
            // an independent snapshot.
            maybe_page_map: self.maybe_page_map.clone(),
            delta_log_sizes: self.delta_log_sizes.clone(),
            // OnceLock is not Clone, so we must manually clone the state.
            header_cache: match self.header_cache.get() {
                Some(val) => OnceLock::from(*val),
                None => OnceLock::new(),
            },
        }
    }
}

impl PartialEq for LogMemoryStore {
    fn eq(&self, other: &Self) -> bool {
        // header_cache is a transient cache and should not be compared.
        self.maybe_page_map == other.maybe_page_map && self.delta_log_sizes == other.delta_log_sizes
    }
}

impl Eq for LogMemoryStore {}

#[cfg(test)]
mod tests;
