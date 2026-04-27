mod header;
mod index_table;
mod log_record;
mod memory;
mod ring_buffer;
mod struct_io;

use crate::canister_state::system_state::log_memory_store::{
    header::Header,
    log_record::LogRecord,
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
use std::sync::OnceLock;
use std::time::Duration;

/// Upper bound on stored delta-log sizes used for metrics.
/// Limits memory growth, 10k covers expected per-round
/// number of messages per canister (and so delta log appends).
const DELTA_LOG_SIZES_CAP: usize = 10_000;

/// Canister log storage backed by a PageMap-based ring buffer.
///
/// Using PageMap allows log data to be stored outside the heap and
/// checkpointed efficiently via copy-on-write pages.
///
/// Stores the canister's accumulated log records. During execution,
/// log messages are collected into delta logs in the sandbox, then
/// appended to this store in bulk after each message completes.
///
/// The ring buffer has a configurable capacity. Resizing reads all
/// existing records and rewrites them into a new ring buffer of the
/// requested size.
///
/// When the ring buffer is full, oldest records at the head are
/// evicted to make room for new ones.
///
/// An index table partitions the data region into segments, enabling
/// filtered queries by record index or timestamp without scanning
/// the entire ring buffer. Returned results are trimmed to fit within
/// the maximum message response size.
#[derive(Debug, ValidateEq)]
pub struct LogMemoryStore {
    /// Feature flag for controlling LogMemoryStore enabled.
    feature_flag: FlagStatus,

    /// Optional PageMap for storing log records ring-buffer with metadata.
    /// It can be None when canister code is uninstalled and logs are
    /// removed.
    #[validate_eq(CompareWithValidateEq)]
    maybe_page_map: Option<PageMap>,

    /// A persistent high-water mark for log record indexing.
    ///
    /// This value is persisted independently of the `PageMap` to ensure that
    /// global record IDs continue to increment monotonically, even if the
    /// underlying logs are cleared or the canister is reinstalled.
    ///
    /// It is updated with the current `next_idx()` whenever the logs are
    /// modified: appended, cleared or deallocated.
    persistent_next_idx: u64,

    /// Caches the ring buffer header to avoid expensive reads from the `PageMap`.
    #[validate_eq(Ignore)]
    header_cache: OnceLock<Option<Header>>,

    /// Cached timestamp of the oldest live record. Makes the retention
    /// metric's per-round observation (`max_timestamp − first_timestamp`)
    /// an O(1) field read instead of a cold page-map read at `data_head`.
    ///
    /// Plain `Option<u64>` (not `OnceLock` like `header_cache`) because we
    /// populate eagerly from every mutation site; no lazy init under
    /// `&self` needed. Not persisted across checkpoints; rebuilt in
    /// `new_inner`.
    #[validate_eq(Ignore)]
    first_timestamp_cache: Option<u64>,

    /// (!) No need to preserve across checkpoints.
    /// Tracks the size of each delta log appended during a round.
    /// Multiple logs can be appended in one round (e.g. heartbeat, timers, or message executions).
    /// The collected sizes are used to expose per-round memory usage metrics
    /// and the record is cleared at the end of the round.
    delta_log_sizes: VecDeque<usize>,
}

impl LogMemoryStore {
    /// Creates a new uninitialized store with an empty ring buffer.
    ///
    /// The store technically exists but has 0 capacity and is considered "uninitialized".
    /// Any attempts to append logs will be silently ignored until the store is
    /// explicitly resized to a non-zero capacity.
    pub fn new(feature_flag: FlagStatus) -> Self {
        const DEFAULT_NEXT_IDX: u64 = 0;
        Self::new_inner(feature_flag, None, DEFAULT_NEXT_IDX)
    }

    /// Creates a new store from a checkpoint.
    pub fn from_checkpoint(
        feature_flag: FlagStatus,
        maybe_page_map: Option<PageMap>,
        persistent_next_idx: u64,
    ) -> Self {
        Self::new_inner(feature_flag, maybe_page_map, persistent_next_idx)
    }

    fn new_inner(
        feature_flag: FlagStatus,
        maybe_page_map: Option<PageMap>,
        persistent_next_idx: u64,
    ) -> Self {
        let maybe_page_map = if feature_flag == FlagStatus::Enabled {
            maybe_page_map
        } else {
            None
        };
        let persistent_next_idx = if feature_flag == FlagStatus::Enabled {
            persistent_next_idx
        } else {
            0
        };
        // Rebuild the first-timestamp cache from the ring buffer so the
        // invariant holds immediately after `from_checkpoint`, without
        // waiting for the next mutation to populate it.
        let first_timestamp_cache = maybe_page_map
            .clone()
            .and_then(RingBuffer::load_checked)
            .and_then(|rb| rb.first_timestamp(&rb.get_header()));
        let store = Self {
            feature_flag,
            maybe_page_map,
            persistent_next_idx,
            header_cache: OnceLock::new(),
            first_timestamp_cache,
            delta_log_sizes: VecDeque::new(),
        };
        debug_assert!(store.stats_ok());
        store
    }

    /// Provides access to the underlying `PageMap`.
    pub fn maybe_page_map(&self) -> Option<&PageMap> {
        self.maybe_page_map.as_ref()
    }

    /// Provides mutable access to the underlying `PageMap`.
    ///
    /// ### IMPORTANT(!) Safety & Invariants
    /// Use this **exclusively** for stripping page map deltas. Do not modify the
    /// map's contents directly, as doing so invalidates the `header_cache` and
    /// forces an unnecessary reload of the page map in subsequent rounds.
    pub fn maybe_page_map_mut(&mut self) -> Option<&mut PageMap> {
        self.maybe_page_map.as_mut()
    }

    /// Returns true if the underlying page map is allocated.
    pub fn is_allocated(&self) -> bool {
        self.maybe_page_map.is_some()
    }

    /// Clears the canister log records without deallocating the ring buffer.
    pub fn clear(&mut self) {
        if let Some(mut ring_buffer) = self.load_ring_buffer() {
            ring_buffer.clear();
            self.save_ring_buffer(ring_buffer);
        } else {
            self.header_cache = OnceLock::new();
            self.first_timestamp_cache = None;
            debug_assert!(self.stats_ok());
        }
    }

    /// Update page_map, header_cache, first_timestamp_cache and persistent_next_idx.
    fn save_ring_buffer(&mut self, ring_buffer: RingBuffer) {
        let header = ring_buffer.get_header();
        let first_timestamp = ring_buffer.first_timestamp(&header);
        self.maybe_page_map = Some(ring_buffer.to_page_map());
        self.header_cache = OnceLock::from(Some(header));
        self.first_timestamp_cache = first_timestamp;
        // Must come after header_cache update, since next_idx() reads from it.
        self.persistent_next_idx = self.next_idx();
        debug_assert!(self.stats_ok());
    }

    /// Deallocates underlying memory.
    pub fn deallocate(&mut self) {
        // Must come before clearing the page map and header cache, since next_idx() reads from them.
        self.persistent_next_idx = self.next_idx();
        self.maybe_page_map = None;
        self.header_cache = OnceLock::new();
        self.first_timestamp_cache = None;
        debug_assert!(self.stats_ok());
    }

    /// Loads the ring buffer from the page map.
    fn load_ring_buffer(&self) -> Option<RingBuffer> {
        self.maybe_page_map
            .clone()
            .and_then(RingBuffer::load_checked)
    }

    /// Invariant: populated caches must match what a fresh read of the ring
    /// buffer would return. Intended to be called only via `debug_assert!`;
    /// the `cfg!` guard keeps the body a no-op in release regardless of
    /// caller, so it's fine for the check to be expensive.
    fn stats_ok(&self) -> bool {
        if !cfg!(debug_assertions) {
            return true;
        }
        let ring_buffer = self.load_ring_buffer();
        let actual_header = ring_buffer.as_ref().map(|rb| rb.get_header());
        // `header_cache` is lazy: if populated, must match; if empty, skip.
        if let Some(cached) = self.header_cache.get()
            && *cached != actual_header
        {
            return false;
        }
        // `first_timestamp_cache` is kept eagerly in sync, so must always match.
        let actual_first_ts = ring_buffer
            .as_ref()
            .zip(actual_header.as_ref())
            .and_then(|(rb, h)| rb.first_timestamp(h));
        if self.first_timestamp_cache != actual_first_ts {
            return false;
        }
        true
    }

    /// Returns the ring buffer header.
    fn get_header(&self) -> Option<Header> {
        *self
            .header_cache
            .get_or_init(|| self.load_ring_buffer().map(|rb| rb.get_header()))
    }

    /// Returns the timestamp of the most recently appended record, or `None`
    /// if the buffer is empty. O(1) via the cached header.
    pub fn max_timestamp(&self) -> Option<u64> {
        let header = self.get_header()?;
        (header.data_size.get() > 0).then_some(header.max_timestamp)
    }

    /// Returns the timestamp of the oldest live record, or `None` if the
    /// buffer is empty. O(1) field read — the cache is kept in sync with
    /// the ring buffer by every mutation.
    pub fn first_timestamp(&self) -> Option<u64> {
        self.first_timestamp_cache
    }

    /// Returns the time span between the oldest and newest records, or
    /// `None` if the buffer is empty. Returns `Duration::ZERO` when both
    /// timestamps are equal (single record).
    pub fn retention(&self) -> Option<Duration> {
        let max = self.max_timestamp()?;
        let first = self.first_timestamp()?;
        Some(Duration::from_nanos(max.saturating_sub(first)))
    }

    /// Returns the total allocated memory.
    pub fn memory_usage(&self) -> usize {
        self.total_virtual_memory_usage()
    }

    /// Returns the total virtual memory usage of the ring buffer.
    ///
    /// Includes header, index table and data region.
    /// It is 'virtual' because it is not aligned to actual OS page size.
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

    /// Returns `true` if calling `resize(limit)` would actually do work
    /// (migrate records, reallocate, or deallocate), `false` if it would
    /// be a no-op.
    ///
    /// Also used as the early-return guard inside `resize_impl`, so the
    /// two cannot diverge.
    pub fn would_resize(&self, limit: usize) -> bool {
        if self.feature_flag == FlagStatus::Disabled {
            // When disabled, resize deallocates — work only if allocated.
            return self.maybe_page_map.is_some();
        }
        if limit == 0 {
            // Limit zero deallocates — work only if allocated.
            return self.maybe_page_map.is_some();
        }
        let target_limit = limit.max(DATA_CAPACITY_MIN);
        let current_capacity = self.get_header().map(|h| h.data_capacity.get() as usize);
        current_capacity != Some(target_limit)
    }

    /// Resizes the ring buffer to the specified limit, preserving existing records.
    ///
    /// This method enforces a minimum safe capacity and performs no operation if the
    /// effective capacity has not changed.
    pub fn resize(&mut self, limit: usize, fd_factory: Arc<dyn PageAllocatorFileDescriptor>) {
        self.resize_impl(limit, || PageMap::new(fd_factory))
    }

    /// Resizes the ring buffer to the specified limit, preserving existing records.
    ///
    /// This method is used for testing purposes and does not use file descriptors.
    pub fn resize_for_testing(&mut self, limit: usize) {
        self.resize_impl(limit, PageMap::new_for_testing)
    }

    fn resize_impl(&mut self, limit: usize, create_page_map: impl FnOnce() -> PageMap) {
        if !self.would_resize(limit) {
            return;
        }
        if self.feature_flag == FlagStatus::Disabled || limit == 0 {
            self.deallocate();
            return;
        }
        let target_limit = limit.max(DATA_CAPACITY_MIN);
        let current_capacity = self.get_header().map(|h| h.data_capacity.get() as usize);

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
            new_buffer.append_log(old_buffer.iter());
        }

        // Update of the state.
        self.save_ring_buffer(new_buffer);
    }

    /// Returns the monotonic sequence index for the next log record.
    ///
    /// Calculates the maximum of the `persistent_next_idx` and the current
    /// buffer's index to prevent ID collisions across lifecycle events.
    pub fn next_idx(&self) -> u64 {
        self.persistent_next_idx
            .max(self.get_header().map(|h| h.next_idx).unwrap_or(0))
    }

    /// Returns true if the ring buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes_used() == 0
    }

    /// Returns bytes occupied by stored log records (not allocated capacity).
    pub fn bytes_used(&self) -> usize {
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
        ring_buffer.append_log(delta_log.records_mut().drain(..));
        self.save_ring_buffer(ring_buffer);
    }

    /// Records the size of the appended delta log.
    fn push_delta_log_size(&mut self, size: usize) {
        if self.delta_log_sizes.len() >= DELTA_LOG_SIZES_CAP {
            self.delta_log_sizes.pop_front();
        }
        self.delta_log_sizes.push_back(size);
    }

    /// Returns true if the delta log sizes are not empty.
    pub fn has_delta_log_sizes(&self) -> bool {
        !self.delta_log_sizes.is_empty()
    }

    /// Returns delta_log sizes.
    pub fn delta_log_sizes(&self) -> Vec<usize> {
        self.delta_log_sizes.iter().cloned().collect()
    }

    /// Clears the delta_log sizes.
    pub fn clear_delta_log_sizes(&mut self) {
        self.delta_log_sizes.clear();
    }

    /// Calculates the total memory footprint of canister log records
    /// when encoded and stored within the `LogMemoryStore`.
    ///
    /// `CanisterLog` and `LogMemoryStore` use different structures for storing
    /// log records, so we need to calculate the storage size for each type separately.
    pub fn estimate_storage_size(log: &CanisterLog) -> usize {
        log.records()
            .iter()
            .map(|r| LogRecord::estimate_bytes_len(r.content.len()))
            .sum()
    }

    /// Calculates the size of a single log record when encoded
    /// and stored within the `LogMemoryStore`.
    pub const fn estimate_record_size(content_size: usize) -> usize {
        LogRecord::estimate_bytes_len(content_size)
    }
}

impl Clone for LogMemoryStore {
    fn clone(&self) -> Self {
        Self {
            feature_flag: self.feature_flag,
            // PageMap is a persistent data structure, so clone is cheap and creates
            // an independent snapshot.
            maybe_page_map: self.maybe_page_map.clone(),
            persistent_next_idx: self.persistent_next_idx,
            delta_log_sizes: self.delta_log_sizes.clone(),
            // OnceLock is not Clone, so we must manually clone the state.
            header_cache: match self.header_cache.get() {
                Some(val) => OnceLock::from(*val),
                None => OnceLock::new(),
            },
            first_timestamp_cache: self.first_timestamp_cache,
        }
    }
}

impl PartialEq for LogMemoryStore {
    fn eq(&self, other: &Self) -> bool {
        // header_cache and first_timestamp_cache are transient caches and
        // should not be compared.
        self.feature_flag == other.feature_flag
            && self.maybe_page_map == other.maybe_page_map
            && self.persistent_next_idx == other.persistent_next_idx
            && self.delta_log_sizes == other.delta_log_sizes
    }
}

impl Eq for LogMemoryStore {}

#[cfg(test)]
mod tests;
