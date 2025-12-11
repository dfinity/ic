mod header;
mod index_table;
mod log_record;
mod memory;
mod ring_buffer;
mod struct_io;

use crate::canister_state::system_state::log_memory_store::{
    memory::MemorySize,
    ring_buffer::{DATA_CAPACITY_MIN, RingBuffer},
};
use crate::page_map::{PageAllocatorFileDescriptor, PageMap};
use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};
use ic_types::{CanisterLog, DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT, NumBytes};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::VecDeque;
use std::sync::Arc;

/// Upper bound on stored delta-log sizes used for metrics.
/// Limits memory growth, 10k covers expected per-round
/// number of messages per canister (and so delta log appends).
const DELTA_LOG_SIZES_CAP: usize = 10_000;

#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct LogMemoryStore {
    #[validate_eq(Ignore)]
    page_map: PageMap,

    /// Stores the log memory limit for the canister.
    ///
    /// This is important for the cases when the canister
    /// is created without a Wasm module or after uninstall.
    /// In these cases the canister should not be charged,
    /// so the page_map must be empty, but we still need to
    /// preserve the log_memory_limit.
    log_memory_limit: NumBytes,

    /// (!) No need to preserve across checkpoints.
    /// Tracks the size of each delta log appended during a round.
    /// Multiple logs can be appended in one round (e.g. heartbeat, timers, or message executions).
    /// The collected sizes are used to expose per-round memory usage metrics
    /// and the record is cleared at the end of the round.
    #[validate_eq(Ignore)]
    delta_log_sizes: VecDeque<usize>,
}

impl LogMemoryStore {
    /// Creates a new store with an empty ring buffer to avoid unnecessary log-memory charges.
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        // This creates a new empty page map with invalid ring buffer header.
        Self::new_inner(RingBuffer::load_raw(PageMap::new(fd_factory)).to_page_map())
    }

    /// Creates a new store that will use the temp file system for allocating new pages.
    pub fn new_for_testing() -> Self {
        Self::new_inner(RingBuffer::load_raw(PageMap::new_for_testing()).to_page_map())
    }

    fn new_inner(page_map: PageMap) -> Self {
        Self {
            page_map,
            delta_log_sizes: VecDeque::new(),
            log_memory_limit: NumBytes::from(DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT as u64),
        }
    }

    pub fn from_checkpoint(page_map: PageMap, log_memory_limit: NumBytes) -> Self {
        Self {
            page_map,
            delta_log_sizes: VecDeque::new(),
            log_memory_limit,
        }
    }

    pub fn page_map(&self) -> &PageMap {
        &self.page_map
    }

    pub fn page_map_mut(&mut self) -> &mut PageMap {
        &mut self.page_map
    }

    /// Clears the canister log records.
    pub fn clear(&mut self, fd_factory: Arc<dyn PageAllocatorFileDescriptor>) {
        // This creates a new empty page map with invalid ring buffer header.
        self.page_map = PageMap::new(fd_factory);
    }

    /// Loads the ring buffer from the page map.
    fn load_ring_buffer(&self) -> Option<RingBuffer> {
        RingBuffer::load_checked(self.page_map.clone())
    }

    /// Returns the total allocated bytes for the ring buffer
    /// including header, index table and data region.
    pub fn total_allocated_bytes(&self) -> usize {
        self.load_ring_buffer()
            .map(|rb| rb.total_allocated_bytes())
            .unwrap_or(0)
    }

    /// Returns the data capacity of the ring buffer.
    pub fn byte_capacity(&self) -> usize {
        self.load_ring_buffer()
            .map(|rb| rb.byte_capacity())
            .unwrap_or(0)
    }

    /// Returns the data size of the ring buffer.
    pub fn bytes_used(&self) -> usize {
        self.load_ring_buffer()
            .map(|rb| rb.bytes_used())
            .unwrap_or(0)
    }

    pub fn log_memory_limit(&self) -> NumBytes {
        self.log_memory_limit
    }

    /// Sets the log memory limit for this canister.
    ///
    /// The ring buffer is updated only when it already exists and the new
    /// limit changes its byte capacity. This avoids creating a ring buffer
    /// for canisters without a Wasm module or after uninstall, preventing
    /// unnecessary log-memory charges.
    pub fn set_log_memory_limit(&mut self, new_log_memory_limit: NumBytes) {
        // Enforce a safe minimum for data capacity.
        let new_log_memory_limit = new_log_memory_limit.get().max(DATA_CAPACITY_MIN as u64);
        self.log_memory_limit = NumBytes::from(new_log_memory_limit);

        // Only resize on an existing ring buffer.
        if let Some(old) = self.load_ring_buffer() {
            // Only resize when the capacity actually changes.
            if old.byte_capacity() != new_log_memory_limit as usize {
                // NOTE — PageMap cannot be shrunk today. Reducing capacity keeps
                // allocated pages in place; in practice the ring buffer max is
                // currently ~55 MB. Future improvement — allocate a new PageMap
                // with the desired capacity, refeed records, then drop the old
                // map or add a `PageMap::shrink` API to reclaim pages.
                //
                // Recreate a ring buffer with the new capacity and restore records.
                let mut new =
                    RingBuffer::new(self.page_map.clone(), MemorySize::new(new_log_memory_limit));
                new.append_log(old.all_records());
                self.page_map = new.to_page_map();
            }
        }
    }

    /// Returns the next log record `idx`.
    pub fn next_idx(&self) -> u64 {
        self.load_ring_buffer().map(|rb| rb.next_idx()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.load_ring_buffer()
            .map(|rb| rb.is_empty())
            .unwrap_or(true)
    }

    /// Returns the canister log records, optionally filtered.
    pub fn records(&self, filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        self.load_ring_buffer()
            .map(|rb| rb.records(filter))
            .unwrap_or_default()
    }

    /// Returns all canister log records.
    pub fn all_records(&self) -> Vec<CanisterLogRecord> {
        self.load_ring_buffer()
            .map(|rb| rb.all_records())
            .unwrap_or_default()
    }

    /// Appends a delta log to the ring buffer.
    /// If the ring buffer does not exist, it is created with the current log memory limit.
    pub fn append_delta_log(&mut self, delta_log: &mut CanisterLog) {
        // Record the size of the appended delta log for metrics.
        self.push_delta_log_size(delta_log.bytes_used());
        let records: Vec<CanisterLogRecord> = delta_log
            .records_mut()
            .iter_mut()
            .map(std::mem::take)
            .collect();
        let mut ring_buffer = self.load_ring_buffer().unwrap_or(RingBuffer::new(
            self.page_map.clone(),
            MemorySize::new(self.log_memory_limit.get()),
        ));
        ring_buffer.append_log(records);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister_state::system_state::log_memory_store::ring_buffer::RESULT_MAX_SIZE;
    use ic_management_canister_types_private::{DataSize, FetchCanisterLogsRange};

    fn make_canister_record(idx: u64, ts: u64, message: &str) -> CanisterLogRecord {
        CanisterLogRecord {
            idx,
            timestamp_nanos: ts,
            content: message.as_bytes().to_vec(),
        }
    }

    /// Creates a full delta log without exceeding the byte capacity.
    fn make_full_delta(mut next_idx: u64, byte_capacity: usize, content_len: usize) -> CanisterLog {
        let mut delta = CanisterLog::new_delta_with_next_index(next_idx, byte_capacity);
        let fake_record = make_canister_record(0, 0, &"x".repeat(content_len));
        let count = delta.byte_capacity() / fake_record.data_size();
        for _ in 0..count {
            delta.add_record(next_idx * 1_000, vec![b'x'; content_len]);
            next_idx = delta.next_idx();
        }
        delta
    }

    fn append_deltas(
        store: &mut LogMemoryStore,
        start_idx: u64,
        volume_bytes: usize,
        delta_log_byte_capacity: usize,
        content_len: usize,
    ) {
        let mut next_idx = start_idx;
        let mut total = 0;
        loop {
            let mut delta = make_full_delta(next_idx, delta_log_byte_capacity, content_len);
            total += delta.bytes_used();
            if total > volume_bytes {
                return;
            }
            store.append_delta_log(&mut delta);
            next_idx = store.next_idx();
        }
    }

    fn total_size(records: &[CanisterLogRecord]) -> usize {
        records.iter().map(|r| r.data_size()).sum()
    }

    #[test]
    fn initialization_defaults() {
        let s = LogMemoryStore::new_for_testing();
        assert_eq!(s.next_idx(), 0);
        assert!(s.is_empty());
        assert_eq!(s.bytes_used(), 0);
        assert_eq!(s.byte_capacity(), 0);
        assert_eq!(
            s.log_memory_limit(),
            NumBytes::new(DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT as u64)
        );
        assert_eq!(s.total_allocated_bytes(), 0);
        assert_eq!(s.records(None).len(), 0);
    }

    #[test]
    fn test_memory_usage_after_appending_logs() {
        let s = LogMemoryStore::new_for_testing();

        // Canister created, but no wasm module uploaded, so no logs recorded.
        assert_eq!(s.next_idx(), 0);
        assert!(s.is_empty());
        assert_eq!(s.bytes_used(), 0);
        assert_eq!(s.byte_capacity(), 0);
        assert_eq!(
            s.log_memory_limit(),
            NumBytes::new(DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT as u64)
        );
        assert_eq!(s.total_allocated_bytes(), 0);
        assert_eq!(s.records(None).len(), 0);

        // Append some logs.
        let mut delta = CanisterLog::default_delta();
        delta.add_record(100, b"a".to_vec());
        delta.add_record(200, b"bb".to_vec());
        delta.add_record(300, b"ccc".to_vec());
        let mut s = LogMemoryStore::new_for_testing();
        s.append_delta_log(&mut delta);

        // Assert memory usage.
        assert_eq!(s.next_idx(), 3);
        assert!(!s.is_empty());
        assert!(s.bytes_used() > 0);
        assert!(s.bytes_used() < DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT);
        assert_eq!(s.byte_capacity(), DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT);
        assert_eq!(
            s.log_memory_limit(),
            NumBytes::new(DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT as u64)
        );
        assert!(s.total_allocated_bytes() > DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT);
        assert_eq!(s.records(None).len(), 3);
    }

    #[test]
    fn append_preserves_order_and_metadata() {
        // Append a small delta and verify ordering + metadata.
        let mut delta = CanisterLog::default_delta();
        delta.add_record(100, b"a".to_vec());
        delta.add_record(200, b"bb".to_vec());
        delta.add_record(300, b"ccc".to_vec());

        let mut s = LogMemoryStore::new_for_testing();
        s.append_delta_log(&mut delta);

        assert_eq!(s.next_idx(), 3);
        assert!(!s.is_empty());
        assert!(s.bytes_used() > 0);
        assert_eq!(
            s.records(None),
            vec![
                make_canister_record(0, 100, "a"),
                make_canister_record(1, 200, "bb"),
                make_canister_record(2, 300, "ccc"),
            ]
        );
    }

    #[test]
    fn filtering_by_idx_and_timestamp() {
        // Same small dataset — test index and timestamp filters.
        let mut delta = CanisterLog::default_delta();
        delta.add_record(10, b"a".to_vec());
        delta.add_record(20, b"b".to_vec());
        delta.add_record(30, b"c".to_vec());

        let mut s = LogMemoryStore::new_for_testing();
        s.append_delta_log(&mut delta);

        // By index — inclusive range.
        // Range is [1, 2).
        let records = s.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange { start: 1, end: 2 },
        )));
        assert_eq!(records, vec![make_canister_record(1, 20, "b")]);

        // By timestamp — inclusive range that picks middle record.
        // Range is [15, 25).
        let records = s.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
            FetchCanisterLogsRange { start: 15, end: 25 },
        )));
        assert_eq!(records, vec![make_canister_record(1, 20, "b")]);
    }

    #[test]
    fn eviction_when_capacity_reached() {
        // Force repeated large appends so aggregate log approaches capacity — beginning records should be dropped.
        let aggregate_capacity = NumBytes::from(50_000); // keep small for the test.
        let start_idx = 0;
        let mut s = LogMemoryStore::new_for_testing();
        s.set_log_memory_limit(aggregate_capacity);

        // Append 100k records in batches of 10k deltas of ~1KB record each.
        append_deltas(&mut s, start_idx, 100_000, 10_000, 1_000);

        let used = s.bytes_used();
        assert!(used <= s.byte_capacity());
        // If store is non-empty, at least one record should remain and next_id advances.
        let records = s.records(None);
        assert!(!records.is_empty());
        assert_ne!(
            records.first().unwrap().idx,
            start_idx,
            "beginning records should be evicted"
        );
        assert_eq!(
            records.last().unwrap().idx + 1,
            s.next_idx(),
            "end records should be present"
        );
    }

    #[test]
    fn max_response_size_respected_without_filtering() {
        // Ensure results are trimmed to RESULT_MAX_SIZE — both for full range and for range-filtered queries.
        let aggregate_capacity = NumBytes::from(10_000_000);
        let start_idx = 1_000;
        assert!(
            aggregate_capacity.get() > RESULT_MAX_SIZE.get(),
            "large enough capacity"
        );

        let mut s = LogMemoryStore::new_for_testing();
        s.set_log_memory_limit(aggregate_capacity);
        // Append 5 MB records in batches of 1 MB deltas of ~1KB record each.
        append_deltas(&mut s, start_idx, 5_000_000, 1_000_000, 1_000);

        // Without filters — returned bytes must not exceed RESULT_MAX_SIZE.
        let result = s.records(None);
        assert!(total_size(&result) <= RESULT_MAX_SIZE.get() as usize);
        // And recent records (tail) must be present.
        assert_eq!(result.last().unwrap().idx + 1, s.next_idx());
    }

    #[test]
    fn max_response_size_respected_with_filtering_by_idx() {
        // Ensure results are trimmed to RESULT_MAX_SIZE — both for full range and for range-filtered queries.
        let aggregate_capacity = NumBytes::from(10_000_000);
        let start_idx = 1_000;
        assert!(
            aggregate_capacity.get() > RESULT_MAX_SIZE.get(),
            "large enough capacity"
        );

        let mut s = LogMemoryStore::new_for_testing();
        s.set_log_memory_limit(aggregate_capacity);
        // Append 5 MB records in batches of 1 MB deltas of ~1KB record each.
        append_deltas(&mut s, start_idx, 5_000_000, 1_000_000, 1_000);

        // With an explicit wide index filter — response must also be capped.
        let result = s.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange {
                start: 0,
                end: u64::MAX,
            },
        )));
        assert!(total_size(&result) <= RESULT_MAX_SIZE.get() as usize);
        // Oldest records (head) must be present.
        assert_eq!(result.first().unwrap().idx, start_idx);

        // For a partial range that fits within the available records — beginning should match requested start.
        let partial_start = start_idx + 50;
        let result = s.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange {
                start: partial_start,
                end: partial_start + 300,
            },
        )));
        assert!(total_size(&result) <= RESULT_MAX_SIZE.get() as usize);
        // Oldest records (head) must be present.
        assert_eq!(result.first().unwrap().idx, partial_start);
    }

    #[test]
    fn max_response_size_respected_with_filtering_by_timestamp() {
        // Ensure results are trimmed to RESULT_MAX_SIZE — both for full range and for range-filtered queries.
        let aggregate_capacity = NumBytes::from(10_000_000);
        let start_idx = 1_000;
        assert!(
            aggregate_capacity.get() > RESULT_MAX_SIZE.get(),
            "large enough capacity"
        );

        let mut s = LogMemoryStore::new_for_testing();
        s.set_log_memory_limit(aggregate_capacity);
        // Append 5 MB records in batches of 1 MB deltas of ~1KB record each.
        append_deltas(&mut s, start_idx, 5_000_000, 1_000_000, 1_000);

        // With an explicit wide timestamp filter — response must also be capped.
        let result = s.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
            FetchCanisterLogsRange {
                start: 0,
                end: u64::MAX,
            },
        )));
        assert!(total_size(&result) <= RESULT_MAX_SIZE.get() as usize);
        // Oldest records (head) must be present.
        assert_eq!(result.first().unwrap().timestamp_nanos, start_idx * 1_000);

        // For a partial range that fits within the available records — beginning should match requested start.
        let partial_start_ts = (start_idx + 50) * 1_000;
        let result = s.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
            FetchCanisterLogsRange {
                start: partial_start_ts,
                end: partial_start_ts + 300_000,
            },
        )));
        assert!(total_size(&result) <= RESULT_MAX_SIZE.get() as usize);
        // Oldest records (head) must be present.
        assert_eq!(result.first().unwrap().timestamp_nanos, partial_start_ts);
    }

    #[test]
    fn test_increasing_capacity_preserves_records() {
        let mut store = LogMemoryStore::new_for_testing();
        store.set_log_memory_limit(NumBytes::new(1_000_000)); // 1 MB

        // Append 200 KB records in batches of 100 KB deltas of ~1KB record each.
        append_deltas(&mut store, 0, 200_000, 100_000, 1_000);

        let records_before = store.records(None);
        let bytes_used_before = store.bytes_used();

        // Increase capacity.
        store.set_log_memory_limit(NumBytes::new(2_000_000)); // 2 MB

        let records_after = store.records(None);
        let bytes_used_after = store.bytes_used();

        // Verify all records are preserved.
        assert_eq!(records_before, records_after);
        assert_eq!(bytes_used_before, bytes_used_after);
    }

    #[test]
    fn test_decreasing_capacity_drops_oldest_records_but_preserves_recent() {
        let mut store = LogMemoryStore::new_for_testing();
        store.set_log_memory_limit(NumBytes::new(500_000)); // 500 KB

        // Append 200 KB records in batches of 100 KB deltas of ~1KB record each.
        append_deltas(&mut store, 0, 200_000, 100_000, 1_000);

        let records_before = store.records(None);
        let bytes_used_before = store.bytes_used();
        let next_idx_before = store.next_idx();

        // Decrease capacity.
        store.set_log_memory_limit(NumBytes::new(100_000)); // 100 KB

        let records_after = store.records(None);
        let bytes_used_after = store.bytes_used();

        // Verify some records are dropped.
        assert!(records_after.len() < records_before.len());
        assert!(bytes_used_after < bytes_used_before);
        // Verify recent records are preserved.
        assert_eq!(next_idx_before, store.next_idx());
    }

    #[test]
    fn test_small_capacity_indexing() {
        let mut store = LogMemoryStore::new_for_testing();
        // Set a very small capacity, smaller than 146 bytes (INDEX_ENTRY_COUNT_MAX).
        // 146 entries. If capacity is 100. 100 / 146 = 0.
        store.set_log_memory_limit(NumBytes::new(100));

        let mut delta = CanisterLog::new_delta_with_next_index(0, 100);
        // Add multiple records.
        // Header overhead is 8+8+4 = 20 bytes.
        // Content "a" is 1 byte.
        // Total 21 bytes per record.
        delta.add_record(0, b"a".to_vec());
        delta.add_record(1, b"b".to_vec());

        store.append_delta_log(&mut delta);

        assert!(!store.is_empty());
        // 21 * 2 = 42 bytes used.
        assert_eq!(store.bytes_used(), 42);

        // Try to read it back.
        let records = store.records(None);
        assert_eq!(records.len(), 2, "Should return 2 records");
        assert_eq!(records[0].content, b"a");
        assert_eq!(records[1].content, b"b");
    }

    #[test]
    fn test_multiple_records_in_same_segment() {
        let mut store = LogMemoryStore::new_for_testing();
        // Capacity 100KB. Segment size ~685 bytes.
        store.set_log_memory_limit(NumBytes::new(100_000));

        let mut delta = CanisterLog::new_delta_with_next_index(0, 100_000);
        // Add 10 records, each ~21 bytes. All should fit in segment 0.
        for i in 0..10 {
            delta.add_record(i, vec![i as u8]);
        }
        store.append_delta_log(&mut delta);

        // Verify we can retrieve all of them.
        let records = store.records(None);
        assert_eq!(records.len(), 10);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.idx, i as u64);
        }

        // Verify filtering works.
        // Filter for record 5. Range is [5, 6).
        let records = store.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange { start: 5, end: 6 },
        )));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].idx, 5);
    }

    #[test]
    fn test_very_small_capacity_single_byte() {
        let mut store = LogMemoryStore::new_for_testing();
        // Set capacity to 1 byte - this will be clamped to DATA_CAPACITY_MIN (4096 bytes).
        store.set_log_memory_limit(NumBytes::new(1));

        // Verify log memory limit was clamped to minimum.
        assert_eq!(store.log_memory_limit(), NumBytes::new(4096));
        assert_eq!(store.byte_capacity(), 0); // Actual capacity is 0 because no records were added.

        let mut delta = CanisterLog::new_delta_with_next_index(0, 4096);
        // Add a record - it should fit within the minimum capacity.
        delta.add_record(0, b"a".to_vec());

        store.append_delta_log(&mut delta);

        // The record should be stored.
        assert_eq!(store.byte_capacity(), 4096);
        assert_eq!(store.next_idx(), 1);
        assert_eq!(store.bytes_used(), 21);
        let records = store.records(None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content, b"a");
    }

    #[test]
    fn test_small_capacity_with_eviction() {
        let mut store = LogMemoryStore::new_for_testing();
        let capacity = NumBytes::new(4096);
        store.set_log_memory_limit(capacity);

        assert_eq!(store.log_memory_limit(), capacity);
        assert_eq!(store.byte_capacity(), 0); // Actual capacity is 0 because no records were added.

        // Fill the buffer with records until we're close to capacity.
        // Each record is ~21 bytes (8+8+4+1), so we can fit ~195 records.
        let record_size = 21;
        let max_records = capacity.get() as usize / record_size; // ~195

        // Add records to fill the buffer.
        for i in 0..max_records {
            let mut delta =
                CanisterLog::new_delta_with_next_index(i as u64, capacity.get() as usize);
            delta.add_record(i as u64, vec![i as u8]);
            store.append_delta_log(&mut delta);
        }

        // Verify all records fit.
        assert_eq!(store.byte_capacity(), capacity.get() as usize);
        assert_eq!(store.next_idx(), max_records as u64);
        let records = store.records(None);
        assert_eq!(records.len(), max_records);

        // Add one more record - this should evict the oldest one.
        let mut delta =
            CanisterLog::new_delta_with_next_index(max_records as u64, capacity.get() as usize);
        delta.add_record(max_records as u64, vec![255]);
        store.append_delta_log(&mut delta);

        // Verify the oldest record was evicted.
        assert_eq!(store.next_idx(), (max_records + 1) as u64);
        let records = store.records(None);
        assert_eq!(records.len(), max_records);
        assert_eq!(records[0].idx, 1); // First record (idx=0) was evicted.
        assert_eq!(records.last().unwrap().idx, max_records as u64);
    }

    #[test]
    fn test_filtering_with_multiple_records_in_same_segment() {
        let mut store = LogMemoryStore::new_for_testing();
        // Capacity 100KB. Segment size ~685 bytes.
        store.set_log_memory_limit(NumBytes::new(100_000));

        let mut delta = CanisterLog::new_delta_with_next_index(0, 100_000);
        // Add 20 records, each ~21 bytes. All should fit in segment 0.
        for i in 0..20 {
            delta.add_record(i * 1000, vec![i as u8]);
        }
        store.append_delta_log(&mut delta);

        // Filter for records in the middle: [5000, 15000).
        let records = store.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
            FetchCanisterLogsRange {
                start: 5000,
                end: 15000,
            },
        )));
        // Should return records 5-14 (10 records).
        assert_eq!(records.len(), 10);
        assert_eq!(records[0].idx, 5);
        assert_eq!(records[9].idx, 14);

        // Filter by idx: [10, 15).
        let records = store.records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange { start: 10, end: 15 },
        )));
        // Should return records 10-14 (5 records).
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].idx, 10);
        assert_eq!(records[4].idx, 14);
    }
}
