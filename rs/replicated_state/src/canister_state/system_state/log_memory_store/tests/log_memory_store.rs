use super::super::ring_buffer::RESULT_MAX_SIZE;
use super::super::*;
use ic_management_canister_types_private::{
    DataSize, FetchCanisterLogsFilter, FetchCanisterLogsRange,
};
use more_asserts::{assert_gt, assert_le, assert_lt};

const KIB: usize = 1024;
const EXPECTED_DATA_CAPACITY_MIN: usize = 4 * KIB;
const TEST_LOG_MEMORY_LIMIT: usize = 6 * KIB; // Different value from minimal value.

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
    let s = LogMemoryStore::new();
    assert!(s.is_empty());
    assert_eq!(s.memory_usage(), 0);
    assert_eq!(s.byte_capacity(), 0);
    assert_eq!(s.bytes_used(), 0);
    assert_eq!(s.records(None).len(), 0);
    assert_eq!(s.next_idx(), 0);
}

#[test]
fn test_appending_to_uninitialized_store_is_no_op() {
    let mut s = LogMemoryStore::new();
    let mut delta = CanisterLog::default_delta();
    delta.add_record(1, b"data".to_vec());

    // Append without setting limit
    s.append_delta_log(&mut delta);

    // Should still be empty
    assert!(s.is_empty());
    assert_eq!(s.memory_usage(), 0);
    assert_eq!(s.byte_capacity(), 0);
    assert_eq!(s.bytes_used(), 0);
    assert_eq!(s.records(None).len(), 0);
    assert_eq!(s.next_idx(), 0);
}

#[test]
fn test_minimal_allowed_capacity() {
    let mut s = LogMemoryStore::new();

    s.resize_for_testing(1); // Set a small limit.

    assert_eq!(s.byte_capacity(), EXPECTED_DATA_CAPACITY_MIN);
}

#[test]
fn test_memory_usage_after_appending_logs() {
    // Collect some delta logs.
    let mut delta = CanisterLog::default_delta();
    delta.add_record(100, b"a".to_vec());
    delta.add_record(200, b"bb".to_vec());
    delta.add_record(300, b"ccc".to_vec());

    let mut s = LogMemoryStore::new();
    s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
    s.append_delta_log(&mut delta);

    // Assert memory usage.
    assert!(!s.is_empty());
    assert_eq!(s.memory_usage(), 4 * KIB + 4 * KIB + TEST_LOG_MEMORY_LIMIT);
    assert_eq!(
        s.total_virtual_memory_usage(),
        4 * KIB + 4 * KIB + TEST_LOG_MEMORY_LIMIT // header + index + data
    );
    assert_eq!(s.byte_capacity(), TEST_LOG_MEMORY_LIMIT);
    assert_gt!(s.bytes_used(), 0);
    assert_lt!(s.bytes_used(), TEST_LOG_MEMORY_LIMIT);
    assert_eq!(s.records(None).len(), 3);
    assert_eq!(s.next_idx(), 3);
}

#[test]
fn append_preserves_order_and_metadata() {
    // Append a small delta and verify ordering + metadata.
    let mut delta = CanisterLog::default_delta();
    delta.add_record(100, b"a".to_vec());
    delta.add_record(200, b"bb".to_vec());
    delta.add_record(300, b"ccc".to_vec());

    let mut s = LogMemoryStore::new();
    s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
    s.append_delta_log(&mut delta);

    assert!(!s.is_empty());
    assert_eq!(s.next_idx(), 3);
    assert_gt!(s.bytes_used(), 0);
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

    let mut s = LogMemoryStore::new();
    s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
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
    let aggregate_capacity = 50_000; // keep small for the test.
    let start_idx = 0;
    let mut s = LogMemoryStore::new();
    s.resize_for_testing(aggregate_capacity);

    // Append 100k records in batches of 10k deltas of ~1KB record each.
    append_deltas(&mut s, start_idx, 100_000, 10_000, 1_000);

    let used = s.bytes_used();
    assert_le!(used, s.byte_capacity());
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
    let aggregate_capacity = 10_000_000;
    let start_idx = 1_000;
    assert_gt!(
        aggregate_capacity,
        RESULT_MAX_SIZE.get() as usize,
        "large enough capacity"
    );

    let mut s = LogMemoryStore::new();
    s.resize_for_testing(aggregate_capacity);
    // Append 5 MB records in batches of 1 MB deltas of ~1KB record each.
    append_deltas(&mut s, start_idx, 5_000_000, 1_000_000, 1_000);

    // Without filters — returned bytes must not exceed RESULT_MAX_SIZE.
    let result = s.records(None);
    assert_le!(total_size(&result), RESULT_MAX_SIZE.get() as usize);
    // And recent records (tail) must be present.
    assert_eq!(result.last().unwrap().idx + 1, s.next_idx());
}

#[test]
fn max_response_size_respected_with_filtering_by_idx() {
    // Ensure results are trimmed to RESULT_MAX_SIZE — both for full range and for range-filtered queries.
    let aggregate_capacity = 10_000_000;
    let start_idx = 1_000;
    assert_gt!(
        aggregate_capacity,
        RESULT_MAX_SIZE.get() as usize,
        "large enough capacity"
    );

    let mut s = LogMemoryStore::new();
    s.resize_for_testing(aggregate_capacity);
    // Append 5 MB records in batches of 1 MB deltas of ~1KB record each.
    append_deltas(&mut s, start_idx, 5_000_000, 1_000_000, 1_000);

    // With an explicit wide index filter — response must also be capped.
    let result = s.records(Some(FetchCanisterLogsFilter::ByIdx(
        FetchCanisterLogsRange {
            start: 0,
            end: u64::MAX,
        },
    )));
    assert_le!(total_size(&result), RESULT_MAX_SIZE.get() as usize);
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
    assert_le!(total_size(&result), RESULT_MAX_SIZE.get() as usize);
    // Oldest records (head) must be present.
    assert_eq!(result.first().unwrap().idx, partial_start);
}

#[test]
fn max_response_size_respected_with_filtering_by_timestamp() {
    // Ensure results are trimmed to RESULT_MAX_SIZE — both for full range and for range-filtered queries.
    let aggregate_capacity = 10_000_000;
    let start_idx = 1_000;
    assert_gt!(
        aggregate_capacity,
        RESULT_MAX_SIZE.get() as usize,
        "large enough capacity"
    );

    let mut s = LogMemoryStore::new();
    s.resize_for_testing(aggregate_capacity);
    // Append 5 MB records in batches of 1 MB deltas of ~1KB record each.
    append_deltas(&mut s, start_idx, 5_000_000, 1_000_000, 1_000);

    // With an explicit wide timestamp filter — response must also be capped.
    let result = s.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
        FetchCanisterLogsRange {
            start: 0,
            end: u64::MAX,
        },
    )));
    assert_le!(total_size(&result), RESULT_MAX_SIZE.get() as usize);
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
    assert_le!(total_size(&result), RESULT_MAX_SIZE.get() as usize);
    // Oldest records (head) must be present.
    assert_eq!(result.first().unwrap().timestamp_nanos, partial_start_ts);
}

#[test]
fn test_increasing_capacity_preserves_records() {
    let mut s = LogMemoryStore::new();
    s.resize_for_testing(1_000_000); // 1 MB

    // Append 200 KB records in batches of 100 KB deltas of ~1KB record each.
    append_deltas(&mut s, 0, 200_000, 100_000, 1_000);

    let records_before = s.records(None);
    let bytes_used_before = s.bytes_used();

    // Increase capacity.
    s.resize_for_testing(2_000_000); // 2 MB

    let records_after = s.records(None);
    let bytes_used_after = s.bytes_used();

    // Verify all records are preserved.
    assert_eq!(records_before, records_after);
    assert_eq!(bytes_used_before, bytes_used_after);
}

#[test]
fn test_decreasing_capacity_drops_oldest_records_but_preserves_recent() {
    let mut s = LogMemoryStore::new();
    s.resize_for_testing(500_000); // 500 KB

    // Append 200 KB records in batches of 100 KB deltas of ~1KB record each.
    append_deltas(&mut s, 0, 200_000, 100_000, 1_000);

    let records_before = s.records(None);
    let bytes_used_before = s.bytes_used();
    let next_idx_before = s.next_idx();

    // Decrease capacity.
    s.resize_for_testing(100_000); // 100 KB

    let records_after = s.records(None);
    let bytes_used_after = s.bytes_used();

    // Verify some records are dropped.
    assert_lt!(records_after.len(), records_before.len());
    assert_lt!(bytes_used_after, bytes_used_before);
    // Verify recent records are preserved.
    assert_eq!(next_idx_before, s.next_idx());
}

#[test]
fn test_small_capacity_indexing() {
    let mut s = LogMemoryStore::new();
    // Set a very small capacity, smaller than 146 bytes (INDEX_ENTRY_COUNT_MAX).
    // 146 entries. If capacity is 100. 100 / 146 = 0.
    s.resize_for_testing(100);

    let mut delta = CanisterLog::new_delta_with_next_index(0, 100);
    // Add multiple records.
    // Header overhead is 8+8+4 = 20 bytes.
    // Content "a" is 1 byte.
    // Total 21 bytes per record.
    delta.add_record(0, b"a".to_vec());
    delta.add_record(1, b"b".to_vec());

    s.append_delta_log(&mut delta);

    assert!(!s.is_empty());
    // 21 * 2 = 42 bytes used.
    assert_eq!(s.bytes_used(), 42);

    // Try to read it back.
    let records = s.records(None);
    assert_eq!(records.len(), 2, "Should return 2 records");
    assert_eq!(records[0].content, b"a");
    assert_eq!(records[1].content, b"b");
}

#[test]
fn test_multiple_records_in_same_segment() {
    let mut s = LogMemoryStore::new();
    // Capacity 100KB. Segment size ~685 bytes.
    s.resize_for_testing(100_000);

    let mut delta = CanisterLog::new_delta_with_next_index(0, 100_000);
    // Add 10 records, each ~21 bytes. All should fit in segment 0.
    for i in 0..10 {
        delta.add_record(i, vec![i as u8]);
    }
    s.append_delta_log(&mut delta);

    // Verify we can retrieve all of them.
    let records = s.records(None);
    assert_eq!(records.len(), 10);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.idx, i as u64);
    }

    // Verify filtering works.
    // Filter for record 5. Range is [5, 6).
    let records = s.records(Some(FetchCanisterLogsFilter::ByIdx(
        FetchCanisterLogsRange { start: 5, end: 6 },
    )));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].idx, 5);
}

#[test]
fn test_very_small_capacity_single_byte() {
    let mut s = LogMemoryStore::new();
    // Set capacity to 1 byte - this will be clamped to DATA_CAPACITY_MIN (4096 bytes).
    s.resize_for_testing(1);

    // Verify byte capacity was clamped to minimum.
    assert_eq!(s.byte_capacity(), 4096);

    let mut delta = CanisterLog::new_delta_with_next_index(0, 4096);
    // Add a record - it should fit within the minimum capacity.
    delta.add_record(0, b"a".to_vec());

    s.append_delta_log(&mut delta);

    // The record should be stored.
    assert_eq!(s.byte_capacity(), 4096);
    assert_eq!(s.next_idx(), 1);
    assert_eq!(s.bytes_used(), 21);
    let records = s.records(None);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].content, b"a");
}

#[test]
fn test_small_capacity_with_eviction() {
    let mut s = LogMemoryStore::new();
    let capacity = 4096;
    s.resize_for_testing(capacity);

    assert_eq!(s.byte_capacity(), capacity);

    // Fill the buffer with records until we're close to capacity.
    // Each record is ~21 bytes (8+8+4+1), so we can fit ~195 records.
    let record_size = 21;
    let max_records = capacity / record_size; // ~195

    // Add records to fill the buffer.
    for i in 0..max_records {
        let mut delta = CanisterLog::new_delta_with_next_index(i as u64, capacity);
        delta.add_record(i as u64, vec![i as u8]);
        s.append_delta_log(&mut delta);
    }

    // Verify all records fit.
    assert_eq!(s.byte_capacity(), capacity);
    assert_eq!(s.next_idx(), max_records as u64);
    let records = s.records(None);
    assert_eq!(records.len(), max_records);

    // Add one more record - this should evict the oldest one.
    let mut delta = CanisterLog::new_delta_with_next_index(max_records as u64, capacity);
    delta.add_record(max_records as u64, vec![255]);
    s.append_delta_log(&mut delta);

    // Verify the oldest record was evicted.
    assert_eq!(s.next_idx(), (max_records + 1) as u64);
    let records = s.records(None);
    assert_eq!(records.len(), max_records);
    assert_eq!(records[0].idx, 1); // First record (idx=0) was evicted.
    assert_eq!(records.last().unwrap().idx, max_records as u64);
}

#[test]
fn test_filtering_with_multiple_records_in_same_segment() {
    let mut s = LogMemoryStore::new();
    // Capacity 100KB. Segment size ~685 bytes.
    s.resize_for_testing(100_000);

    let mut delta = CanisterLog::new_delta_with_next_index(0, 100_000);
    // Add 20 records, each ~21 bytes. All should fit in segment 0.
    for i in 0..20 {
        delta.add_record(i * 1000, vec![i as u8]);
    }
    s.append_delta_log(&mut delta);

    // Filter for records in the middle: [5000, 15000).
    let records = s.records(Some(FetchCanisterLogsFilter::ByTimestampNanos(
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
    let records = s.records(Some(FetchCanisterLogsFilter::ByIdx(
        FetchCanisterLogsRange { start: 10, end: 15 },
    )));
    // Should return records 10-14 (5 records).
    assert_eq!(records.len(), 5);
    assert_eq!(records[0].idx, 10);
    assert_eq!(records[4].idx, 14);
}
mod cache_tests {
    use super::*;

    #[test]
    fn test_cache_lifecycle() {
        let mut s = LogMemoryStore::new();

        // 1. Initial state: Uninitialized (None in OnceLock)
        assert!(s.header_cache.get().is_none());

        // 2. Read triggers load: Uninitialized -> Empty (since no ring buffer yet)
        assert_eq!(s.byte_capacity(), 0);
        assert_eq!(s.header_cache.get(), Some(&None));

        // 3. Set limit: Empty -> Initialized
        s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
        match s.header_cache.get() {
            Some(Some(h)) => {
                assert_eq!(h.data_capacity.get() as usize, TEST_LOG_MEMORY_LIMIT);
            }
            state => panic!("Expected Initialized, got {:?}", state),
        }

        // 4. Append: Initialized -> Initialized (updated)
        let mut delta = CanisterLog::default_delta();
        delta.add_record(1, b"test".to_vec());
        s.append_delta_log(&mut delta);

        match s.header_cache.get() {
            Some(Some(h)) => {
                assert_gt!(h.data_size.get(), 0);
            }
            state => panic!("Expected Initialized, got {:?}", state),
        }

        // 5. Invalidate: Initialized -> Uninitialized
        s.maybe_page_map_mut();
        assert!(s.header_cache.get().is_none());
    }
}

#[test]
fn test_clear() {
    let mut delta = CanisterLog::default_delta();
    delta.add_record(1, b"a".to_vec());
    delta.add_record(2, b"b".to_vec());

    let mut s = LogMemoryStore::new();
    s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
    s.append_delta_log(&mut delta);

    assert!(!s.is_empty());
    assert_gt!(s.bytes_used(), 0);

    s.clear();

    assert!(s.is_empty());
    assert_eq!(s.bytes_used(), 0);
    assert_eq!(s.records(None).len(), 0);
    // Next index is reset to 0.
    assert_eq!(s.next_idx(), 0);
    // Capacity is preserved.
    assert_eq!(s.byte_capacity(), TEST_LOG_MEMORY_LIMIT);
}

#[test]
fn test_deallocate() {
    let mut s = LogMemoryStore::new();
    s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
    assert!(s.maybe_page_map().is_some());
    assert_eq!(s.byte_capacity(), TEST_LOG_MEMORY_LIMIT);

    s.deallocate();

    assert!(s.maybe_page_map().is_none());
    assert_eq!(s.byte_capacity(), 0);
    // Re-initializing (e.g. via resize) should work.
    s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
    assert_eq!(s.byte_capacity(), TEST_LOG_MEMORY_LIMIT);
}

#[test]
fn test_deallocate_when_resize_to_zero() {
    let mut s = LogMemoryStore::new();
    s.resize_for_testing(TEST_LOG_MEMORY_LIMIT);
    assert!(s.maybe_page_map().is_some());
    assert_eq!(s.byte_capacity(), TEST_LOG_MEMORY_LIMIT);

    s.resize_for_testing(0);

    assert!(s.maybe_page_map().is_none());
    assert_eq!(s.byte_capacity(), 0);
}
