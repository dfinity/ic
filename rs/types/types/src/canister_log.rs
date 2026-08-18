use candid::Deserialize;
use ic_management_canister_types_private::{CanisterLogRecord, DataSize};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::Duration;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// The maximum size of an aggregate canister log buffer.
pub const MAX_AGGREGATE_LOG_MEMORY_LIMIT: usize = 2 * MIB;

/// The minimum non-zero size of an aggregate canister log buffer.
///
/// A limit of zero disables logging altogether; any other limit must be at
/// least this value, which is the log memory store's minimum ring buffer data
/// capacity of one OS page.
pub const MIN_AGGREGATE_LOG_MEMORY_LIMIT: usize = 4 * KIB;

/// The default size of an aggregate canister log buffer.
pub const DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT: usize = 4 * KIB;

/// The maximum size of a delta (per message) canister log buffer.
pub const MAX_DELTA_LOG_MEMORY_LIMIT: usize = 2 * MIB;

/// Maximum stored data size (in bytes) of the log records returned by a single
/// `fetch_canister_logs` request.
///
/// The log memory store's ring buffer trims its result to this limit, measured by
/// `CanisterLogRecord::data_size()`. This is the single source of truth for that
/// limit: `RESULT_MAX_SIZE` in `ic-replicated-state` is defined from it.
pub const MAX_FETCH_CANISTER_LOGS_RESULT_BYTES: usize = 2_000_000;

// Compile-time assertions to ensure the constants are within valid ranges.
const _: () = assert!(MIN_AGGREGATE_LOG_MEMORY_LIMIT <= DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT);
const _: () = assert!(DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT <= MAX_AGGREGATE_LOG_MEMORY_LIMIT);
const _: () = assert!(MAX_DELTA_LOG_MEMORY_LIMIT <= MAX_AGGREGATE_LOG_MEMORY_LIMIT);
// A `fetch_canister_logs` response is the returned records (trimmed to
// `MAX_FETCH_CANISTER_LOGS_RESULT_BYTES` by stored data size) plus fixed Candid
// framing (magic bytes and type table, well under one page); it must fit within a
// single inter-canister message so it can be returned to the caller. The
// `fetch_canister_logs_response_within_limit` test in `ic-replicated-state` verifies
// the encoded response stays within this bound.
const _: () = assert!(
    MAX_FETCH_CANISTER_LOGS_RESULT_BYTES + 4 * KIB
        <= crate::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize
);

/// Truncates the content of a log record so that the record fits within the allowed size.
fn truncate_content(byte_capacity: usize, mut record: CanisterLogRecord) -> CanisterLogRecord {
    let max_content_size = byte_capacity.saturating_sub(std::mem::size_of::<CanisterLogRecord>());
    record.content.truncate(max_content_size);
    record
}

/// Stores log records and maintains their total byte usage so new entries can be
/// appended while enforcing the provided capacity limit.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, ValidateEq)]
struct Records {
    #[validate_eq(Ignore)]
    records: VecDeque<CanisterLogRecord>,
    byte_capacity: usize,
    bytes_used: usize,
}

impl Records {
    /// Creates a new `Records` from the given records and byte capacity.
    fn from(records: Vec<CanisterLogRecord>, byte_capacity: usize) -> Self {
        let records: VecDeque<_> = records
            .into_iter()
            .map(|r| truncate_content(byte_capacity, r)) // Apply size limit to each record's content.
            .collect();
        let bytes_used = records.iter().map(|r| r.data_size()).sum();
        let mut result = Self {
            records,
            byte_capacity,
            bytes_used,
        };
        // Make sure the buffer is within limit.
        result.make_free_space_within_limit(0);
        result
    }

    /// Clears the canister log records and resets the used bytes.
    fn clear(&mut self) {
        self.records.clear();
        self.bytes_used = 0;
    }

    /// Returns the canister log records.
    fn get(&self) -> &VecDeque<CanisterLogRecord> {
        &self.records
    }

    /// Returns mutable reference to the canister log records.
    fn get_mut(&mut self) -> &mut VecDeque<CanisterLogRecord> {
        &mut self.records
    }

    /// Pushes a new record to the back, updating the used bytes.
    fn push_back(&mut self, record: CanisterLogRecord) {
        let added_size = record.data_size();
        // LINT.IfChange
        // Keep the new log record size within limit,
        // this must be in sync with `logging_charge_bytes` in `system_api.rs`.
        self.make_free_space_within_limit(added_size);
        self.records.push_back(record);
        // LINT.ThenChange(logging_charge_bytes_rule)
        self.bytes_used += added_size;
    }

    /// Pops the oldest record from the front, updating the used bytes.
    fn pop_front(&mut self) -> Option<usize> {
        if let Some(record) = self.records.pop_front() {
            let removed_size = record.data_size();
            self.bytes_used = self.bytes_used.saturating_sub(removed_size);
            Some(removed_size)
        } else {
            None
        }
    }

    /// Appends all records from `other` to `self`, making sure the size limit is respected.
    fn append(&mut self, other: &mut Self) {
        // The caller must have trimmed `other` to `self.byte_capacity` beforehand (see
        // `trim_to_capacity`).
        debug_assert!(other.bytes_used <= self.byte_capacity);
        self.make_free_space_within_limit(other.bytes_used);
        self.records.append(&mut other.records);
        self.bytes_used += other.bytes_used;
        other.clear();
    }

    /// Drops the oldest records so that the used bytes fit within `byte_capacity`.
    ///
    /// If the newest record alone does not fit, its content is truncated; should even
    /// an empty record not fit (i.e. `byte_capacity` is below the fixed record size),
    /// the buffer is left empty, just like `Records::from` would.
    fn trim_to_capacity(&mut self, byte_capacity: usize) {
        // Drop the oldest records, keeping the newest ones that fit.
        while self.bytes_used > byte_capacity && self.records.len() > 1 {
            self.pop_front();
        }
        // The single remaining record may still be too big on its own.
        if self.bytes_used > byte_capacity
            && let Some(record) = self.records.pop_front()
        {
            let record = truncate_content(byte_capacity, record);
            let record_size = record.data_size();
            if record_size <= byte_capacity {
                self.records.push_front(record);
                self.bytes_used = record_size;
            } else {
                self.bytes_used = 0;
            }
        }
    }

    /// Removes old records to make enough free space for new data within the limit.
    fn make_free_space_within_limit(&mut self, new_data_size: usize) {
        let mut total_size = new_data_size + self.bytes_used;
        while total_size > self.byte_capacity {
            if let Some(removed_size) = self.pop_front() {
                total_size = total_size.saturating_sub(removed_size);
            } else {
                break; // No more records to pop, limit reached.
            }
        }
    }
}

/// Holds canister log records and keeps track of the next canister log record index.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, ValidateEq)]
pub struct CanisterLog {
    next_idx: u64,

    #[validate_eq(CompareWithValidateEq)]
    records: Records,
}

impl CanisterLog {
    /// Creates a new log with the given next index, records and byte capacity.
    fn new_inner(next_idx: u64, records: Vec<CanisterLogRecord>, byte_capacity: usize) -> Self {
        Self {
            next_idx,
            records: Records::from(records, byte_capacity),
        }
    }

    /// Creates a new log that is supposed to be used as an aggregate (total) canister log.
    /// Aggregate canister log of this type does not store records efficiently,
    /// so it should be limited in size.
    /// TODO(DSM-11): remove this after migration is done.
    pub fn new_aggregate(next_idx: u64, records: Vec<CanisterLogRecord>) -> Self {
        Self::new_inner(next_idx, records, DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT)
    }

    /// Creates a default empty aggregate canister log.
    pub fn default_aggregate() -> Self {
        Self::new_aggregate(0, vec![])
    }

    /// Creates a default empty delta canister log.
    pub fn default_delta() -> Self {
        Self::new_inner(0, vec![], MAX_DELTA_LOG_MEMORY_LIMIT)
    }

    /// Creates a new empty log with the given next index and byte capacity.
    pub fn new_delta_with_next_index(next_idx: u64, byte_capacity: usize) -> Self {
        // Limit the delta canister log memory to the maximum allowed.
        let byte_capacity = byte_capacity.min(MAX_DELTA_LOG_MEMORY_LIMIT);
        Self::new_inner(next_idx, vec![], byte_capacity)
    }

    /// Takes the canister log, leaving an empty log in its place.
    pub fn take(&mut self) -> Self {
        // Just in case preserve next_idx and byte_capacity for the new empty log — otherwise
        // we could leave a zero-capacity log and cause underflow on later truncations.
        let next_idx = self.next_idx;
        let byte_capacity = self.byte_capacity();
        std::mem::replace(self, Self::new_inner(next_idx, vec![], byte_capacity))
    }

    /// Returns the next canister log record index.
    pub fn next_idx(&self) -> u64 {
        self.next_idx
    }

    /// Returns the canister log records.
    pub fn records(&self) -> &VecDeque<CanisterLogRecord> {
        self.records.get()
    }

    // TODO(DSM-11): remove allow(dead_code) when log memory store is used in production.
    /// Returns mutable reference to the canister log records.
    #[allow(dead_code)]
    pub fn records_mut(&mut self) -> &mut VecDeque<CanisterLogRecord> {
        self.records.get_mut()
    }

    /// Clears the canister log records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns true if the canister log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.records.is_empty()
    }

    /// Returns the maximum allowed size of a canister log buffer.
    pub fn byte_capacity(&self) -> usize {
        self.records.byte_capacity
    }

    /// Returns the used space in the canister log buffer.
    pub fn bytes_used(&self) -> usize {
        self.records.bytes_used
    }

    /// Returns the remaining space in the canister log buffer.
    pub fn remaining_bytes(&self) -> usize {
        let records = &self.records;
        records.byte_capacity.saturating_sub(records.bytes_used)
    }

    /// Returns the time span between the oldest and newest records in the
    /// buffer, or `None` if the buffer is empty. Returns `Duration::ZERO`
    /// when the buffer holds a single record.
    pub fn retention(&self) -> Option<Duration> {
        let records = self.records.get();
        let first = records.front()?.timestamp_nanos;
        let last = records.back()?.timestamp_nanos;
        Some(Duration::from_nanos(last.saturating_sub(first)))
    }

    /// Adds a new log record.
    pub fn add_record(&mut self, timestamp_nanos: u64, content: Vec<u8>) {
        // Add record and update the next index.
        self.records.push_back(truncate_content(
            self.byte_capacity(),
            CanisterLogRecord {
                idx: self.next_idx,
                timestamp_nanos,
                content,
            },
        ));
        self.next_idx += 1;
    }

    /// Moves all the logs from `delta_log` to `self`.
    pub fn append_delta_log(&mut self, delta_log: &mut Self) {
        if delta_log.is_empty() {
            return; // Don't append if delta is empty.
        }

        // Assume records sorted chronologically (with increasing idx): the new next
        // index is the one following the delta's last record. Read here and not after
        // the trimming below, as that may drop some or even all delta records.
        let next_idx = delta_log
            .records
            .get()
            .back()
            .map_or(self.next_idx, |last| last.idx + 1);

        // The delta log may have a bigger capacity than this (aggregate) log, in which
        // case the delta records that don't fit here have to be dropped, oldest first;
        // otherwise the aggregate would end up exceeding its own capacity. This must
        // happen before the gap check below, so that the records dropped here are
        // accounted for as a gap as well.
        delta_log.records.trim_to_capacity(self.byte_capacity());

        match delta_log.records.get().front() {
            // The delta continues where the aggregate left off, keep both.
            Some(first) if first.idx <= self.next_idx => {}
            // Records were evicted (by the delta itself or by the trimming
            // above), leaving a gap between the aggregate's next expected index and
            // the delta's first record. Drop the aggregate records to maintain
            // index continuity.
            _ => self.records.clear(),
        }

        self.next_idx = next_idx;
        self.records.append(&mut delta_log.records);
    }
}

/// Trait for canister log instrumentation.
pub trait CanisterLogMetrics {
    /// Observes the size of an appended delta log.
    fn observe_delta_log_size(&self, size: usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_management_canister_types_private::CanisterLogRecord;

    const TEST_MAX_ALLOWED_SIZE: usize = 4 * KIB;
    const BIGGER_THAN_LIMIT_MESSAGE: &[u8] = &[b'a'; 2 * TEST_MAX_ALLOWED_SIZE];
    /// The size a log record occupies on top of its content.
    const RECORD_SIZE: usize = std::mem::size_of::<CanisterLogRecord>();

    fn canister_log_records(data: &[(u64, u64, &[u8])]) -> Vec<CanisterLogRecord> {
        data.iter()
            .map(|&(idx, timestamp_nanos, content)| CanisterLogRecord {
                idx,
                timestamp_nanos,
                content: content.to_vec(),
            })
            .collect()
    }

    #[test]
    fn test_canister_log_memory_usage_by_default() {
        let log = CanisterLog::default_aggregate();
        // Assert log has no records and memory usage is zero.
        assert_eq!(log.records().len(), 0);
        assert_eq!(log.bytes_used(), 0);
        assert_eq!(log.remaining_bytes(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_new_applies_memory_limit() {
        let log = CanisterLog::new_aggregate(
            3,
            canister_log_records(&[
                (0, 100, BIGGER_THAN_LIMIT_MESSAGE),
                (1, 100, BIGGER_THAN_LIMIT_MESSAGE),
                (2, 100, BIGGER_THAN_LIMIT_MESSAGE),
            ]),
        );
        // Assert log has only one record and it's size is within limit.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.bytes_used(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.remaining_bytes(), 0);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_add_record_applies_memory_limit() {
        let mut log = CanisterLog::default_aggregate();
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        // Assert log has only one record and it's size is within limit.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.bytes_used(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.remaining_bytes(), 0);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_clear() {
        // Arrange.
        let mut log = CanisterLog::default_aggregate();
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        // Act.
        log.clear();
        // Assert log has no records and memory usage is zero.
        assert_eq!(log.records().len(), 0);
        assert_eq!(log.bytes_used(), 0);
        assert_eq!(log.remaining_bytes(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_increases_next_idx_after_reaching_memory_limit() {
        let records_number = 42;
        let mut log = CanisterLog::default_aggregate();
        for _ in 0..records_number {
            log.add_record(0, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        }
        // Assert log has only one record and next_idx is increased.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.next_idx(), records_number as u64);
    }

    #[test]
    fn test_canister_log_adds_records() {
        let mut log = CanisterLog::default_aggregate();
        log.add_record(100, b"record #0".to_vec());
        log.add_record(101, b"record #1".to_vec());
        log.add_record(102, b"record #2".to_vec());
        assert_eq!(
            log.records(),
            &VecDeque::from(canister_log_records(&[
                (0, 100, b"record #0"),
                (1, 101, b"record #1"),
                (2, 102, b"record #2"),
            ]))
        );
    }

    #[test]
    fn test_canister_log_append() {
        // Arrange.
        let mut main = CanisterLog::new_aggregate(
            3,
            canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
            ]),
        );
        let mut delta =
            CanisterLog::new_delta_with_next_index(main.next_idx(), TEST_MAX_ALLOWED_SIZE);
        delta.add_record(200, b"delta #0".to_vec());
        delta.add_record(201, b"delta #1".to_vec());
        delta.add_record(202, b"delta #2".to_vec());

        // Act.
        main.append_delta_log(&mut delta);

        // Assert.
        assert_eq!(
            main.records(),
            &VecDeque::from(canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
                (3, 200, b"delta #0"),
                (4, 201, b"delta #1"),
                (5, 202, b"delta #2"),
            ]))
        );
    }

    #[test]
    fn test_canister_log_append_when_delta_reached_memory_limit() {
        // Arrange.
        let mut main = CanisterLog::new_aggregate(
            3,
            canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
            ]),
        );
        let mut delta =
            CanisterLog::new_delta_with_next_index(main.next_idx(), TEST_MAX_ALLOWED_SIZE);
        // Add big records to reach memory limit and a small one at the end.
        delta.add_record(200, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        delta.add_record(201, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        delta.add_record(202, b"delta #2".to_vec());

        // Act.
        main.append_delta_log(&mut delta);

        // Assert main log was cleared due to the gap (delta evicted records 3 and 4,
        // so delta starts at idx 5 > next_idx 3; aggregate records are dropped).
        assert_eq!(
            main.records(),
            &VecDeque::from(canister_log_records(&[(5, 202, b"delta #2"),]))
        );
    }

    #[test]
    fn test_canister_log_append_empty_delta_keeps_aggregate_records() {
        // Arrange: an empty delta log, both starting at the aggregate's next index and
        // at a later one (the delta's index comes from a different store, which may
        // have moved on, e.g. after uninstalling the canister).
        for delta_next_idx in [3, 10] {
            let records = canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
            ]);
            let mut main = CanisterLog::new_aggregate(3, records.clone());
            let mut delta =
                CanisterLog::new_delta_with_next_index(delta_next_idx, TEST_MAX_ALLOWED_SIZE);
            assert!(delta.is_empty());

            // Act.
            main.append_delta_log(&mut delta);

            // Assert an empty delta neither drops the aggregate records (it carries no
            // evidence of any record having been evicted) nor moves the next index.
            assert_eq!(main.records(), &VecDeque::from(records));
            assert_eq!(main.next_idx(), 3);
        }
    }

    #[test]
    fn test_canister_log_append_delta_bigger_than_aggregate_capacity() {
        // Arrange: an aggregate log at the default (small) capacity and a delta log
        // with a much bigger capacity, filled well beyond the aggregate's capacity.
        let mut main = CanisterLog::new_aggregate(
            3,
            canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
            ]),
        );
        let mut delta =
            CanisterLog::new_delta_with_next_index(main.next_idx(), 4 * TEST_MAX_ALLOWED_SIZE);
        let record_content = &[b'a'; 512];
        let records_number = 20; // 20 * (512 + 48) = 11200 bytes > 4 KiB.
        for i in 0..records_number {
            delta.add_record(200 + i, record_content.to_vec());
        }
        assert!(delta.bytes_used() > main.byte_capacity());

        // Act.
        main.append_delta_log(&mut delta);

        // Assert the aggregate log stays within its capacity, keeping the newest
        // records only (the older ones, including all of the aggregate's own, are
        // dropped as they don't fit) and with the next index carried over.
        assert!(main.bytes_used() <= main.byte_capacity());
        let expected_records_number = main.byte_capacity() / (record_content.len() + RECORD_SIZE);
        assert_eq!(main.records().len(), expected_records_number);
        assert_eq!(
            main.records().front().unwrap().idx,
            3 + records_number - expected_records_number as u64
        );
        assert_eq!(
            main.records().back().unwrap().idx,
            3 + records_number - 1 // The newest delta record is always kept.
        );
        assert_eq!(main.next_idx(), 3 + records_number);
        assert!(delta.is_empty());
    }

    #[test]
    fn test_canister_log_append_delta_record_bigger_than_aggregate_capacity() {
        // Arrange: a delta log with a single record bigger than the aggregate capacity.
        let mut main = CanisterLog::new_aggregate(1, canister_log_records(&[(0, 100, b"main #0")]));
        let mut delta =
            CanisterLog::new_delta_with_next_index(main.next_idx(), 4 * TEST_MAX_ALLOWED_SIZE);
        delta.add_record(200, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        assert!(delta.bytes_used() > main.byte_capacity());

        // Act.
        main.append_delta_log(&mut delta);

        // Assert the record's content was truncated to fit the aggregate capacity
        // and the pre-existing aggregate record was evicted to make room for it.
        assert_eq!(main.bytes_used(), main.byte_capacity());
        assert_eq!(
            main.records(),
            &VecDeque::from(canister_log_records(&[(
                1,
                200,
                &BIGGER_THAN_LIMIT_MESSAGE[..TEST_MAX_ALLOWED_SIZE - RECORD_SIZE]
            )]))
        );
        assert_eq!(main.next_idx(), 2);
    }

    #[test]
    fn test_canister_log_append_delta_clears_aggregate_on_gap_from_trimming() {
        // Arrange: an aggregate log with records that would fit together with the
        // delta's newest record, but where the delta's oldest record does not fit.
        let mut main = CanisterLog::new_aggregate(
            3,
            canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
            ]),
        );
        let mut delta =
            CanisterLog::new_delta_with_next_index(main.next_idx(), 4 * TEST_MAX_ALLOWED_SIZE);
        delta.add_record(200, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        delta.add_record(201, b"delta #1".to_vec());

        // Act.
        main.append_delta_log(&mut delta);

        // Assert only the delta's newest record is left: record 3 was dropped as it
        // does not fit, so keeping records 0..2 would leave a gap before record 4.
        assert!(main.bytes_used() <= main.byte_capacity());
        assert_eq!(
            main.records(),
            &VecDeque::from(canister_log_records(&[(4, 201, b"delta #1")]))
        );
        assert_eq!(main.next_idx(), 5);
    }

    #[test]
    fn test_canister_log_record_used_space() {
        let (size_a, size_b, size_c) = (3 * 48, 3 * 48, 4 * 48);
        // Batch A.
        let mut main = CanisterLog::new_aggregate(
            3,
            canister_log_records(&[
                (0, 100, b"main_ #0"),
                (1, 101, b"main_ #1"),
                (2, 102, b"main_ #2"),
            ]),
        );
        assert_eq!(main.bytes_used(), size_a);

        // Batch B.
        let mut delta =
            CanisterLog::new_delta_with_next_index(main.next_idx(), TEST_MAX_ALLOWED_SIZE);
        delta.add_record(200, b"delta #0".to_vec());
        delta.add_record(201, b"delta #1".to_vec());
        delta.add_record(202, b"delta #2".to_vec());
        assert_eq!(delta.bytes_used(), size_b);
        main.append_delta_log(&mut delta);

        // Batch C.
        let mut delta =
            CanisterLog::new_delta_with_next_index(main.next_idx(), TEST_MAX_ALLOWED_SIZE);
        delta.add_record(300, b"delta #3".to_vec());
        delta.add_record(301, b"delta #4".to_vec());
        delta.add_record(302, b"delta #5".to_vec());
        delta.add_record(303, b"delta #6".to_vec());
        assert_eq!(delta.bytes_used(), size_c);
        main.append_delta_log(&mut delta);

        // Assert main log has all records and correct used space.
        assert_eq!(
            main.records(),
            &VecDeque::from(canister_log_records(&[
                (0, 100, b"main_ #0"),
                (1, 101, b"main_ #1"),
                (2, 102, b"main_ #2"),
                (3, 200, b"delta #0"),
                (4, 201, b"delta #1"),
                (5, 202, b"delta #2"),
                (6, 300, b"delta #3"),
                (7, 301, b"delta #4"),
                (8, 302, b"delta #5"),
                (9, 303, b"delta #6"),
            ]))
        );
        assert_eq!(main.bytes_used(), size_a + size_b + size_c);
    }

    #[test]
    fn test_canister_log_retention() {
        // Empty buffer: no retention.
        let empty = CanisterLog::default_aggregate();
        assert_eq!(empty.retention(), None);

        // Single record: retention is zero.
        let single = CanisterLog::new_aggregate(1, canister_log_records(&[(0, 100, b"a")]));
        assert_eq!(single.retention(), Some(Duration::ZERO));

        // Multiple records: retention spans first..last.
        let span = CanisterLog::new_aggregate(
            3,
            canister_log_records(&[
                (0, 1_000_000_000, b"a"),  // t = 1 s
                (1, 1_500_000_000, b"b"),  // t = 1.5 s
                (2, 61_000_000_000, b"c"), // t = 61 s
            ]),
        );
        assert_eq!(span.retention(), Some(Duration::from_secs(60)));

        // After clear the buffer is empty again.
        let mut to_clear = span;
        to_clear.clear();
        assert_eq!(to_clear.retention(), None);
    }
}
