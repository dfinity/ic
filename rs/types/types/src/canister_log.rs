use candid::Deserialize;
use ic_management_canister_types_private::{CanisterLogRecord, DataSize};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use serde::Serialize;
use std::collections::VecDeque;

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
    /// Creates a new empty `Records` with the given byte capacity.
    fn new(byte_capacity: usize) -> Self {
        Self {
            records: VecDeque::new(),
            byte_capacity,
            bytes_used: 0,
        }
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

/// Holds the canister log records emitted by a single message execution (the delta
/// log) and keeps track of the next canister log record index.
///
/// The aggregate (whole canister) log is kept in the `LogMemoryStore` of
/// `ic-replicated-state`, which absorbs the delta log once the message completes.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, ValidateEq)]
pub struct CanisterLog {
    next_idx: u64,

    #[validate_eq(CompareWithValidateEq)]
    records: Records,
}

impl CanisterLog {
    /// Creates a new empty log with the given next index and byte capacity.
    fn new_inner(next_idx: u64, byte_capacity: usize) -> Self {
        Self {
            next_idx,
            records: Records::new(byte_capacity),
        }
    }

    /// Creates a default empty delta canister log.
    pub fn default_delta() -> Self {
        Self::new_inner(0, MAX_DELTA_LOG_MEMORY_LIMIT)
    }

    /// Creates a new empty log with the given next index and byte capacity.
    pub fn new_delta_with_next_index(next_idx: u64, byte_capacity: usize) -> Self {
        // Limit the delta canister log memory to the maximum allowed.
        let byte_capacity = byte_capacity.min(MAX_DELTA_LOG_MEMORY_LIMIT);
        Self::new_inner(next_idx, byte_capacity)
    }

    /// Takes the canister log, leaving an empty log in its place.
    pub fn take(&mut self) -> Self {
        // Just in case preserve next_idx and byte_capacity for the new empty log — otherwise
        // we could leave a zero-capacity log and cause underflow on later truncations.
        let next_idx = self.next_idx;
        let byte_capacity = self.byte_capacity();
        std::mem::replace(self, Self::new_inner(next_idx, byte_capacity))
    }

    /// Returns the next canister log record index.
    pub fn next_idx(&self) -> u64 {
        self.next_idx
    }

    /// Returns the canister log records.
    pub fn records(&self) -> &VecDeque<CanisterLogRecord> {
        self.records.get()
    }

    /// Returns mutable reference to the canister log records.
    pub fn records_mut(&mut self) -> &mut VecDeque<CanisterLogRecord> {
        self.records.get_mut()
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

    /// A delta log with the test capacity, starting at index zero.
    fn test_log() -> CanisterLog {
        CanisterLog::new_delta_with_next_index(0, TEST_MAX_ALLOWED_SIZE)
    }

    #[test]
    fn test_canister_log_memory_usage_when_empty() {
        let log = test_log();
        // Assert log has no records and memory usage is zero.
        assert!(log.is_empty());
        assert_eq!(log.records().len(), 0);
        assert_eq!(log.bytes_used(), 0);
        assert_eq!(log.remaining_bytes(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_default_delta_capacity() {
        let log = CanisterLog::default_delta();
        assert_eq!(log.next_idx(), 0);
        assert_eq!(log.byte_capacity(), MAX_DELTA_LOG_MEMORY_LIMIT);
    }

    #[test]
    fn test_canister_log_delta_capacity_is_capped() {
        // A requested capacity above the maximum is capped, anything else is kept.
        let log = CanisterLog::new_delta_with_next_index(7, 2 * MAX_DELTA_LOG_MEMORY_LIMIT);
        assert_eq!(log.next_idx(), 7);
        assert_eq!(log.byte_capacity(), MAX_DELTA_LOG_MEMORY_LIMIT);
        let log = CanisterLog::new_delta_with_next_index(7, TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_add_record_applies_memory_limit() {
        let mut log = test_log();
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        // Assert log has only one record and its size is within limit.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.bytes_used(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.remaining_bytes(), 0);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
        // Assert the record content was truncated to fit the capacity.
        assert_eq!(
            log.records().back().unwrap().content,
            BIGGER_THAN_LIMIT_MESSAGE[..TEST_MAX_ALLOWED_SIZE - RECORD_SIZE]
        );
    }

    #[test]
    fn test_canister_log_add_record_evicts_multiple_oldest_records() {
        const SMALL_CONTENT_SIZE: usize = 100;
        const SMALL_RECORDS_NUMBER: usize = 20;
        /// The number of small records expected to survive the large record's arrival.
        const EXPECTED_SURVIVORS: usize = 14;

        const SMALL_USED_SPACE: usize = RECORD_SIZE + SMALL_CONTENT_SIZE;
        /// The large record is sized so that exactly `EXPECTED_SURVIVORS` small records
        /// fit next to it, filling the capacity to the byte.
        const LARGE_USED_SPACE: usize =
            TEST_MAX_ALLOWED_SIZE - EXPECTED_SURVIVORS * SMALL_USED_SPACE;

        // Sanity checks on the setup: all the small records fit at first, the large
        // record then evicts more than one of them but not all, and one more survivor
        // would not fit next to it.
        const _: () = assert!(SMALL_RECORDS_NUMBER * SMALL_USED_SPACE <= TEST_MAX_ALLOWED_SIZE);
        const _: () = assert!(EXPECTED_SURVIVORS + 1 < SMALL_RECORDS_NUMBER);
        const _: () = assert!(
            (EXPECTED_SURVIVORS + 1) * SMALL_USED_SPACE + LARGE_USED_SPACE > TEST_MAX_ALLOWED_SIZE
        );

        let small_content = &[b'a'; SMALL_CONTENT_SIZE];
        let large_content = vec![b'b'; LARGE_USED_SPACE - RECORD_SIZE];

        // Arrange: fill the log with small records, none of them evicted yet.
        let mut log = test_log();
        for i in 0..SMALL_RECORDS_NUMBER as u64 {
            log.add_record(100 + i, small_content.to_vec());
        }
        assert_eq!(log.records().len(), SMALL_RECORDS_NUMBER);
        assert_eq!(log.bytes_used(), SMALL_RECORDS_NUMBER * SMALL_USED_SPACE);

        // Act: add a single large record that does not fit in the remaining space.
        log.add_record(500, large_content.clone());

        // Assert the large record evicted several of the oldest small records at once,
        // keeping the newest ones, and that its own content was not truncated.
        let evicted = (SMALL_RECORDS_NUMBER - EXPECTED_SURVIVORS) as u64;
        assert_eq!(log.records().len(), EXPECTED_SURVIVORS + 1);
        assert_eq!(log.bytes_used(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.remaining_bytes(), 0);
        let mut expected_records = (evicted..SMALL_RECORDS_NUMBER as u64)
            .map(|i| (i, 100 + i, &small_content[..]))
            .collect::<Vec<_>>();
        expected_records.push((SMALL_RECORDS_NUMBER as u64, 500, &large_content[..]));
        assert_eq!(
            log.records(),
            &VecDeque::from(canister_log_records(&expected_records))
        );
        assert_eq!(log.next_idx(), SMALL_RECORDS_NUMBER as u64 + 1);
    }

    #[test]
    fn test_canister_log_increases_next_idx_after_reaching_memory_limit() {
        let records_number = 42;
        let mut log = test_log();
        for _ in 0..records_number {
            log.add_record(0, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        }
        // Assert log has only one record and next_idx is increased.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.next_idx(), records_number as u64);
    }

    #[test]
    fn test_canister_log_adds_records() {
        let mut log = test_log();
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
        assert_eq!(log.next_idx(), 3);
    }

    #[test]
    fn test_canister_log_adds_records_starting_at_next_idx() {
        let mut log = CanisterLog::new_delta_with_next_index(3, TEST_MAX_ALLOWED_SIZE);
        log.add_record(200, b"record #3".to_vec());
        log.add_record(201, b"record #4".to_vec());
        assert_eq!(
            log.records(),
            &VecDeque::from(canister_log_records(&[
                (3, 200, b"record #3"),
                (4, 201, b"record #4"),
            ]))
        );
        assert_eq!(log.next_idx(), 5);
    }

    #[test]
    fn test_canister_log_record_used_space() {
        let content = b"record #0";
        let record_used_space = RECORD_SIZE + content.len();
        let mut log = test_log();
        for i in 0..3 {
            log.add_record(100 + i, content.to_vec());
            let records_number = i as usize + 1;
            assert_eq!(log.bytes_used(), records_number * record_used_space);
            assert_eq!(
                log.remaining_bytes(),
                TEST_MAX_ALLOWED_SIZE - records_number * record_used_space
            );
        }
    }

    #[test]
    fn test_canister_log_take() {
        let mut log = test_log();
        log.add_record(100, b"record #0".to_vec());
        log.add_record(101, b"record #1".to_vec());

        let taken = log.take();

        // Assert the taken log holds the records and the original one is empty,
        // preserving both the next index and the byte capacity.
        assert_eq!(
            taken.records(),
            &VecDeque::from(canister_log_records(&[
                (0, 100, b"record #0"),
                (1, 101, b"record #1"),
            ]))
        );
        assert_eq!(taken.next_idx(), 2);
        assert!(log.is_empty());
        assert_eq!(log.bytes_used(), 0);
        assert_eq!(log.next_idx(), 2);
        assert_eq!(log.byte_capacity(), TEST_MAX_ALLOWED_SIZE);
    }
}
