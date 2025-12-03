use candid::Deserialize;
use ic_management_canister_types_private::{CanisterLogRecord, DataSize};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use serde::Serialize;
use std::collections::VecDeque;

#[allow(non_upper_case_globals)]
const KiB: usize = 1024;
#[allow(non_upper_case_globals)]
const MiB: usize = 1024 * KiB;

/// The minimum size of an aggregate canister log buffer.
pub const MIN_AGGREGATE_LOG_MEMORY_LIMIT: usize = 4 * KiB;
/// The maximum size of an aggregate canister log buffer.
pub const MAX_AGGREGATE_LOG_MEMORY_LIMIT: usize = 4 * KiB;
/// The default size of an aggregate canister log buffer.
pub const DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT: usize = 4 * KiB;

/// The maximum size of a delta (per message) canister log buffer.
pub const MAX_DELTA_LOG_MEMORY_LIMIT: usize = 2 * MiB;

// TODO(DSM-11): these metrics should be tracked in aggregate logs only,
// remove after migration is done.
/// Upper bound on stored delta-log sizes used for metrics.
/// Limits memory growth, 10k covers expected per-round
/// number of messages per canister (and so delta log appends).
const DELTA_LOG_SIZES_CAP: usize = 10_000;

/// Maximum number of response bytes for a fetch canister logs request.
pub const MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES: usize = 2_000_000;

// Compile-time assertions to ensure the constants are within valid ranges.
const _: () = assert!(MIN_AGGREGATE_LOG_MEMORY_LIMIT <= DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT);
const _: () = assert!(DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT <= MAX_AGGREGATE_LOG_MEMORY_LIMIT);

const _: () = assert!(std::mem::size_of::<CanisterLogRecord>() <= MIN_AGGREGATE_LOG_MEMORY_LIMIT);

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
        self.make_free_space_within_limit(other.bytes_used);
        self.records.append(&mut other.records);
        self.bytes_used += other.bytes_used;
        other.clear();
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

    /// Tracks per-round sizes of appended delta logs — used solely for metrics.
    ///
    /// A round may append multiple logs (e.g. from heartbeats, timers, or message
    /// executions). Their sizes are collected during the round and cleared after
    /// metrics are recorded.
    delta_log_sizes: VecDeque<usize>,
}

impl CanisterLog {
    /// Creates a new log with the given next index, records and byte capacity.
    fn new_inner(next_idx: u64, records: Vec<CanisterLogRecord>, byte_capacity: usize) -> Self {
        Self {
            next_idx,
            records: Records::from(records, byte_capacity),
            delta_log_sizes: VecDeque::new(),
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

    /// Returns mutable reference to the canister log records.
    pub fn records_mut(&mut self) -> &mut VecDeque<CanisterLogRecord> {
        self.records.get_mut()
    }

    /// Clears the canister log records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns the maximum allowed size of a canister log buffer.
    pub fn byte_capacity(&self) -> usize {
        self.records.byte_capacity
    }

    /// Returns the used space in the canister log buffer.
    pub fn bytes_used(&self) -> usize {
        self.records.bytes_used
    }

    /// Returns true if the canister log buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes_used() == 0
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

    /// Moves all the logs from `delta_log` to `self`.
    pub fn append_delta_log(&mut self, delta_log: &mut Self) {
        // Record the size of the appended delta log for metrics.
        self.push_delta_log_size(delta_log.records.bytes_used);

        // Assume records sorted cronologically (with increasing idx) and
        // update the system state's next index with the last record's index.
        if let Some(last) = delta_log.records.get().back() {
            self.next_idx = last.idx + 1;
        }
        self.records.append(&mut delta_log.records);
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
    use ic_management_canister_types_private::CanisterLogRecord;

    const TEST_MAX_ALLOWED_SIZE: usize = 4 * KiB;
    const BIGGER_THAN_LIMIT_MESSAGE: &[u8] = &[b'a'; 2 * TEST_MAX_ALLOWED_SIZE];

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

        // Assert main log had data loss.
        assert_eq!(
            main.records(),
            &VecDeque::from(canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
                // Expected data loss.
                (5, 202, b"delta #2"),
            ]))
        );
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
        assert_eq!(main.take_delta_log_sizes(), vec![size_b, size_c]);
        assert_eq!(main.take_delta_log_sizes(), Vec::<usize>::new()); // Second call returns empty.
        assert_eq!(main.bytes_used(), size_a + size_b + size_c);
    }
}
