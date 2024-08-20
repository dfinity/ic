use candid::Deserialize;
use ic_management_canister_types::{CanisterLogRecord, DataSize};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use serde::Serialize;
use std::collections::VecDeque;

/// The maximum allowed size of a canister log buffer.
pub const MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE: usize = 4 * 1024;

fn truncate_content(mut record: CanisterLogRecord) -> CanisterLogRecord {
    let max_content_size =
        MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE - std::mem::size_of::<CanisterLogRecord>();
    record.content.truncate(max_content_size);
    record
}

// Helper struct to hold canister log records and keep track of the used space.
// This is needed to avoid iterating over all records to calculate the used space.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ValidateEq)]
struct Records {
    #[validate_eq(Ignore)]
    records: VecDeque<CanisterLogRecord>,
    used_space: usize,
}

impl Records {
    fn from(records: Vec<CanisterLogRecord>) -> Self {
        let records: Vec<_> = records
            .into_iter()
            .map(truncate_content) // Apply size limit to each record's content.
            .collect();
        let used_space = records.iter().map(|r| r.data_size()).sum();
        let mut result = Self {
            records: records.into(),
            used_space,
        };
        // Make sure the buffer is within limit.
        result.make_free_space_within_limit(0);
        result
    }

    fn clear(&mut self) {
        self.records.clear();
        self.used_space = 0;
    }

    fn get(&self) -> &VecDeque<CanisterLogRecord> {
        &self.records
    }

    fn used_space(&self) -> usize {
        self.used_space
    }

    fn push_back(&mut self, record: CanisterLogRecord) {
        let added_size = record.data_size();
        // LINT.IfChange
        // Keep the new log record size within limit,
        // this must be in sync with `logging_charge_bytes` in `system_api.rs`.
        self.make_free_space_within_limit(added_size);
        self.records.push_back(record);
        // LINT.ThenChange(logging_charge_bytes_rule)
        self.used_space += added_size;
    }

    fn pop_front(&mut self) -> Option<usize> {
        if let Some(record) = self.records.pop_front() {
            let removed_size = record.data_size();
            self.used_space = self.used_space().saturating_sub(removed_size);
            Some(removed_size)
        } else {
            None
        }
    }

    fn append(&mut self, other: &mut Self) {
        self.make_free_space_within_limit(other.used_space());
        self.records.append(&mut other.records);
        self.used_space += other.used_space();
        other.clear();
    }

    fn capacity(&self) -> usize {
        MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE
    }

    fn make_free_space_within_limit(&mut self, new_data_size: usize) {
        // Removes old records to make enough free space for new data within the limit.
        let mut total_size = new_data_size + self.used_space();
        while total_size > self.capacity() {
            if let Some(removed_size) = self.pop_front() {
                total_size = total_size.saturating_sub(removed_size);
            } else {
                break; // No more records to pop, limit reached.
            }
        }
    }
}

/// Holds canister log records and keeps track of the next canister log record index.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ValidateEq)]
pub struct CanisterLog {
    next_idx: u64,
    #[validate_eq(CompareWithValidateEq)]
    records: Records,
}

impl CanisterLog {
    /// Creates a new `CanisterLog` with the given next index and records.
    pub fn new(next_idx: u64, records: Vec<CanisterLogRecord>) -> Self {
        Self {
            next_idx,
            records: Records::from(records),
        }
    }

    /// Creates a new `CanisterLog` with the given next index and an empty records list.
    pub fn new_with_next_index(next_idx: u64) -> Self {
        Self {
            next_idx,
            records: Default::default(),
        }
    }

    /// Returns the next canister log record index.
    pub fn next_idx(&self) -> u64 {
        self.next_idx
    }

    /// Returns the canister log records.
    pub fn records(&self) -> &VecDeque<CanisterLogRecord> {
        self.records.get()
    }

    /// Clears the canister log records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns the maximum allowed size of a canister log buffer.
    pub fn capacity(&self) -> usize {
        self.records.capacity()
    }

    /// Returns the used space in the canister log buffer.
    pub fn used_space(&self) -> usize {
        self.records.used_space()
    }

    /// Returns the remaining space in the canister log buffer.
    pub fn remaining_space(&self) -> usize {
        let records = &self.records;
        records.capacity().saturating_sub(records.used_space())
    }

    /// Adds a new log record.
    pub fn add_record(&mut self, timestamp_nanos: u64, content: Vec<u8>) {
        // Add record and update the next index.
        self.records.push_back(truncate_content(CanisterLogRecord {
            idx: self.next_idx,
            timestamp_nanos,
            content,
        }));
        self.next_idx += 1;
    }

    /// Moves all the logs from `other` to `self`.
    pub fn append(&mut self, other: &mut Self) {
        // Assume records sorted cronologically (with increasing idx) and
        // update the system state's next index with the last record's index.
        if let Some(last) = other.records.get().back() {
            self.next_idx = last.idx + 1;
        }
        self.records.append(&mut other.records);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_management_canister_types::CanisterLogRecord;

    const TEST_MAX_ALLOWED_SIZE: usize = 4 * 1024;
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
        let log = CanisterLog::default();
        // Assert log has no records and memory usage is zero.
        assert_eq!(log.records().len(), 0);
        assert_eq!(log.used_space(), 0);
        assert_eq!(log.remaining_space(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_new_applies_memory_limit() {
        let log = CanisterLog::new(
            3,
            canister_log_records(&[
                (0, 100, BIGGER_THAN_LIMIT_MESSAGE),
                (1, 100, BIGGER_THAN_LIMIT_MESSAGE),
                (2, 100, BIGGER_THAN_LIMIT_MESSAGE),
            ]),
        );
        // Assert log has only one record and it's size is within limit.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.used_space(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.remaining_space(), 0);
        assert_eq!(log.capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_add_record_applies_memory_limit() {
        let mut log = CanisterLog::default();
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        // Assert log has only one record and it's size is within limit.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.used_space(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.remaining_space(), 0);
        assert_eq!(log.capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_clear() {
        // Arrange.
        let mut log = CanisterLog::default();
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        log.add_record(100, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        // Act.
        log.clear();
        // Assert log has no records and memory usage is zero.
        assert_eq!(log.records().len(), 0);
        assert_eq!(log.used_space(), 0);
        assert_eq!(log.remaining_space(), TEST_MAX_ALLOWED_SIZE);
        assert_eq!(log.capacity(), TEST_MAX_ALLOWED_SIZE);
    }

    #[test]
    fn test_canister_log_increases_next_idx_after_reaching_memory_limit() {
        let records_number = 42;
        let mut log = CanisterLog::default();
        for _ in 0..records_number {
            log.add_record(0, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        }
        // Assert log has only one record and next_idx is increased.
        assert_eq!(log.records().len(), 1);
        assert_eq!(log.next_idx(), records_number as u64);
    }

    #[test]
    fn test_canister_log_adds_records() {
        let mut log = CanisterLog::default();
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
        let mut main = CanisterLog::new(
            3,
            canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
            ]),
        );
        let mut delta = CanisterLog::new_with_next_index(main.next_idx());
        delta.add_record(200, b"delta #0".to_vec());
        delta.add_record(201, b"delta #1".to_vec());
        delta.add_record(202, b"delta #2".to_vec());

        // Act.
        main.append(&mut delta);

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
        let mut main = CanisterLog::new(
            3,
            canister_log_records(&[
                (0, 100, b"main #0"),
                (1, 101, b"main #1"),
                (2, 102, b"main #2"),
            ]),
        );
        let mut delta = CanisterLog::new_with_next_index(main.next_idx());
        // Add big records to reach memory limit and a small one at the end.
        delta.add_record(200, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        delta.add_record(201, BIGGER_THAN_LIMIT_MESSAGE.to_vec());
        delta.add_record(202, b"delta #2".to_vec());

        // Act.
        main.append(&mut delta);

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
}
