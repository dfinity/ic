use candid::Deserialize;
use ic_management_canister_types::{CanisterLogRecord, DataSize};
use serde::Serialize;
use std::collections::VecDeque;

/// The maximum allowed size of a canister log buffer.
pub const MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE: usize = 4 * 1024;

/// Holds canister log records and keeps track of the next canister log record index.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanisterLog {
    next_idx: u64,
    records: VecDeque<CanisterLogRecord>,
}

impl CanisterLog {
    /// Creates a new `CanisterLog` with the given next index and records.
    pub fn new(next_idx: u64, records: Vec<CanisterLogRecord>) -> Self {
        Self {
            next_idx,
            records: VecDeque::from(records),
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
        &self.records
    }

    /// Clears the canister log records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns the maximum allowed size of a canister log buffer.
    pub fn capacity(&self) -> usize {
        MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE
    }

    /// Returns the used space in the canister log buffer.
    pub fn used_space(&self) -> usize {
        self.records.data_size()
    }

    /// Returns the remaining space in the canister log buffer.
    pub fn remaining_space(&self) -> usize {
        MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE.saturating_sub(self.records.data_size())
    }

    /// Removes old records to make enough free space for new data within the limit.
    fn make_free_space_within_limit(&mut self, new_data_size: usize) {
        let mut total_size = new_data_size + self.records.data_size();
        while total_size > MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE {
            if let Some(removed_record) = self.records.pop_front() {
                total_size -= removed_record.data_size();
            } else {
                break; // No more records to pop, limit reached.
            }
        }
    }

    /// Adds a new log record.
    pub fn add_record(&mut self, is_enabled: bool, timestamp_nanos: u64, content: &[u8]) {
        if !is_enabled {
            // If logging is disabled do not add new records,
            // but still make sure the buffer is within limit.
            self.make_free_space_within_limit(0);
            return;
        }

        // LINT.IfChange
        // Keep the new log record size within limit,
        // this must be in sync with `logging_charge_bytes` in `system_api.rs`.
        let max_content_size =
            MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE - CanisterLogRecord::default().data_size();
        let size = content.len().min(max_content_size);
        let record = CanisterLogRecord {
            idx: self.next_idx,
            timestamp_nanos,
            content: content[..size].to_vec(),
        };
        self.make_free_space_within_limit(record.data_size());
        self.records.push_back(record);
        // LINT.ThenChange(logging_charge_bytes_rule)
        // Update the next canister log record index.
        self.next_idx += 1;
    }

    /// Moves all the logs from `other` to `self`.
    pub fn append(&mut self, other: &mut Self) {
        // Assume records sorted cronologically (with increasing idx) and
        // update the system state's next index with the last record's index.
        if let Some(last) = other.records.back() {
            self.next_idx = last.idx + 1;
        }
        self.make_free_space_within_limit(other.records.data_size());
        self.records.append(&mut other.records);
    }
}
