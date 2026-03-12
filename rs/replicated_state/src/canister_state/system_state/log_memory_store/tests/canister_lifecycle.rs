//! This file is not a 'source of truth' test.
//!
//! `LogMemoryStore` is supposed to be used as a field to the `SystemState` and
//! properly incorporated into real canister lifecycle. But since this change
//! touches many different places it's difficult to properly test it fast.
//!
//! So this file contains a simplified test that is supposed to mimic the
//! expected behavior with a `MockCanister` and test how `LogMemoryStore` works
//! on it.

use super::super::*;
use ic_management_canister_types_private::CanisterLogRecord;
use ic_types::{CanisterLog, NumBytes};
use more_asserts::{assert_gt, assert_lt};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Minimal non-zero log memory limit.
/// Must be rounded up to at least one OS page.
const TEST_MINIMAL_LOG_MEMORY_LIMIT: NumBytes = NumBytes::new(4 * KIB);

/// Default log memory limit.
const TEST_DEFAULT_LOG_MEMORY_LIMIT: NumBytes = NumBytes::new(6 * KIB);

struct MockCanister {
    log_memory_store: LogMemoryStore,
    fake_timestamp: u64,
}

impl MockCanister {
    /// Creates a new canister with default settings.
    fn create_canister() -> Self {
        let mut canister = Self {
            log_memory_store: LogMemoryStore::new(FlagStatus::Enabled),
            fake_timestamp: 0,
        };
        canister.update_settings(TEST_DEFAULT_LOG_MEMORY_LIMIT);
        canister
    }

    /// Updates the maximum capacity of the log memory store.
    ///
    /// Resizes the underlying storage to match the provided byte limit.
    fn update_settings(&mut self, log_memory_limit: NumBytes) {
        self.log_memory_store
            .resize_for_testing(log_memory_limit.get() as usize);
    }

    /// Installs or reinstalls the canister code.
    ///
    /// Starts with a clean state by clearing the log memory store.
    fn install_code(&mut self) {
        self.log_memory_store.clear();
    }

    /// Uninstalls the canister.
    ///
    /// Deallocates the log memory store and its configuration.
    /// Removes all logs and metadata; a manual settings update is required to reuse the store.
    fn uninstall_code(&mut self) {
        self.log_memory_store.deallocate();
    }

    /// Returns the memory usage of the log memory store.
    fn log_memory_usage(&self) -> NumBytes {
        NumBytes::from(self.log_memory_store.memory_usage() as u64)
    }

    /// Logs a message.
    fn log(&mut self, message: &str) {
        let next_idx = self.log_memory_store.next_idx();
        let mut delta = CanisterLog::new_delta_with_next_index(next_idx, 2 * MIB as usize);
        delta.add_record(self.fake_timestamp, message.as_bytes().to_vec());
        self.fake_timestamp += 1;
        self.log_memory_store.append_delta_log(&mut delta);
    }

    /// Returns all records in the log.
    fn fetch_canister_logs(&self) -> Vec<CanisterLogRecord> {
        self.log_memory_store.records(None)
    }
}

// Calculates actual log memory usage based on the data capacity.
fn total_allocated_bytes(data_capacity: NumBytes) -> NumBytes {
    // header + index table + data
    NumBytes::from(4 * KIB) + NumBytes::from(4 * KIB) + data_capacity
}

#[test]
fn test_canister_creation_initially_default_size() {
    let canister = MockCanister::create_canister();

    assert_eq!(canister.fetch_canister_logs().len(), 0);
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(TEST_DEFAULT_LOG_MEMORY_LIMIT)
    );
}

#[test]
fn test_canister_minimal_log_memory_limit() {
    let mut canister = MockCanister::create_canister();

    // Small non-zero value.
    canister.update_settings(NumBytes::new(1));

    // Small non-zero value must be rounded up to at
    // least one OS page.
    assert_eq!(canister.fetch_canister_logs().len(), 0);
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(TEST_MINIMAL_LOG_MEMORY_LIMIT)
    );
}

#[test]
fn test_canister_resize_to_zero_deallocates() {
    let mut canister = MockCanister::create_canister();
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(TEST_DEFAULT_LOG_MEMORY_LIMIT)
    );

    // User can fully disable logging by setting log memory limit to zero.
    canister.update_settings(NumBytes::new(0));

    assert_eq!(canister.log_memory_usage(), NumBytes::new(0));
}

#[test]
fn test_canister_update_log_memory_limit() {
    let new_log_memory_limit = NumBytes::new(100 * KIB);
    assert_gt!(new_log_memory_limit, TEST_MINIMAL_LOG_MEMORY_LIMIT);

    let mut canister = MockCanister::create_canister();
    canister.update_settings(new_log_memory_limit);

    assert_eq!(canister.fetch_canister_logs().len(), 0);
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(new_log_memory_limit)
    );
}

#[test]
fn test_canister_logging_appends_records() {
    let mut canister = MockCanister::create_canister();

    canister.log("Hello");
    canister.log("World");

    let records = canister.fetch_canister_logs();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].content, b"Hello");
    assert_eq!(records[1].content, b"World");
}

#[test]
fn test_canister_reinstall_clears_logs_but_preserves_log_memory_limit() {
    let new_log_memory_limit = NumBytes::new(100 * KIB);
    assert_gt!(new_log_memory_limit, TEST_DEFAULT_LOG_MEMORY_LIMIT);
    let mut canister = MockCanister::create_canister();
    canister.update_settings(new_log_memory_limit);
    canister.log("Important Data");
    assert_gt!(canister.fetch_canister_logs().len(), 0);
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(new_log_memory_limit)
    );

    // Install or reinstall.
    canister.install_code();

    // Assert logs are cleared and log memory limit is preserved.
    assert_eq!(canister.fetch_canister_logs().len(), 0);
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(new_log_memory_limit)
    );
}

#[test]
fn test_canister_uninstall_deallocates() {
    let mut canister = MockCanister::create_canister();
    canister.log("Data");
    assert_gt!(canister.log_memory_usage().get(), 0);

    canister.uninstall_code();

    // Assert logs are cleared and log memory is deallocated.
    assert_eq!(canister.fetch_canister_logs().len(), 0);
    assert_eq!(canister.log_memory_usage().get(), 0);
}

#[test]
fn test_canister_uninstall_and_install_clears_log_memory() {
    let mut canister = MockCanister::create_canister();
    canister.update_settings(NumBytes::new(100 * KIB));
    canister.log("Message 1");

    canister.uninstall_code();
    canister.install_code();
    canister.log("Message 2");

    // Assert logs memory allocation is cleared.
    assert_eq!(canister.fetch_canister_logs().len(), 0);
    assert_eq!(canister.log_memory_usage().get(), 0);
}

#[test]
fn test_canister_resize_up_preserves_logs() {
    let log_memory_limit_before = NumBytes::new(10 * KIB);
    let log_memory_limit_after = NumBytes::new(100 * KIB);
    assert_lt!(log_memory_limit_before, log_memory_limit_after);
    let mut canister = MockCanister::create_canister();
    canister.update_settings(log_memory_limit_before);
    canister.log("Data");

    let logs_before = canister.fetch_canister_logs();
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(log_memory_limit_before)
    );
    canister.update_settings(log_memory_limit_after);

    // Assert logs are preserved.
    assert_eq!(canister.fetch_canister_logs(), logs_before);
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(log_memory_limit_after)
    );
}

#[test]
fn test_canister_resize_down_preserves_logs() {
    let log_memory_limit_before = NumBytes::new(100 * KIB);
    let log_memory_limit_after = NumBytes::new(10 * KIB);
    assert_gt!(log_memory_limit_before, log_memory_limit_after);
    let mut canister = MockCanister::create_canister();
    canister.update_settings(log_memory_limit_before);
    canister.log("Data");

    let logs_before = canister.fetch_canister_logs();
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(log_memory_limit_before)
    );
    canister.update_settings(log_memory_limit_after);

    // Assert logs are preserved.
    assert_eq!(canister.fetch_canister_logs(), logs_before);
    assert_eq!(
        canister.log_memory_usage(),
        total_allocated_bytes(log_memory_limit_after)
    );
}
