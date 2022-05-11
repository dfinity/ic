//! Common initialization and proposal submission code and utilities to write
//! and execute SNS tests.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod itest_helpers;

pub const NUM_SNS_CANISTERS: usize = 3;

// The memory allocation for the ledger, governance and registry canisters
// (4GiB)
pub const SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Commonly used method for getting the time since Unix Epoch for SNS integration tests.
/// Since integration tests will sometimes use timewarp, this method takes an argument
/// that will apply the same delta to the current time.
pub fn now_seconds(delta_seconds: Option<u64>) -> u64 {
    let mut now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if let Some(ds) = delta_seconds {
        now = now.saturating_add(ds);
    }

    now
}
