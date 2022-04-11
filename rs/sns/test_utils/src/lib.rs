//! Common initialization and proposal submission code and utilities to write
//! and execute SNS tests.

pub mod itest_helpers;

pub const NUM_SNS_CANISTERS: usize = 3;

// The memory allocation for the ledger, governance and registry canisters
// (4GiB)
pub const SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 4 * 1024 * 1024 * 1024;
