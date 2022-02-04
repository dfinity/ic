//! Common initialization and proposal submission code and utilities to write
//! and execute SNS tests.
use ic_types::CanisterId;

pub mod itest_helpers;

pub const NUM_SNS_CANISTERS: usize = 3;

pub const REGISTRY_CANISTER_ID: CanisterId = CanisterId::from_u64(0);
pub const GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from_u64(1);
pub const LEDGER_CANISTER_ID: CanisterId = CanisterId::from_u64(2);
pub const ROOT_CANISTER_ID: CanisterId = CanisterId::from_u64(3);

pub const ALL_SNS_CANISTER_IDS: [&CanisterId; 3] = [
    &REGISTRY_CANISTER_ID,
    &GOVERNANCE_CANISTER_ID,
    &LEDGER_CANISTER_ID,
];

// The memory allocation for the ledger, governance and registry canisters
// (4GiB)
const SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

// The default memory allocation to set for the remaining SNS canister (1GiB)
const SNS_DEFAULT_CANISTER_MEMORY_ALLOCATION_IN_BYTES: u64 = 1024 * 1024 * 1024;

/// Returns the memory allocation of the given sns canister.
pub fn memory_allocation_of(canister_id: CanisterId) -> u64 {
    if [
        LEDGER_CANISTER_ID,
        GOVERNANCE_CANISTER_ID,
        REGISTRY_CANISTER_ID,
    ]
    .contains(&canister_id)
    {
        SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES
    } else {
        SNS_DEFAULT_CANISTER_MEMORY_ALLOCATION_IN_BYTES
    }
}
