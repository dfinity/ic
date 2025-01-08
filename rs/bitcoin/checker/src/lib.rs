pub mod blocklist;
mod types;

pub use types::*;

/// Caller of check_transaction must attach this amount of cycles with the call.
pub const CHECK_TRANSACTION_CYCLES_REQUIRED: u128 = 40_000_000_000;

/// One-time charge for every check_transaction call.
pub const CHECK_TRANSACTION_CYCLES_SERVICE_FEE: u128 = 100_000_000;

// The max_response_bytes is initially set to 4kB, and then
// increased to 400kB if the initial size isn't enough.
// - The maximum size of a standard non-taproot transaction is 400k vBytes.
// - Taproot transactions could be as big as full block size (4MiB).
// - Currently a subnet's maximum response size is only 2MiB.
// - Transaction size between 400kB and 2MiB are also uncommon, we could
//   handle them in the future if required.
// - Transactions bigger than 2MiB are very rare, and we can't handle them.

/// Initial max response bytes is 4kB
pub const INITIAL_MAX_RESPONSE_BYTES: u32 = 4 * 1024;

/// Retry max response bytes is 400kB
pub const RETRY_MAX_RESPONSE_BYTES: u32 = 400 * 1024;

pub fn get_tx_cycle_cost(max_response_bytes: u32, num_subnet_nodes: u16) -> u128 {
    let n = num_subnet_nodes as u128;
    let m = max_response_bytes as u128;
    let base_fee = (3_000_000 + 60_000 * n) * n;
    // 1 KiB for request, max_response_bytes for response
    let request_fee = 400 * n * 1024;
    let response_fee = 800 * n * m;
    base_fee + request_fee + response_fee
}
