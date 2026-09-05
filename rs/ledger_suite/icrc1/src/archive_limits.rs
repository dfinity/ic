//! Limits the ICRC archive canister applies to itself.

/// The default maximum number of transactions returned by an ICRC archive's
/// `get_transactions` endpoint, applied when `max_transactions_per_response` is
/// not set.
pub const DEFAULT_MAX_TRANSACTIONS_PER_RESPONSE: u64 = 2000;

/// The hard upper bound an ICRC archive places on the number of bytes it will
/// use to store encoded blocks.
pub const ARCHIVE_MEMORY_LIMIT: u64 = 3 * 1024 * 1024 * 1024;
