//! Limits the ICRC archive canister applies to itself.
//!
//! These live here, rather than privately in the archive canister, because the
//! ledger has to report the values that will actually take effect: it decides
//! what to pass to a new archive, but the archive is what enforces them. Keeping
//! them in a crate both canisters depend on means the two cannot disagree.
//!
//! They are deliberately not in `ic_ledger_canister_core`, which the ICP ledger
//! also uses: neither limit applies there. The ICP archive has no
//! `max_transactions_per_response` setting at all, and does not bound the memory
//! cap it is given.

/// The default maximum number of transactions returned by an ICRC archive's
/// `get_transactions` endpoint, applied when `max_transactions_per_response` is
/// not set.
///
/// This bears only on archives the ledger spawns from now on. An archive that
/// already exists was installed with whatever value was configured, and with
/// whatever default the archive Wasm of the day applied, and keeps using it.
pub const DEFAULT_MAX_TRANSACTIONS_PER_RESPONSE: u64 = 2000;

/// The hard upper bound an ICRC archive places on the number of bytes it will
/// use to store encoded blocks. Its `init` both defaults to and clamps to this
/// value, so a larger `node_max_memory_size_bytes` configured on the ledger has
/// no effect: the archive will still store at most this much.
pub const ARCHIVE_MEMORY_LIMIT: u64 = 3 * 1024 * 1024 * 1024;
