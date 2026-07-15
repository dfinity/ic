use crate::canister_manager::types::{CanisterManagerError, CanisterManagerResponse};
use crate::canister_settings::VisibilitySettings;
use crate::execution_environment::{RoundLimits, as_round_instructions};
use candid::Encode;
use ic_management_canister_types_private::{
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2,
};
use ic_replicated_state::CanisterState;
use ic_types::{NumBytes, NumInstructions, PrincipalId};

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
    round_limits: &mut RoundLimits,
) -> Result<CanisterManagerResponse, CanisterManagerError> {
    let canister_id = canister.canister_id();
    let (reply, record_count, content_size) = fetch_canister_logs_response(sender, canister, args)?;
    // Account for the read/encode work — from the number of records returned and
    // their total content size (see `fetch_canister_logs_instructions`) — against
    // the round's instruction budget. No cycles fee is charged for the call: every
    // term of that cost is already covered by a fee the caller pays. The fixed base
    // is bounded by the flat per-message execution fee the caller pays to run its
    // response callback; the per-record and per-content-byte terms are dominated by
    // the per-byte message transmission fee the caller pays on the response
    // (which is ~1000x the per-byte instruction cost). On a subnet with a "free"
    // cost schedule the fee for the call is zero, but the fee for the subnet
    // covers the work.
    let instructions = fetch_canister_logs_instructions(record_count, content_size);
    round_limits.instructions -= as_round_instructions(instructions);
    Ok(CanisterManagerResponse {
        canister_id,
        reply: Some(reply),
        heap_delta_increase: NumBytes::new(0),
        unflushed_checkpoint_op: None,
        deleted_call_context_responses: vec![],
        stop_call_id_to_remove: None,
        stop_contexts_to_reject: vec![],
    })
}

/// Derives the number of round instructions to deduct for executing a
/// `fetch_canister_logs` call from the response it produces: the number of records
/// returned and the total size of their content.
///
/// This is a conservative linear upper bound on the measured `fetch_canister_logs`
/// execution time (see the `fetch_canister_log` benchmark in
/// `rs/execution_environment/benches/management_canister/canister_logging.rs`,
/// which times `fetch_canister_logs_response` directly on a full log buffer — the
/// exact read/encode work charged here, excluding the surrounding subnet-message
/// machinery and per-iteration state setup), chosen so the deduction stays above
/// the measured cost of every case with a modest (~1.3–1.5x) margin. The log buffer
/// is capped at 2 MiB (`MAX_AGGREGATE_LOG_MEMORY_LIMIT`), so the benchmarked buffer
/// sizes cover the whole configurable range:
///
/// ```text
/// time ≲ 75 µs + 0.45 µs × record_count + 0.5 ns × content_size
/// ```
///
/// Each term is calibrated to a measured worst case and stays below a fee the caller
/// already pays, which is why the call itself charges no cycles fee:
///
/// - The fixed 75 µs base (`150_000` instructions) covers the worst fixed/seek cost
///   of a fetch that returns almost nothing: a single-record index lookup on a full
///   2 MiB buffer measures ~48 µs (an empty or no-match fetch is cheaper, ~30 µs).
///   It stays far below the flat per-message execution fee
///   (`update_message_execution_fee`, 5_000_000 cycles) the caller pays to run its
///   response callback.
/// - The per-record term (~0.45 µs/record) bounds the record-dominated worst case: a
///   full 2 MiB buffer of 0-byte messages returns ~50_000 records in ~17 ms, i.e.
///   ~0.35 µs/record measured. The per-content-byte term (~0.5 ns/byte) bounds the
///   ~0.2 ns/byte measured for a full 2 MiB content payload. Both stay well below the
///   per-byte message transmission fee (1000 cycles/byte) the caller pays on the
///   response, since each record adds ~17 response bytes and each content byte adds
///   one.
///
/// At 2 billion instructions per second (2_000_000 instructions per millisecond):
///
/// ```text
/// instructions ≈ 150_000 + 900 × record_count + 1 × content_size
/// ```
pub(crate) fn fetch_canister_logs_instructions(
    record_count: u64,
    content_size: NumBytes,
) -> NumInstructions {
    // Fixed ~75 µs base: the worst fixed/seek cost of a near-empty fetch (a
    // single-record lookup on a full 2 MiB buffer, ~48 µs measured), well below the
    // 5_000_000-cycle per-message execution fee (2_000_000 instructions/ms).
    const BASE_INSTRUCTIONS: u64 = 150_000;
    // ~0.45 µs/record: the per-record decode/encode overhead.
    const INSTRUCTIONS_PER_RECORD: u64 = 900;
    // ~0.5 ns/byte: the cost of copying and encoding the record content.
    const INSTRUCTIONS_PER_CONTENT_BYTE: u64 = 1;
    NumInstructions::new(
        BASE_INSTRUCTIONS
            .saturating_add(INSTRUCTIONS_PER_RECORD.saturating_mul(record_count))
            .saturating_add(INSTRUCTIONS_PER_CONTENT_BYTE.saturating_mul(content_size.get())),
    )
}

/// Reads the requested canister log records and returns the Candid-encoded
/// `FetchCanisterLogsResponse` together with the number of records returned and the
/// total size of their content. The record count and content size are used to
/// deduct round instructions for the call (see `fetch_canister_logs_instructions`).
pub(crate) fn fetch_canister_logs_response(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
) -> Result<(Vec<u8>, u64, NumBytes), CanisterManagerError> {
    check_log_visibility_permission(&sender, canister.log_visibility(), canister.controllers())?;
    let canister_log_records = canister.system_state.log_memory_store.records(args.filter);
    let record_count = canister_log_records.len() as u64;
    let content_size = canister_log_records
        .iter()
        .map(|r| r.content.len())
        .sum::<usize>();
    let reply = Encode!(&FetchCanisterLogsResponse {
        canister_log_records
    })
    .unwrap();
    Ok((reply, record_count, NumBytes::new(content_size as u64)))
}

/// Benchmark-only entry point for the `management_canister_bench`: runs
/// [`fetch_canister_logs_response`] and returns its result, panicking on error.
///
/// Exposed (via a `pub use` re-export from the crate root) so the benchmark can
/// time the exact read/encode work that drives `fetch_canister_logs_instructions`
/// directly, without the surrounding subnet-message and inter-canister-call
/// machinery (which otherwise dominates the sub-millisecond read on large
/// buffers and is not part of what the call is charged for).
#[doc(hidden)]
pub fn fetch_canister_logs_response_for_bench(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
) -> (Vec<u8>, u64, NumBytes) {
    fetch_canister_logs_response(sender, canister, args)
        .expect("fetch_canister_logs_response failed")
}

/// Checks if the caller has permission to access the logs based on the canister's log visibility settings.
pub(crate) fn check_log_visibility_permission(
    caller: &PrincipalId,
    log_visibility: &LogVisibilityV2,
    controllers: &std::collections::BTreeSet<PrincipalId>,
) -> Result<(), CanisterManagerError> {
    if !VisibilitySettings::from(log_visibility).has_access(caller, controllers) {
        return Err(CanisterManagerError::FetchCanisterLogsAccessDenied { caller: *caller });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_canister_logs_instructions_matches_linear_approximation() {
        // Empty response → only the fixed ~75 µs base (150_000 instructions).
        assert_eq!(
            fetch_canister_logs_instructions(0, NumBytes::new(0)),
            NumInstructions::new(150_000)
        );
        // 150_000 + 900 × record_count + 1 × content_size instructions.
        assert_eq!(
            fetch_canister_logs_instructions(50_000, NumBytes::new(0)),
            NumInstructions::new(150_000 + 900 * 50_000)
        );
        assert_eq!(
            fetch_canister_logs_instructions(10, NumBytes::new(4_096)),
            NumInstructions::new(150_000 + 900 * 10 + 4_096)
        );
        // Monotonically non-decreasing in both the record count and content size.
        assert!(
            fetch_canister_logs_instructions(100, NumBytes::new(1_000))
                < fetch_canister_logs_instructions(200, NumBytes::new(1_000))
        );
        assert!(
            fetch_canister_logs_instructions(100, NumBytes::new(1_000))
                < fetch_canister_logs_instructions(100, NumBytes::new(2_000))
        );
    }
}
