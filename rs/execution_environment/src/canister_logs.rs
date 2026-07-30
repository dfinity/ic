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
    // Charge the read/encode work against the round's instruction budget. No cycles
    // fee is charged for the call because every term is already covered by fees the
    // caller pays (per-message execution fee and per-byte response transmission fee).
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

/// Derives the number of round instructions to deduct for a `fetch_canister_logs`
/// call from its response: the number of records returned and their total content
/// size.
///
/// The constants below are a conservative linear upper bound on the measured
/// read/encode time, with a modest margin over every case. To re-derive them, run
/// the `fetch_canister_log` benchmark in
/// `rs/execution_environment/benches/management_canister/canister_logging.rs` and
/// convert the measured times at 2_000_000 instructions/ms.
pub(crate) fn fetch_canister_logs_instructions(
    record_count: u64,
    content_size: NumBytes,
) -> NumInstructions {
    // Fixed base for a near-empty fetch (index lookup on a full log buffer).
    const BASE_INSTRUCTIONS: u64 = 150_000;
    // Per-record decode/encode overhead.
    const INSTRUCTIONS_PER_RECORD: u64 = 900;
    // Per-byte cost of copying and encoding the record content.
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
/// Re-exported from the crate root so the benchmark can time the read/encode work
/// that drives `fetch_canister_logs_instructions` without the surrounding
/// subnet-message machinery.
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
        // Empty response → only the fixed base (150_000 instructions).
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
        // Monotonically increasing in both the record count and content size.
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
