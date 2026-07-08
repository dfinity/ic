use crate::canister_manager::types::{CanisterManagerError, CanisterManagerResponse};
use crate::canister_settings::VisibilitySettings;
use crate::execution_environment::{RoundLimits, as_round_instructions};
use candid::Encode;
use ic_config::flag_status::FlagStatus;
use ic_management_canister_types_private::{
    CanisterLogRecord, FetchCanisterLogsFilter, FetchCanisterLogsRange, FetchCanisterLogsRequest,
    FetchCanisterLogsResponse, LogVisibilityV2,
};
use ic_replicated_state::CanisterState;
use ic_types::{NumBytes, NumInstructions, PrincipalId};
use std::collections::VecDeque;

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
    log_memory_store_feature: FlagStatus,
    round_limits: &mut RoundLimits,
) -> Result<CanisterManagerResponse, CanisterManagerError> {
    let canister_id = canister.canister_id();
    let (reply, record_count) =
        fetch_canister_logs_response(sender, canister, args, log_memory_store_feature)?;
    // The caller is authorized (the visibility check inside
    // `fetch_canister_logs_response` passed). Account for the work of reading and
    // encoding the logs against the round's instruction budget, approximated from
    // the number of records returned (see `fetch_canister_logs_instructions`). No
    // cycles are charged for this work: the caller already pays the per-byte
    // message transmission fee on the (potentially large) response, which
    // dominates the execution cost.
    let instructions = fetch_canister_logs_instructions(record_count);
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
/// `fetch_canister_logs` call from the response it produces: the number of
/// records returned.
///
/// The cost is a function of the record count (rather than the log memory buffer
/// size) because the log memory store's index lets a fetch read only about the
/// records it returns. The measured execution time is dominated by the number
/// of records (per-record decode/encode overhead); the smaller cost of copying
/// the record content is folded into the fixed term at its worst case, so the
/// response content size no longer needs to be tracked.
///
/// This is a conservative linear upper bound on the measured
/// `fetch_canister_logs` execution time (see the `fetch_canister_log` benchmark
/// in `rs/execution_environment/benches/management_canister/canister_logging.rs`),
/// chosen so the deduction never falls below the measured cost of any case:
///
/// ```text
/// time ≲ 12 ms + 0.45 µs × record_count
/// ```
///
/// The per-record term comes from the record-dominated worst case: a full 2 MiB
/// buffer of 0-byte log messages returns 50_000 records in ~27 ms, i.e. ~0.44
/// µs/record above the fixed cost. The fixed term covers a full-buffer fetch that
/// returns nothing (~5 ms) plus the content-copy cost of the largest possible
/// response (up to the 2 MB `MAX_FETCH_CANISTER_LOGS_RESULT_BYTES` result-size
/// limit); it is sized so the bound also stays above the mixed record-and-content
/// cases — the tightest, a full 2 MiB buffer of 100-byte messages, measures ~17 ms
/// against an ~18 ms bound. At 2 billion instructions per second (2_000_000
/// instructions per millisecond):
///
/// ```text
/// instructions ≈ 24_000_000 + 900 × record_count
/// ```
pub(crate) fn fetch_canister_logs_instructions(record_count: u64) -> NumInstructions {
    // Fixed cost of ~12 ms, at 2_000_000 instructions/ms (2 billion per second),
    // covering a full-buffer fetch that returns nothing (~5 ms) plus the content
    // copy of the largest possible response (up to the 2 MB
    // `MAX_FETCH_CANISTER_LOGS_RESULT_BYTES` result-size limit); sized so the bound
    // stays above the mixed cases too (a full 2 MiB buffer of 100-byte messages
    // measures ~17 ms).
    const BASE_INSTRUCTIONS: u64 = 24_000_000;
    // ~0.45 µs/record: the per-record decode/encode overhead dominates the cost.
    const INSTRUCTIONS_PER_RECORD: u64 = 900;
    NumInstructions::new(
        BASE_INSTRUCTIONS.saturating_add(INSTRUCTIONS_PER_RECORD.saturating_mul(record_count)),
    )
}

/// Reads the requested canister log records and returns the Candid-encoded
/// `FetchCanisterLogsResponse` together with the number of records returned. The
/// record count is used to deduct round instructions for the call (see
/// `fetch_canister_logs_instructions`).
pub(crate) fn fetch_canister_logs_response(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
    log_memory_store_feature: FlagStatus,
) -> Result<(Vec<u8>, u64), CanisterManagerError> {
    check_log_visibility_permission(&sender, canister.log_visibility(), canister.controllers())?;
    let s = &canister.system_state;
    let canister_log_records = match log_memory_store_feature {
        FlagStatus::Enabled if s.log_memory_store.is_migrated() => {
            s.log_memory_store.records(args.filter)
        }
        _ => filter_records(&args, s.canister_log.records()),
    };
    let record_count = canister_log_records.len() as u64;
    let reply = Encode!(&FetchCanisterLogsResponse {
        canister_log_records
    })
    .unwrap();
    Ok((reply, record_count))
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

fn filter_records(
    args: &FetchCanisterLogsRequest,
    records: &VecDeque<CanisterLogRecord>,
) -> Vec<CanisterLogRecord> {
    let Some(filter) = &args.filter else {
        return records.iter().cloned().collect();
    };

    let (range, key): (&FetchCanisterLogsRange, fn(&CanisterLogRecord) -> u64) = match filter {
        FetchCanisterLogsFilter::ByIdx(r) => (r, |rec| rec.idx),
        FetchCanisterLogsFilter::ByTimestampNanos(r) => (r, |rec| rec.timestamp_nanos),
    };

    if range.is_empty() {
        return Vec::new();
    }

    records
        .iter()
        .filter(|r| range.contains(key(r)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_canister_logs_instructions_matches_linear_approximation() {
        // Empty response → only the ~12 ms fixed cost (24_000_000 instructions).
        assert_eq!(
            fetch_canister_logs_instructions(0),
            NumInstructions::new(24_000_000)
        );
        // 24_000_000 + 900 × record_count instructions.
        assert_eq!(
            fetch_canister_logs_instructions(50_000),
            NumInstructions::new(24_000_000 + 900 * 50_000)
        );
        assert_eq!(
            fetch_canister_logs_instructions(10),
            NumInstructions::new(24_000_000 + 900 * 10)
        );
        // Monotonically non-decreasing in the record count.
        assert!(fetch_canister_logs_instructions(100) < fetch_canister_logs_instructions(200));
    }
}
