use crate::canister_manager::types::{CanisterManagerError, CanisterManagerResponse};
use crate::canister_settings::VisibilitySettings;
use crate::execution_environment::{RoundLimits, as_round_instructions};
use candid::Encode;
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerSubnetConfig};
use ic_management_canister_types_private::{
    CanisterLogRecord, FetchCanisterLogsFilter, FetchCanisterLogsRange, FetchCanisterLogsRequest,
    FetchCanisterLogsResponse, LogVisibilityV2,
};
use ic_replicated_state::CanisterState;
use ic_types::canister_log::MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES;
use ic_types::messages::CanisterCall;
use ic_types::{NumBytes, NumInstructions, PrincipalId};
use std::collections::VecDeque;

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
    log_memory_store_feature: FlagStatus,
    msg: &mut CanisterCall,
    round_limits: &mut RoundLimits,
    cycles_account_manager: &CyclesAccountManager,
    subnet_cycles_config: CyclesAccountManagerSubnetConfig,
) -> Result<CanisterManagerResponse, CanisterManagerError> {
    // The response (and hence the fee) is only known after reading the logs, so
    // reject up front any call that could not afford the worst-case response:
    // the maximum number of records, which is `RESULT_MAX_SIZE` divided by the
    // minimum per-record size. This ensures we never do the read work for free.
    let max_record_count = MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES as u64
        / std::mem::size_of::<CanisterLogRecord>() as u64;
    let max_fee = cycles_account_manager
        .management_canister_cost(
            fetch_canister_logs_instructions(max_record_count, NumBytes::new(0)),
            subnet_cycles_config,
        )
        .real();
    let payment = msg.cycles();
    if payment < max_fee {
        return Err(CanisterManagerError::FetchCanisterLogsNotEnoughCycles {
            sent: payment,
            required: max_fee,
        });
    }
    let canister_id = canister.canister_id();
    let (reply, record_count, content_size) =
        fetch_canister_logs_response(sender, canister, args, log_memory_store_feature)?;
    // The caller is authorized (the visibility check inside
    // `fetch_canister_logs_response` passed). Charge for the work of reading and
    // encoding the logs, approximated from the number of records returned and
    // their content size (see `fetch_canister_logs_instructions`): deduct the
    // cycles fee from the call's payment and the corresponding instructions from
    // the round's budget.
    let instructions = fetch_canister_logs_instructions(record_count, content_size);
    let fee = cycles_account_manager
        .management_canister_cost(instructions, subnet_cycles_config)
        .real();
    msg.deduct_cycles(fee);
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

/// Derives the number of instructions to charge for executing a
/// `fetch_canister_logs` call from the response it produces: the number of
/// records returned and the total size of their content.
///
/// The cost is a function of the response (rather than the log memory buffer
/// size) because the log memory store's index lets a fetch read only about the
/// records it returns. The measured execution time is dominated by the number
/// of records (per-record decode/encode overhead), with a smaller term for
/// copying the record content, so both are charged separately.
///
/// This is a conservative linear upper bound on the measured
/// `fetch_canister_logs` execution time (see the `fetch_canister_log` benchmark
/// in `rs/execution_environment/benches/management_canister/canister_logging.rs`),
/// chosen so the charge never falls below the measured cost of any case:
///
/// ```text
/// time ≲ 7 ms + 0.45 µs × record_count + 2.5 ns × content_size
/// ```
///
/// The fixed term covers a full-buffer fetch that returns nothing (~6.4 ms),
/// the per-record term covers the worst case of 0-byte log messages (a full
/// 2 MiB buffer returns ~50k records in ~27 ms), and the per-content-byte term
/// covers the content copy (a full 2 MiB buffer of ~100-byte messages). At 2
/// billion instructions per second (2_000_000 instructions per millisecond):
///
/// ```text
/// instructions ≈ 14_000_000 + 900 × record_count + 5 × content_size
/// ```
pub(crate) fn fetch_canister_logs_instructions(
    record_count: u64,
    content_size: NumBytes,
) -> NumInstructions {
    // Fixed cost of ~7 ms, at 2_000_000 instructions/ms (2 billion per second),
    // covering a full-buffer fetch whose filter matches nothing (~6.4 ms).
    const BASE_INSTRUCTIONS: u64 = 14_000_000;
    // ~0.45 µs/record: the per-record decode/encode overhead dominates the cost.
    const INSTRUCTIONS_PER_RECORD: u64 = 900;
    // ~2.5 ns/byte: the cost of copying and encoding the record content.
    const INSTRUCTIONS_PER_CONTENT_BYTE: u64 = 5;
    NumInstructions::new(
        BASE_INSTRUCTIONS
            .saturating_add(INSTRUCTIONS_PER_RECORD.saturating_mul(record_count))
            .saturating_add(INSTRUCTIONS_PER_CONTENT_BYTE.saturating_mul(content_size.get())),
    )
}

/// Reads the requested canister log records and returns the Candid-encoded
/// `FetchCanisterLogsResponse` together with the number of records returned and
/// the total size of their content. The record count and content size are used
/// to charge for the call (see `fetch_canister_logs_instructions`).
pub(crate) fn fetch_canister_logs_response(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
    log_memory_store_feature: FlagStatus,
) -> Result<(Vec<u8>, u64, NumBytes), CanisterManagerError> {
    check_log_visibility_permission(&sender, canister.log_visibility(), canister.controllers())?;
    let s = &canister.system_state;
    let canister_log_records = match log_memory_store_feature {
        FlagStatus::Enabled if s.log_memory_store.is_migrated() => {
            s.log_memory_store.records(args.filter)
        }
        _ => filter_records(&args, s.canister_log.records()),
    };
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
        // Empty response → only the ~7 ms fixed cost (14_000_000 instructions).
        assert_eq!(
            fetch_canister_logs_instructions(0, NumBytes::new(0)),
            NumInstructions::new(14_000_000)
        );
        // 14_000_000 + 900 × record_count + 5 × content_size instructions.
        assert_eq!(
            fetch_canister_logs_instructions(50_000, NumBytes::new(0)),
            NumInstructions::new(14_000_000 + 900 * 50_000)
        );
        assert_eq!(
            fetch_canister_logs_instructions(10, NumBytes::new(4_096)),
            NumInstructions::new(14_000_000 + 900 * 10 + 5 * 4_096)
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
