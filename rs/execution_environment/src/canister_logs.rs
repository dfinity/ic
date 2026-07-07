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
    // The response size (and hence the fee) is only known after reading the
    // logs, so reject up front any call that could not afford the worst-case
    // (maximum) response size. This ensures we never do the read work for free.
    let max_fee = cycles_account_manager
        .management_canister_cost(
            fetch_canister_logs_instructions(NumBytes::new(
                MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES as u64,
            )),
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
    let reply = fetch_canister_logs_response(sender, canister, args, log_memory_store_feature)?;
    // The caller is authorized (the visibility check inside
    // `fetch_canister_logs_response` passed). Charge for the work of reading and
    // encoding the logs, approximated from the actual response size (see
    // `fetch_canister_logs_instructions`): deduct the cycles fee from the call's
    // payment and the corresponding instructions from the round's budget.
    let instructions = fetch_canister_logs_instructions(NumBytes::new(reply.len() as u64));
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
/// `fetch_canister_logs` call from the size of the response it produces.
///
/// The cost is a function of the response size (rather than the log memory
/// buffer size) because the log memory store's index lets a fetch read only
/// about the records it returns, so the computational overhead is dependent on
/// the response size.
///
/// This is a linear approximation of the measured `fetch_canister_logs`
/// execution time (see the `fetch_canister_log` benchmark in
/// `rs/execution_environment/benches/management_canister/canister_logging.rs`),
/// with the factors derived from those benchmarks:
///
/// ```text
/// time ≈ 1.15 ms + 13.3 ms/MiB × response_size
/// ```
///
/// Converting at 2 billion instructions per second (2_000_000 instructions per
/// millisecond) yields:
///
/// ```text
/// instructions ≈ 2_300_000 + 25.4 × response_size_bytes
/// ```
///
/// The per-byte factor is rounded up to stay conservative (never undercharge).
pub(crate) fn fetch_canister_logs_instructions(response_size: NumBytes) -> NumInstructions {
    // Fixed cost of ~1.15 ms of call overhead, at 2_000_000 instructions/ms
    // (2 billion instructions per second): 1.15 × 2_000_000.
    const BASE_INSTRUCTIONS: u64 = 2_300_000;
    // ~13.3 ms/MiB at 2_000_000 instructions/ms ≈ 25.4 instructions/byte,
    // rounded up to 26 to stay conservative.
    const INSTRUCTIONS_PER_BYTE: u64 = 26;
    NumInstructions::new(
        BASE_INSTRUCTIONS.saturating_add(INSTRUCTIONS_PER_BYTE.saturating_mul(response_size.get())),
    )
}

pub(crate) fn fetch_canister_logs_response(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
    log_memory_store_feature: FlagStatus,
) -> Result<Vec<u8>, CanisterManagerError> {
    check_log_visibility_permission(&sender, canister.log_visibility(), canister.controllers())?;
    let s = &canister.system_state;
    let canister_log_records = match log_memory_store_feature {
        FlagStatus::Enabled if s.log_memory_store.is_migrated() => {
            s.log_memory_store.records(args.filter)
        }
        _ => filter_records(&args, s.canister_log.records()),
    };
    Ok(Encode!(&FetchCanisterLogsResponse {
        canister_log_records
    })
    .unwrap())
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
        // Empty response → only the ~1.15 ms fixed cost (2_300_000 instructions).
        assert_eq!(
            fetch_canister_logs_instructions(NumBytes::new(0)),
            NumInstructions::new(2_300_000)
        );
        // Maximum response size: 2_300_000 + 26 × response_size instructions.
        let max_response = MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES as u64;
        assert_eq!(
            fetch_canister_logs_instructions(NumBytes::new(max_response)),
            NumInstructions::new(2_300_000 + 26 * max_response)
        );
        // Monotonically non-decreasing in the response size.
        assert!(
            fetch_canister_logs_instructions(NumBytes::new(max_response / 2))
                < fetch_canister_logs_instructions(NumBytes::new(max_response))
        );
    }
}
