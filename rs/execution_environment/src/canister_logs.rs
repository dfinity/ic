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
    let max_fee = cycles_account_manager.max_fetch_canister_logs_fee(subnet_cycles_config);
    let payment = msg.cycles();
    if payment < max_fee {
        return Err(CanisterManagerError::FetchCanisterLogsNotEnoughCycles {
            sent: payment,
            required: max_fee,
        });
    }
    let canister_id = canister.canister_id();
    let reply = fetch_canister_logs_response(sender, canister, args, log_memory_store_feature)?;
    msg.deduct_cycles(
        cycles_account_manager
            .fetch_canister_logs_fee(NumBytes::new(reply.len() as u64), subnet_cycles_config),
    );
    // The caller is authorized (the visibility check inside
    // `fetch_canister_logs_response` passed), so charge for the work of reading
    // and encoding the logs. The cost is approximated from the canister's log
    // memory limit (see `fetch_canister_logs_instructions`).
    round_limits.instructions -= as_round_instructions(fetch_canister_logs_instructions(
        canister.log_memory_limit(),
    ));
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
/// `fetch_canister_logs` call from the canister's log memory limit.
///
/// This is a linear approximation of the measured `fetch_canister_logs`
/// execution time as a function of the log memory limit (see the
/// `fetch_canister_log` benchmark in
/// `rs/execution_environment/benches/management_canister/canister_logging.rs`).
/// The worst case is 0-byte log messages, which maximize the number of records
/// read and encoded for a given limit:
///
/// ```text
/// time ≈ 1.15 ms + 13.3 ms/MiB × log_memory_limit
/// ```
///
/// Converting at 2 billion instructions per second (2_000_000 instructions per
/// millisecond) yields:
///
/// ```text
/// instructions ≈ 2_300_000 + 25.4 × log_memory_limit_bytes
/// ```
///
/// The per-byte factor is rounded up to stay conservative (never undercharge).
pub(crate) fn fetch_canister_logs_instructions(log_memory_limit: NumBytes) -> NumInstructions {
    // Fixed cost of ~1.15 ms of call overhead, at 2_000_000 instructions/ms
    // (2 billion instructions per second): 1.15 × 2_000_000.
    const BASE_INSTRUCTIONS: u64 = 2_300_000;
    // ~13.3 ms/MiB at 2_000_000 instructions/ms ≈ 25.4 instructions/byte,
    // rounded up to 26 to stay conservative.
    const INSTRUCTIONS_PER_BYTE: u64 = 26;
    NumInstructions::new(
        BASE_INSTRUCTIONS
            .saturating_add(INSTRUCTIONS_PER_BYTE.saturating_mul(log_memory_limit.get())),
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
        // Empty limit → only the ~1.15 ms fixed cost (2_300_000 instructions).
        assert_eq!(
            fetch_canister_logs_instructions(NumBytes::new(0)),
            NumInstructions::new(2_300_000)
        );
        // A full 2 MiB buffer: 2_300_000 + 26 × 2_097_152 ≈ 56.8M instructions
        // (~28.4 ms at 2e6 instructions/ms), matching the measured worst-case
        // ~27.8 ms for a 2 MiB / 0-byte-message buffer.
        let two_mib = 2 * 1024 * 1024;
        assert_eq!(
            fetch_canister_logs_instructions(NumBytes::new(two_mib)),
            NumInstructions::new(2_300_000 + 26 * two_mib)
        );
        // Monotonically non-decreasing in the limit.
        assert!(
            fetch_canister_logs_instructions(NumBytes::new(1024 * 1024))
                < fetch_canister_logs_instructions(NumBytes::new(two_mib))
        );
    }
}
