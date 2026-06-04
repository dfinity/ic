use crate::canister_manager::types::{CanisterManagerError, CanisterManagerResponse};
use crate::canister_settings::VisibilitySettings;
use candid::Encode;
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_management_canister_types_private::{
    CanisterLogRecord, FetchCanisterLogsFilter, FetchCanisterLogsRange, FetchCanisterLogsRequest,
    FetchCanisterLogsResponse, LogVisibilityV2,
};
use ic_replicated_state::CanisterState;
use ic_types::messages::CanisterCall;
use ic_types::{NumBytes, PrincipalId};
use ic_types_cycles::CanisterCyclesCostSchedule;
use std::collections::VecDeque;

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    canister: &CanisterState,
    args: FetchCanisterLogsRequest,
    log_memory_store_feature: FlagStatus,
    msg: &mut CanisterCall,
    cycles_account_manager: &CyclesAccountManager,
    subnet_size: usize,
    cost_schedule: CanisterCyclesCostSchedule,
) -> Result<CanisterManagerResponse, CanisterManagerError> {
    let max_fee = cycles_account_manager.max_fetch_canister_logs_fee(subnet_size, cost_schedule);
    let payment = msg.cycles();
    if payment < max_fee {
        return Err(CanisterManagerError::FetchCanisterLogsNotEnoughCycles {
            sent: payment,
            required: max_fee,
        });
    }
    let canister_id = canister.canister_id();
    let reply = fetch_canister_logs_response(sender, canister, args, log_memory_store_feature)?;
    msg.deduct_cycles(cycles_account_manager.fetch_canister_logs_fee(
        NumBytes::new(reply.len() as u64),
        subnet_size,
        cost_schedule,
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
