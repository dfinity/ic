use std::collections::VecDeque;

use ic_config::flag_status::FlagStatus;
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    CanisterLogRecord, FetchCanisterLogsRequest, FetchCanisterLogsResponse, IndexRange,
    LogVisibilityV2, TimestampNanosRange,
};
use ic_replicated_state::ReplicatedState;
use ic_types::PrincipalId;

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    state: &ReplicatedState,
    args: FetchCanisterLogsRequest,
    fetch_canister_logs_filter: FlagStatus,
) -> Result<FetchCanisterLogsResponse, UserError> {
    let canister_id = args.get_canister_id();
    let canister = state.canister_state(&canister_id).ok_or_else(|| {
        UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {canister_id} not found"),
        )
    })?;

    // Check if the sender has permission to access logs
    check_log_visibility_permission(&sender, canister.log_visibility(), canister.controllers())?;

    let records = canister.system_state.canister_log.records();
    let canister_log_records = match fetch_canister_logs_filter {
        FlagStatus::Disabled => records.iter().cloned().collect(),
        FlagStatus::Enabled => filter_records(&args, records)?,
    };

    Ok(FetchCanisterLogsResponse {
        canister_log_records,
    })
}

/// Checks if the caller has permission to access the logs based on the canister's log visibility settings.
pub(crate) fn check_log_visibility_permission(
    caller: &PrincipalId,
    log_visibility: &LogVisibilityV2,
    controllers: &std::collections::BTreeSet<PrincipalId>,
) -> Result<(), UserError> {
    let has_access = match log_visibility {
        LogVisibilityV2::Public => true,
        LogVisibilityV2::Controllers => controllers.contains(caller),
        LogVisibilityV2::AllowedViewers(principals) => {
            principals.get().contains(caller) || controllers.contains(caller)
        }
    };

    if has_access {
        Ok(())
    } else {
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!("Caller {caller} is not allowed to access canister logs"),
        ))
    }
}

fn filter_records(
    args: &FetchCanisterLogsRequest,
    records: &VecDeque<CanisterLogRecord>,
) -> Result<Vec<CanisterLogRecord>, UserError> {
    match (&args.filter_by_idx, &args.filter_by_timestamp_nanos) {
        (Some(_), Some(_)) => Err(contract_violation("Only one of filters can be set")),
        (Some(IndexRange { start, end }), None) => {
            validate_range(start, end, "index")?;
            Ok(records
                .iter()
                .filter(|r| start <= &r.idx && &r.idx <= end)
                .cloned()
                .collect())
        }
        (None, Some(TimestampNanosRange { start, end })) => {
            validate_range(start, end, "timestamp")?;
            Ok(records
                .iter()
                .filter(|r| start <= &r.timestamp_nanos && &r.timestamp_nanos <= end)
                .cloned()
                .collect())
        }
        (None, None) => Ok(records.iter().cloned().collect()),
    }
}

fn validate_range<T: PartialOrd>(start: &T, end: &T, range_type: &str) -> Result<(), UserError> {
    if start > end {
        Err(contract_violation(&format!(
            "Invalid {range_type} range: start is greater than end"
        )))
    } else {
        Ok(())
    }
}

fn contract_violation(msg: &str) -> UserError {
    UserError::new(ErrorCode::CanisterContractViolation, msg.to_string())
}
