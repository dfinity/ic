use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2,
};
use ic_replicated_state::ReplicatedState;
use ic_types::PrincipalId;

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    state: &ReplicatedState,
    args: FetchCanisterLogsRequest,
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

    let canister_log_records = match args.filter_by_idx {
        None => records.iter().cloned().collect(),
        Some(IndexRange { start, end }) => {
            if start > end {
                // Invalid range — return empty result.
                Vec::new()
            } else {
                // TODO: optimize filtering.
                records
                    .iter()
                    .filter(|r| start <= r.idx && r.idx <= end)
                    .cloned()
                    .collect()
            }
        }
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
