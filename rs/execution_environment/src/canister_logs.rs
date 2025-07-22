use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2, QueryMethod,
};
use ic_replicated_state::ReplicatedState;
use ic_types::PrincipalId;

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    state: &ReplicatedState,
    args: FetchCanisterLogsRequest,
) -> Result<FetchCanisterLogsResponse, UserError> {
    // println!("ABC fetch_canister_logs called with sender: {:?}", sender);
    // println!("ABC fetch_canister_logs called with args: {:?}", args);
    let canister_id = args.get_canister_id();
    let canister = state.canister_state(&canister_id).ok_or_else(|| {
        UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {canister_id} not found BLA1"),
        )
    })?;

    // Check if the sender has permission to access logs
    check_log_access_permission(&sender, canister.log_visibility(), canister.controllers())?;

    Ok(FetchCanisterLogsResponse {
        canister_log_records: canister
            .system_state
            .canister_log
            .records()
            .iter()
            .cloned()
            .collect(),
    })
}

/// Checks if the sender has permission to access canister logs based on visibility settings
fn check_log_access_permission(
    sender: &PrincipalId,
    log_visibility: &LogVisibilityV2,
    controllers: &std::collections::BTreeSet<PrincipalId>,
) -> Result<(), UserError> {
    let has_access = match log_visibility {
        LogVisibilityV2::Public => true,
        LogVisibilityV2::Controllers => controllers.contains(sender),
        LogVisibilityV2::AllowedViewers(principals) => {
            principals.get().contains(sender) || controllers.contains(sender)
        }
    };

    if has_access {
        Ok(())
    } else {
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!(
                "Caller {} is not allowed to query ic00 method {}",
                sender,
                QueryMethod::FetchCanisterLogs
            ),
        ))
    }
}
