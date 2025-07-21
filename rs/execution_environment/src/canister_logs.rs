use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2, Payload, QueryMethod,
};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    ingress::WasmResult,
    messages::{Blob, Certificate, CertificateDelegation, Query},
    CanisterId, NumInstructions, PrincipalId,
};

pub(crate) fn fetch_canister_logs(
    sender: PrincipalId,
    state: &ReplicatedState,
    args: FetchCanisterLogsRequest,
) -> Result<WasmResult, UserError> {
    let canister_id = args.get_canister_id();
    let canister = state.canister_state(&canister_id).ok_or_else(|| {
        UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {canister_id} not found"),
        )
    })?;

    match canister.log_visibility() {
        LogVisibilityV2::Public => Ok(()),
        LogVisibilityV2::Controllers if canister.controllers().contains(&sender) => Ok(()),
        LogVisibilityV2::AllowedViewers(principals) if principals.get().contains(&sender) => Ok(()),
        LogVisibilityV2::AllowedViewers(_) if canister.controllers().contains(&sender) => Ok(()),
        LogVisibilityV2::AllowedViewers(_) | LogVisibilityV2::Controllers => Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!(
                "Caller {} is not allowed to query ic00 method {}",
                sender,
                QueryMethod::FetchCanisterLogs
            ),
        )),
    }?;

    let response = FetchCanisterLogsResponse {
        canister_log_records: canister
            .system_state
            .canister_log
            .records()
            .iter()
            .cloned()
            .collect(),
    };
    Ok(WasmResult::Reply(Encode!(&response).unwrap()))
}
