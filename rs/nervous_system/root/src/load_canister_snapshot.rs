use crate::private::{OfflineMaintenanceError, perform_offline_canister_maintenance};
use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId, SnapshotId};
use ic_management_canister_types_private::LoadCanisterSnapshotArgs;
use ic_nervous_system_clients::management_canister_client::ManagementCanisterClient;
use serde::Deserialize;

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotRequest {
    pub canister_id: PrincipalId,
    pub snapshot_id: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum LoadCanisterSnapshotResponse {
    Ok(LoadCanisterSnapshotOk),
    Err(LoadCanisterSnapshotError),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotOk {}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct LoadCanisterSnapshotError {
    pub code: Option<i32>,
    pub description: String,
}

/// Restores a canister to a previously taken snapshot, an earlier state,
/// which includes its memory (normal and stable) and code.
///
/// When the target canister is Governance, the operation is performed in the
/// background and this function returns immediately with a placeholder `Ok`
/// response. This avoids a deadlock: Root would need to stop Governance, but
/// Governance cannot stop while it is waiting for Root to reply.
pub async fn load_canister_snapshot(
    load_canister_snapshot_request: LoadCanisterSnapshotRequest,
    management_canister_client: impl ManagementCanisterClient + 'static,
) -> LoadCanisterSnapshotResponse {
    // Convert input.
    let operation_description = format!("{:?}", load_canister_snapshot_request);
    let args = match LoadCanisterSnapshotArgs::try_from(load_canister_snapshot_request) {
        Ok(args) => args,
        Err(err) => return LoadCanisterSnapshotResponse::Err(err),
    };
    let canister_id = args.get_canister_id();

    let do_the_real_work = move || async move {
        management_canister_client
            .load_canister_snapshot(args)
            .await
    };
    let result: Result<Result<(), (i32, String)>, OfflineMaintenanceError> =
        perform_offline_canister_maintenance(
            canister_id,
            &operation_description,
            true, // stop_before
            do_the_real_work,
        )
        .await;

    LoadCanisterSnapshotResponse::from(result)
}

impl TryFrom<LoadCanisterSnapshotRequest> for LoadCanisterSnapshotArgs {
    type Error = LoadCanisterSnapshotError;

    fn try_from(request: LoadCanisterSnapshotRequest) -> Result<Self, LoadCanisterSnapshotError> {
        let LoadCanisterSnapshotRequest {
            canister_id,
            snapshot_id,
        } = request;

        let canister_id =
            CanisterId::try_from(canister_id).map_err(|err| LoadCanisterSnapshotError {
                code: None,
                description: format!("Invalid canister ID: {err}"),
            })?;

        let snapshot_id =
            SnapshotId::try_from(snapshot_id).map_err(|err| LoadCanisterSnapshotError {
                code: None,
                description: format!("Invalid snapshot ID: {err}"),
            })?;

        Ok(LoadCanisterSnapshotArgs::new(
            canister_id,
            snapshot_id,
            None,
        ))
    }
}

// Convert output from Management canister to ours.

impl From<Result<Result<(), (i32, String)>, OfflineMaintenanceError>>
    for LoadCanisterSnapshotResponse
{
    fn from(result: Result<Result<(), (i32, String)>, OfflineMaintenanceError>) -> Self {
        match result {
            Ok(Ok(())) => LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {}),
            Ok(Err((code, description))) => {
                LoadCanisterSnapshotResponse::Err(LoadCanisterSnapshotError {
                    code: Some(code),
                    description,
                })
            }
            Err(err) => LoadCanisterSnapshotResponse::Err(LoadCanisterSnapshotError {
                code: None,
                description: format!("{err}"),
            }),
        }
    }
}
