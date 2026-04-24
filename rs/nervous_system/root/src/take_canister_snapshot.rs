use crate::private::{OfflineMaintenanceError, Optimistic, perform_offline_canister_maintenance};
use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId, SnapshotId};
use ic_management_canister_types_private::{CanisterSnapshotResponse, TakeCanisterSnapshotArgs};
use ic_nervous_system_clients::management_canister_client::ManagementCanisterClient;
use serde::Deserialize;

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotRequest {
    pub canister_id: PrincipalId,
    pub replace_snapshot: Option</* snapshot ID */ Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum TakeCanisterSnapshotResponse {
    Ok(TakeCanisterSnapshotOk),
    Err(TakeCanisterSnapshotError),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotOk {
    pub id: Vec<u8>,
    pub taken_at_timestamp: u64,
    pub total_size: u64,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct TakeCanisterSnapshotError {
    pub code: Option<i32>,
    pub description: String,
}

/// A snapshot consists of a canister's memory (normal and stable) and code.
/// Taking a snapshot simply means that we capture that data atomically.
/// A snapshot can then later be used (usually for disaster recovery)
/// to restore the canister to the state it was in when the snapshot was taken.
///
/// When the target canister is Governance, the operation is performed in the
/// background and this function returns immediately with a placeholder `Ok`
/// response (fields zeroed). This avoids a deadlock: Root would need to stop
/// Governance, but Governance cannot stop while it is waiting for Root to reply.
pub async fn take_canister_snapshot(
    take_canister_snapshot_request: TakeCanisterSnapshotRequest,
    management_canister_client: impl ManagementCanisterClient + 'static,
) -> TakeCanisterSnapshotResponse {
    // Convert input.
    let operation_description = format!("{:?}", take_canister_snapshot_request);
    let args = match TakeCanisterSnapshotArgs::try_from(take_canister_snapshot_request) {
        Ok(args) => args,
        Err(err) => return TakeCanisterSnapshotResponse::Err(err),
    };
    let canister_id = args.get_canister_id();

    let do_the_real_work = move || async move {
        management_canister_client
            .take_canister_snapshot(args)
            .await
    };
    let result: Result<Result<CanisterSnapshotResponse, (i32, String)>, OfflineMaintenanceError> =
        perform_offline_canister_maintenance(
            canister_id,
            &operation_description,
            true, // stop_before
            do_the_real_work,
        )
        .await;

    // Convert output.
    TakeCanisterSnapshotResponse::from(result)
}

impl Optimistic for Result<CanisterSnapshotResponse, (i32, String)> {
    fn new_optimistic() -> Self {
        Ok(CanisterSnapshotResponse {
            id: SnapshotId::from((CanisterId::from_u64(0), 0_u64)),
            taken_at_timestamp: 0,
            total_size: 0,
        })
    }
}

// Convert input from ours to what Management canister wants.
impl TryFrom<TakeCanisterSnapshotRequest> for TakeCanisterSnapshotArgs {
    type Error = TakeCanisterSnapshotError;

    fn try_from(request: TakeCanisterSnapshotRequest) -> Result<Self, TakeCanisterSnapshotError> {
        let TakeCanisterSnapshotRequest {
            canister_id,
            replace_snapshot,
        } = request;

        let canister_id =
            CanisterId::try_from(canister_id).map_err(|err| TakeCanisterSnapshotError {
                code: None,
                description: format!("Invalid canister ID: {err}"),
            })?;

        let replace_snapshot = replace_snapshot
            .map(|snapshot_id| {
                SnapshotId::try_from(&snapshot_id).map_err(|err| TakeCanisterSnapshotError {
                    code: None,
                    description: format!("Invalid snapshot ID: {err}"),
                })
            })
            .transpose()?;

        Ok(TakeCanisterSnapshotArgs::new(
            canister_id,
            replace_snapshot,
            None, // uninstall_code
            None, // sender_canister_version
        ))
    }
}

// Convert output from Management canister to ours.

impl From<Result<Result<CanisterSnapshotResponse, (i32, String)>, OfflineMaintenanceError>>
    for TakeCanisterSnapshotResponse
{
    fn from(
        result: Result<Result<CanisterSnapshotResponse, (i32, String)>, OfflineMaintenanceError>,
    ) -> Self {
        match result {
            Ok(Ok(snapshot)) => {
                TakeCanisterSnapshotResponse::Ok(TakeCanisterSnapshotOk::from(snapshot))
            }
            Ok(Err((code, description))) => {
                TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
                    code: Some(code),
                    description,
                })
            }
            Err(err) => TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
                code: None,
                description: format!("{err}"),
            }),
        }
    }
}

impl From<CanisterSnapshotResponse> for TakeCanisterSnapshotOk {
    fn from(response: CanisterSnapshotResponse) -> Self {
        let CanisterSnapshotResponse {
            id,
            taken_at_timestamp,
            total_size,
        } = response;

        TakeCanisterSnapshotOk {
            id: id.to_vec(),
            taken_at_timestamp,
            total_size,
        }
    }
}
