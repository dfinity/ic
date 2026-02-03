use crate::private::exclusively_stop_and_start_canister;
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

pub async fn take_canister_snapshot(
    take_canister_snapshot_request: TakeCanisterSnapshotRequest,
    management_canister_client: &mut impl ManagementCanisterClient,
) -> TakeCanisterSnapshotResponse {
    let operation_description = format!("{:?}", take_canister_snapshot_request);

    let TakeCanisterSnapshotRequest {
        canister_id,
        replace_snapshot,
    } = take_canister_snapshot_request;

    let replace_snapshot = match replace_snapshot {
        None => None,
        Some(snapshot_id) => {
            let snapshot_id = match SnapshotId::try_from(&snapshot_id) {
                Ok(ok) => ok,
                Err(err) => {
                    return TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
                        code: None,
                        description: format!("Invalid snapshot ID ({snapshot_id:02X?}): {err}"),
                    });
                }
            };

            Some(snapshot_id)
        }
    };

    let canister_id = match CanisterId::try_from(canister_id) {
        Ok(id) => id,
        Err(e) => {
            return TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
                code: None,
                description: format!("Invalid canister ID: {:?}", e),
            });
        }
    };

    let result = exclusively_stop_and_start_canister(
        canister_id,
        &operation_description,
        true, // stop_before
        || async {
            let canister_id = PrincipalId::from(canister_id);

            let take_canister_snapshot_args = TakeCanisterSnapshotArgs {
                canister_id,
                replace_snapshot,
                uninstall_code: None,
                sender_canister_version: management_canister_client.canister_version(),
            };

            management_canister_client
                .take_canister_snapshot(take_canister_snapshot_args)
                .await
        },
    )
    .await;

    let result = match result {
        Ok(ok) => ok,
        Err(err) => {
            return TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
                code: None,
                description: format!("{err}"),
            });
        }
    };

    match result {
        Ok(result) => {
            let result =
                convert_from_canister_snapshot_response_to_take_canister_snapshot_ok(result);
            TakeCanisterSnapshotResponse::Ok(result)
        }

        Err((code, description)) => TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
            code: Some(code),
            description,
        }),
    }
}

fn convert_from_canister_snapshot_response_to_take_canister_snapshot_ok(
    response: CanisterSnapshotResponse,
) -> TakeCanisterSnapshotOk {
    let CanisterSnapshotResponse {
        id,
        taken_at_timestamp,
        total_size,
    } = response;

    let id = id.to_vec();

    TakeCanisterSnapshotOk {
        id,
        taken_at_timestamp,
        total_size,
    }
}
