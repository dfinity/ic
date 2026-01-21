use crate::private::exclusively_stop_and_start_canister;
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

pub async fn load_canister_snapshot(
    load_canister_snapshot_request: LoadCanisterSnapshotRequest,
    management_canister_client: &mut impl ManagementCanisterClient,
) -> LoadCanisterSnapshotResponse {
    let operation_description = format!("{:?}", load_canister_snapshot_request);

    let LoadCanisterSnapshotRequest {
        canister_id,
        snapshot_id,
    } = load_canister_snapshot_request;

    let snapshot_id = match SnapshotId::try_from(snapshot_id) {
        Ok(ok) => ok,
        Err(err) => {
            return LoadCanisterSnapshotResponse::Err(LoadCanisterSnapshotError {
                code: None,
                description: format!("Invalid snapshot ID: {err}"),
            });
        }
    };

    let canister_id = match CanisterId::try_from(canister_id) {
        Ok(ok) => ok,
        Err(err) => {
            return LoadCanisterSnapshotResponse::Err(LoadCanisterSnapshotError {
                code: None,
                description: format!("Invalid canister ID: {err}"),
            });
        }
    };

    let result = exclusively_stop_and_start_canister::<_, _, _>(
        canister_id,
        &operation_description,
        true, // stop_before
        || async {
            let load_canister_snapshot_args = LoadCanisterSnapshotArgs::new(
                canister_id,
                snapshot_id,
                management_canister_client.canister_version(),
            );

            management_canister_client
                .load_canister_snapshot(load_canister_snapshot_args)
                .await
        },
    )
    .await;

    let result = match result {
        Ok(ok) => ok,
        Err(err) => {
            let description = format!("{err}");
            return LoadCanisterSnapshotResponse::Err(LoadCanisterSnapshotError {
                code: None,
                description,
            });
        }
    };

    match result {
        Ok(()) => LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {}),
        Err((code, description)) => LoadCanisterSnapshotResponse::Err(LoadCanisterSnapshotError {
            code: Some(code),
            description,
        }),
    }
}
