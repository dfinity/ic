use crate::{LOG_PREFIX, private::exclusively_stop_and_start_canister};
use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId, SnapshotId};
use ic_cdk::{futures::spawn_017_compat, println};
use ic_management_canister_types_private::LoadCanisterSnapshotArgs;
use ic_nervous_system_clients::management_canister_client::ManagementCanisterClient;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
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
    let operation_description = format!("{:?}", load_canister_snapshot_request);
    // Retain our own copy, because the async block will take the original.
    let operation_description_for_log = operation_description.clone();

    // Used later, but calculated now, because the main async block is going
    // to take load_canister_snapshot_request.
    let targets_governance =
        load_canister_snapshot_request.canister_id == PrincipalId::from(GOVERNANCE_CANISTER_ID);

    let operation = async move {
        // Construct the request that we will be sending to the Management canister
        // in the next (large) statement.
        let load_canister_snapshot_args =
            LoadCanisterSnapshotArgs::try_from(load_canister_snapshot_request)?;

        // Call the Management canister (but make sure we are not already
        // operating on the canister, and also, stop before and start
        // again after).
        let result = exclusively_stop_and_start_canister::<_, _, _>(
            load_canister_snapshot_args.get_canister_id(),
            &operation_description,
            true, // stop_before
            || async {
                management_canister_client
                    .load_canister_snapshot(load_canister_snapshot_args)
                    .await
            },
        )
        .await;

        // Handle errors.
        // This line explicitly shows that no data is thrown away.
        let _: () = result
            // Handle errors from exclusively_stop_and_start_canister.
            .map_err(|err| LoadCanisterSnapshotError {
                code: None,
                description: format!("{err}"),
            })?
            // Handle errors from calling management_canister_client.
            .map_err(|(code, description)| LoadCanisterSnapshotError {
                code: Some(code),
                description,
            })?;

        Ok(LoadCanisterSnapshotOk {})
    };

    // Log result.
    let operation = async move {
        let result = LoadCanisterSnapshotResponse::from(operation.await);
        println!("{LOG_PREFIX}{operation_description_for_log}: {result:?}");
        result
    };

    // In the case of Governance, do the operation in the background.
    // This is necessary to avoid deadlock:
    //
    // 1. the Governance canister calls the Root canister's load_canister_snapshot
    //    method, but
    // 2. the first thing load_canister_snapshot does (via
    //    exclusively_stop_and_start_canister) is to stop the target canister,
    //    which in this case, is Governance, but
    // 3. Governance is waiting for the call in step 1 to return.
    //
    // So, what we have is Governance waiting for Root to reply in order to stop, but Root
    // is waiting for Governance to stop before it can reply. Circular waiting, i.e. deadlock.
    if targets_governance {
        spawn_017_compat(async move {
            // It is ok to throw this away, because it is already logged above.
            let _: LoadCanisterSnapshotResponse = operation.await;

            // Because spawn_017_compat does not know what to do with
            // a LoadCanisterSnapshotResponse.
            ()
        });

        // Even though we do not yet know that the operation will succeed,
        // we return Ok here, because we also do not know that it will fail.
        // The important thing is that we launched the operation. That's
        // the definition of success in the special case of Governance.
        return LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {});
    }

    operation.await
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

impl From<LoadCanisterSnapshotError> for LoadCanisterSnapshotResponse {
    fn from(err: LoadCanisterSnapshotError) -> Self {
        LoadCanisterSnapshotResponse::Err(err)
    }
}

impl From<Result<LoadCanisterSnapshotOk, LoadCanisterSnapshotError>>
    for LoadCanisterSnapshotResponse
{
    fn from(result: Result<LoadCanisterSnapshotOk, LoadCanisterSnapshotError>) -> Self {
        match result {
            Ok(ok) => LoadCanisterSnapshotResponse::Ok(ok),
            Err(err) => LoadCanisterSnapshotResponse::Err(err),
        }
    }
}
