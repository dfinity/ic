use crate::{LOG_PREFIX, private::exclusively_stop_and_start_canister};
use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId, SnapshotId};
use ic_cdk::{futures::spawn_017_compat, println};
use ic_management_canister_types_private::{CanisterSnapshotResponse, TakeCanisterSnapshotArgs};
use ic_nervous_system_clients::management_canister_client::ManagementCanisterClient;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
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
    let operation_description = format!("{:?}", take_canister_snapshot_request);
    // Retain our own copy, because the async block will take the original.
    let operation_description_for_log = operation_description.clone();

    // Used later, but calculated now, because the main async block is going
    // to take take_canister_snapshot_request.
    let targets_governance =
        take_canister_snapshot_request.canister_id == PrincipalId::from(GOVERNANCE_CANISTER_ID);

    let operation = async move {
        // Construct the request that we will be sending to the Management canister
        // in the next (large) statement.
        let take_canister_snapshot_args =
            TakeCanisterSnapshotArgs::try_from(take_canister_snapshot_request)?;

        // Call the Management canister (but make sure we are not already
        // operating on the canister, and also, stop before and start
        // again after).
        let result = exclusively_stop_and_start_canister(
            take_canister_snapshot_args.get_canister_id(),
            &operation_description,
            true, // stop_before
            || async {
                management_canister_client
                    .take_canister_snapshot(take_canister_snapshot_args)
                    .await
            },
        )
        .await;

        // Handle errors.
        let snapshot: CanisterSnapshotResponse = result
            // Handle errors from exclusively_stop_and_start_canister.
            .map_err(|err| TakeCanisterSnapshotError {
                code: None,
                description: format!("{err}"),
            })?
            // Handle errors from calling management_canister_client.
            .map_err(|(code, description)| TakeCanisterSnapshotError {
                code: Some(code),
                description,
            })?;

        Ok(TakeCanisterSnapshotOk::from(snapshot))
    };

    // Log result.
    let operation = async move {
        let result = TakeCanisterSnapshotResponse::from(operation.await);
        println!("{LOG_PREFIX}{operation_description_for_log}: {result:?}");
        result
    };

    // In the case of Governance, do the operation in the background.
    // This is necessary to avoid deadlock:
    //
    // 1. the Governance canister calls the Root canister's take_canister_snapshot
    //    method, but
    // 2. the first thing take_canister_snapshot does (via
    //    exclusively_stop_and_start_canister) is to stop the target canister,
    //    which in this case, is Governance, but
    // 3. Governance is waiting for the call in step 1 to return.
    //
    // So, what we have is Governance waiting for Root to reply in order to stop, but Root
    // is waiting for Governance to stop before it can reply. Circular waiting, i.e. deadlock.
    if targets_governance {
        spawn_017_compat(async move {
            // It is ok to throw this away, because it is already logged above.
            let _: TakeCanisterSnapshotResponse = operation.await;

            // Because spawn_017_compat does not know what to do with
            // a TakeCanisterSnapshotResponse.
            ()
        });

        // Even though we do not yet know that the operation will succeed,
        // we return Ok here, because we also do not know that it will fail.
        // The important thing is that we launched the operation. That's
        // the definition of success in the special case of Governance.
        return TakeCanisterSnapshotResponse::Ok(TakeCanisterSnapshotOk {
            id: vec![],
            taken_at_timestamp: 0,
            total_size: 0,
        });
    }

    operation.await
}

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

impl From<TakeCanisterSnapshotError> for TakeCanisterSnapshotResponse {
    fn from(err: TakeCanisterSnapshotError) -> Self {
        TakeCanisterSnapshotResponse::Err(err)
    }
}

impl From<Result<TakeCanisterSnapshotOk, TakeCanisterSnapshotError>>
    for TakeCanisterSnapshotResponse
{
    fn from(result: Result<TakeCanisterSnapshotOk, TakeCanisterSnapshotError>) -> Self {
        match result {
            Ok(ok) => TakeCanisterSnapshotResponse::Ok(ok),
            Err(err) => TakeCanisterSnapshotResponse::Err(err),
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
