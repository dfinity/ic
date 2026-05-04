use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::{
    CanisterMetadataRequest, CanisterMetadataResponse, IC_00,
};
use ic_nervous_system_runtime::Runtime;

/// A wrapper call to the management canister `canister_metadata` API.
pub async fn canister_metadata<Rt>(
    canister_id: PrincipalId,
    name: String,
) -> Result<Vec<u8>, (i32, String)>
where
    Rt: Runtime,
{
    let canister_id = match CanisterId::try_from(canister_id) {
        Ok(canister_id) => canister_id,
        Err(err) => return Err((1, format!("Invalid canister ID: {}", err))),
    };

    let request = CanisterMetadataRequest::new(canister_id, name);
    let response: Result<(CanisterMetadataResponse,), (i32, String)> =
        Rt::call_with_cleanup(IC_00, "canister_metadata", (request,)).await;

    response.map(|response| response.0.value().to_vec())
}
