use candid::CandidType;
use ic_base_types::PrincipalId;
use serde::Deserialize;

pub mod client;

/// The request structure to the `change_canister_controllers` API.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub struct ChangeCanisterControllersRequest {
    /// The principal of the target canister that will have its controllers changed. This
    /// canister must be controlled by the canister executing a ChangeCanisterControllersRequest
    /// else a ChangeCanisterControllersError response will be returned.
    pub target_canister_id: PrincipalId,

    /// The list of controllers that the `target_canister_id` will be changed to have. This will
    /// overwrite all controllers of the canister, so if the current controlling canister wishes
    /// to remain in control, it should be included in `new_controllers`.
    pub new_controllers: Vec<PrincipalId>,
}

/// The response structure to the `change_canister_controllers` API.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub struct ChangeCanisterControllersResponse {
    /// The result of the request to the API.
    pub change_canister_controllers_result: ChangeCanisterControllersResult,
}

/// The possible results from calling the `change_canister_controllers` API.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub enum ChangeCanisterControllersResult {
    /// The successful result.
    Ok(()),

    /// The error result.
    Err(ChangeCanisterControllersError),
}

/// The structure encapsulating errors encountered in the `change_canister_controllers` API.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub struct ChangeCanisterControllersError {
    /// The optional error code encountered during execution. This maps to the IC replica error
    /// codes.
    pub code: Option<i32>,

    /// A description of the encountered error.
    pub description: String,
}
