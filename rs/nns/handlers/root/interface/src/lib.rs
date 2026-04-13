use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_clients::update_settings::CanisterSettings;
use serde::Deserialize;

#[doc(inline)]
pub use ic_nervous_system_root::take_canister_snapshot::{
    TakeCanisterSnapshotError, TakeCanisterSnapshotOk, TakeCanisterSnapshotRequest,
    TakeCanisterSnapshotResponse,
};

#[doc(inline)]
pub use ic_nervous_system_root::load_canister_snapshot::{
    LoadCanisterSnapshotError, LoadCanisterSnapshotOk, LoadCanisterSnapshotRequest,
    LoadCanisterSnapshotResponse,
};

pub mod client;

/// The request structure to the `change_canister_controllers` API.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
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

/// The possible results from calling the `change_canister_controllers` API.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum ChangeCanisterControllersResult {
    /// The successful result.
    Ok(()),

    /// The error result.
    Err(ChangeCanisterControllersError),
}

/// The structure encapsulating errors encountered in the `change_canister_controllers` API.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct ChangeCanisterControllersError {
    /// The optional error code encountered during execution. This maps to the IC replica error
    /// codes.
    pub code: Option<i32>,

    /// A description of the encountered error.
    pub description: String,
}

/// The response structure to the `change_canister_controllers` API.
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct ChangeCanisterControllersResponse {
    /// The result of the request to the API.
    pub change_canister_controllers_result: ChangeCanisterControllersResult,
}

impl ChangeCanisterControllersResponse {
    pub fn error(code: Option<i32>, description: String) -> Self {
        Self {
            change_canister_controllers_result: ChangeCanisterControllersResult::Err(
                ChangeCanisterControllersError { code, description },
            ),
        }
    }

    pub fn ok() -> Self {
        Self {
            change_canister_controllers_result: ChangeCanisterControllersResult::Ok(()),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct UpdateCanisterSettingsRequest {
    // The canister ID of the target canister.
    pub canister_id: PrincipalId,
    // The settings to be updated.
    pub settings: CanisterSettings,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum UpdateCanisterSettingsResponse {
    Ok(()),
    Err(UpdateCanisterSettingsError),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct UpdateCanisterSettingsError {
    pub code: Option<i32>,
    pub description: String,
}

/// Request to create a new canister on a specified subnet and install code into
/// it. The canister is created by NNS Root, which becomes a controller.
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct CreateCanisterAndInstallCodeRequest {
    /// The subnet where the canister will be created.
    pub host_subnet_id: PrincipalId,

    /// Settings for the new canister. If controllers is not specified, Root
    /// will be the sole controller.
    pub canister_settings: Option<CanisterSettings>,

    /// The WASM module to install.
    pub wasm_module: Vec<u8>,

    /// The argument to pass to the canister's install handler.
    pub install_arg: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum CreateCanisterAndInstallCodeResponse {
    Ok(CreateCanisterAndInstallCodeOk),
    Err(CreateCanisterAndInstallCodeError),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct CreateCanisterAndInstallCodeOk {
    /// The ID of the newly created canister.
    pub canister_id: PrincipalId,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct CreateCanisterAndInstallCodeError {
    pub code: Option<i32>,
    pub description: String,
}

impl From<Result<CanisterId, CreateCanisterAndInstallCodeError>>
    for CreateCanisterAndInstallCodeResponse
{
    fn from(result: Result<CanisterId, CreateCanisterAndInstallCodeError>) -> Self {
        match result {
            Ok(canister_id) => {
                CreateCanisterAndInstallCodeResponse::Ok(CreateCanisterAndInstallCodeOk {
                    canister_id: canister_id.get(),
                })
            }
            Err(err) => CreateCanisterAndInstallCodeResponse::Err(err),
        }
    }
}
