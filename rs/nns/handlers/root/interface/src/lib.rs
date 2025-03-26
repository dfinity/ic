use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_nervous_system_clients::update_settings::CanisterSettings;
use serde::Deserialize;

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
