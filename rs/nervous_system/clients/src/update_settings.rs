use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_management_canister_types_private as management_canister;
use ic_management_canister_types_private::IC_00;
use ic_nervous_system_runtime::Runtime;
use serde::Deserialize;

/// The UpdateSettings struct as defined in the ic-interface-spec
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candids
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct UpdateSettings {
    pub canister_id: PrincipalId,
    pub settings: CanisterSettings,
    pub sender_canister_version: Option<u64>,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default, CandidType, Deserialize)]
pub enum LogVisibility {
    #[default]
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
}

/// The CanisterSettings struct as defined in the ic-interface-spec
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candid
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, CandidType, Deserialize)]
pub struct CanisterSettings {
    pub controllers: Option<Vec<PrincipalId>>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibility>,
    pub wasm_memory_limit: Option<candid::Nat>,
    pub wasm_memory_threshold: Option<candid::Nat>,
}

impl From<LogVisibility> for management_canister::LogVisibilityV2 {
    fn from(original: LogVisibility) -> Self {
        match original {
            LogVisibility::Controllers => management_canister::LogVisibilityV2::Controllers,
            LogVisibility::Public => management_canister::LogVisibilityV2::Public,
        }
    }
}

impl From<CanisterSettings> for management_canister::CanisterSettingsArgs {
    fn from(original: CanisterSettings) -> Self {
        let CanisterSettings {
            controllers,
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            reserved_cycles_limit,
            log_visibility,
            wasm_memory_limit,
            wasm_memory_threshold,
        } = original;

        management_canister::CanisterSettingsArgs {
            controllers: controllers.map(management_canister::BoundedControllers::new),
            compute_allocation,
            memory_allocation,
            freezing_threshold,
            reserved_cycles_limit,
            log_visibility: log_visibility.map(management_canister::LogVisibilityV2::from),
            snapshot_visibility: None,
            log_memory_limit: None,
            wasm_memory_limit,
            wasm_memory_threshold,
            environment_variables: None,
        }
    }
}

/// A wrapper call to the management canister `update_settings` API.
pub async fn update_settings<Rt>(update_settings: UpdateSettings) -> Result<(), (i32, String)>
where
    Rt: Runtime,
{
    Rt::call_with_cleanup(IC_00, "update_settings", (update_settings,)).await
}
