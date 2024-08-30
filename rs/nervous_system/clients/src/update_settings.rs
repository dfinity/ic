use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_management_canister_types::IC_00;
use ic_nervous_system_runtime::Runtime;
use serde::Deserialize;

/// The UpdateSettings struct as defined in the ic-interface-spec
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candids
#[derive(Clone, PartialEq, Eq, Debug, CandidType, Deserialize)]
pub struct UpdateSettings {
    pub canister_id: PrincipalId,
    pub settings: CanisterSettings,
    pub sender_canister_version: Option<u64>,
}

#[derive(Default, Clone, Copy, CandidType, Deserialize, Debug, PartialEq, Eq, Hash)]
pub enum LogVisibility {
    #[default]
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
}

/// The CanisterSettings struct as defined in the ic-interface-spec
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candid
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub struct CanisterSettings {
    pub controllers: Option<Vec<PrincipalId>>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
    pub reserved_cycles_limit: Option<candid::Nat>,
    pub log_visibility: Option<LogVisibility>,
    pub wasm_memory_limit: Option<candid::Nat>,
}

/// A wrapper call to the management canister `update_settings` API.
pub async fn update_settings<Rt>(update_settings: UpdateSettings) -> Result<(), (i32, String)>
where
    Rt: Runtime,
{
    Rt::call_with_cleanup(IC_00, "update_settings", (update_settings,)).await
}
