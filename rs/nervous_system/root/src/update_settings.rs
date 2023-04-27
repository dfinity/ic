use candid::CandidType;
use dfn_core::call;
use ic_base_types::PrincipalId;
use ic_ic00_types::IC_00;
use serde::Deserialize;

/// The UpdateSettings struct as defined in the ic-interface-spec
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candids
#[derive(Clone, PartialEq, Eq, Debug, CandidType, Deserialize)]
pub struct UpdateSettings {
    pub canister_id: PrincipalId,
    pub settings: CanisterSettings,
}

/// The CanisterSettings struct as defined in the ic-interface-spec
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candid
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub struct CanisterSettings {
    pub controllers: Option<Vec<PrincipalId>>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
}

/// A wrapper call to the management canister `update_settings` API.
pub async fn update_settings(update_settings: UpdateSettings) -> Result<(), (Option<i32>, String)> {
    call(
        IC_00,
        "update_settings",
        dfn_candid::candid,
        (update_settings,),
    )
    .await
}
