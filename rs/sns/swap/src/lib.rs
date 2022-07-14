use ic_ic00_types::CanisterStatusResultV2;

pub mod pb;
pub mod swap;

#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub struct GetCanisterStatusResponse {
    // Whatever ic0.canister_status returns.
    //
    // See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-canister_status
    pub status: CanisterStatusResultV2,
}
