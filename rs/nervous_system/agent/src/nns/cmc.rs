use crate::CallCanisters;
use cycles_minting_canister::{CanisterSettingsArgs, CreateCanister, SubnetSelection};
use ic_base_types::CanisterId;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;

pub mod requests;

pub async fn create_canister<C: CallCanisters>(
    agent: &C,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettingsArgs>,
) -> Result<CanisterId, C::Error> {
    let request = CreateCanister {
        subnet_selection,
        settings,
        ..Default::default()
    };
    let result: Result<CanisterId, _> = agent.call(CYCLES_MINTING_CANISTER_ID, request).await?;

    Ok(result.expect("Cannot create canister"))
}
