use crate::CallCanisters;
use candid::Nat;
use cycles_minting_canister::{CanisterSettingsArgs, CreateCanister, SubnetSelection};
use ic_base_types::PrincipalId;
use ic_nns_constants::CYCLES_LEDGER_CANISTER_ID;

pub mod requests;

use requests::*;

pub async fn create_canister<C: CallCanisters>(
    agent: &C,
    cycles_amount: u128,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettingsArgs>,
) -> Result<CreateCanisterSuccess, CreateCanisterError> {
    let request = CreateCanisterArgs {
        from_subaccount: None,
        created_at_time: None,
        amount: Nat::from(cycles_amount),
        creation_args: Some(CreateCanister {
            subnet_selection,
            settings,
            ..Default::default()
        }),
    };
    agent
        .call(CYCLES_LEDGER_CANISTER_ID, request)
        .await
        .expect("Cannot create canister")
}

pub async fn icrc1_balance_of<C: CallCanisters>(
    agent: &C,
    owner: PrincipalId,
    subaccount: Option<Vec<u8>>,
) -> Nat {
    let request = Account { owner, subaccount };
    agent
        .call(CYCLES_LEDGER_CANISTER_ID, request)
        .await
        .expect("Cannot check cycles balance")
}
