use candid::types::number::Nat;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_canister_client_sender::Sender;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account,
};
use ic_ledger_core::block::BlockIndex;
use num_traits::ToPrimitive;

pub async fn balance_of<'a>(canister: &Canister<'a>, account: Account) -> Result<u64, String> {
    canister
        .query_("icrc1_balance_of", candid_one, account)
        .await
        .map(|n: Nat| n.0.to_u64().unwrap())
}

pub async fn transfer<'a>(
    canister: &Canister<'a>,
    sender: &Sender,
    args: TransferArg,
) -> Result<BlockIndex, String> {
    let res: Result<Nat, TransferError> = canister
        .update_from_sender("icrc1_transfer", candid_one, args, sender)
        .await?;
    match res {
        Ok(n) => Ok(n.0.to_u64().unwrap()),
        Err(e) => Err(format!("{:?}", e)),
    }
}
