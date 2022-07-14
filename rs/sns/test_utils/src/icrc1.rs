use canister_test::Canister;
use dfn_candid::candid_one;
use ic_canister_client_sender::Sender;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account,
};
use ic_ledger_core::block::BlockHeight;

pub async fn balance_of<'a>(canister: &Canister<'a>, account: Account) -> Result<u64, String> {
    canister
        .query_("icrc1_balanceOf", candid_one, account)
        .await
}

pub async fn transfer<'a>(
    canister: &Canister<'a>,
    sender: &Sender,
    args: TransferArg,
) -> Result<BlockHeight, String> {
    let res: Result<BlockHeight, TransferError> = canister
        .update_from_sender("icrc1_transfer", candid_one, args, sender)
        .await?;
    res.map_err(|te| format!("{:#?}", te))
}
