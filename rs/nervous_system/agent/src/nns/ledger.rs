use crate::CallCanisters;

use ic_nns_constants::LEDGER_CANISTER_ID;
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, Tokens, TransferArgs,
    TransferError as ICPTransferError,
};
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};

pub async fn icrc1_transfer<C: CallCanisters>(
    agent: &C,
    transfer: TransferArg,
) -> Result<Result<BlockIndex, TransferError>, C::Error> {
    agent.call(LEDGER_CANISTER_ID, transfer).await
}

pub async fn transfer<C: CallCanisters>(
    agent: &C,
    transfer: TransferArgs,
) -> Result<Result<u64, ICPTransferError>, C::Error> {
    agent.call(LEDGER_CANISTER_ID, transfer).await
}

pub async fn account_balance<C: CallCanisters>(
    agent: &C,
    account: AccountIdentifier,
) -> Result<Tokens, C::Error> {
    agent
        .call(
            LEDGER_CANISTER_ID,
            BinaryAccountBalanceArgs {
                account: account.to_address(),
            },
        )
        .await
}
