use async_trait::async_trait;
use candid::Nat;
use dfn_core::CanisterId;
use ic_ledger_core::block::BlockIndex;
use ic_nervous_system_common::{
    ledger::{ICRC1Ledger, IcpLedger},
    NervousSystemError,
};
use ic_nervous_system_runtime::Runtime;
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, Memo, Subaccount as IcpSubaccount, Tokens,
    TransferArgs, TransferError,
};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use std::marker::PhantomData;

pub struct IcpLedgerCanister<Rt: Runtime> {
    canister_id: CanisterId,
    _phantom: PhantomData<Rt>,
}

impl<Rt: Runtime + Send + Sync> IcpLedgerCanister<Rt> {
    pub fn new(canister_id: CanisterId) -> Self {
        IcpLedgerCanister {
            canister_id,
            _phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<Rt: Runtime + Send + Sync> ICRC1Ledger for IcpLedgerCanister<Rt> {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<BlockIndex, NervousSystemError> {
        <IcpLedgerCanister<Rt> as IcpLedger>::transfer_funds(
            self,
            amount_e8s,
            fee_e8s,
            from_subaccount.map(IcpSubaccount),
            icrc1_account_to_icp_accountidentifier(to),
            memo,
        )
        .await
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        <IcpLedgerCanister<Rt> as IcpLedger>::total_supply(self).await
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        <IcpLedgerCanister<Rt> as IcpLedger>::account_balance(
            self,
            icrc1_account_to_icp_accountidentifier(account),
        )
        .await
    }

    fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

#[async_trait]
impl<Rt: Runtime + Send + Sync> IcpLedger for IcpLedgerCanister<Rt> {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<IcpSubaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        // Send 'amount_e8s' to the target account.
        //
        // We expect the 'fee_e8s' AND 'amount_e8s' to be
        // deducted from the from_subaccount. When calling
        // this method, make sure that the staked amount
        // can cover BOTH of these amounts, otherwise there
        // will be an error.
        let result: Result<(Result<u64, TransferError>,), (i32, String)> = Rt::call_with_cleanup(
            self.canister_id,
            "transfer",
            (TransferArgs {
                memo: Memo(memo),
                amount: Tokens::from_e8s(amount_e8s),
                fee: Tokens::from_e8s(fee_e8s),
                from_subaccount,
                to: to.to_address(),
                created_at_time: None,
            },),
        )
        .await;

        result
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(format!(
                    "Error calling method 'transfer' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                ))
            })
            .and_then(|inner_result: (Result<u64, TransferError>,)| {
                inner_result.0.map_err(|e: TransferError| {
                    NervousSystemError::new_with_message(format!("Error transferring funds: {}", e))
                })
            })
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        let result: Result<Tokens, (i32, String)> =
            Rt::call_with_cleanup(self.canister_id, "icrc1_total_supply", ((),))
                .await
                .map(|e8s: (Nat,)| {
                    Tokens::try_from(e8s.0)
                        .expect("Should always succeed, as ICP ledger internally stores u64")
                });

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(
                format!(
                    "Error calling method 'icrc1_total_supply' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                )
            )
        })
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        let result: Result<Tokens, (i32, String)> = Rt::call_with_cleanup(
            self.canister_id,
            "account_balance",
            (BinaryAccountBalanceArgs {
                account: account.to_address(),
            },),
        )
        .await
        .map(|tokens: (Tokens,)| tokens.0);

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(
                format!(
                    "Error calling method 'account_balance' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                )
            )
        })
    }

    fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
}

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(account.owner.into(), account.subaccount.map(IcpSubaccount))
}
