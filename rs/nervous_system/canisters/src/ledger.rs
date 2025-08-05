use async_trait::async_trait;
use candid::Nat;
use dfn_core::CanisterId;
use ic_ledger_core::block::BlockIndex;
use ic_nervous_system_common::NervousSystemError;
use ic_nervous_system_runtime::Runtime;
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, Memo, Subaccount as IcpSubaccount, Tokens,
    TransferArgs, TransferError,
};
use icrc_ledger_types::icrc1::{
    account::{Account, Subaccount},
    transfer::Memo as Icrc1Memo,
};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use mockall::automock;
use rust_decimal::prelude::ToPrimitive;
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

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
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

    async fn icrc2_transfer_from(
        &self,
        from: Account,
        to: Account,
        amount_e8s: u64,
        fee_e8s: u64,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        let result: Result<(Result<Nat, TransferFromError>,), (i32, String)> =
            Rt::call_with_cleanup(
                self.canister_id,
                "icrc2_transfer_from",
                (TransferFromArgs {
                    spender_subaccount: None,
                    from,
                    to,
                    amount: Nat::from(amount_e8s),
                    fee: Some(Nat::from(fee_e8s)),
                    memo: Some(Icrc1Memo::from(memo)),
                    created_at_time: None,
                },),
            )
            .await;

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(format!(
                "Error calling method 'icrc2_transfer_from' of the ledger canister. Code: {:?}. Message: {}",
                code, msg
            ))
        })
        .and_then(|(inner_result,)| {
            inner_result.map_err(|e: TransferFromError| {
                NervousSystemError::new_with_message(format!("Error transferring funds: {}", e))
            })
        })
        .and_then(|block_index| block_index.0.to_u64().ok_or(NervousSystemError::new_with_message("Block index is too large")))
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

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }
}

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(account.owner.into(), account.subaccount.map(IcpSubaccount))
}

/// A trait defining common patterns for accessing the ICRC1 Ledger canister.
#[automock]
#[async_trait]
pub trait ICRC1Ledger: Send + Sync {
    /// Transfers funds from one of this canister's subaccount to
    /// the provided account.
    ///
    /// Returns the block height at which the transfer was recorded.
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<BlockIndex, NervousSystemError>;

    /// Gets the total supply of tokens from the sum of all accounts except for the
    /// minting canister's.
    async fn total_supply(&self) -> Result<Tokens, NervousSystemError>;

    /// Gets the account balance in Tokens of the given AccountIdentifier in the Ledger.
    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError>;

    /// Returns the CanisterId of the Ledger being accessed.
    fn canister_id(&self) -> CanisterId;

    /// Returns an array of blocks for the ranges specified in args.
    async fn icrc3_get_blocks(
        &self,
        args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError>;
}

/// A trait defining common patterns for accessing the Ledger canister.
#[automock]
#[async_trait]
pub trait IcpLedger: Send + Sync {
    /// Transfers funds from one of this canister's subaccount to
    /// the provided account.
    ///
    /// Returns the block height at which the transfer was recorded.
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<IcpSubaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result<u64, NervousSystemError>;

    /// Transfers funds from one account to another.
    async fn icrc2_transfer_from(
        &self,
        from: Account,
        to: Account,
        amount_e8s: u64,
        fee_e8s: u64,
        memo: u64,
    ) -> Result<u64, NervousSystemError>;

    /// Gets the total supply of tokens from the sum of all accounts except for the
    /// minting canister's.
    async fn total_supply(&self) -> Result<Tokens, NervousSystemError>;

    /// Gets the account balance in Tokens of the given AccountIdentifier in the Ledger.
    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError>;

    /// Returns the CanisterId of the Ledger being accessed.
    fn canister_id(&self) -> CanisterId;

    /// Returns an array of blocks for the ranges specified in args.
    async fn icrc3_get_blocks(
        &self,
        args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError>;
}
