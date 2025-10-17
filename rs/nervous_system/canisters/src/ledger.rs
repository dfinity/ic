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
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use mockall::automock;
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

    async fn icrc2_approve(
        &self,
        spender: Account,
        amount: u64,
        expires_at: Option<u64>,
        fee: u64,
        from_subaccount: Option<Subaccount>,
        expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError> {
        <IcpLedgerCanister<Rt> as IcpLedger>::icrc2_approve(
            self,
            spender,
            amount,
            expires_at,
            fee,
            from_subaccount,
            expected_allowance,
        )
        .await
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
                    "Error calling method 'transfer' of the ledger canister. Code: {code:?}. Message: {msg}"
                ))
            })
            .and_then(|inner_result: (Result<u64, TransferError>,)| {
                inner_result.0.map_err(|e: TransferError| {
                    NervousSystemError::new_with_message(format!("Error transferring funds: {e}"))
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
                    "Error calling method 'icrc1_total_supply' of the ledger canister. Code: {code:?}. Message: {msg}"
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
                    "Error calling method 'account_balance' of the ledger canister. Code: {code:?}. Message: {msg}"
                )
            )
        })
    }

    fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    async fn icrc2_approve(
        &self,
        spender: Account,
        amount: u64,
        expires_at: Option<u64>,
        fee: u64,
        from_subaccount: Option<Subaccount>,
        expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError> {
        let result: Result<(Result<Nat, ApproveError>,), (i32, String)> = Rt::call_with_cleanup(
            self.canister_id,
            "icrc2_approve",
            (ApproveArgs {
                spender,
                amount: Nat::from(amount),
                expires_at,
                fee: Some(Nat::from(fee)),
                from_subaccount,
                created_at_time: None,
                expected_allowance: expected_allowance.map(Nat::from),
                memo: None,
            },),
        )
        .await;

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(format!(
                "Error calling method 'icrc2_approve' of the ledger canister. Code: {code:?}. Message: {msg}"
            ))
        })
        .and_then(|inner_result: (Result<Nat, ApproveError>,)| {
            inner_result.0.map_err(|e: ApproveError| {
                NervousSystemError::new_with_message(format!("Error approving funds: {e}"))
            })
        })
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

    /// Gives approval for `amount` of asset to `spender`.
    async fn icrc2_approve(
        &self,
        spender: Account,
        amount: u64,
        expires_at: Option<u64>,
        fee: u64,
        from_subaccount: Option<Subaccount>,
        expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError>;

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

    /// Gives approval for `amount` of asset to `spender`.
    async fn icrc2_approve(
        &self,
        spender: Account,
        amount: u64,
        expires_at: Option<u64>,
        fee: u64,
        from_subaccount: Option<Subaccount>,
        expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError>;

    /// Returns an array of blocks for the ranges specified in args.
    async fn icrc3_get_blocks(
        &self,
        args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError>;
}
