use async_trait::async_trait;
use candid::types::number::Nat;
use candid::Principal;
use dfn_candid::{ArgumentDecoder, ArgumentEncoder};
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_icrc1::{endpoints::TransferArg, Account, Memo, Subaccount};
use ic_icrc1_client::{ICRC1Client, Runtime};
use ic_ledger_core::{block::BlockHeight, Tokens};
use ic_nervous_system_common::ledger::Ledger as IcpLedger;
use ic_nervous_system_common::ledger::LedgerCanister as IcpLedgerCanister;
use ic_nervous_system_common::NervousSystemError;
use ledger_canister::AccountIdentifier;
use ledger_canister::Subaccount as IcpSubaccount;

// A ICRC1 client runtime that uses dfn_* functionalities
struct DfnRuntime {}

#[async_trait]
impl Runtime for DfnRuntime {
    async fn call<In, Out>(
        &self,
        id: Principal,
        method: &str,
        args: In,
    ) -> Result<Out, (i32, String)>
    where
        In: ArgumentEncoder + Send,
        Out: for<'a> ArgumentDecoder<'a>,
    {
        let principal_id = CanisterId::new(PrincipalId::from(id)).map_err(|e| {
            (
                0, /* TODO */
                format!("Invalid canisterId {}: {}", id, e),
            )
        })?;
        dfn_core::api::call_with_cleanup(principal_id, method, dfn_candid::candid_multi_arity, args)
            .await
            .map_err(|(code, msg)| (code.unwrap_or_default(), msg))
    }
}

/// A trait defining common patterns for accessing the ICRC1 Ledger canister.
#[async_trait]
pub trait Ledger: Send + Sync {
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
    ) -> Result<BlockHeight, NervousSystemError>;

    /// Gets the total supply of tokens from the sum of all accounts except for the
    /// minting canister's.
    async fn total_supply(&self) -> Result<Tokens, NervousSystemError>;

    /// Gets the account balance in Tokens of the given AccountIdentifier in the Ledger.
    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError>;
}

pub struct LedgerCanister {
    client: ICRC1Client<DfnRuntime>,
}

impl LedgerCanister {
    pub fn new(ledger_canister_id: CanisterId) -> Self {
        Self {
            client: ICRC1Client::<DfnRuntime> {
                runtime: DfnRuntime {},
                ledger_canister_id: ledger_canister_id.get().into(),
            },
        }
    }
}

#[async_trait]
impl Ledger for LedgerCanister {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<BlockHeight, NervousSystemError> {
        let args = TransferArg {
            from_subaccount,
            to,
            fee: Some(Nat::from(fee_e8s)),
            created_at_time: None,
            amount: Nat::from(amount_e8s),
            memo: Some(Memo::from(memo)),
        };
        let res = self.client.transfer(args).await
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(format!(
                    "Error calling method 'icrc1_transfer' of the icrc1 ledger canister. Code: {:?}. Message: {}",
                    code, msg
                ))
            })?;
        res.map_err(|err| {
            NervousSystemError::new_with_message(format!(
                "'icrc1_transfer' of the icrc1 ledger canister failed. Error: {:?}",
                err
            ))
        })
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        self.client.total_supply().await
            .map(Tokens::from_e8s)
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(
                    format!(
                        "Error calling method 'icrc1_total_supply' of the ledger canister. Code: {:?}. Message: {}",
                        code, msg
                    )
                )
            })
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        self.client.balance_of(account).await
            .map(Tokens::from_e8s)
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(
                    format!(
                        "Error calling method 'icrc1_balance_of' of the ledger canister. Code: {:?}. Message: {}",
                        code, msg
                    )
                )
            })
    }
}

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(account.owner, account.subaccount.map(IcpSubaccount))
}

#[async_trait]
impl Ledger for IcpLedgerCanister {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<BlockHeight, NervousSystemError> {
        <IcpLedgerCanister as IcpLedger>::transfer_funds(
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
        <IcpLedgerCanister as IcpLedger>::total_supply(self).await
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        <IcpLedgerCanister as IcpLedger>::account_balance(
            self,
            icrc1_account_to_icp_accountidentifier(account),
        )
        .await
    }
}
