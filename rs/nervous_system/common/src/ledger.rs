use crate::NervousSystemError;
use async_trait::async_trait;
use dfn_core::api::PrincipalId;
use dfn_core::{call, CanisterId};
use dfn_protobuf::protobuf;
use ic_crypto_sha::Sha256;
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, Memo, SendArgs, Subaccount, Tokens, TotalSupplyArgs,
};

pub struct LedgerCanister {
    id: CanisterId,
}

impl LedgerCanister {
    pub fn new(id: CanisterId) -> Self {
        LedgerCanister { id }
    }
}

/// A trait defining common patterns for accessing the Ledger canister.
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
}

#[async_trait]
impl Ledger for LedgerCanister {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
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
        let result: Result<u64, (Option<i32>, String)> = call(
            self.id,
            "send_pb",
            protobuf,
            SendArgs {
                memo: Memo(memo),
                amount: Tokens::from_e8s(amount_e8s),
                fee: Tokens::from_e8s(fee_e8s),
                from_subaccount,
                to,
                created_at_time: None,
            },
        )
        .await;

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(format!(
                "Error calling method 'send' of the ledger canister. Code: {:?}. Message: {}",
                code, msg
            ))
        })
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        let result: Result<Tokens, (Option<i32>, String)> =
            call(self.id, "total_supply_pb", protobuf, TotalSupplyArgs {}).await;

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(
                format!(
                    "Error calling method 'total_supply' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                )
            )
        })
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        let result: Result<Tokens, (Option<i32>, String)> = call(
            self.id,
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs { account },
        )
        .await;

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(
                format!(
                    "Error calling method 'account_balance_pb' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                )
            )
        })
    }
}

/// Computes the subaccount to which neuron staking transfers are made. This
/// function must be kept in sync with the Nervous System UI equivalent.
pub fn compute_neuron_staking_subaccount(controller: PrincipalId, nonce: u64) -> Subaccount {
    // The equivalent function in the NNS UI is
    // https://github.com/dfinity/dfinity_wallet/blob/351e07d3e6d007b090117161a94ce8ec9d5a6b49/js-agent/src/canisters/createNeuron.ts#L63
    const DOMAIN: &[u8] = b"neuron-stake";
    const DOMAIN_LENGTH: [u8; 1] = [0x0c];

    Subaccount({
        let mut hasher = Sha256::new();
        hasher.write(&DOMAIN_LENGTH);
        hasher.write(DOMAIN);
        hasher.write(controller.as_slice());
        hasher.write(&nonce.to_be_bytes());
        hasher.finish()
    })
}
