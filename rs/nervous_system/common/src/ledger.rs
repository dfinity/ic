use crate::NervousSystemError;
use async_trait::async_trait;
use dfn_core::{api::PrincipalId, call, CanisterId};
use dfn_protobuf::protobuf;
use ic_crypto_sha2::Sha256;
use ic_ledger_core::block::BlockIndex;
use icp_ledger::{
    tokens_from_proto, AccountBalanceArgs, AccountIdentifier, Memo, SendArgs,
    Subaccount as IcpSubaccount, Tokens, TotalSupplyArgs,
};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use mockall::automock;

pub struct IcpLedgerCanister {
    id: CanisterId,
}

impl IcpLedgerCanister {
    pub fn new(id: CanisterId) -> Self {
        IcpLedgerCanister { id }
    }
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
}

fn icrc1_account_to_icp_accountidentifier(account: Account) -> AccountIdentifier {
    AccountIdentifier::new(account.owner.into(), account.subaccount.map(IcpSubaccount))
}

#[async_trait]
impl ICRC1Ledger for IcpLedgerCanister {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<BlockIndex, NervousSystemError> {
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

    fn canister_id(&self) -> CanisterId {
        self.id
    }
}

#[async_trait]
impl IcpLedger for IcpLedgerCanister {
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
            call(self.id, "total_supply_pb", protobuf, TotalSupplyArgs {})
                .await
                .map(tokens_from_proto);

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
        .await
        .map(tokens_from_proto);

        result.map_err(|(code, msg)| {
            NervousSystemError::new_with_message(
                format!(
                    "Error calling method 'account_balance_pb' of the ledger canister. Code: {:?}. Message: {}",
                    code, msg
                )
            )
        })
    }

    fn canister_id(&self) -> CanisterId {
        self.id
    }
}

/// Computes the bytes of the subaccount to which neuron staking transfers are made. This
/// function must be kept in sync with the Nervous System UI equivalent.
pub fn compute_neuron_staking_subaccount_bytes(controller: PrincipalId, nonce: u64) -> [u8; 32] {
    compute_neuron_domain_subaccount_bytes(controller, b"neuron-stake", nonce)
}

/// Computes the subaccount to which neuron staking transfers are made. This
/// function must be kept in sync with the Nervous System UI equivalent.
pub fn compute_neuron_staking_subaccount(controller: PrincipalId, nonce: u64) -> IcpSubaccount {
    IcpSubaccount(compute_neuron_staking_subaccount_bytes(controller, nonce))
}

/// Computes the subaccount to which locked token distributions are initialized to.
pub fn compute_distribution_subaccount_bytes(principal_id: PrincipalId, nonce: u64) -> [u8; 32] {
    compute_neuron_domain_subaccount_bytes(principal_id, b"token-distribution", nonce)
}

// Computes the subaccount to which neuron disburse transfers are made.
pub fn compute_neuron_disburse_subaccount_bytes(controller: PrincipalId, nonce: u64) -> [u8; 32] {
    // The "domain" for neuron disburse was unfortunately chosen to be "neuron-split". It might be
    // possible to change to a more meaningful name, but there is no strong reason to do so, and
    // there is some risk that this behavior is depended on.
    compute_neuron_domain_subaccount_bytes(controller, b"neuron-split", nonce)
}

fn compute_neuron_domain_subaccount_bytes(
    controller: PrincipalId,
    domain: &[u8],
    nonce: u64,
) -> [u8; 32] {
    let domain_length: [u8; 1] = [domain.len() as u8];
    let mut hasher = Sha256::new();
    hasher.write(&domain_length);
    hasher.write(domain);
    hasher.write(controller.as_slice());
    hasher.write(&nonce.to_be_bytes());
    hasher.finish()
}

/// Computes the subaccount to which locked token distributions are initialized to.
pub fn compute_distribution_subaccount(principal_id: PrincipalId, nonce: u64) -> IcpSubaccount {
    IcpSubaccount(compute_distribution_subaccount_bytes(principal_id, nonce))
}
