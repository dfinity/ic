use crate::NervousSystemError;
use async_trait::async_trait;
use dfn_core::{api::PrincipalId, CanisterId};
use ic_crypto_sha2::Sha256;
use ic_ledger_core::block::BlockIndex;
use icp_ledger::{AccountIdentifier, Subaccount as IcpSubaccount, Tokens};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use mockall::automock;

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
