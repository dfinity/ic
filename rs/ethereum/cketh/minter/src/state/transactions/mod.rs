mod request;

#[cfg(test)]
pub(in crate::state) mod tests;

pub use request::PipelineRequest;

use crate::endpoints::{EthTransaction, RetrieveEthStatus, TxFinalizedStatus, WithdrawalStatus};
use crate::eth_logs::LedgerSubaccount;
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::eth_rpc_client::responses::TransactionStatus;
use crate::logs::INFO;
use crate::map::MultiKeyMap;
use crate::numeric::{
    CkTokenAmount, Erc20Value, GasAmount, LedgerBurnIndex, LedgerMintIndex, TransactionCount,
    TransactionNonce, Wei,
};
use crate::sweeper_contract::{SweepItem, encode_sweep_erc20_batch};
use crate::tx::{
    Eip1559TransactionRequest, Finalized, FinalizedEip1559Transaction, GasFeeEstimate,
    Resubmittable, SignableTransaction, Signed, SignedAuthorization,
    SignedEip1559TransactionRequest, TransactionPrice,
};
use candid::Principal;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use minicbor::{Decode, Encode};
use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum WithdrawalSearchParameter {
    ByWithdrawalId(LedgerBurnIndex),
    ByRecipient(Address),
    BySenderAccount(Account),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum WithdrawalRequest {
    CkEth(EthWithdrawalRequest),
    CkErc20(Erc20WithdrawalRequest),
    /// Carries the same payload as [`WithdrawalRequest::CkEth`] — a burn of the minter's own
    /// ckETH, transferred to the sweeper address — but is never reimbursed, so it needs a
    /// variant of its own rather than a flag on the payload.
    SweeperFunding(EthWithdrawalRequest),
}

impl WithdrawalRequest {
    pub fn cketh_ledger_burn_index(&self) -> LedgerBurnIndex {
        match self {
            WithdrawalRequest::CkEth(request) => request.ledger_burn_index,
            WithdrawalRequest::CkErc20(request) => request.cketh_ledger_burn_index,
            WithdrawalRequest::SweeperFunding(request) => request.ledger_burn_index,
        }
    }

    pub fn created_at(&self) -> Option<u64> {
        match self {
            WithdrawalRequest::CkEth(request) | WithdrawalRequest::SweeperFunding(request) => {
                request.created_at
            }
            WithdrawalRequest::CkErc20(request) => Some(request.created_at),
        }
    }

    /// Address to which the funds are to be sent to.
    pub fn payee(&self) -> Address {
        match self {
            WithdrawalRequest::CkEth(request) | WithdrawalRequest::SweeperFunding(request) => {
                request.destination
            }
            WithdrawalRequest::CkErc20(request) => request.destination,
        }
    }

    /// Address to which the transaction is to be sent to.
    pub fn destination(&self) -> Address {
        match self {
            WithdrawalRequest::CkEth(request) | WithdrawalRequest::SweeperFunding(request) => {
                request.destination
            }
            WithdrawalRequest::CkErc20(request) => request.erc20_contract_address,
        }
    }

    pub fn from(&self) -> Principal {
        match self {
            WithdrawalRequest::CkEth(request) | WithdrawalRequest::SweeperFunding(request) => {
                request.from
            }
            WithdrawalRequest::CkErc20(request) => request.from,
        }
    }

    pub fn from_subaccount(&self) -> Option<&LedgerSubaccount> {
        match self {
            WithdrawalRequest::CkEth(request) | WithdrawalRequest::SweeperFunding(request) => {
                request.from_subaccount.as_ref()
            }
            WithdrawalRequest::CkErc20(request) => request.from_subaccount.as_ref(),
        }
    }

    /// Whether this request can be paid back if its transaction fails.
    pub fn is_reimbursable(&self) -> bool {
        match self {
            WithdrawalRequest::CkEth(_) | WithdrawalRequest::CkErc20(_) => true,
            WithdrawalRequest::SweeperFunding(_) => false,
        }
    }

    pub fn match_parameter(&self, parameter: &WithdrawalSearchParameter) -> bool {
        use WithdrawalSearchParameter::*;
        match parameter {
            ByWithdrawalId(index) => &self.cketh_ledger_burn_index() == index,
            ByRecipient(address) => &self.payee() == address,
            BySenderAccount(Account { owner, subaccount }) => {
                &self.from() == owner
                    && self.from_subaccount()
                        == subaccount.and_then(LedgerSubaccount::from_bytes).as_ref()
            }
        }
    }
}

impl From<EthWithdrawalRequest> for WithdrawalRequest {
    fn from(value: EthWithdrawalRequest) -> Self {
        WithdrawalRequest::CkEth(value)
    }
}

impl From<Erc20WithdrawalRequest> for WithdrawalRequest {
    fn from(value: Erc20WithdrawalRequest) -> Self {
        WithdrawalRequest::CkErc20(value)
    }
}

/// Ethereum withdrawal request issued by the user.
#[derive(Clone, Eq, PartialEq, Decode, Encode)]
pub struct EthWithdrawalRequest {
    /// The ETH amount that the receiver will get, not accounting for the Ethereum transaction fees.
    #[n(0)]
    pub withdrawal_amount: Wei,
    /// The address to which the minter will send ETH.
    #[n(1)]
    pub destination: Address,
    /// The transaction ID of the ckETH burn operation.
    #[cbor(n(2), with = "crate::cbor::id")]
    pub ledger_burn_index: LedgerBurnIndex,
    /// The owner of the account from which the minter burned ckETH.
    #[cbor(n(3), with = "icrc_cbor::principal")]
    pub from: Principal,
    /// The subaccount from which the minter burned ckETH.
    #[n(4)]
    pub from_subaccount: Option<LedgerSubaccount>,
    /// The IC time at which the withdrawal request arrived.
    #[n(5)]
    pub created_at: Option<u64>,
}

/// ERC-20 withdrawal request issued by the user.
#[derive(Clone, Eq, PartialEq, Decode, Encode)]
pub struct Erc20WithdrawalRequest {
    /// Amount of burn ckETH that can be used to pay for the Ethereum transaction fees.
    #[n(0)]
    pub max_transaction_fee: Wei,
    /// The ERC-20 amount that the receiver will get.
    #[n(1)]
    pub withdrawal_amount: Erc20Value,
    /// The recipient's address of the sent ERC-20 tokens.
    #[n(2)]
    pub destination: Address,
    /// The transaction ID of the ckETH burn operation on the ckETH ledger.
    #[cbor(n(3), with = "crate::cbor::id")]
    pub cketh_ledger_burn_index: LedgerBurnIndex,
    /// Address of the ERC-20 smart contract that is the message call's recipient.
    #[n(4)]
    pub erc20_contract_address: Address,
    /// The ckERC20 ledger on which the minter burned the ckERC20 tokens.
    #[cbor(n(5), with = "icrc_cbor::principal")]
    pub ckerc20_ledger_id: Principal,
    /// The transaction ID of the ckERC20 burn operation on the ckERC20 ledger.
    #[cbor(n(6), with = "crate::cbor::id")]
    pub ckerc20_ledger_burn_index: LedgerBurnIndex,
    /// The owner of the account from which the minter burned ckETH.
    #[cbor(n(7), with = "icrc_cbor::principal")]
    pub from: Principal,
    /// The subaccount from which the minter burned ckETH.
    #[n(8)]
    pub from_subaccount: Option<LedgerSubaccount>,
    /// The IC time at which the withdrawal request arrived.
    #[n(9)]
    pub created_at: u64,
}

/// Monotonic identity of a sweep, used as the sweeper pipeline's alternate map key. Unlike a
/// withdrawal's `LedgerBurnIndex`, a sweep burns no ckETH, so its id is a plain counter.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug, Hash, Decode, Encode)]
#[cbor(transparent)]
pub struct SweepId(#[n(0)] pub u64);

impl SweepId {
    /// The id following this one, minted when a sweep is accepted.
    pub fn next(self) -> Self {
        SweepId(
            self.0
                .checked_add(1)
                .expect("BUG: sweep id space exhausted"),
        )
    }
}

/// A sweep the minter issues **from its dedicated sweeper address**, on the sweeper's own nonce
/// sequence — the request type of the sweeper [`TransactionPipeline`]. It carries no ckETH burn
/// and is never reimbursed.
///
/// Like [`WithdrawalRequest`], this says *what* to sweep, not how the transaction carrying it
/// looks: the nonce, the gas price and the call data are the pipeline's to decide in
/// [`PipelineRequest::create_transaction`].
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct SweepRequest {
    /// This sweep's identity (the pipeline's alternate map key).
    #[n(0)]
    pub id: SweepId,
    /// Address the sweep transaction is sent to: the sweeper contract, whose batch entry point
    /// sweeps every delegated deposit address the sweep names.
    #[n(1)]
    pub destination: Address,
    /// The single ERC-20 this sweep moves. One token per sweep: the delegate applies the token
    /// list to every item it walks, so a sweep mixing tokens would check balances that cannot be
    /// there. Holding it as one address rather than a list is what makes that an invariant of the
    /// request instead of a property of how the batch happened to be picked.
    #[n(2)]
    pub token: Address,
    /// The deposits this sweep moves, one per account. A deposit address is derived per account,
    /// so an account has one address, one attestation and one authorization however many tokens
    /// it has queued.
    #[n(3)]
    pub items: Vec<AuthorizedSweepItem>,
    /// Ceiling on the transaction fee, used as the resubmission fee cap.
    #[n(4)]
    pub max_transaction_fee: Wei,
    /// The IC time at which the sweep was decided.
    #[n(5)]
    pub created_at: u64,
}

/// A sweep item together with the delegation that lets the delegate code run at its address.
///
/// The two travel together but land in different parts of the transaction: the item is call data,
/// the authorization is a transaction field. Pairing them here is what stops the two lists from
/// drifting out of order against the account they describe.
///
/// The delegation is absent for an address already delegated to the sweeper contract, which needs
/// no tuple to install one again. A sweep all of whose items are delegated carries no
/// authorization at all, and is sent as a plain EIP-1559 transaction.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct AuthorizedSweepItem {
    #[n(0)]
    pub item: SweepItem,
    #[n(1)]
    pub authorization: Option<SignedAuthorization>,
}

/// This and the constants below are derived from the EVM's own costs rather than from the ~42'000
/// per deposit measured for a batch of 20, which does not record how many distinct tokens that
/// batch covered and so cannot separate the work that grows with the pairs from the work that grows
/// with the transfers. Each is deliberately generous: unspent gas is refunded, whereas an
/// underestimate wastes the whole transaction.
const SWEEP_BASE_GAS: GasAmount = GasAmount::new(60_000);

/// Gas each `balanceOf` the delegate makes costs. `sweepErc20Batch` hands the whole token array to
/// every item and `sweepErc20` loops over it, so a sweep pays one balance check per
/// `(address, token)` pair whether or not the pair holds anything — and therefore at least one per
/// address, which is where that address' calldata, `ecrecover` and delegated call are accounted
/// for. A cold `balanceOf` is ~5'000 (2'600 account access, 2'100 cold slot, call overhead) and the
/// per-address dispatch ~10'000.
const SWEEP_GAS_PER_BALANCE_CHECK: GasAmount = GasAmount::new(15_000);

/// Gas moving one pair costs beyond its balance check: the `approve` (a 20'000 slot write), the
/// helper's `depositErc20` and the `transferFrom` it makes (two slot writes and two logs), ~55'000
/// in the worst case, doubled.
///
/// Budgeted for every pair the batch touches rather than only for the deposits the queue named:
/// `sweepErc20` moves whatever balance it finds, and a deposit address accumulates residue — a pair
/// armed but not yet scanned, a pair whose watchlist window closed before the funds arrived, a token
/// the sender was never asked for. A pair therefore costs a balance check and, on top of it,
/// possibly a transfer.
const SWEEP_GAS_PER_TRANSFER: GasAmount = GasAmount::new(110_000);

/// Gas one EIP-7702 authorization costs: 25'000 (`PER_EMPTY_ACCOUNT_COST`) charged upfront for
/// every tuple, before any of them is looked at.
///
/// Budgeted for every address the sweep touches, since every one of them carries a tuple. A tuple
/// the EVM skips — the address is already delegated, so the nonce it was signed for no longer
/// matches — is charged the same 25'000 and refunded 12'500 for an authority the state trie
/// already holds. That refund lands after execution and so cannot shrink the limit the transaction
/// had to declare, leaving 25'000 the figure to budget either way. Rounded up as its siblings are.
const SWEEP_GAS_PER_AUTHORIZATION: GasAmount = GasAmount::new(40_000);

pub fn sweep_gas_limit(items: &[AuthorizedSweepItem]) -> GasAmount {
    let addresses = u64::try_from(
        items
            .iter()
            .map(|authorized| authorized.item.deposit)
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap_or(u64::MAX);
    [
        SWEEP_GAS_PER_BALANCE_CHECK,
        SWEEP_GAS_PER_TRANSFER,
        SWEEP_GAS_PER_AUTHORIZATION,
    ]
    .into_iter()
    .fold(SWEEP_BASE_GAS, |total, gas_per_address| {
        total
            .checked_add(
                gas_per_address
                    .checked_mul(addresses)
                    .unwrap_or(GasAmount::MAX),
            )
            .unwrap_or(GasAmount::MAX)
    })
}

impl SweepRequest {
    pub fn gas_limit(&self) -> GasAmount {
        sweep_gas_limit(&self.items)
    }

    /// The delegate's batch call, naming every deposit address this sweep walks and the single
    /// token it moves.
    pub fn call_data(&self) -> Vec<u8> {
        let items: Vec<_> = self.items.iter().map(|item| item.item.clone()).collect();
        encode_sweep_erc20_batch(&items, &[self.token])
    }

    /// The delegations the sweep installs on the way, one per deposit address it still has to
    /// delegate. Signed for nonce zero, so a tuple whose delegation is already installed is
    /// skipped rather than sinking the sweep. Empty once every address the sweep touches is
    /// delegated, which is what makes it a plain EIP-1559 transaction.
    pub fn authorizations(&self) -> Vec<SignedAuthorization> {
        self.items
            .iter()
            .filter_map(|item| item.authorization.clone())
            .collect()
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Decode, Encode)]
pub enum ReimbursementIndex {
    #[n(0)]
    CkEth {
        /// Burn index on the ckETH ledger
        #[cbor(n(0), with = "crate::cbor::id")]
        ledger_burn_index: LedgerBurnIndex,
    },
    #[n(1)]
    CkErc20 {
        #[cbor(n(0), with = "crate::cbor::id")]
        cketh_ledger_burn_index: LedgerBurnIndex,
        /// The ckERC20 ledger canister ID identifying the ledger on which the burn to be reimbursed was made.
        #[cbor(n(1), with = "icrc_cbor::principal")]
        ledger_id: Principal,
        /// Burn index on the ckERC20 ledger
        #[cbor(n(2), with = "crate::cbor::id")]
        ckerc20_ledger_burn_index: LedgerBurnIndex,
    },
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct NotReimbursable;

impl TryFrom<&WithdrawalRequest> for ReimbursementIndex {
    type Error = NotReimbursable;

    fn try_from(value: &WithdrawalRequest) -> Result<Self, Self::Error> {
        match value {
            WithdrawalRequest::CkEth(request) => Ok(ReimbursementIndex::CkEth {
                ledger_burn_index: request.ledger_burn_index,
            }),
            WithdrawalRequest::CkErc20(request) => Ok(ReimbursementIndex::CkErc20 {
                cketh_ledger_burn_index: request.cketh_ledger_burn_index,
                ledger_id: request.ckerc20_ledger_id,
                ckerc20_ledger_burn_index: request.ckerc20_ledger_burn_index,
            }),
            WithdrawalRequest::SweeperFunding(_) => Err(NotReimbursable),
        }
    }
}

impl ReimbursementIndex {
    pub fn withdrawal_id(&self) -> LedgerBurnIndex {
        match self {
            ReimbursementIndex::CkEth { ledger_burn_index } => *ledger_burn_index,
            ReimbursementIndex::CkErc20 {
                cketh_ledger_burn_index,
                ..
            } => *cketh_ledger_burn_index,
        }
    }
    pub fn burn_in_block(&self) -> LedgerBurnIndex {
        match self {
            ReimbursementIndex::CkEth { ledger_burn_index } => *ledger_burn_index,
            ReimbursementIndex::CkErc20 {
                ckerc20_ledger_burn_index,
                ..
            } => *ckerc20_ledger_burn_index,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct ReimbursementRequest {
    /// Burn index on the ledger that should be reimbursed.
    #[cbor(n(0), with = "crate::cbor::id")]
    pub ledger_burn_index: LedgerBurnIndex,
    /// The amount that should be reimbursed in the smallest denomination.
    #[n(1)]
    pub reimbursed_amount: CkTokenAmount,
    #[cbor(n(2), with = "icrc_cbor::principal")]
    pub to: Principal,
    #[n(3)]
    pub to_subaccount: Option<LedgerSubaccount>,
    /// Transaction hash of the failed ETH transaction.
    /// We use this hash to link the mint reimbursement transaction
    /// on the ledger with the failed ETH transaction.
    #[n(4)]
    pub transaction_hash: Option<Hash>,
}

#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct Reimbursed {
    #[cbor(n(0), with = "crate::cbor::id")]
    pub reimbursed_in_block: LedgerMintIndex,
    #[cbor(n(1), with = "crate::cbor::id")]
    pub burn_in_block: LedgerBurnIndex,
    /// The amount reimbursed in the smallest denomination.
    #[n(2)]
    pub reimbursed_amount: CkTokenAmount,
    #[n(3)]
    pub transaction_hash: Option<Hash>,
}

pub type ReimbursedResult = Result<Reimbursed, ReimbursedError>;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ReimbursedError {
    /// Whether reimbursement was minted or not is unknown,
    /// most likely because there was an unexpected panic in the callback.
    /// The reimbursement request is quarantined to avoid any double minting and
    /// will not be further processed without manual intervention.
    Quarantined,
}

struct DisplayOption<'a, T>(&'a Option<T>);

impl<T: fmt::Display> fmt::Display for DisplayOption<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self.0 {
            Some(t) => write!(f, "Some({t})"),
            None => write!(f, "None"),
        }
    }
}

impl fmt::Debug for EthWithdrawalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let EthWithdrawalRequest {
            withdrawal_amount,
            destination,
            ledger_burn_index,
            from,
            from_subaccount,
            created_at,
        } = self;
        f.debug_struct("EthWithdrawalRequest")
            .field("withdrawal_amount", withdrawal_amount)
            .field("destination", destination)
            .field("ledger_burn_index", ledger_burn_index)
            .field("from", &format_args!("{from}"))
            .field(
                "from_subaccount",
                &format_args!("{}", DisplayOption(from_subaccount)),
            )
            .field("created_at", created_at)
            .finish()
    }
}

impl fmt::Debug for Erc20WithdrawalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Erc20WithdrawalRequest {
            max_transaction_fee,
            withdrawal_amount,
            destination,
            cketh_ledger_burn_index,
            erc20_contract_address,
            ckerc20_ledger_id,
            ckerc20_ledger_burn_index,
            from,
            from_subaccount,
            created_at,
        } = self;
        f.debug_struct("Erc20WithdrawalRequest")
            .field("max_transaction_fee", max_transaction_fee)
            .field("withdrawal_amount", withdrawal_amount)
            .field("erc20_contract_address", erc20_contract_address)
            .field("destination", destination)
            .field("cketh_ledger_burn_index", cketh_ledger_burn_index)
            .field("ckerc20_ledger_id", &format_args!("{ckerc20_ledger_id}"))
            .field("ckerc20_ledger_burn_index", ckerc20_ledger_burn_index)
            .field("from", &format_args!("{from}"))
            .field(
                "from_subaccount",
                &format_args!("{}", DisplayOption(from_subaccount)),
            )
            .field("created_at", created_at)
            .finish()
    }
}

/// State machine holding Ethereum transactions issued by the minter from a **single sender
/// address**, on that address' **own nonce sequence** — generic over the request type `R` so the
/// same machinery serves both the main-address withdrawal pipeline (`R = WithdrawalRequest`, aliased
/// as [`WithdrawalTransactions`]) and the dedicated sweeper-address pipeline (`R = SweepRequest`).
///
/// Overall the transaction lifecycle is as follows:
/// 1. The request is enqueued and processed in a FIFO order.
/// 2. A transaction is created by either consuming a request
///    (the first time a transaction is created for that nonce and id)
///    or re-submitting an already sent transaction for that nonce and id.
/// 3. The transaction is signed via threshold ECDSA and recorded by either consuming the
///    previously created transaction or re-submitting an already sent transaction as is.
/// 4. The transaction is sent to Ethereum. There may have been multiple
///    sent transactions for that nonce and id in case of resubmissions.
/// 5. For a given nonce (and id), at most one sent transaction is finalized; a failed one is
///    reported as such. The other sent transactions for that nonce were never mined and can be
///    discarded. Paying the requester back is not the pipeline's concern — see
///    [`WithdrawalTransactions`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TransactionPipeline<R: PipelineRequest> {
    pending_requests: VecDeque<R>,
    // Processed requests (transaction created, sent, or finalized).
    processed_requests: BTreeMap<R::Id, R>,
    created_tx: MultiKeyMap<TransactionNonce, R::Id, CreatedTransaction<R>>,
    sent_tx: MultiKeyMap<TransactionNonce, R::Id, Vec<SentTransaction<R>>>,
    finalized_tx: MultiKeyMap<TransactionNonce, R::Id, Finalized<R::Transaction>>,
    next_nonce: TransactionNonce,
}

/// The pipeline sending from the minter's main address, on which user withdrawals travel.
pub type MinterTransactionPipeline = TransactionPipeline<WithdrawalRequest>;

/// The pipeline sending from the minter's dedicated sweeper address.
pub type SweeperTransactionPipeline = TransactionPipeline<SweepRequest>;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CreateTransactionError {
    InsufficientTransactionFee {
        cketh_ledger_burn_index: LedgerBurnIndex,
        allowed_max_transaction_fee: Wei,
        actual_max_transaction_fee: Wei,
    },
}

/// Why a sweep could not be turned into a transaction.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CreateSweepTransactionError {
    /// The gas prepaid for this sweep cannot pay the current fee, so no transaction is created:
    /// one priced within the allowance could not be mined, and would hold the sweeper's nonce
    /// while the resubmission strategy refused to bump it past the same allowance.
    InsufficientTransactionFee {
        id: SweepId,
        allowed_max_transaction_fee: Wei,
        actual_max_transaction_fee: Wei,
    },
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ResubmitTransactionError<Id> {
    InsufficientTransactionFee {
        id: Id,
        transaction_nonce: TransactionNonce,
        allowed_max_transaction_fee: Wei,
        max_transaction_fee: Wei,
    },
}

/// How far a transaction has got through the pipeline. Carries the transaction itself, since
/// every caller that asks the stage also wants the transaction at it.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum TransactionStage<'a, T: SignableTransaction> {
    Created(&'a T),
    /// The most recently sent transaction, i.e. the one with the highest fee.
    Sent(&'a Resubmittable<Signed<T>>),
    Finalized(&'a Finalized<T>),
}

/// One outcome of [`TransactionPipeline::create_resubmit_transactions`]: the fee-bumped transaction to
/// re-sign (paired with its pipeline id), or why it could not be bumped.
type ResubmitResult<Id, Tx> = Result<(Id, Tx), ResubmitTransactionError<Id>>;

/// A transaction created for a request, with the strategy for bumping its fee.
type CreatedTransaction<R> = Resubmittable<<R as PipelineRequest>::Transaction>;

/// A transaction signed and sent for a request, with the strategy for bumping its fee.
type SentTransaction<R> = Resubmittable<Signed<<R as PipelineRequest>::Transaction>>;

impl<R> TransactionPipeline<R>
where
    R: PipelineRequest + Clone + Eq + fmt::Debug,
    R::Transaction: Clone + Eq + fmt::Debug,
{
    pub fn new(next_nonce: TransactionNonce) -> Self {
        Self {
            pending_requests: VecDeque::new(),
            processed_requests: BTreeMap::new(),
            created_tx: MultiKeyMap::default(),
            sent_tx: MultiKeyMap::default(),
            finalized_tx: MultiKeyMap::default(),
            next_nonce,
        }
    }

    pub fn next_transaction_nonce(&self) -> TransactionNonce {
        self.next_nonce
    }

    pub fn update_next_transaction_nonce(&mut self, new_nonce: TransactionNonce) {
        self.next_nonce = new_nonce;
    }

    pub fn record_request<Req: Into<R>>(&mut self, request: Req) {
        let request = request.into();
        let id = request.id();
        if self.pending_requests.iter().any(|r| r.id() == id)
            || self.created_tx.contains_alt(&id)
            || self.sent_tx.contains_alt(&id)
            || self.finalized_tx.contains_alt(&id)
        {
            panic!("BUG: duplicate transaction id {id:?}");
        }
        self.pending_requests.push_back(request);
    }

    /// Move an existing request to the back of the queue.
    pub fn reschedule_request(&mut self, id: R::Id) {
        assert_eq!(
            self.pending_requests
                .iter()
                .filter(|r| r.id() == id)
                .count(),
            1,
            "BUG: expected exactly one request with id {id:?}"
        );
        let position = self
            .pending_requests
            .iter()
            .position(|r| r.id() == id)
            .expect("BUG: exactly one request with this id was just counted");
        let request = self
            .pending_requests
            .remove(position)
            .expect("BUG: position was just found in the queue");
        self.record_request(request);
    }

    pub fn record_created_transaction(&mut self, id: R::Id, transaction: R::Transaction) {
        let position = self
            .pending_requests
            .iter()
            .position(|req| req.id() == id)
            .unwrap_or_else(|| panic!("BUG: request {id:?} not found"));
        let request = &self.pending_requests[position];
        request.assert_created_transaction(&transaction);
        let resubmission = request.resubmission_strategy();
        let nonce = self.next_nonce;
        assert_eq!(
            transaction.nonce(),
            nonce,
            "BUG: transaction nonce mismatch"
        );
        self.next_nonce = self
            .next_nonce
            .checked_increment()
            .expect("Transaction nonce overflow");
        let request = self
            .pending_requests
            .remove(position)
            .expect("BUG: position was just found in the queue");
        let transaction_request = Resubmittable {
            transaction,
            resubmission,
        };
        assert_eq!(
            self.created_tx
                .try_insert(nonce, request.id(), transaction_request),
            Ok(())
        );
        assert_eq!(self.processed_requests.insert(id, request), None);
    }

    pub fn record_signed_transaction(&mut self, signed_transaction: Signed<R::Transaction>) {
        let created_tx = self
            .created_tx
            .get(&signed_transaction.nonce())
            .expect("BUG: missing created transaction");
        assert_eq!(
            created_tx.as_ref(),
            signed_transaction.transaction(),
            "BUG: mismatch between sent transaction and created transaction"
        );
        let signed_tx = created_tx.clone_resubmission_strategy(signed_transaction);
        let (nonce, id, _created_tx) = self
            .created_tx
            .remove_entry(&signed_tx.as_ref().nonce())
            .expect("BUG: missing created transaction");
        if let Some(sent_tx) = self.sent_tx.get_mut(&nonce) {
            sent_tx.push(signed_tx);
        } else {
            assert_eq!(self.sent_tx.try_insert(nonce, id, vec![signed_tx]), Ok(()));
        }
    }

    /// Create transactions to resubmit corresponding to already sent transactions
    /// with nonces greater than the latest mined transaction nonce:
    /// * the resubmitted transaction will need to be re-signed if its transaction fee was increased
    /// * the resubmitted transaction can be resent as is if its transaction fee was not increased
    ///
    /// We stop on the first error since if a transaction with nonce n could not be resubmitted
    /// (e.g., the transaction amount does not cover the new fees),
    /// then the next transactions with nonces n+1, n+2, ... are blocked anyway
    /// and trying to resubmit them would only artificially increase their transaction fees.
    pub fn create_resubmit_transactions(
        &self,
        latest_transaction_count: TransactionCount,
        current_gas_fee: GasFeeEstimate,
    ) -> Vec<ResubmitResult<R::Id, R::Transaction>> {
        // If transaction count at block height H is c > 0, then transactions with nonces
        // 0, 1, ..., c - 1 were mined. If transaction count is 0, then no transactions were mined.
        // The nonce of the first pending transaction is then exactly c.
        let first_pending_tx_nonce: TransactionNonce = latest_transaction_count.change_units();
        let mut transactions_to_resubmit = Vec::new();
        for (nonce, id, signed_tx) in self
            .sent_tx
            .iter()
            .filter(|(nonce, _id, _signed_tx)| *nonce >= &first_pending_tx_nonce)
        {
            let last_signed_tx = signed_tx.last().expect("BUG: empty sent transactions list");
            match last_signed_tx.resubmit(current_gas_fee.clone()) {
                Ok(Some(new_tx)) => {
                    transactions_to_resubmit.push(Ok((*id, new_tx)));
                }
                Ok(None) => {
                    // the transaction fee is still up-to-date but because the transaction did not get included,
                    // we re-send it as is to be sure that it remains known to the mempool and hopefully be included at some point.
                    // Since we always re-send the last non-included transactions in sent_tx, there is nothing to do.
                }
                Err(crate::tx::ResubmitTransactionError::InsufficientTransactionFee {
                    allowed_max_transaction_fee,
                    actual_max_transaction_fee,
                }) => {
                    transactions_to_resubmit.push(Err(
                        ResubmitTransactionError::InsufficientTransactionFee {
                            id: *id,
                            transaction_nonce: *nonce,
                            allowed_max_transaction_fee,
                            max_transaction_fee: actual_max_transaction_fee,
                        },
                    ));
                    return transactions_to_resubmit;
                }
            }
        }
        transactions_to_resubmit
    }

    pub fn record_resubmit_transaction(&mut self, new_tx: R::Transaction) {
        let nonce = new_tx.nonce();
        let (id, last_sent_tx) = Self::expect_last_sent_tx_entry(&self.sent_tx, &nonce);
        assert!(
            equal_ignoring_fee_and_amount(last_sent_tx.as_ref().transaction(), &new_tx),
            "BUG: mismatch between last sent transaction {last_sent_tx:?} and the transaction to resubmit {new_tx:?}"
        );
        Self::cleanup_failed_resubmitted_transactions(&mut self.created_tx, &nonce);
        let new_tx = last_sent_tx.clone_resubmission_strategy(new_tx);
        assert_eq!(self.created_tx.try_insert(nonce, *id, new_tx), Ok(()));
    }

    pub fn sent_transactions_to_finalize(
        &self,
        finalized_transaction_count: &TransactionCount,
    ) -> BTreeMap<Hash, R::Id> {
        let first_non_finalized_tx_nonce: TransactionNonce =
            finalized_transaction_count.change_units();
        let mut transactions = BTreeMap::new();
        for (_nonce, index, sent_txs) in self
            .sent_tx
            .iter()
            .filter(|(nonce, _id, _signed_txs)| *nonce < &first_non_finalized_tx_nonce)
        {
            for sent_tx in sent_txs {
                if let Some(prev_index) = transactions.insert(sent_tx.as_ref().hash(), *index) {
                    assert_eq!(
                        prev_index,
                        *index,
                        "BUG: duplicate transaction hash {} for ids {prev_index:?} and {index:?}",
                        sent_tx.as_ref().hash()
                    );
                }
            }
        }
        transactions
    }

    /// Move the transaction matching `receipt` into the finalized map and clean up its
    /// superseded resubmissions, returning the finalized transaction.
    pub fn record_finalized_transaction(
        &mut self,
        id: R::Id,
        receipt: &TransactionReceipt,
    ) -> Finalized<R::Transaction> {
        let sent_tx = self
            .sent_tx
            .get_alt(&id)
            .expect("BUG: missing sent transactions")
            .iter()
            .find(|sent_tx| sent_tx.as_ref().hash() == receipt.transaction_hash)
            .expect("ERROR: no transaction matching receipt");
        let finalized_tx = sent_tx
            .as_ref()
            .clone()
            .try_finalize(receipt.clone())
            .expect("ERROR: invalid transaction receipt");

        let nonce = sent_tx.as_ref().nonce();
        {
            self.sent_tx.remove_entry(&nonce);
            Self::cleanup_failed_resubmitted_transactions(&mut self.created_tx, &nonce);
        }
        assert_eq!(
            self.finalized_tx
                .try_insert(nonce, id, finalized_tx.clone()),
            Ok(())
        );
        finalized_tx
    }

    pub fn requests_batch(&self, requested_batch_size: usize) -> Vec<R> {
        // The number of pending transaction nonces is counted and not the number of pending transactions
        // because a nonce may be associated with several distinct transactions (due to re-submission and dynamic fees).
        // However, once a nonce is chosen for a request, it's in our interest that the corresponding transaction be finalized asap.
        // Limiting the number of transactions would be counter-productive.
        const MAX_NUM_PENDING_TRANSACTION_NONCES: usize = 1000;
        let unique_pending_transaction_nonces: BTreeSet<_> =
            self.created_tx.keys().chain(self.sent_tx.keys()).collect();
        let actual_batch_size = min(
            MAX_NUM_PENDING_TRANSACTION_NONCES
                .saturating_sub(unique_pending_transaction_nonces.len()),
            requested_batch_size,
        );
        self.requests_iter()
            .take(actual_batch_size)
            .cloned()
            .collect()
    }

    pub fn requests_iter(&self) -> impl Iterator<Item = &R> {
        self.pending_requests.iter()
    }

    pub fn requests_len(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn transactions_to_sign_iter(
        &self,
    ) -> impl Iterator<Item = (&TransactionNonce, &R::Id, &R::Transaction)> {
        self.created_tx
            .iter()
            .map(|(nonce, id, tx)| (nonce, id, tx.as_ref()))
    }

    pub fn transactions_to_sign_batch(&self, batch_size: usize) -> Vec<(R::Id, R::Transaction)> {
        self.transactions_to_sign_iter()
            .take(batch_size)
            .map(|(_nonce, id, tx)| (*id, tx.clone()))
            .collect()
    }

    pub fn transactions_to_send_batch(
        &self,
        latest_transaction_count: TransactionCount,
        batch_size: usize,
    ) -> Vec<Signed<R::Transaction>> {
        let first_pending_tx_nonce: TransactionNonce = latest_transaction_count.change_units();
        self.sent_tx
            .iter()
            .filter_map(move |(nonce, id, txs)| {
                txs.last()
                    .map(|tx| (nonce, id, tx))
                    .filter(|(nonce, _id, _tx)| *nonce >= &first_pending_tx_nonce)
            })
            .take(batch_size)
            .map(|(_nonce, _index, tx)| tx.as_ref())
            .cloned()
            .collect()
    }

    pub fn sent_transactions_iter(
        &self,
    ) -> impl Iterator<Item = (&TransactionNonce, &R::Id, Vec<&Signed<R::Transaction>>)> {
        self.sent_tx
            .iter()
            .map(|(nonce, index, txs)| (nonce, index, txs.iter().map(|tx| tx.as_ref()).collect()))
    }

    pub fn get_finalized_transaction(&self, id: &R::Id) -> Option<&Finalized<R::Transaction>> {
        self.finalized_tx.get_alt(id)
    }

    pub fn processed_requests_iter(&self) -> impl Iterator<Item = &R> {
        self.processed_requests.values()
    }

    /// How far the transaction for `id` has got, or `None` if the pipeline holds none.
    pub fn transaction_stage(&self, id: &R::Id) -> Option<TransactionStage<'_, R::Transaction>> {
        if let Some(tx) = self.created_tx.get_alt(id) {
            return Some(TransactionStage::Created(tx.as_ref()));
        }
        // The last one sent is the one with the highest fee, so it is the one that may be mined.
        if let Some(tx) = self.sent_tx.get_alt(id).and_then(|txs| txs.last()) {
            return Some(TransactionStage::Sent(tx));
        }
        self.finalized_tx
            .get_alt(id)
            .map(TransactionStage::Finalized)
    }

    pub fn get_processed_request(&self, id: &R::Id) -> Option<&R> {
        self.processed_requests.get(id)
    }

    pub fn finalized_transactions_iter(
        &self,
    ) -> impl Iterator<Item = (&TransactionNonce, &R::Id, &Finalized<R::Transaction>)> {
        self.finalized_tx.iter()
    }

    pub fn is_sent_tx_empty(&self) -> bool {
        self.sent_tx.is_empty()
    }

    pub fn has_pending_requests(&self) -> bool {
        !self.pending_requests.is_empty() || !self.created_tx.is_empty() || !self.sent_tx.is_empty()
    }

    fn expect_last_sent_tx_entry<'a>(
        sent_tx: &'a MultiKeyMap<TransactionNonce, R::Id, Vec<SentTransaction<R>>>,
        nonce: &TransactionNonce,
    ) -> (&'a R::Id, &'a SentTransaction<R>) {
        let (id, sent_txs) = sent_tx
            .get_entry(nonce)
            .expect("BUG: sent transaction not found");
        let last_sent_tx = sent_txs.last().expect("BUG: empty sent transactions list");
        (id, last_sent_tx)
    }

    fn cleanup_failed_resubmitted_transactions(
        created_tx: &mut MultiKeyMap<TransactionNonce, R::Id, CreatedTransaction<R>>,
        nonce: &TransactionNonce,
    ) {
        use crate::logs::INFO;
        use ic_canister_log::log;

        if let Some((_nonce, _index, prev_resubmitted_tx)) = created_tx.remove_entry(nonce) {
            log!(
                INFO,
                "[cleanup_failed_resubmitted_transactions]: removing previously resubmitted transaction {prev_resubmitted_tx:?} that failed to progress"
            );
        }
    }

    /// Checks whether two transaction state machines are equivalent.
    pub fn is_equivalent_to(&self, other: &Self) -> Result<(), String> {
        use ic_utils_ensure::ensure_eq;

        fn sorted_requests<R: PipelineRequest + Clone>(requests: &VecDeque<R>) -> Vec<R> {
            let mut buf: Vec<_> = requests.iter().cloned().collect();
            buf.sort_unstable_by_key(|req| req.id());
            buf
        }

        let Self {
            pending_requests,
            processed_requests,
            created_tx,
            sent_tx,
            finalized_tx,
            next_nonce,
        } = self;

        // We can reorder request in `reschedule_request`. The audit log won't
        // reflect this change, so we must sort the queues before comparing them.
        ensure_eq!(
            sorted_requests(pending_requests),
            sorted_requests(&other.pending_requests)
        );
        ensure_eq!(processed_requests, &other.processed_requests);
        ensure_eq!(created_tx, &other.created_tx);
        ensure_eq!(sent_tx, &other.sent_tx);
        ensure_eq!(finalized_tx, &other.finalized_tx);
        ensure_eq!(next_nonce, &other.next_nonce);

        Ok(())
    }
}

/// The minter's main-address pipeline, carrying user withdrawals, together with the reimbursement
/// bookkeeping that only a withdrawal can need: a failed ckETH/ckERC20 transaction pays the user
/// back, so the pipeline's send machinery and the ledger-side refund have to stay in step.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct WithdrawalTransactions {
    pipeline: MinterTransactionPipeline,
    /// Requests whose transaction was created but has not yet finally settled, and which would
    /// therefore have to be paid back if it failed.
    maybe_reimburse: BTreeSet<LedgerBurnIndex>,
    reimbursement_requests: BTreeMap<ReimbursementIndex, ReimbursementRequest>,
    reimbursed: BTreeMap<ReimbursementIndex, ReimbursedResult>,
}

impl WithdrawalTransactions {
    pub fn new(next_nonce: TransactionNonce) -> Self {
        Self {
            pipeline: TransactionPipeline::new(next_nonce),
            maybe_reimburse: Default::default(),
            reimbursement_requests: Default::default(),
            reimbursed: Default::default(),
        }
    }

    /// Record a created transaction, and remember that the request may still need paying back.
    pub fn record_created_transaction(
        &mut self,
        id: LedgerBurnIndex,
        transaction: Eip1559TransactionRequest,
    ) {
        self.pipeline.record_created_transaction(id, transaction);
        if self.is_reimbursable(&id) {
            assert!(self.maybe_reimburse.insert(id));
        }
    }

    /// Whether a failed transaction for this request would pay the requester back. A sweeper
    /// funding never is, so it is never armed for reimbursement in the first place.
    fn is_reimbursable(&self, withdrawal_id: &LedgerBurnIndex) -> bool {
        self.pipeline
            .get_processed_request(withdrawal_id)
            .expect("BUG: missing processed withdrawal request")
            .is_reimbursable()
    }

    /// Finalize the transaction for `ledger_burn_index` matching `receipt`, then — if it failed on
    /// chain — record the corresponding ckETH/ckERC20 reimbursement.
    pub fn record_finalized_transaction(
        &mut self,
        ledger_burn_index: LedgerBurnIndex,
        receipt: TransactionReceipt,
    ) {
        let finalized_tx = self
            .pipeline
            .record_finalized_transaction(ledger_burn_index, &receipt);
        if self.is_reimbursable(&ledger_burn_index) {
            assert!(
                self.maybe_reimburse.remove(&ledger_burn_index),
                "failed to remove entry from maybe_reimburse with block index: {ledger_burn_index}",
            );
        }

        let request = self
            .pipeline
            .get_processed_request(&ledger_burn_index)
            .expect("BUG: missing processed withdrawal request");
        if receipt.status != TransactionStatus::Failure {
            return;
        }
        let (index, reimbursement) = match request {
            WithdrawalRequest::CkEth(request) => (
                ReimbursementIndex::CkEth {
                    ledger_burn_index: request.ledger_burn_index,
                },
                ReimbursementRequest {
                    ledger_burn_index,
                    to: request.from,
                    to_subaccount: request.from_subaccount.clone(),
                    reimbursed_amount: finalized_tx.transaction_amount().change_units(),
                    transaction_hash: Some(receipt.transaction_hash),
                },
            ),
            WithdrawalRequest::CkErc20(request) => (
                ReimbursementIndex::CkErc20 {
                    cketh_ledger_burn_index: request.cketh_ledger_burn_index,
                    ledger_id: request.ckerc20_ledger_id,
                    ckerc20_ledger_burn_index: request.ckerc20_ledger_burn_index,
                },
                ReimbursementRequest {
                    ledger_burn_index: request.ckerc20_ledger_burn_index,
                    reimbursed_amount: request.withdrawal_amount.change_units(),
                    to: request.from,
                    to_subaccount: request.from_subaccount.clone(),
                    transaction_hash: Some(receipt.transaction_hash),
                },
            ),
            WithdrawalRequest::SweeperFunding(request) => {
                // A funding is a plain transfer to an address derived from the minter's own key,
                // so there is no code for it to revert in: reaching this means an assumption
                // broke. Logged rather than trapped, since the accounting holds either way — the
                // burn stays burned, and of the ETH it covered only the gas of the failed
                // transaction actually left the main address.
                log!(
                    INFO,
                    "[record_finalized_transaction]: UNEXPECTED: sweeper funding {} of {} to {} \
                     FAILED (tx {}), which should be impossible for a transfer to an address the \
                     minter controls; the burn is NOT reimbursed: no ETH reached the sweeper, the \
                     failed transaction still paid {} of gas, and the rest of the burn now \
                     over-backs ckETH",
                    ledger_burn_index,
                    request.withdrawal_amount,
                    request.destination,
                    receipt.transaction_hash,
                    receipt.effective_transaction_fee(),
                );
                return;
            }
        };
        self.record_reimbursement_request(index, reimbursement);
    }

    pub fn is_equivalent_to(&self, other: &Self) -> Result<(), String> {
        use ic_utils_ensure::ensure_eq;

        let Self {
            pipeline,
            maybe_reimburse,
            reimbursement_requests,
            reimbursed,
        } = self;

        ensure_eq!(maybe_reimburse, &other.maybe_reimburse);
        ensure_eq!(reimbursement_requests, &other.reimbursement_requests);
        ensure_eq!(reimbursed, &other.reimbursed);
        pipeline.is_equivalent_to(&other.pipeline)
    }

    pub fn next_transaction_nonce(&self) -> TransactionNonce {
        self.pipeline.next_transaction_nonce()
    }

    pub fn update_next_transaction_nonce(&mut self, new_nonce: TransactionNonce) {
        self.pipeline.update_next_transaction_nonce(new_nonce)
    }

    pub fn record_request<Req: Into<WithdrawalRequest>>(&mut self, request: Req) {
        self.pipeline.record_request(request)
    }

    pub fn reschedule_request(&mut self, id: LedgerBurnIndex) {
        self.pipeline.reschedule_request(id)
    }

    pub fn record_signed_transaction(
        &mut self,
        signed_transaction: SignedEip1559TransactionRequest,
    ) {
        self.pipeline.record_signed_transaction(signed_transaction)
    }

    pub fn create_resubmit_transactions(
        &self,
        latest_transaction_count: TransactionCount,
        current_gas_fee: GasFeeEstimate,
    ) -> Vec<ResubmitResult<LedgerBurnIndex, Eip1559TransactionRequest>> {
        self.pipeline
            .create_resubmit_transactions(latest_transaction_count, current_gas_fee)
    }

    pub fn record_resubmit_transaction(&mut self, new_tx: Eip1559TransactionRequest) {
        self.pipeline.record_resubmit_transaction(new_tx)
    }

    pub fn sent_transactions_to_finalize(
        &self,
        finalized_transaction_count: &TransactionCount,
    ) -> BTreeMap<Hash, LedgerBurnIndex> {
        self.pipeline
            .sent_transactions_to_finalize(finalized_transaction_count)
    }

    pub fn requests_batch(&self, requested_batch_size: usize) -> Vec<WithdrawalRequest> {
        self.pipeline.requests_batch(requested_batch_size)
    }

    pub fn requests_iter(&self) -> impl Iterator<Item = &WithdrawalRequest> {
        self.pipeline.requests_iter()
    }

    /// The sweeper funding whose transaction has not finalized yet, if any.
    ///
    /// Read off the pipeline rather than tracked next to it, so the two cannot disagree, and walked
    /// from the furthest stage backwards, so that two outstanding fundings report the older one.
    pub fn outstanding_sweeper_funding(&self) -> Option<&EthWithdrawalRequest> {
        fn as_funding(request: &WithdrawalRequest) -> Option<&EthWithdrawalRequest> {
            match request {
                WithdrawalRequest::SweeperFunding(request) => Some(request),
                WithdrawalRequest::CkEth(_) | WithdrawalRequest::CkErc20(_) => None,
            }
        }

        self.pipeline
            .sent_tx
            .alt_keys()
            .chain(self.pipeline.created_tx.alt_keys())
            .filter_map(|id| self.pipeline.processed_requests.get(id))
            .chain(self.pipeline.pending_requests.iter())
            .find_map(as_funding)
    }

    pub fn requests_len(&self) -> usize {
        self.pipeline.requests_len()
    }

    pub fn transactions_to_sign_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            &Eip1559TransactionRequest,
        ),
    > {
        self.pipeline.transactions_to_sign_iter()
    }

    pub fn transactions_to_sign_batch(
        &self,
        batch_size: usize,
    ) -> Vec<(LedgerBurnIndex, Eip1559TransactionRequest)> {
        self.pipeline.transactions_to_sign_batch(batch_size)
    }

    pub fn transactions_to_send_batch(
        &self,
        latest_transaction_count: TransactionCount,
        batch_size: usize,
    ) -> Vec<SignedEip1559TransactionRequest> {
        self.pipeline
            .transactions_to_send_batch(latest_transaction_count, batch_size)
    }

    pub fn sent_transactions_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            Vec<&SignedEip1559TransactionRequest>,
        ),
    > {
        self.pipeline.sent_transactions_iter()
    }

    pub fn get_finalized_transaction(
        &self,
        burn_index: &LedgerBurnIndex,
    ) -> Option<&FinalizedEip1559Transaction> {
        self.pipeline.get_finalized_transaction(burn_index)
    }

    pub fn get_processed_request(
        &self,
        burn_index: &LedgerBurnIndex,
    ) -> Option<&WithdrawalRequest> {
        self.pipeline.get_processed_request(burn_index)
    }

    pub fn finalized_transactions_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &TransactionNonce,
            &LedgerBurnIndex,
            &FinalizedEip1559Transaction,
        ),
    > {
        self.pipeline.finalized_transactions_iter()
    }

    pub fn is_sent_tx_empty(&self) -> bool {
        self.pipeline.is_sent_tx_empty()
    }

    pub fn has_pending_requests(&self) -> bool {
        self.pipeline.has_pending_requests()
    }

    pub fn reimbursement_requests_iter(
        &self,
    ) -> impl Iterator<Item = (&ReimbursementIndex, &ReimbursementRequest)> {
        self.reimbursement_requests.iter()
    }

    pub fn reimbursed_transactions_iter(
        &self,
    ) -> impl Iterator<Item = (&ReimbursementIndex, &ReimbursedResult)> {
        self.reimbursed.iter()
    }

    fn find_reimbursed_transaction_by_cketh_ledger_burn_index(
        &self,
        searched_burn_index: &LedgerBurnIndex,
    ) -> Option<&ReimbursedResult> {
        self.reimbursed
            .iter()
            .find_map(|(index, value)| match index {
                ReimbursementIndex::CkEth { ledger_burn_index }
                    if ledger_burn_index == searched_burn_index =>
                {
                    Some(value)
                }
                ReimbursementIndex::CkErc20 {
                    cketh_ledger_burn_index,
                    ..
                } if cketh_ledger_burn_index == searched_burn_index => Some(value),
                _ => None,
            })
    }

    /// Quarantine the reimbursement request identified by its index to prevent double minting.
    /// WARNING!: It's crucial that this method does not panic,
    /// since it's called inside the clean-up callback, when an unexpected panic did occur before.
    pub fn record_quarantined_reimbursement(&mut self, index: ReimbursementIndex) {
        self.reimbursement_requests.remove(&index);
        self.reimbursed
            .insert(index, Err(ReimbursedError::Quarantined));
    }

    pub fn record_finalized_reimbursement(
        &mut self,
        index: ReimbursementIndex,
        reimbursed_in_block: LedgerMintIndex,
    ) {
        let reimbursement_request = self
            .reimbursement_requests
            .remove(&index)
            .unwrap_or_else(|| panic!("BUG: missing reimbursement request with index {index:?}"));
        let burn_in_block = index.burn_in_block();
        assert_eq!(
            self.reimbursed.insert(
                index,
                Ok(Reimbursed {
                    burn_in_block,
                    reimbursed_in_block,
                    reimbursed_amount: reimbursement_request.reimbursed_amount,
                    transaction_hash: reimbursement_request.transaction_hash,
                }),
            ),
            None
        );
    }

    /// Arm the reimbursement for a withdrawal whose transaction failed on chain.
    ///
    /// # Panics
    /// If the withdrawal is still armed for reimbursement, or was already reimbursed — either
    /// would let the same burn be minted back twice.
    pub fn record_reimbursement_request(
        &mut self,
        index: ReimbursementIndex,
        request: ReimbursementRequest,
    ) {
        assert_eq!(
            self.maybe_reimburse.get(&index.withdrawal_id()),
            None,
            "BUG: withdrawal request still in maybe_reimburse could lead to double minting!"
        );
        assert_eq!(
            self.reimbursed.get(&index),
            None,
            "BUG: reimbursement request was already processed"
        );
        assert_eq!(
            self.reimbursement_requests.insert(index.clone(), request),
            None,
            "BUG: reimbursement request for withdrawal {index:?} already exists"
        );
    }

    fn maybe_reimburse_requests_iter(&self) -> impl Iterator<Item = &WithdrawalRequest> {
        self.maybe_reimburse
            .iter()
            .filter_map(|index| self.pipeline.get_processed_request(index))
    }

    /// Whether any request is still in flight, either awaiting a transaction or a reimbursement.
    pub fn oldest_incomplete_request_timestamp(&self) -> Option<u64> {
        self.requests_iter()
            .chain(self.maybe_reimburse_requests_iter())
            .flat_map(|req| req.created_at().into_iter())
            .min()
    }

    pub fn withdrawal_status(
        &self,
        parameter: &WithdrawalSearchParameter,
    ) -> Vec<(
        &WithdrawalRequest,
        WithdrawalStatus,
        Option<&Eip1559TransactionRequest>,
    )> {
        // Pending requests matching the given search parameter
        let pending = self.pipeline.requests_iter().filter_map(|r| {
            r.match_parameter(parameter)
                .then_some((r, WithdrawalStatus::Pending, None))
        });

        // Processed withdrawal requests matching the given search parameter.
        let processed = self
            .pipeline
            .processed_requests_iter()
            .filter(|r| r.match_parameter(parameter))
            .map(|request| {
                match self.processed_transaction_status(&request.cketh_ledger_burn_index()) {
                    (RetrieveEthStatus::TxCreated, Some(tx)) => {
                        (request, WithdrawalStatus::TxCreated, Some(tx))
                    }
                    (RetrieveEthStatus::TxSent(sent), Some(tx)) => {
                        (request, WithdrawalStatus::TxSent(sent), Some(tx))
                    }
                    (RetrieveEthStatus::TxFinalized(status), Some(tx)) => {
                        (request, WithdrawalStatus::TxFinalized(status), Some(tx))
                    }
                    _ => {
                        panic!("Status of processed request is not found {request:?}")
                    }
                }
            });

        pending.chain(processed).collect()
    }

    pub fn transaction_status(&self, burn_index: &LedgerBurnIndex) -> RetrieveEthStatus {
        if self
            .pipeline
            .requests_iter()
            .any(|r| &r.cketh_ledger_burn_index() == burn_index)
        {
            return RetrieveEthStatus::Pending;
        }
        self.processed_transaction_status(burn_index).0
    }

    fn processed_transaction_status(
        &self,
        burn_index: &LedgerBurnIndex,
    ) -> (RetrieveEthStatus, Option<&Eip1559TransactionRequest>) {
        let tx = match self.pipeline.transaction_stage(burn_index) {
            Some(TransactionStage::Created(tx)) => return (RetrieveEthStatus::TxCreated, Some(tx)),
            Some(TransactionStage::Sent(tx)) => {
                return (
                    RetrieveEthStatus::TxSent(EthTransaction::from(tx.as_ref())),
                    Some(tx.as_ref().as_ref()),
                );
            }
            Some(TransactionStage::Finalized(tx)) => tx,
            None => return (RetrieveEthStatus::NotFound, None),
        };

        if let Some(Ok(reimbursed)) =
            self.find_reimbursed_transaction_by_cketh_ledger_burn_index(burn_index)
        {
            return (
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Reimbursed {
                    reimbursed_in_block: reimbursed.reimbursed_in_block.get().into(),
                    transaction_hash: tx.transaction_hash().to_string(),
                    reimbursed_amount: reimbursed.reimbursed_amount.into(),
                }),
                Some(tx.as_ref()),
            );
        }
        if tx.transaction_status() == &TransactionStatus::Failure {
            // Unreachable for a funding: the destination is derived from the minter's own
            // key, so a bare transfer there has no code to revert in. Were it reached, the
            // status would be wrong, since nothing reimburses a funding — tolerable only
            // because it cannot happen, and not worth a status of its own, which would mean
            // adding a variant to `retrieve_eth_status`' return type and breaking existing
            // clients. Revisit if funding ever goes through a contract, where a revert becomes
            // possible.
            return (
                RetrieveEthStatus::TxFinalized(TxFinalizedStatus::PendingReimbursement(
                    EthTransaction {
                        transaction_hash: tx.transaction_hash().to_string(),
                    },
                )),
                Some(tx.as_ref()),
            );
        }

        (
            RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Success {
                transaction_hash: tx.transaction_hash().to_string(),
                effective_transaction_fee: Some(tx.effective_transaction_fee().into()),
            }),
            Some(tx.as_ref()),
        )
    }
}

// First 4 bytes of keccak256(transfer(address,uint256))
const ERC_20_TRANSFER_FUNCTION_SELECTOR: [u8; 4] = hex_literal::hex!("a9059cbb");

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum TransactionCallData {
    Erc20Transfer { to: Address, value: Erc20Value },
}

impl TransactionCallData {
    /// Encode the transaction call data to interact with an Ethereum smart contract.
    /// See the [Contract ABI Specification](https://docs.soliditylang.org/en/develop/abi-spec.html#contract-abi-specification).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            TransactionCallData::Erc20Transfer { to, value } => {
                let mut data = Vec::with_capacity(68);
                data.extend(ERC_20_TRANSFER_FUNCTION_SELECTOR);
                data.extend(<[u8; 32]>::from(to));
                data.extend(value.to_be_bytes());
                data
            }
        }
    }

    pub fn decode<T: AsRef<[u8]>>(data: T) -> Result<Self, String> {
        let data = data.as_ref();
        match data.get(0..4) {
            Some(selector) if selector == ERC_20_TRANSFER_FUNCTION_SELECTOR => {
                if data.len() != 68 {
                    return Err("Invalid data length".to_string());
                }
                let address = <[u8; 32]>::try_from(&data[4..36]).unwrap();
                let to = Address::try_from(&address).unwrap();

                let value = <[u8; 32]>::try_from(&data[36..]).unwrap();
                let value = Erc20Value::from_be_bytes(value);

                Ok(TransactionCallData::Erc20Transfer { to, value })
            }
            Some(selector) => Err(format!(
                "Unknown function selector 0x{:?}",
                hex::encode(selector)
            )),
            None => Err("missing function selector".to_string()),
        }
    }
}

/// Returns true if the two transactions are equal ignoring the transaction fee and amount.
/// The following fields are ignored:
/// * `max_fee_per_gas`
/// * `max_priority_fee_per_gas`
/// * `amount` (because the cost of the transaction is paid by the beneficiary and so influencing the fee does influence the transaction amount)
fn equal_ignoring_fee_and_amount<T: SignableTransaction + Eq>(lhs: &T, rhs: &T) -> bool {
    let rhs_with_lhs_fee_and_amount = rhs.with_price_and_amount(
        TransactionPrice {
            gas_limit: rhs.gas_limit(),
            max_fee_per_gas: lhs.max_fee_per_gas(),
            max_priority_fee_per_gas: lhs.max_priority_fee_per_gas(),
        },
        *lhs.amount(),
    );

    lhs == &rhs_with_lhs_fee_and_amount
}
