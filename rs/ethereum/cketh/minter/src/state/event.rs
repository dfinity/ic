use crate::attestation::AttestationRequest;
use crate::deposit_address::DepositAddress;
use crate::erc20::CkErc20Token;
use crate::eth_logs::{EventSource, ReceivedErc20Event, ReceivedEthEvent, ReceivedEvent};
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::lifecycle::{init::InitArg, upgrade::UpgradeArg};
use crate::numeric::{BlockNumber, Erc20Value, LedgerBurnIndex, LedgerMintIndex};
use crate::state::transactions::{
    Erc20WithdrawalRequest, EthWithdrawalRequest, Reimbursed, ReimbursementIndex,
    ReimbursementRequest, SweepId, SweepRequest,
};
use crate::timed_sized_map::Timestamp;
use crate::tx::{
    AuthorizationRequest, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    SignedSweepTransaction, SweepTransaction, TransactionSignature,
};
use candid::Principal;
use ic_ethereum_types::Address;
use minicbor::{Decode, Encode};

/// The event describing the ckETH minter state transition.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub enum EventType {
    /// The minter initialization event.
    /// Must be the first event in the log.
    #[n(0)]
    Init(#[n(0)] InitArg),
    /// The minter upgraded with the specified arguments.
    #[n(1)]
    Upgrade(#[n(0)] UpgradeArg),
    /// The minter discovered a ckETH deposit in the helper contract logs.
    #[n(2)]
    AcceptedDeposit(#[n(0)] ReceivedEthEvent),
    /// The minter discovered an invalid ckETH deposit in the helper contract logs.
    #[n(4)]
    InvalidDeposit {
        /// The unique identifier of the deposit on the Ethereum network.
        #[n(0)]
        event_source: EventSource,
        /// The reason why minter considers the deposit invalid.
        #[n(1)]
        reason: String,
    },
    /// The minter minted ckETH in response to a deposit.
    #[n(5)]
    MintedCkEth {
        /// The unique identifier of the deposit on the Ethereum network.
        #[n(0)]
        event_source: EventSource,
        /// The transaction index on the ckETH ledger.
        #[cbor(n(1), with = "crate::cbor::id")]
        mint_block_index: LedgerMintIndex,
    },
    /// The minter processed the helper smart contract logs up to the specified height.
    #[n(6)]
    SyncedToBlock {
        /// The last processed block number for ETH helper contract (inclusive).
        #[n(0)]
        block_number: BlockNumber,
    },
    /// The minter accepted a new ETH withdrawal request.
    #[n(7)]
    AcceptedEthWithdrawalRequest(#[n(0)] EthWithdrawalRequest),
    /// The minter created a new transaction to handle a withdrawal request.
    #[n(8)]
    CreatedTransaction {
        #[cbor(n(0), with = "crate::cbor::id")]
        withdrawal_id: LedgerBurnIndex,
        #[n(1)]
        transaction: Eip1559TransactionRequest,
    },
    /// The minter signed a transaction.
    #[n(9)]
    SignedTransaction {
        /// The withdrawal identifier.
        #[cbor(n(0), with = "crate::cbor::id")]
        withdrawal_id: LedgerBurnIndex,
        /// The signed transaction.
        #[n(1)]
        transaction: SignedEip1559TransactionRequest,
    },
    /// The minter created a new transaction to handle an existing withdrawal request.
    #[n(10)]
    ReplacedTransaction {
        /// The withdrawal identifier.
        #[cbor(n(0), with = "crate::cbor::id")]
        withdrawal_id: LedgerBurnIndex,
        /// The replacement transaction.
        #[n(1)]
        transaction: Eip1559TransactionRequest,
    },
    /// The minter observed the transaction being included in a finalized Ethereum block.
    #[n(11)]
    FinalizedTransaction {
        /// The withdrawal identifier.
        #[cbor(n(0), with = "crate::cbor::id")]
        withdrawal_id: LedgerBurnIndex,
        /// The receipt for the finalized transaction.
        #[n(1)]
        transaction_receipt: TransactionReceipt,
    },
    /// The minter successfully reimbursed a failed withdrawal
    /// or the transaction fee associated with a ckERC20 withdrawal.
    #[n(12)]
    ReimbursedEthWithdrawal(#[n(0)] Reimbursed),
    /// Add a new ckERC20 token.
    #[n(14)]
    AddedCkErc20Token(#[n(0)] CkErc20Token),
    /// The minter discovered a ckERC20 deposit in the helper contract logs.
    #[n(15)]
    AcceptedErc20Deposit(#[n(0)] ReceivedErc20Event),
    /// The minter accepted a new ERC-20 withdrawal request.
    #[n(16)]
    AcceptedErc20WithdrawalRequest(#[n(0)] Erc20WithdrawalRequest),
    #[n(17)]
    MintedCkErc20 {
        /// The unique identifier of the deposit on the Ethereum network.
        #[n(0)]
        event_source: EventSource,
        /// The transaction index on the ckETH ledger.
        #[cbor(n(1), with = "crate::cbor::id")]
        mint_block_index: LedgerMintIndex,
        #[n(2)]
        ckerc20_token_symbol: String,
        #[n(3)]
        erc20_contract_address: Address,
    },
    /// The minter processed the helper smart contract logs up to the specified height.
    #[n(18)]
    SyncedErc20ToBlock {
        /// The last processed block number for ERC20 helper contract (inclusive).
        #[n(0)]
        block_number: BlockNumber,
    },
    #[n(19)]
    ReimbursedErc20Withdrawal {
        #[cbor(n(0), with = "crate::cbor::id")]
        cketh_ledger_burn_index: LedgerBurnIndex,
        #[cbor(n(1), with = "icrc_cbor::principal")]
        ckerc20_ledger_id: Principal,
        #[n(2)]
        reimbursed: Reimbursed,
    },
    /// The minter could not burn the given amount of ckERC20 tokens.
    #[n(20)]
    FailedErc20WithdrawalRequest(#[n(0)] ReimbursementRequest),
    /// The minter unexpectedly panic while processing a deposit.
    /// The deposit is quarantined to prevent any double minting and
    /// will not be processed without further manual intervention.
    #[n(21)]
    QuarantinedDeposit {
        /// The unique identifier of the deposit on the Ethereum network.
        #[n(0)]
        event_source: EventSource,
    },
    /// The minter unexpectedly panic while processing a reimbursement.
    /// The reimbursement is quarantined to prevent any double minting and
    /// will not be processed without further manual intervention.
    #[n(22)]
    QuarantinedReimbursement {
        /// The unique identifier of the reimbursement.
        #[n(0)]
        index: ReimbursementIndex,
    },
    /// Skipped block for a specific helper contract.
    #[n(23)]
    SkippedBlockForContract {
        #[n(0)]
        contract_address: Address,
        #[n(1)]
        block_number: BlockNumber,
    },
    /// The minter processed the deposit helper smart contract with subaccount logs up to the specified height.
    #[n(24)]
    SyncedDepositWithSubaccountToBlock {
        /// The last processed block number for the helper contract (inclusive).
        #[n(0)]
        block_number: BlockNumber,
    },
    /// Full snapshot of the ckERC20 deposit addresses registered via `deposit_erc20`.
    /// Emitted at pre-upgrade and replayed to restore the in-heap registry.
    #[n(25)]
    RegisteredDepositAddresses(#[n(0)] DepositAddressRegistry),
    /// A funded `(account, token)` pair was found by a balance scan and moved out of the
    /// watchlist into the balance-sweep queue. Recorded the moment the funds are detected, so
    /// the sweep queue is durable even across an ungraceful trap (unlike the pre-upgrade
    /// snapshot).
    #[n(26)]
    AutomaticDepositReceived(#[n(0)] AutomaticDeposit),
    /// The minter burned ckETH from its fee subaccount to top up the sweeper address with gas.
    #[n(27)]
    AcceptedSweeperFundingRequest(#[n(0)] EthWithdrawalRequest),
    /// The minter enqueued a sweep to be sent from its dedicated sweeper address.
    #[n(28)]
    AcceptedSweepRequest(#[n(0)] SweepRequest),
    /// The minter created a sweep transaction.
    #[n(29)]
    CreatedSweeperTransaction {
        #[n(0)]
        sweep_id: SweepId,
        #[n(1)]
        transaction: SweepTransaction,
    },
    /// The minter signed a sweep transaction.
    #[n(30)]
    SignedSweeperTransaction {
        #[n(0)]
        sweep_id: SweepId,
        #[n(1)]
        transaction: SignedSweepTransaction,
    },
    /// The minter replaced a sweep transaction after a fee bump.
    #[n(31)]
    ReplacedSweeperTransaction {
        #[n(0)]
        sweep_id: SweepId,
        #[n(1)]
        transaction: SweepTransaction,
    },
    /// The minter observed a sweep transaction being included in a finalized Ethereum block.
    #[n(32)]
    FinalizedSweeperTransaction {
        #[n(0)]
        sweep_id: SweepId,
        #[n(1)]
        transaction_receipt: TransactionReceipt,
    },
    /// A deposit address attested to the account it credits. Signing costs a threshold-ECDSA
    /// signature and can fail, so it is recorded on its own rather than with the sweep that
    /// needed it: the attestation outlives that sweep and every later one reuses it.
    #[n(33)]
    AttestedDepositAddress {
        /// What was signed, which is also what replay keys the attestation by: a signature is only
        /// usable for the chain, the deposit helper and the account named here.
        #[n(0)]
        request: AttestationRequest,
        #[n(1)]
        signature: TransactionSignature,
    },
    /// A deposit address authorized the sweeper contract to run as its code. Signing costs a
    /// threshold-ECDSA signature, so the tuple is recorded and every later sweep of the same
    /// address reuses it rather than signing another.
    #[n(34)]
    AuthorizedDepositAddress {
        /// What was signed, which is also what replay keys the authorization by: a signature is
        /// only usable for the chain, the delegate and the nonce named here.
        #[n(0)]
        request: AuthorizationRequest,
        #[n(1)]
        signature: TransactionSignature,
    },
}

/// Full snapshot of the ckERC20 deposit address registry. Carries the limits in
/// force when it was taken (`scan_window_nanos` = the watchlist ttl, `capacity`
/// = the maximum number of armed addresses) so the watchlist is rebuilt exactly
/// on replay. Changing these limits across canister versions is deliberately
/// left for future work.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct DepositAddressRegistry {
    #[n(0)]
    pub scan_window_nanos: u64,
    #[n(1)]
    pub capacity: u64,
    /// Registered addresses in time-index order (ascending expiry, insertion
    /// order within a shared expiry), as produced by `watchlist_snapshot`.
    #[n(2)]
    pub registrations: Vec<DepositAddressRegistration>,
}

/// Payload of [`EventType::AutomaticDepositReceived`]: a funded `(account, token)` pair moved
/// into the balance-sweep queue by a balance scan, together with the balance detected. One
/// event per funded pair, so replaying it removes the pair from the watchlist and queues it
/// for sweeping.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct AutomaticDeposit {
    #[cbor(n(0), with = "icrc_cbor::principal")]
    pub owner: Principal,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub subaccount: Option<[u8; 32]>,
    #[n(2)]
    pub address: DepositAddress,
    #[n(3)]
    pub erc20_contract_address: Address,
    #[n(4)]
    pub last_scanned_block: BlockNumber,
    #[n(5)]
    pub scan_count: u32,
    /// The balance detected for `erc20_contract_address` at `last_scanned_block`.
    #[n(6)]
    pub scanned_balance: Erc20Value,
}

/// A single entry of the ckERC20 deposit registry snapshot.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct DepositAddressRegistration {
    #[cbor(n(0), with = "icrc_cbor::principal")]
    pub owner: Principal,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub subaccount: Option<[u8; 32]>,
    #[n(2)]
    pub address: DepositAddress,
    #[n(3)]
    pub erc20_contract_address: Address,
    #[n(4)]
    pub expires_at_nanos: Timestamp,
    /// Latest block number at which this pair's balance was scanned; `None` if
    /// never scanned.
    #[n(5)]
    pub last_scanned_block: Option<BlockNumber>,
    /// How many times this pair has been scanned.
    #[n(6)]
    pub scan_count: u32,
}

impl ReceivedEvent {
    pub fn into_deposit(self) -> EventType {
        match self {
            ReceivedEvent::Eth(event) => EventType::AcceptedDeposit(event),
            ReceivedEvent::Erc20(event) => EventType::AcceptedErc20Deposit(event),
        }
    }
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
pub struct Event {
    /// The canister time at which the minter generated this event.
    #[n(0)]
    pub timestamp: u64,
    /// The event type.
    #[n(1)]
    pub payload: EventType,
}
