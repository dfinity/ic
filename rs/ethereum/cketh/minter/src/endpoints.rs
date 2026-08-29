use crate::CKETH_LEDGER_MEMO_SIZE;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::ledger_client::LedgerBurnError;
use crate::memo;
use crate::numeric::LedgerBurnIndex;
use crate::state::{transactions, transactions::EthWithdrawalRequest};
use crate::tx::{SignedEip1559TransactionRequest, TransactionPrice};
use candid::{CandidType, Deserialize, Nat, Principal};
use evm_rpc_types::BlockTag;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use minicbor::{Decode, Encode};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub mod ckerc20;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct Eip1559TransactionPriceArg {
    pub ckerc20_ledger_id: Principal,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct Eip1559TransactionPrice {
    pub gas_limit: Nat,
    pub max_fee_per_gas: Nat,
    pub max_priority_fee_per_gas: Nat,
    pub max_transaction_fee: Nat,
    pub timestamp: Option<u64>,
}

impl From<TransactionPrice> for Eip1559TransactionPrice {
    fn from(value: TransactionPrice) -> Self {
        Self {
            gas_limit: value.gas_limit.into(),
            max_fee_per_gas: value.max_fee_per_gas.into(),
            max_priority_fee_per_gas: value.max_priority_fee_per_gas.into(),
            max_transaction_fee: value.max_transaction_fee().into(),
            timestamp: None,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Deserialize)]
pub struct CkErc20Token {
    pub ckerc20_token_symbol: String,
    pub erc20_contract_address: String,
    pub ledger_canister_id: Principal,
}

impl From<crate::erc20::CkErc20Token> for CkErc20Token {
    fn from(value: crate::erc20::CkErc20Token) -> Self {
        Self {
            ckerc20_token_symbol: value.ckerc20_token_symbol.to_string(),
            erc20_contract_address: value.erc20_contract_address.to_string(),
            ledger_canister_id: value.ckerc20_ledger_id,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Deserialize)]
pub struct Erc20Balance {
    pub erc20_contract_address: String,
    pub balance: Nat,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, CandidType, Deserialize)]
pub struct Erc20MinimumDeposit {
    pub erc20_contract_address: String,
    pub minimum_deposit_amount: Nat,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct MinterInfo {
    pub minter_address: Option<String>,
    pub sweeper_address: Option<String>,
    #[deprecated(note = "use eth_helper_contract_address instead")]
    pub smart_contract_address: Option<String>,
    pub eth_helper_contract_address: Option<String>,
    pub erc20_helper_contract_address: Option<String>,
    pub deposit_with_subaccount_helper_contract_address: Option<String>,
    pub sweeper_contract_address: Option<String>,
    pub supported_ckerc20_tokens: Option<Vec<CkErc20Token>>,
    pub minimum_withdrawal_amount: Option<Nat>,
    pub ethereum_block_height: Option<CandidBlockTag>,
    pub last_observed_block_number: Option<Nat>,
    pub eth_balance: Option<Nat>,
    pub last_gas_fee_estimate: Option<GasFeeEstimate>,
    pub erc20_balances: Option<Vec<Erc20Balance>>,
    pub minimum_deposit_amounts: Option<Vec<Erc20MinimumDeposit>>,
    pub last_eth_scraped_block_number: Option<Nat>,
    pub last_erc20_scraped_block_number: Option<Nat>,
    pub last_deposit_with_subaccount_scraped_block_number: Option<Nat>,
    pub cketh_ledger_id: Option<Principal>,
    pub evm_rpc_id: Option<Principal>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct GasFeeEstimate {
    pub max_fee_per_gas: Nat,
    pub max_priority_fee_per_gas: Nat,
    pub timestamp: u64,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct EthTransaction {
    pub transaction_hash: String,
}

impl From<&SignedEip1559TransactionRequest> for EthTransaction {
    fn from(value: &SignedEip1559TransactionRequest) -> Self {
        Self {
            transaction_hash: value.hash().to_string(),
        }
    }
}

impl From<&TransactionReceipt> for EthTransaction {
    fn from(receipt: &TransactionReceipt) -> Self {
        Self {
            transaction_hash: receipt.transaction_hash.to_string(),
        }
    }
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveEthRequest {
    pub block_index: Nat,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Decode, Deserialize, Encode)]
#[cbor(index_only)]
pub enum CandidBlockTag {
    /// The latest mined block.
    #[default]
    #[cbor(n(0))]
    Latest,
    /// The latest safe head block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    #[cbor(n(1))]
    Safe,
    /// The latest finalized block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    #[cbor(n(2))]
    Finalized,
}

impl From<CandidBlockTag> for BlockTag {
    fn from(block_tag: CandidBlockTag) -> BlockTag {
        match block_tag {
            CandidBlockTag::Latest => BlockTag::Latest,
            CandidBlockTag::Safe => BlockTag::Safe,
            CandidBlockTag::Finalized => BlockTag::Finalized,
        }
    }
}

impl From<EthWithdrawalRequest> for RetrieveEthRequest {
    fn from(value: EthWithdrawalRequest) -> Self {
        Self {
            block_index: Nat::from(value.ledger_burn_index.get()),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum RetrieveEthStatus {
    NotFound,
    Pending,
    TxCreated,
    TxSent(EthTransaction),
    TxFinalized(TxFinalizedStatus),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum TxFinalizedStatus {
    Success {
        transaction_hash: String,
        effective_transaction_fee: Option<Nat>,
    },
    PendingReimbursement(EthTransaction),
    Reimbursed {
        transaction_hash: String,
        reimbursed_amount: Nat,
        reimbursed_in_block: Nat,
    },
}

impl Display for RetrieveEthStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RetrieveEthStatus::NotFound => write!(f, "Not Found"),
            RetrieveEthStatus::Pending => write!(f, "Pending"),
            RetrieveEthStatus::TxCreated => write!(f, "Created"),
            RetrieveEthStatus::TxSent(tx) => write!(f, "Sent({})", tx.transaction_hash),
            RetrieveEthStatus::TxFinalized(tx_status) => match tx_status {
                TxFinalizedStatus::Success {
                    transaction_hash, ..
                } => write!(f, "Confirmed({transaction_hash})"),
                TxFinalizedStatus::PendingReimbursement(tx) => {
                    write!(f, "PendingReimbursement({})", tx.transaction_hash)
                }
                TxFinalizedStatus::Reimbursed {
                    reimbursed_in_block,
                    transaction_hash,
                    reimbursed_amount,
                } => write!(
                    f,
                    "Failure({transaction_hash}, reimbursed: {reimbursed_amount} Wei in block: {reimbursed_in_block})"
                ),
            },
        }
    }
}

#[derive(CandidType, Deserialize)]
pub struct WithdrawalArg {
    pub amount: Nat,
    pub recipient: String,
    pub from_subaccount: Option<Subaccount>,
}

/// Argument for the `deposit_erc20` endpoint.
#[derive(CandidType, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DepositErc20Arg {
    /// The Ethereum ERC-20 contract address of the token to deposit (e.g. USDC). Traps if it
    /// cannot be parsed as an Ethereum address. Must be a ckERC20 token supported by the minter.
    pub erc20_contract_address: String,
    pub mode: DepositMode,
}

/// How the fee for a ckERC20 deposit address registration is settled.
#[derive(CandidType, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum DepositMode {
    /// The registration fee is deducted from the deposited amount. The deposit
    /// address is derived from the caller's principal and the given subaccount.
    Unsponsored { subaccount: Option<[u8; 32]> },
    // TODO(DEFI-2927): a sponsor pays the registration fee upfront so the user
    // receives the full deposited amount.
    // Sponsored {
    //     from_subaccount: Option<[u8; 32]>,
    //     max_fee: Nat,
    // },
}

/// Response of the `deposit_erc20` endpoint.
#[derive(CandidType, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DepositErc20Response {
    /// The Ethereum deposit address derived for the caller.
    pub address: String,
    /// Minimum balance, in the token's own units, that the deposit address must hold for the
    /// balance scan to detect it. The scan reads the address' whole balance for the token, so
    /// several smaller transfers count together; the funds stay undetected only while their
    /// total is below this.
    ///
    /// A supported token with no configured minimum reports `2^256 - 1`, which no real balance
    /// can reach: a deposit of that token would never be detected. Treat such a value as
    /// "deposits unavailable for this token" rather than as an amount to display.
    pub minimum_deposit_amount: Nat,
    /// Where the deposit stands in the detect-and-sweep pipeline.
    pub status: DepositStatus,
}

/// The stage a ckERC20 deposit address is at. Extensible with `Sweeping`/`Swept`
/// once sweeping lands (DEFI-2924).
#[derive(CandidType, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum DepositStatus {
    /// Armed and being scanned; no deposit at or above the minimum detected yet.
    Scanning {
        /// Timestamp in nanoseconds since the Unix epoch until which a deposit
        /// sent to the address is guaranteed to be noticed by the minter.
        valid_until: u64,
        /// The latest Ethereum block at which the address' balance was scanned,
        /// or `None` if it has not been scanned yet.
        last_scanned_block: Option<Nat>,
        /// How many times the address' balance has been scanned so far.
        scan_count: u64,
    },
    /// Funds were detected at or above the minimum and queued for sweeping.
    AwaitingSweep(DetectedDeposit),
}

/// A funded token detected at a deposit address and queued for sweeping.
#[derive(CandidType, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DetectedDeposit {
    /// The ERC-20 token contract whose balance was found.
    pub erc20_contract_address: String,
    /// The balance scanned for `erc20_contract_address`; may change before the sweep.
    pub scanned_balance: Nat,
    /// The Ethereum block at which the balance was detected.
    pub detected_at_block: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum DepositErc20Error {
    /// The `erc20_contract_address` is not a ckERC20 token supported by the minter.
    TokenNotSupported { supported_tokens: Vec<CkErc20Token> },
    /// The account already has the maximum number of ERC-20 tokens armed.
    TooManyTokensForAccount,
    /// The maximum number of concurrently armed deposits (`(account, token)` pairs) has been
    /// reached.
    TooManyActiveDeposits,
    /// The minter is temporarily unavailable, retry the request.
    TemporarilyUnavailable(String),
}

#[derive(PartialEq, Debug, CandidType, Deserialize)]
pub enum WithdrawalError {
    AmountTooLow { min_withdrawal_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    RecipientAddressBlocked { address: String },
    TemporarilyUnavailable(String),
}

impl From<LedgerBurnError> for WithdrawalError {
    fn from(error: LedgerBurnError) -> Self {
        match error {
            LedgerBurnError::TemporarilyUnavailable { message, .. } => {
                Self::TemporarilyUnavailable(message)
            }
            LedgerBurnError::InsufficientFunds { balance, .. } => {
                Self::InsufficientFunds { balance }
            }
            LedgerBurnError::InsufficientAllowance { allowance, .. } => {
                Self::InsufficientAllowance { allowance }
            }
            LedgerBurnError::AmountTooLow {
                minimum_burn_amount,
                failed_burn_amount,
                ledger,
            } => {
                panic!(
                    "BUG: withdrawal amount {failed_burn_amount} on the ckETH ledger {ledger:?} should always be higher than the ledger transaction fee {minimum_burn_amount}"
                )
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum WithdrawalSearchParameter {
    ByWithdrawalId(u64),
    ByRecipient(String),
    BySenderAccount(Account),
}

impl TryFrom<WithdrawalSearchParameter> for transactions::WithdrawalSearchParameter {
    type Error = String;

    fn try_from(parameter: WithdrawalSearchParameter) -> Result<Self, String> {
        use WithdrawalSearchParameter::*;
        match parameter {
            ByWithdrawalId(index) => Ok(Self::ByWithdrawalId(LedgerBurnIndex::new(index))),
            ByRecipient(address) => Ok(Self::ByRecipient(ic_ethereum_types::Address::from_str(
                &address,
            )?)),
            BySenderAccount(account) => Ok(Self::BySenderAccount(account)),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub struct WithdrawalDetail {
    pub withdrawal_id: u64,
    pub recipient_address: String,
    pub from: Principal,
    pub from_subaccount: Option<[u8; 32]>,
    pub token_symbol: String,
    pub withdrawal_amount: Nat,
    pub max_transaction_fee: Option<Nat>,
    pub status: WithdrawalStatus,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize)]
pub enum WithdrawalStatus {
    Pending,
    TxCreated,
    TxSent(EthTransaction),
    TxFinalized(TxFinalizedStatus),
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct AddCkErc20Token {
    pub chain_id: Nat,
    pub address: String,
    pub ckerc20_token_symbol: String,
    pub ckerc20_ledger_id: Principal,
}

pub mod events {
    use crate::lifecycle::init::InitArg;
    use crate::lifecycle::upgrade::UpgradeArg;
    use candid::{CandidType, Deserialize, Nat, Principal};
    use serde_bytes::ByteBuf;

    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub struct GetEventsArg {
        pub start: u64,
        pub length: u64,
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub struct GetEventsResult {
        pub events: Vec<Event>,
        pub total_event_count: u64,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct Event {
        pub timestamp: u64,
        pub payload: EventPayload,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct EventSource {
        pub transaction_hash: String,
        pub log_index: Nat,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub enum ReimbursementIndex {
        CkEth {
            ledger_burn_index: Nat,
        },
        CkErc20 {
            cketh_ledger_burn_index: Nat,
            ledger_id: Principal,
            ckerc20_ledger_burn_index: Nat,
        },
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct AccessListItem {
        pub address: String,
        pub storage_keys: Vec<ByteBuf>,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct UnsignedTransaction {
        pub chain_id: Nat,
        pub nonce: Nat,
        pub max_priority_fee_per_gas: Nat,
        pub max_fee_per_gas: Nat,
        pub gas_limit: Nat,
        pub destination: String,
        pub value: Nat,
        pub data: ByteBuf,
        pub access_list: Vec<AccessListItem>,
    }

    /// A secp256k1 signature: the two 32-byte components and the parity recovering the signing
    /// key from them.
    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct TransactionSignature {
        pub y_parity: bool,
        /// 32-byte signature component.
        pub r: ByteBuf,
        /// 32-byte signature component.
        pub s: ByteBuf,
    }

    /// An [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) authorization tuple: a deposit
    /// address' signed consent to delegate its code to `delegate`, signed by the address itself.
    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct SignedAuthorization {
        pub chain_id: Nat,
        pub delegate: String,
        pub nonce: Nat,
        pub signature: TransactionSignature,
    }

    /// One deposit a sweep moves: the address the funds sit at, the account they are credited to,
    /// the attestation binding the two, and the delegation letting the sweeper's code run there.
    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct AuthorizedSweepItem {
        pub deposit: String,
        pub owner: Principal,
        pub subaccount: Option<ByteBuf>,
        /// The attestation signed by the deposit address itself.
        pub attestation: TransactionSignature,
        /// The delegation installed on the way, absent if the address is already delegated.
        pub authorization: Option<SignedAuthorization>,
    }

    /// A sweep transaction the minter has created but not yet signed: a transaction, plus the
    /// delegations it installs on the way. With none it is sent as a plain EIP-1559 (`0x02`)
    /// transaction, and otherwise as an EIP-7702 (`0x04`) one.
    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct UnsignedSweeperTransaction {
        pub transaction: UnsignedTransaction,
        pub authorization_list: Vec<SignedAuthorization>,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub enum TransactionStatus {
        Success,
        Failure,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct TransactionReceipt {
        pub block_hash: String,
        pub block_number: Nat,
        pub effective_gas_price: Nat,
        pub gas_used: Nat,
        pub status: TransactionStatus,
        pub transaction_hash: String,
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub enum EventPayload {
        Init(InitArg),
        Upgrade(UpgradeArg),
        AcceptedDeposit {
            transaction_hash: String,
            block_number: Nat,
            log_index: Nat,
            from_address: String,
            value: Nat,
            principal: Principal,
            subaccount: Option<[u8; 32]>,
        },
        AcceptedErc20Deposit {
            transaction_hash: String,
            block_number: Nat,
            log_index: Nat,
            from_address: String,
            value: Nat,
            principal: Principal,
            erc20_contract_address: String,
            subaccount: Option<[u8; 32]>,
        },
        InvalidDeposit {
            event_source: EventSource,
            reason: String,
        },
        MintedCkEth {
            event_source: EventSource,
            mint_block_index: Nat,
        },
        SyncedToBlock {
            block_number: Nat,
        },
        SyncedErc20ToBlock {
            block_number: Nat,
        },
        SyncedDepositWithSubaccountToBlock {
            block_number: Nat,
        },
        AcceptedEthWithdrawalRequest {
            withdrawal_amount: Nat,
            destination: String,
            ledger_burn_index: Nat,
            from: Principal,
            from_subaccount: Option<[u8; 32]>,
            created_at: Option<u64>,
        },
        AcceptedSweeperFundingRequest {
            withdrawal_amount: Nat,
            destination: String,
            ledger_burn_index: Nat,
            from: Principal,
            from_subaccount: Option<[u8; 32]>,
            created_at: Option<u64>,
        },
        CreatedTransaction {
            withdrawal_id: Nat,
            transaction: UnsignedTransaction,
        },
        SignedTransaction {
            withdrawal_id: Nat,
            raw_transaction: String,
        },
        ReplacedTransaction {
            withdrawal_id: Nat,
            transaction: UnsignedTransaction,
        },
        FinalizedTransaction {
            withdrawal_id: Nat,
            transaction_receipt: TransactionReceipt,
        },
        AttestedDepositAddress {
            chain_id: Nat,
            /// The deposit helper the attestation names; it is only valid against this deployment.
            deposit_helper: String,
            owner: Principal,
            subaccount: Option<ByteBuf>,
            /// The attestation signed by the deposit address itself.
            attestation: TransactionSignature,
        },
        AuthorizedDepositAddress {
            owner: Principal,
            subaccount: Option<ByteBuf>,
            authorization: SignedAuthorization,
        },
        AcceptedSweepRequest {
            sweep_id: Nat,
            destination: String,
            /// The single ERC-20 contract this sweep moves.
            token: String,
            /// The deposits the sweep moves, one per account.
            items: Vec<AuthorizedSweepItem>,
            max_transaction_fee: Nat,
            created_at: u64,
        },
        CreatedSweeperTransaction {
            sweep_id: Nat,
            transaction: UnsignedSweeperTransaction,
        },
        SignedSweeperTransaction {
            sweep_id: Nat,
            raw_transaction: String,
        },
        ReplacedSweeperTransaction {
            sweep_id: Nat,
            transaction: UnsignedSweeperTransaction,
        },
        FinalizedSweeperTransaction {
            sweep_id: Nat,
            transaction_receipt: TransactionReceipt,
        },
        ReimbursedEthWithdrawal {
            reimbursed_in_block: Nat,
            withdrawal_id: Nat,
            reimbursed_amount: Nat,
            transaction_hash: Option<String>,
        },
        ReimbursedErc20Withdrawal {
            withdrawal_id: Nat,
            burn_in_block: Nat,
            reimbursed_in_block: Nat,
            ledger_id: Principal,
            reimbursed_amount: Nat,
            transaction_hash: Option<String>,
        },
        SkippedBlock {
            contract_address: Option<String>,
            block_number: Nat,
        },
        AddedCkErc20Token {
            chain_id: Nat,
            address: String,
            ckerc20_token_symbol: String,
            ckerc20_ledger_id: Principal,
        },
        AcceptedErc20WithdrawalRequest {
            max_transaction_fee: Nat,
            withdrawal_amount: Nat,
            erc20_contract_address: String,
            destination: String,
            cketh_ledger_burn_index: Nat,
            ckerc20_ledger_id: Principal,
            ckerc20_ledger_burn_index: Nat,
            from: Principal,
            from_subaccount: Option<[u8; 32]>,
            created_at: u64,
        },
        FailedErc20WithdrawalRequest {
            withdrawal_id: Nat,
            reimbursed_amount: Nat,
            to: Principal,
            to_subaccount: Option<[u8; 32]>,
        },
        MintedCkErc20 {
            event_source: EventSource,
            mint_block_index: Nat,
            ckerc20_token_symbol: String,
            erc20_contract_address: String,
        },
        QuarantinedDeposit {
            event_source: EventSource,
        },
        QuarantinedReimbursement {
            index: ReimbursementIndex,
        },
        RegisteredDepositAddresses {
            scan_window_nanos: u64,
            capacity: u64,
            registrations: Vec<DepositAddressRegistration>,
        },
        AutomaticDepositReceived {
            owner: Principal,
            subaccount: Option<[u8; 32]>,
            address: String,
            erc20_contract_address: String,
            last_scanned_block: Nat,
            scan_count: u64,
            scanned_balance: Nat,
        },
    }

    #[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
    pub struct DepositAddressRegistration {
        pub owner: Principal,
        pub subaccount: Option<[u8; 32]>,
        pub erc20_contract_address: String,
        pub address: String,
        pub expires_at_nanos: u64,
        pub last_scanned_block: Option<Nat>,
        pub scan_count: u64,
    }
}

#[derive(Clone, Copy, Debug, CandidType, serde::Serialize, serde::Deserialize)]
pub enum MemoType {
    Burn,
    Mint,
}

#[derive(Debug, CandidType, serde::Serialize, serde::Deserialize)]
pub struct DecodeLedgerMemoArgs {
    pub memo_type: MemoType,
    pub encoded_memo: Vec<u8>,
}

impl DecodeLedgerMemoArgs {
    pub fn validate_input(&self) -> Result<(), String> {
        if self.encoded_memo.len() > CKETH_LEDGER_MEMO_SIZE as usize {
            Err(format!(
                "Memo longer than permitted length {}",
                CKETH_LEDGER_MEMO_SIZE
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Eq, PartialEq, CandidType, serde::Serialize, serde::Deserialize)]
pub enum MintMemo {
    Convert {
        from_address: String,
        tx_hash: String,
        log_index: Nat,
    },
    ReimburseTransaction {
        withdrawal_id: u64,
        tx_hash: String,
    },
    ReimburseWithdrawal {
        withdrawal_id: u64,
    },
}

impl From<memo::MintMemo> for MintMemo {
    fn from(m: memo::MintMemo) -> Self {
        match m {
            memo::MintMemo::Convert {
                from_address,
                tx_hash,
                log_index,
            } => MintMemo::Convert {
                from_address: from_address.to_string(),
                tx_hash: tx_hash.to_string(),
                log_index: Nat::from(log_index),
            },
            memo::MintMemo::ReimburseTransaction {
                withdrawal_id,
                tx_hash,
            } => MintMemo::ReimburseTransaction {
                withdrawal_id,
                tx_hash: tx_hash.to_string(),
            },
            memo::MintMemo::ReimburseWithdrawal { withdrawal_id } => {
                MintMemo::ReimburseWithdrawal { withdrawal_id }
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq, CandidType, serde::Serialize, serde::Deserialize)]
pub enum BurnMemo {
    Convert {
        to_address: String,
    },
    Erc20GasFee {
        ckerc20_token_symbol: String,
        ckerc20_withdrawal_amount: Nat,
        to_address: String,
    },
    Erc20Convert {
        ckerc20_withdrawal_id: u64,
        to_address: String,
    },
}

impl From<memo::BurnMemo> for BurnMemo {
    fn from(m: memo::BurnMemo) -> Self {
        match m {
            memo::BurnMemo::Convert { to_address } => BurnMemo::Convert {
                to_address: to_address.to_string(),
            },
            memo::BurnMemo::Erc20GasFee {
                ckerc20_token_symbol,
                ckerc20_withdrawal_amount,
                to_address,
            } => BurnMemo::Erc20GasFee {
                ckerc20_token_symbol: ckerc20_token_symbol.to_string(),
                ckerc20_withdrawal_amount: Nat::from(ckerc20_withdrawal_amount),
                to_address: to_address.to_string(),
            },
            memo::BurnMemo::Erc20Convert {
                ckerc20_withdrawal_id,
                to_address,
            } => BurnMemo::Erc20Convert {
                ckerc20_withdrawal_id,
                to_address: to_address.to_string(),
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq, CandidType, serde::Serialize, serde::Deserialize)]
pub enum DecodedMemo {
    Mint(Option<MintMemo>),
    Burn(Option<BurnMemo>),
}

#[derive(Debug, Eq, PartialEq, CandidType, serde::Serialize, serde::Deserialize)]
pub enum DecodeLedgerMemoError {
    InvalidMemo(String),
}

pub type DecodeLedgerMemoResult = Result<Option<DecodedMemo>, Option<DecodeLedgerMemoError>>;
