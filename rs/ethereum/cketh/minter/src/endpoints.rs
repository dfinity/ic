use crate::eth_rpc::into_nat;
use crate::transactions::EthWithdrawalRequest;
use crate::tx::{SignedEip1559TransactionRequest, TransactionPrice};
use candid::{CandidType, Deserialize, Nat};
use icrc_ledger_types::icrc2::transfer_from::TransferFromError;
use minicbor::{Decode, Encode};
use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Eip1559TransactionPrice {
    pub gas_limit: Nat,
    pub max_fee_per_gas: Nat,
    pub max_priority_fee_per_gas: Nat,
    pub max_transaction_fee: Nat,
}

impl From<TransactionPrice> for Eip1559TransactionPrice {
    fn from(value: TransactionPrice) -> Self {
        Self {
            gas_limit: into_nat(value.gas_limit),
            max_fee_per_gas: value.max_fee_per_gas.into(),
            max_priority_fee_per_gas: value.max_priority_fee_per_gas.into(),
            max_transaction_fee: value.max_transaction_fee().into(),
        }
    }
}
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RetrieveEthRequest {
    pub block_index: Nat,
}

#[derive(
    CandidType, Debug, Default, Serialize, Deserialize, Clone, Encode, Decode, PartialEq, Eq,
)]
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

impl From<EthWithdrawalRequest> for RetrieveEthRequest {
    fn from(value: EthWithdrawalRequest) -> Self {
        Self {
            block_index: candid::Nat::from(value.ledger_burn_index.get()),
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum RetrieveEthStatus {
    NotFound,
    Pending,
    TxCreated,
    TxSigned(EthTransaction),
    TxSent(EthTransaction),
    TxConfirmed(EthTransaction),
}

impl Display for RetrieveEthStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RetrieveEthStatus::NotFound => write!(f, "Not Found"),
            RetrieveEthStatus::Pending => write!(f, "Pending"),
            RetrieveEthStatus::TxCreated => write!(f, "Created"),
            RetrieveEthStatus::TxSigned(tx) => write!(f, "Signed({})", tx.transaction_hash),
            RetrieveEthStatus::TxSent(tx) => write!(f, "Sent({})", tx.transaction_hash),
            RetrieveEthStatus::TxConfirmed(tx) => write!(f, "Confirmed({})", tx.transaction_hash),
        }
    }
}

#[derive(CandidType, Deserialize)]
pub struct WithdrawalArg {
    pub amount: Nat,
    pub recipient: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub enum WithdrawalError {
    AmountTooLow { min_withdrawal_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TemporarilyUnavailable(String),
}

impl From<TransferFromError> for WithdrawalError {
    fn from(transfer_from_error: TransferFromError) -> Self {
        match transfer_from_error {
            TransferFromError::BadFee { expected_fee } => {
                panic!("bug: bad fee, expected fee: {expected_fee}")
            }
            TransferFromError::BadBurn { min_burn_amount } => {
                panic!("bug: bad burn, minimum burn amount: {min_burn_amount}")
            }
            TransferFromError::InsufficientFunds { balance } => Self::InsufficientFunds { balance },
            TransferFromError::InsufficientAllowance { allowance } => {
                Self::InsufficientAllowance { allowance }
            }
            TransferFromError::TooOld => panic!("bug: transfer too old"),
            TransferFromError::CreatedInFuture { ledger_time } => {
                panic!("bug: created in future, ledger time: {ledger_time}")
            }
            TransferFromError::Duplicate { duplicate_of } => {
                panic!("bug: duplicate transfer of: {duplicate_of}")
            }
            TransferFromError::TemporarilyUnavailable => Self::TemporarilyUnavailable(
                "ckETH ledger temporarily unavailable, try again".to_string(),
            ),
            TransferFromError::GenericError {
                error_code,
                message,
            } => Self::TemporarilyUnavailable(format!(
                "ckETH ledger unreachable, error code: {error_code}, with message: {message}"
            )),
        }
    }
}

pub mod events {
    use crate::lifecycle::init::InitArg;
    use crate::lifecycle::upgrade::UpgradeArg;
    use candid::{CandidType, Deserialize, Nat, Principal};

    #[derive(CandidType, Deserialize, Debug, Clone)]
    pub struct GetEventsArg {
        pub start: u64,
        pub length: u64,
    }

    #[derive(CandidType, Deserialize, Debug, Clone)]
    pub struct GetEventsResult {
        pub events: Vec<Event>,
        pub total_event_count: u64,
    }

    #[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub struct Event {
        pub timestamp: u64,
        pub payload: EventPayload,
    }

    #[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
    pub struct EventSource {
        pub transaction_hash: String,
        pub log_index: Nat,
    }

    #[derive(CandidType, Deserialize, Debug, Clone, PartialEq, Eq)]
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
        AcceptedEthWithdrawalRequest {
            withdrawal_amount: Nat,
            destination: String,
            ledger_burn_index: Nat,
        },
        SignedTx {
            withdrawal_id: Nat,
            raw_tx: String,
        },
        SentTransaction {
            withdrawal_id: Nat,
            transaction_hash: String,
        },
        FinalizedTransaction {
            withdrawal_id: Nat,
            transaction_hash: String,
        },
    }
}
