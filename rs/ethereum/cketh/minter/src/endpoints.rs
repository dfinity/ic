use crate::eth_rpc::into_nat;
use crate::transactions::EthWithdrawalRequest;
use crate::tx::TransactionPrice;
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

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RetrieveEthRequest {
    pub block_index: Nat,
}

#[derive(CandidType, Debug, Default, Serialize, Deserialize, Clone, Encode, Decode)]
#[cbor(index_only)]
pub enum CandidBlockTag {
    /// The latest mined block.
    #[default]
    #[cbor(n(0))]
    Latest,
    /// The latest safe head block.
    /// See
    /// https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels.
    #[cbor(n(1))]
    Safe,
    /// The latest finalized block.
    /// See
    /// https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels.
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
            } => Self::TemporarilyUnavailable(
                format!(
                    "ckETH ledger unreachable, error code: {error_code}, with message: {message}"
                )
                .to_string(),
            ),
        }
    }
}
