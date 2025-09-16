use super::account::{Account, Subaccount};
use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::fmt;

pub type NumTokens = Nat;
pub type BlockIndex = Nat;

/// The arguments for the [ICRC-1 `transfer`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md#icrc1_transfer-) endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransferArg {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    pub to: Account,
    #[serde(default)]
    pub fee: Option<NumTokens>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    #[serde(default)]
    pub memo: Option<Memo>,
    pub amount: NumTokens,
}

/// The [`Memo`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md#icrc1_transfer-)
/// is an arbitrary blob that has no meaning to the ledger. The ledger SHOULD allow memos of at
/// least 32 bytes in length.
#[derive(
    Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, Default,
)]
#[serde(transparent)]
pub struct Memo(pub ByteBuf);

impl From<u64> for Memo {
    fn from(num: u64) -> Self {
        Self(ByteBuf::from(num.to_be_bytes().to_vec()))
    }
}

impl From<ByteBuf> for Memo {
    fn from(b: ByteBuf) -> Self {
        Self(b)
    }
}

impl From<Vec<u8>> for Memo {
    fn from(v: Vec<u8>) -> Self {
        Self::from(ByteBuf::from(v))
    }
}

impl From<Memo> for ByteBuf {
    fn from(memo: Memo) -> Self {
        memo.0
    }
}

/// Errors defined for the
/// [ICRC-1 `transfer`](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md#icrc1_transfer-)
/// endpoint.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    BadFee { expected_fee: NumTokens },
    BadBurn { min_burn_amount: NumTokens },
    InsufficientFunds { balance: NumTokens },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    TemporarilyUnavailable,
    Duplicate { duplicate_of: BlockIndex },
    GenericError { error_code: Nat, message: String },
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFee { expected_fee } => {
                write!(f, "transfer fee should be {expected_fee}")
            }
            Self::InsufficientFunds { balance } => {
                write!(
                    f,
                    "the debit account doesn't have enough funds to complete the transaction, current balance: {balance}"
                )
            }
            Self::TooOld {} => write!(f, "transaction's created_at_time is too far in the past"),
            Self::CreatedInFuture { ledger_time } => write!(
                f,
                "transaction's created_at_time is in future, current ledger time is {ledger_time}"
            ),
            Self::Duplicate { duplicate_of } => write!(
                f,
                "transaction is a duplicate of another transaction in block {duplicate_of}"
            ),
            Self::TemporarilyUnavailable {} => write!(f, "the ledger is temporarily unavailable"),
            Self::GenericError {
                error_code,
                message,
            } => write!(f, "{error_code} {message}"),
            Self::BadBurn { min_burn_amount } => write!(
                f,
                "the minimum number of tokens to be burned is {min_burn_amount}"
            ),
        }
    }
}
