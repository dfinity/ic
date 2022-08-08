use crate::Memo;
use candid::types::number::{Int, Nat};
use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_canister_core::ledger::TransferError as CoreTransferError;
use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::{Account, Subaccount};

pub type NumTokens = Nat;
pub type BlockIndex = Nat;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum TransferError {
    BadFee { expected_fee: NumTokens },
    BadBurn { min_burn_amount: NumTokens },
    InsufficientFunds { balance: NumTokens },
    TooOld { allowed_window_nanos: u64 },
    CreatedInFuture,
    Throttled,
    Duplicate { duplicate_of: BlockIndex },
    GenericError { error_code: Nat, message: String },
}

impl From<CoreTransferError> for TransferError {
    fn from(err: CoreTransferError) -> Self {
        use ic_ledger_canister_core::ledger::TransferError as LTE;
        use TransferError as TE;

        match err {
            LTE::BadFee { expected_fee } => TE::BadFee {
                expected_fee: Nat::from(expected_fee.get_e8s()),
            },
            LTE::InsufficientFunds { balance } => TE::InsufficientFunds {
                balance: Nat::from(balance.get_e8s()),
            },
            LTE::TxTooOld {
                allowed_window_nanos,
            } => TE::TooOld {
                allowed_window_nanos,
            },
            LTE::TxCreatedInFuture => TE::CreatedInFuture,
            LTE::TxThrottled => TE::Throttled,
            LTE::TxDuplicate { duplicate_of } => TE::Duplicate {
                duplicate_of: Nat::from(duplicate_of),
            },
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct TransferArg {
    #[serde(default)]
    pub from_subaccount: Option<Subaccount>,
    pub to_principal: PrincipalId,
    #[serde(default)]
    pub to_subaccount: Option<Subaccount>,
    #[serde(default)]
    pub fee: Option<NumTokens>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    #[serde(default)]
    pub memo: Option<Memo>,
    pub amount: NumTokens,
}

impl TransferArg {
    pub fn to_account(&self) -> Account {
        Account {
            of: self.to_principal,
            subaccount: self.to_subaccount,
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct ArchiveInfo {
    pub canister_id: CanisterId,
    pub block_range_start: BlockIndex,
    pub block_range_end: BlockIndex,
}

/// Variant type for the `metadata` endpoint values.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum Value {
    Nat(Nat),
    Int(Int),
    Text(String),
    Blob(ByteBuf),
}

impl Value {
    pub fn entry(key: impl ToString, val: impl Into<Value>) -> (String, Self) {
        (key.to_string(), val.into())
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Int(Int::from(n))
    }
}

impl From<i128> for Value {
    fn from(n: i128) -> Self {
        Value::Int(Int::from(n))
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Nat(Nat::from(n))
    }
}

impl From<u128> for Value {
    fn from(n: u128) -> Self {
        Value::Nat(Nat::from(n))
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl<'a> From<&'a str> for Value {
    fn from(s: &'a str) -> Self {
        Value::Text(s.to_string())
    }
}

impl From<Vec<u8>> for Value {
    fn from(bytes: Vec<u8>) -> Value {
        Value::Blob(ByteBuf::from(bytes))
    }
}

impl<'a> From<&'a [u8]> for Value {
    fn from(bytes: &'a [u8]) -> Value {
        Value::Blob(ByteBuf::from(bytes.to_vec()))
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct StandardRecord {
    pub name: String,
    pub url: String,
}
