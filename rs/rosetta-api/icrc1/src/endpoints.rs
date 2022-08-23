use crate::{Account, Block, Memo, Subaccount};
use candid::types::number::{Int, Nat};
use candid::CandidType;
use ic_base_types::CanisterId;
use ic_ledger_canister_core::ledger::TransferError as CoreTransferError;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::convert::TryFrom;

pub type NumTokens = Nat;
pub type BlockIndex = Nat;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
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
            LTE::TxTooOld { .. } => TE::TooOld,
            LTE::TxCreatedInFuture { ledger_time } => TE::CreatedInFuture {
                ledger_time: ledger_time.as_nanos_since_unix_epoch(),
            },
            LTE::TxThrottled => TE::TemporarilyUnavailable,
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
    pub to: Account,
    #[serde(default)]
    pub fee: Option<NumTokens>,
    #[serde(default)]
    pub created_at_time: Option<u64>,
    #[serde(default)]
    pub memo: Option<Memo>,
    pub amount: NumTokens,
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

// Non-standard queries

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct ArchiveInfo {
    pub canister_id: CanisterId,
    pub block_range_start: BlockIndex,
    pub block_range_end: BlockIndex,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct GetTransactionsRequest {
    pub start: BlockIndex,
    pub length: Nat,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Mint {
    pub amount: Nat,
    pub to: Account,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Burn {
    pub amount: Nat,
    pub from: Account,
    pub memo: Option<Memo>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Transfer {
    pub amount: Nat,
    pub from: Account,
    pub to: Account,
    pub memo: Option<Memo>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct Transaction {
    pub kind: String,
    pub mint: Option<Mint>,
    pub burn: Option<Burn>,
    pub transfer: Option<Transfer>,
    pub timestamp: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct ArchivedTransactionRange {
    pub start: Nat,
    pub length: Nat,
    pub callback: QueryArchiveFn,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct GetTransactionsResponse {
    pub log_length: Nat,
    pub first_index: Nat,
    pub transactions: Vec<Transaction>,
    pub archived_transactions: Vec<ArchivedTransactionRange>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct TransactionRange {
    transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(try_from = "candid::types::reference::Func")]
pub struct QueryArchiveFn {
    pub canister_id: CanisterId,
    pub method: String,
}

impl From<QueryArchiveFn> for candid::types::reference::Func {
    fn from(archive_fn: QueryArchiveFn) -> Self {
        let p: &ic_base_types::PrincipalId = archive_fn.canister_id.as_ref();
        Self {
            principal: p.0,
            method: archive_fn.method,
        }
    }
}

impl TryFrom<candid::types::reference::Func> for QueryArchiveFn {
    type Error = String;
    fn try_from(func: candid::types::reference::Func) -> Result<Self, Self::Error> {
        let canister_id = CanisterId::try_from(func.principal.as_slice())
            .map_err(|e| format!("principal is not a canister id: {}", e))?;
        Ok(QueryArchiveFn {
            canister_id,
            method: func.method,
        })
    }
}

impl CandidType for QueryArchiveFn {
    fn _ty() -> candid::types::Type {
        candid::types::Type::Func(candid::types::Function {
            modes: vec![candid::parser::types::FuncMode::Query],
            args: vec![GetTransactionsRequest::_ty()],
            rets: vec![TransactionRange::_ty()],
        })
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        candid::types::reference::Func::from(self.clone()).idl_serialize(serializer)
    }
}

impl From<Block> for Transaction {
    fn from(b: Block) -> Transaction {
        use crate::Operation;

        let mut tx = Transaction {
            kind: "".to_string(),
            mint: None,
            burn: None,
            transfer: None,
            timestamp: b.timestamp,
        };
        let created_at_time = b.transaction.created_at_time;
        let memo = b.transaction.memo;

        match b.transaction.operation {
            Operation::Mint { to, amount } => {
                tx.kind = "mint".to_string();
                tx.mint = Some(Mint {
                    to,
                    amount: Nat::from(amount),
                    created_at_time,
                    memo,
                });
            }
            Operation::Burn { from, amount } => {
                tx.kind = "burn".to_string();
                tx.burn = Some(Burn {
                    from,
                    amount: Nat::from(amount),
                    created_at_time,
                    memo,
                });
            }
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => {
                tx.kind = "transfer".to_string();
                tx.transfer = Some(Transfer {
                    from,
                    to,
                    amount: Nat::from(amount),
                    fee: Some(Nat::from(fee)),
                    created_at_time,
                    memo,
                });
            }
        }

        tx
    }
}
