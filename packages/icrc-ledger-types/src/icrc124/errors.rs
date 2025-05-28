use crate::icrc1::transfer::BlockIndex;
use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

/// Errors defined for [ICRC-124](https://github.com/dfinity/ICRC/pull/135).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Icrc124Error {
    PermissionDenied,
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    TemporarilyUnavailable,
    Duplicate { duplicate_of: BlockIndex },
    GenericError { error_code: Nat, message: String },
}
