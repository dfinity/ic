use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorInfo {
    pub description: String,
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Icrc21Error {
    UnsupportedCanisterCall(ErrorInfo),
    ConsentMessageUnavailable(ErrorInfo),
    InsufficientPayment(ErrorInfo),
    GenericError {
        error_code: Nat,
        description: String,
    },
}
