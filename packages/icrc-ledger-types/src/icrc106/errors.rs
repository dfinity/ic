use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Icrc106Error {
    IndexNotSet,
    GenericError {
        error_code: Nat,
        description: String,
    },
}
