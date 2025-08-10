use candid::{CandidType, Deserialize, Nat};
use serde::Serialize;

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Icrc106Error {
    IndexPrincipalNotSet,
    GenericError {
        error_code: Nat,
        description: String,
    },
}
