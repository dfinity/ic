use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub struct CheckAddressArgs {
    /// Bitcoin address to be checked.
    pub address: String,
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckAddressResponse {
    Passed,
    Failed,
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub struct CheckTransactionArgs {
    pub txid: Vec<u8>,
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionResponse {
    Passed,
    Failed,
    /// Job is scheduled but result is not yet available. Caller has to call again later.
    Pending,
    /// The service is experiencing high load, and the caller has to call again later.
    HighLoad,
    /// Caller has to call again with minimum required amount of cycles.
    NotEnoughCycles,
    /// Permanent error.
    Error(String),
}
