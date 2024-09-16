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
    /// When check finishes and all input addresses passed KYT.
    Passed,
    /// When check finishes and one or more input addresses failed KYT.
    /// The list of failed addresses are returned as a best effort, which may be non-exhaustive.
    Failed(Vec<String>),
    /// The case where it is unable to give a final answer of Passed or Failed.
    /// The caller should examine the error and decide how to handle it.
    Other(CheckTransactionStatus),
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionStatus {
    /// Caller should call with a minimum of `CHECK_TRANSACTION_CYCLES_REQUIRED` cycles.
    NotEnoughCycles,
    /// The result is pending, and the caller can call again later.
    Pending(CheckTransactionPending),
    /// The result is unknown due to an irrecoverable error.
    Error(CheckTransactionError),
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionPending {
    /// Work is already in progress, and the result is pending.
    Pending,
    /// The service is experience high load.
    HighLoad,
    /// There was a transient error fetching data.
    TransientInternalError(String),
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionError {
    /// Response size is too large (> `RETRY_MAX_RESPONSE_BYTES`) when fetching the transaction data of a txid.
    ResponseTooLarge { txid: Vec<u8> },
    /// Invalid transaction, e.g. error decoding transaction or transaction id mismatch, etc.
    InvalidTransaction(String),
}

impl From<CheckTransactionError> for CheckTransactionResponse {
    fn from(err: CheckTransactionError) -> CheckTransactionResponse {
        CheckTransactionResponse::Other(CheckTransactionStatus::Error(err))
    }
}

impl From<CheckTransactionPending> for CheckTransactionResponse {
    fn from(pending: CheckTransactionPending) -> CheckTransactionResponse {
        CheckTransactionResponse::Other(CheckTransactionStatus::Pending(pending))
    }
}

impl From<CheckTransactionStatus> for CheckTransactionResponse {
    fn from(status: CheckTransactionStatus) -> CheckTransactionResponse {
        CheckTransactionResponse::Other(status)
    }
}
