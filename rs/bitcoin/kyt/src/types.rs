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
    /// More work to be done, and the caller should call again.
    Pending,
    /// The service is experiencing high load, and the caller should call again later.
    HighLoad,
    /// Caller should call with a minimum of 40 billion cycles.
    NotEnoughCycles,
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionError {
    /// Error computing address of a transaction's vout.
    Address {
        txid: Vec<u8>,
        vout: u32,
        message: String,
    },
    /// Canister call is rejected with rejection code and message.
    Rejected {
        code: u32,
        message: String,
    },
    /// Response size is too large (> `RETRY_BUFFER_SIZE`) when fetching the transaction data of a txid.
    ResponseTooLarge {
        txid: Vec<u8>,
    },
    /// Error decoding transaction data of a txid.
    Tx {
        txid: Vec<u8>,
        message: String,
    },
    /// Error decoding transaction id.
    Txid {
        txid: Vec<u8>,
        message: String,
    },
    /// Mismatch between the expected txid, and that computed from fetched transaction data.
    TxidMismatch {
        expected: Vec<u8>,
        decoded: Vec<u8>,
    },
}
