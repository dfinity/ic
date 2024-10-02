use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::fmt;

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
    /// Unknown case where it is unable to give a final answer of Passed or Failed.
    /// The caller should examine the status and decide how to handle it.
    Unknown(CheckTransactionStatus),
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionStatus {
    /// Caller should call with a minimum of `CHECK_TRANSACTION_CYCLES_REQUIRED` cycles.
    NotEnoughCycles,
    /// The result is not available, but calls can be retried.
    Retriable(CheckTransactionRetriable),
    /// The result is unknown due to an irrecoverable error.
    Error(CheckTransactionIrrecoverableError),
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionRetriable {
    /// Work is already in progress, and the result is pending.
    Pending,
    /// The service is experience high load.
    HighLoad,
    /// There was a transient error fetching data.
    TransientInternalError(String),
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckTransactionIrrecoverableError {
    /// Response size is too large (> `RETRY_MAX_RESPONSE_BYTES`) when fetching the transaction data of a txid.
    ResponseTooLarge { txid: Vec<u8> },
    /// Invalid transaction, e.g. error decoding transaction or transaction id mismatch, etc.
    InvalidTransaction(String),
}

impl From<CheckTransactionIrrecoverableError> for CheckTransactionResponse {
    fn from(err: CheckTransactionIrrecoverableError) -> CheckTransactionResponse {
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(err))
    }
}

impl From<CheckTransactionRetriable> for CheckTransactionResponse {
    fn from(pending: CheckTransactionRetriable) -> CheckTransactionResponse {
        CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(pending))
    }
}

impl From<CheckTransactionStatus> for CheckTransactionResponse {
    fn from(status: CheckTransactionStatus) -> CheckTransactionResponse {
        CheckTransactionResponse::Unknown(status)
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct InitArg {
    pub btc_network: BtcNetwork,
}

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum BtcNetwork {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
}

impl From<BtcNetwork> for bitcoin::Network {
    fn from(btc_network: BtcNetwork) -> Self {
        match btc_network {
            BtcNetwork::Mainnet => Self::Bitcoin,
            BtcNetwork::Testnet => Self::Testnet,
        }
    }
}

impl fmt::Display for BtcNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
        }
    }
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub struct UpgradeArg {}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum KytArg {
    InitArg(InitArg),
    UpgradeArg(Option<UpgradeArg>),
}
