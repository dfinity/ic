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
pub struct CheckTransactionStrArgs {
    pub txid: String,
}

#[derive(CandidType, Debug, Clone, Deserialize, Serialize)]
pub enum CheckTransactionResponse {
    /// When check finishes and all input addresses passed.
    Passed,
    /// When check finishes and one or more input addresses failed.
    /// The list of failed addresses are returned as a best effort, which may be non-exhaustive.
    Failed(Vec<String>),
    /// Unknown case where it is unable to give a final answer of Passed or Failed.
    /// The caller should examine the status and decide how to handle it.
    Unknown(CheckTransactionStatus),
}

#[derive(CandidType, Debug, Clone, Deserialize, Serialize)]
pub enum CheckTransactionStatus {
    /// Caller should call with a minimum of `CHECK_TRANSACTION_CYCLES_REQUIRED` cycles.
    NotEnoughCycles,
    /// The result is not available, but calls can be retried.
    Retriable(CheckTransactionRetriable),
    /// The result is unknown due to an irrecoverable error.
    Error(CheckTransactionIrrecoverableError),
}

#[derive(CandidType, Debug, Clone, Deserialize, Serialize)]
pub enum CheckTransactionRetriable {
    /// Work is already in progress, and the result is pending.
    Pending,
    /// The service is experience high load.
    HighLoad,
    /// There was a transient error fetching data.
    TransientInternalError(String),
}

#[derive(CandidType, Debug, Clone, Deserialize, Serialize)]
pub enum CheckTransactionIrrecoverableError {
    /// Response size is too large (> `RETRY_MAX_RESPONSE_BYTES`) when fetching the transaction data of a txid.
    ResponseTooLarge { txid: Vec<u8> },
    /// Invalid transaction id because it fails to decode.
    InvalidTransactionId(String),
    /// Invalid transaction.
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
    pub check_mode: CheckMode,
    pub num_subnet_nodes: u16,
}

#[derive(CandidType, Clone, Deserialize, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum BtcNetwork {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
    #[serde(rename = "regtest")]
    Regtest { json_rpc_url: String },
}

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum CheckMode {
    AcceptAll,
    RejectAll,
    Normal,
}

impl fmt::Display for CheckMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AcceptAll => write!(f, "AcceptAll"),
            Self::RejectAll => write!(f, "RejectAll"),
            Self::Normal => write!(f, "Normal"),
        }
    }
}

impl From<BtcNetwork> for bitcoin::Network {
    fn from(btc_network: BtcNetwork) -> Self {
        match btc_network {
            BtcNetwork::Mainnet => Self::Bitcoin,
            BtcNetwork::Testnet => Self::Testnet,
            BtcNetwork::Regtest { .. } => Self::Regtest,
        }
    }
}

impl fmt::Display for BtcNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Regtest { .. } => write!(f, "regtest"),
        }
    }
}

#[derive(CandidType, Debug, Default, Deserialize, Serialize)]
pub struct UpgradeArg {
    pub check_mode: Option<CheckMode>,
    pub num_subnet_nodes: Option<u16>,
}

#[derive(CandidType, Debug, Deserialize, Serialize)]
pub enum CheckArg {
    InitArg(InitArg),
    UpgradeArg(Option<UpgradeArg>),
}
