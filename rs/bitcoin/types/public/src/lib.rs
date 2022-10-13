//! Types used to support the candid API.

use candid::{CandidType, Deserialize};
use serde::Serialize;
use serde_bytes::ByteBuf;

pub type Address = String;
pub type Satoshi = u64;
pub type MillisatoshiPerByte = u64;
pub type BlockHash = Vec<u8>;
pub type Height = u32;
pub type Page = ByteBuf;

#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Regtest => write!(f, "regtest"),
        }
    }
}

impl From<Network> for NetworkInRequest {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::Mainnet,
            Network::Testnet => Self::Testnet,
            Network::Regtest => Self::Regtest,
        }
    }
}

impl From<NetworkInRequest> for Network {
    fn from(network: NetworkInRequest) -> Self {
        match network {
            NetworkInRequest::Mainnet => Self::Mainnet,
            NetworkInRequest::mainnet => Self::Mainnet,
            NetworkInRequest::Testnet => Self::Testnet,
            NetworkInRequest::testnet => Self::Testnet,
            NetworkInRequest::Regtest => Self::Regtest,
            NetworkInRequest::regtest => Self::Regtest,
        }
    }
}

/// A network enum that allows both upper and lowercase variants.
/// Supporting both variants allows us to be compatible with the spec (lowercase)
/// while not breaking current dapps that are using uppercase variants.
#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum NetworkInRequest {
    Mainnet,
    #[allow(non_camel_case_types)]
    mainnet,
    Testnet,
    #[allow(non_camel_case_types)]
    testnet,
    Regtest,
    #[allow(non_camel_case_types)]
    regtest,
}

impl std::fmt::Display for NetworkInRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Regtest => write!(f, "regtest"),
            Self::mainnet => write!(f, "mainnet"),
            Self::testnet => write!(f, "testnet"),
            Self::regtest => write!(f, "regtest"),
        }
    }
}

/// An enum representing a Bitcoin network.
// TODO(EXC-1234): Exclusively use this enum and remove the legacy `Network` and
// `NetworkInRequest` enums.
#[derive(CandidType, Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, Hash)]
pub enum NetworkSnakeCase {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
    #[serde(rename = "regtest")]
    Regtest,
}

/// A reference to a transaction output.
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    /// A cryptographic hash of the transaction.
    /// A transaction can output multiple UTXOs.
    #[serde(with = "serde_bytes")]
    pub txid: Vec<u8>,
    /// The index of the output within the transaction.
    pub vout: u32,
}

/// An unspent transaction output.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone, Hash, Eq)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: Satoshi,
    pub height: u32,
}

impl std::cmp::PartialOrd for Utxo {
    fn partial_cmp(&self, other: &Utxo) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Utxo {
    fn cmp(&self, other: &Utxo) -> std::cmp::Ordering {
        // The output point uniquely identifies an UTXO; there is no point in
        // comparing the other fields.
        self.outpoint.cmp(&other.outpoint)
    }
}

/// A filter used when requesting UTXOs.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub enum UtxosFilter {
    MinConfirmations(u32),
    Page(Page),
}

impl From<UtxosFilterInRequest> for UtxosFilter {
    fn from(filter: UtxosFilterInRequest) -> Self {
        match filter {
            UtxosFilterInRequest::MinConfirmations(x) => Self::MinConfirmations(x),
            UtxosFilterInRequest::min_confirmations(x) => Self::MinConfirmations(x),
            UtxosFilterInRequest::Page(p) => Self::Page(p),
            UtxosFilterInRequest::page(p) => Self::Page(p),
        }
    }
}

/// A UtxosFilter enum that allows both upper and lowercase variants.
/// Supporting both variants allows us to be compatible with the spec (lowercase)
/// while not breaking current dapps that are using uppercase variants.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub enum UtxosFilterInRequest {
    MinConfirmations(u32),
    #[allow(non_camel_case_types)]
    min_confirmations(u32),
    Page(Page),
    #[allow(non_camel_case_types)]
    page(Page),
}

/// A request for getting the UTXOs for a given address.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetUtxosRequest {
    pub address: Address,
    pub network: NetworkInRequest,
    pub filter: Option<UtxosFilterInRequest>,
}

/// The response returned for a request to get the UTXOs of a given address.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct GetUtxosResponse {
    pub utxos: Vec<Utxo>,
    pub tip_block_hash: BlockHash,
    pub tip_height: u32,
    pub next_page: Option<Page>,
}

/// Errors when processing a `get_utxos` request.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub enum GetUtxosError {
    MalformedAddress,
    MinConfirmationsTooLarge { given: u32, max: u32 },
    UnknownTipBlockHash { tip_block_hash: BlockHash },
    MalformedPage { err: String },
}

/// A request for getting the current fee percentiles.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetCurrentFeePercentilesRequest {
    pub network: NetworkInRequest,
}

impl std::fmt::Display for GetUtxosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedAddress => {
                write!(f, "Malformed address.")
            }
            Self::MinConfirmationsTooLarge { given, max } => {
                write!(
                    f,
                    "The requested min_confirmations is too large. Given: {}, max supported: {}",
                    given, max
                )
            }
            Self::UnknownTipBlockHash { tip_block_hash } => {
                write!(
                    f,
                    "The provided tip block hash {:?} is unknown.",
                    tip_block_hash
                )
            }
            Self::MalformedPage { err } => {
                write!(f, "The provided page is malformed {}", err)
            }
        }
    }
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetBalanceRequest {
    pub address: Address,
    pub network: NetworkInRequest,
    pub min_confirmations: Option<u32>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub enum GetBalanceError {
    MalformedAddress,
    MinConfirmationsTooLarge { given: u32, max: u32 },
}

impl std::fmt::Display for GetBalanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedAddress => {
                write!(f, "Malformed address.")
            }
            Self::MinConfirmationsTooLarge { given, max } => {
                write!(
                    f,
                    "The requested min_confirmations is too large. Given: {}, max supported: {}",
                    given, max
                )
            }
        }
    }
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct SendTransactionRequest {
    #[serde(with = "serde_bytes")]
    pub transaction: Vec<u8>,
    pub network: NetworkInRequest,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub enum SendTransactionError {
    /// Can't deserialize transaction.
    MalformedTransaction,
    /// Enqueueing a request failed due to full queue to the Bitcoin adapter.
    QueueFull,
}

impl std::fmt::Display for SendTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedTransaction => {
                write!(f, "Can't deserialize transaction because it's malformed.")
            }
            Self::QueueFull => {
                write!(
                    f,
                    "Request can not be enqueued because the queue has reached its capacity. Please retry later."
                )
            }
        }
    }
}
