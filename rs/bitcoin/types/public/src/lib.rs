//! Types used to support the candid API.

use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;

pub type Address = String;
pub type Satoshi = u64;
pub type BlockHash = Vec<u8>;
pub type Height = u32;
pub type Page = ByteBuf;

/// A reference to a transaction output.
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    #[serde(with = "serde_bytes")]
    pub txid: Vec<u8>,
    pub vout: u32,
}

/// An unspent transaction output.
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: Satoshi,
    pub height: u32,
}

/// A filter used when requesting UTXOs.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub enum UtxosFilter {
    MinConfirmations(u32),
    Page(Page),
}

/// A request for getting the UTXOs for a given address.
#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetUtxosRequest {
    pub address: String,
    pub filter: Option<UtxosFilter>,
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
#[derive(CandidType, Debug, Deserialize, PartialEq, Clone, Copy)]
pub enum GetUtxosError {
    MalformedAddress,
    MinConfirmationsTooLarge { given: u32, max: u32 },
}

impl std::fmt::Display for GetUtxosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format the error in the same way we format `GetBalanceError`.
        GetBalanceError::from(*self).fmt(f)
    }
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct GetBalanceRequest {
    pub address: String,
    pub min_confirmations: Option<u32>,
}

#[derive(CandidType, Debug, Deserialize, PartialEq, Clone, Copy)]
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

impl From<GetUtxosError> for GetBalanceError {
    fn from(err: GetUtxosError) -> Self {
        match err {
            GetUtxosError::MalformedAddress => Self::MalformedAddress,
            GetUtxosError::MinConfirmationsTooLarge { given, max } => {
                Self::MinConfirmationsTooLarge { given, max }
            }
        }
    }
}

#[derive(CandidType, Debug, Deserialize, PartialEq)]
pub struct SendTransactionRequest {
    #[serde(with = "serde_bytes")]
    pub transaction: Vec<u8>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub enum SendTransactionError {
    MalformedTransaction,
}
