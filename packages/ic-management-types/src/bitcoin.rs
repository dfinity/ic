use candid::CandidType;
use serde::Deserialize;

// bitcoin

#[derive(CandidType, Deserialize)]
pub enum BitcoinNetwork {
    #[serde(rename = "mainnet")]
    Mainnet,
    #[serde(rename = "testnet")]
    Testnet,
}

pub type BitcoinAddress = String;

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetBalanceArgs {
    pub network: BitcoinNetwork,
    pub address: BitcoinAddress,
    pub min_confirmations: Option<u32>,
}

pub type Satoshi = u64;

pub type BitcoinGetBalanceResult = Satoshi;

#[derive(CandidType, Deserialize)]
pub enum BitcoinGetUtxosArgsFilterInner {
    #[serde(rename = "page")]
    Page(Vec<u8>),
    #[serde(rename = "min_confirmations")]
    MinConfirmations(u32),
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetUtxosArgs {
    pub network: BitcoinNetwork,
    pub filter: Option<BitcoinGetUtxosArgsFilterInner>,
    pub address: BitcoinAddress,
}

pub type BitcoinBlockHeight = u32;

pub type BitcoinBlockHash = Vec<u8>;

#[derive(CandidType, Deserialize)]
pub struct Outpoint {
    pub txid: Vec<u8>,
    pub vout: u32,
}

#[derive(CandidType, Deserialize)]
pub struct Utxo {
    pub height: u32,
    pub value: Satoshi,
    pub outpoint: Outpoint,
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetUtxosResult {
    pub next_page: Option<Vec<u8>>,
    pub tip_height: BitcoinBlockHeight,
    pub tip_block_hash: BitcoinBlockHash,
    pub utxos: Vec<Utxo>,
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinSendTransactionArgs {
    pub transaction: Vec<u8>,
    pub network: BitcoinNetwork,
}

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetCurrentFeePercentilesArgs {
    pub network: BitcoinNetwork,
}

pub type MillisatoshiPerByte = u64;

pub type BitcoinGetCurrentFeePercentilesResult = Vec<MillisatoshiPerByte>;

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetBlockHeadersArgs {
    pub start_height: BitcoinBlockHeight,
    pub end_height: Option<BitcoinBlockHeight>,
    pub network: BitcoinNetwork,
}

pub type BitcoinBlockHeader = Vec<u8>;

#[derive(CandidType, Deserialize)]
pub struct BitcoinGetBlockHeadersResult {
    pub tip_height: BitcoinBlockHeight,
    pub block_headers: Vec<BitcoinBlockHeader>,
}
