//! The Rust types in this crate are used by consensus as part of the
//! BatchPayload and by execution as part of the ReplicatedState. The rust
//! types need to be serializable only because of the BatchPayload.
//! Their protobuf counterpart (defined in rs/protobuf/def/bitcoin) are used
//! only for serialization/deserialization of the ReplicatedState.

use candid::CandidType;
use ic_error_types::RejectCode;
use ic_interfaces_adapter_client::RpcAdapterClient;
use ic_protobuf::{
    bitcoin::v1,
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1::RejectCode as pbRejectCode,
};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::mem::size_of_val;

// NOTE: The network variants for Bitcoin need to be named without the bitcoin prefix,
// because these variants need to be backwards compatible with the bitcoin canister.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub enum Network {
    #[serde(rename = "mainnet")]
    BitcoinMainnet,
    #[serde(rename = "testnet")]
    BitcoinTestnet,
    #[serde(rename = "regtest")]
    BitcoinRegtest,
    #[serde(rename = "dogecoin_mainnet")]
    DogecoinMainnet,
    #[serde(rename = "dogecoin_testnet")]
    DogecoinTestnet,
    #[serde(rename = "dogecoin_regtest")]
    DogecoinRegtest,
}

impl From<Network> for v1::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::BitcoinMainnet => v1::Network::BitcoinMainnet,
            Network::BitcoinTestnet => v1::Network::BitcoinTestnet,
            Network::BitcoinRegtest => v1::Network::BitcoinRegtest,
            Network::DogecoinMainnet => v1::Network::DogecoinMainnet,
            Network::DogecoinTestnet => v1::Network::DogecoinTestnet,
            Network::DogecoinRegtest => v1::Network::DogecoinRegtest,
        }
    }
}

impl From<Network> for i32 {
    fn from(network: Network) -> Self {
        v1::Network::from(network).into()
    }
}

impl TryFrom<v1::Network> for Network {
    type Error = ProxyDecodeError;

    fn try_from(network: v1::Network) -> Result<Self, Self::Error> {
        match network {
            v1::Network::BitcoinTestnet => Ok(Network::BitcoinTestnet),
            v1::Network::BitcoinMainnet => Ok(Network::BitcoinMainnet),
            v1::Network::BitcoinRegtest => Ok(Network::BitcoinRegtest),
            v1::Network::DogecoinMainnet => Ok(Network::DogecoinMainnet),
            v1::Network::DogecoinTestnet => Ok(Network::DogecoinTestnet),
            v1::Network::DogecoinRegtest => Ok(Network::DogecoinRegtest),
            _ => Err(ProxyDecodeError::MissingField("network")),
        }
    }
}

impl TryFrom<i32> for Network {
    type Error = ProxyDecodeError;

    fn try_from(network: i32) -> Result<Self, Self::Error> {
        Network::try_from(
            v1::Network::try_from(network).map_err(|_| {
                ProxyDecodeError::Other("Failed to decode network enum".to_string())
            })?,
        )
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct SendTransactionRequest {
    pub network: Network,
    #[serde(with = "serde_bytes")]
    pub transaction: Vec<u8>,
}

impl From<&SendTransactionRequest> for v1::SendTransactionRequest {
    fn from(request: &SendTransactionRequest) -> Self {
        Self {
            network: request.network.into(),
            transaction: request.transaction.clone(),
        }
    }
}

impl TryFrom<v1::SendTransactionRequest> for SendTransactionRequest {
    type Error = ProxyDecodeError;
    fn try_from(request: v1::SendTransactionRequest) -> Result<Self, Self::Error> {
        Ok(SendTransactionRequest {
            network: Network::try_from(request.network)?,
            transaction: request.transaction,
        })
    }
}

pub type AdapterClient = Box<
    dyn RpcAdapterClient<BitcoinAdapterRequestWrapper, Response = BitcoinAdapterResponseWrapper>,
>;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum BitcoinAdapterRequestWrapper {
    GetSuccessorsRequest(GetSuccessorsRequestInitial),
    SendTransactionRequest(SendTransactionRequest),
}

impl BitcoinAdapterRequestWrapper {
    pub fn to_request_type_label(&self) -> &str {
        match self {
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(_) => "get_successors",
            BitcoinAdapterRequestWrapper::SendTransactionRequest(_) => "send_transaction",
        }
    }

    /// Returns which network the request is for.
    pub fn network(&self) -> Network {
        match self {
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
                network,
                ..
            }) => *network,
            BitcoinAdapterRequestWrapper::SendTransactionRequest(SendTransactionRequest {
                network,
                ..
            }) => *network,
        }
    }
}

impl From<&BitcoinAdapterRequestWrapper> for v1::BitcoinAdapterRequestWrapper {
    fn from(request_wrapper: &BitcoinAdapterRequestWrapper) -> Self {
        match request_wrapper {
            BitcoinAdapterRequestWrapper::GetSuccessorsRequest(request) => {
                v1::BitcoinAdapterRequestWrapper {
                    r: Some(
                        v1::bitcoin_adapter_request_wrapper::R::GetSuccessorsRequest(
                            request.into(),
                        ),
                    ),
                }
            }
            BitcoinAdapterRequestWrapper::SendTransactionRequest(request) => {
                v1::BitcoinAdapterRequestWrapper {
                    r: Some(
                        v1::bitcoin_adapter_request_wrapper::R::SendTransactionRequest(
                            request.into(),
                        ),
                    ),
                }
            }
        }
    }
}

impl TryFrom<v1::BitcoinAdapterRequestWrapper> for BitcoinAdapterRequestWrapper {
    type Error = ProxyDecodeError;
    fn try_from(request_wrapper: v1::BitcoinAdapterRequestWrapper) -> Result<Self, Self::Error> {
        match request_wrapper.r.ok_or(ProxyDecodeError::MissingField(
            "BitcoinAdapterRequestWrapper::r",
        ))? {
            v1::bitcoin_adapter_request_wrapper::R::GetSuccessorsRequest(r) => Ok(
                BitcoinAdapterRequestWrapper::GetSuccessorsRequest(r.try_into()?),
            ),
            v1::bitcoin_adapter_request_wrapper::R::SendTransactionRequest(r) => Ok(
                BitcoinAdapterRequestWrapper::SendTransactionRequest(r.try_into()?),
            ),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BitcoinAdapterRequest {
    pub request: BitcoinAdapterRequestWrapper,
    pub callback_id: u64,
}

impl From<&BitcoinAdapterRequest> for v1::BitcoinAdapterRequest {
    fn from(request: &BitcoinAdapterRequest) -> Self {
        v1::BitcoinAdapterRequest {
            request: Some((&request.request).into()),
            callback_id: request.callback_id,
        }
    }
}

impl TryFrom<v1::BitcoinAdapterRequest> for BitcoinAdapterRequest {
    type Error = ProxyDecodeError;
    fn try_from(request: v1::BitcoinAdapterRequest) -> Result<Self, Self::Error> {
        let wrapped_request =
            try_from_option_field(request.request, "BitcoinAdapterRequest::request")?;
        Ok(BitcoinAdapterRequest {
            request: wrapped_request,
            callback_id: request.callback_id,
        })
    }
}
//--------------------------- BLOCK HEADER ------------------------------------
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct BlockHeader {
    pub version: i32,
    #[serde(with = "serde_bytes")]
    pub prev_blockhash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub merkle_root: Vec<u8>,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// Returns the size of this `BlockHeader` in bytes.
    pub fn count_bytes(&self) -> usize {
        size_of_val(&self.version)
            + self.prev_blockhash.len()
            + self.merkle_root.len()
            + size_of_val(&self.time)
            + size_of_val(&self.bits)
            + size_of_val(&self.nonce)
    }
}

impl From<&BlockHeader> for v1::BlockHeader {
    fn from(header: &BlockHeader) -> Self {
        v1::BlockHeader {
            version: header.version,
            prev_blockhash: header.prev_blockhash.clone(),
            merkle_root: header.merkle_root.clone(),
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        }
    }
}

impl From<v1::BlockHeader> for BlockHeader {
    fn from(header: v1::BlockHeader) -> Self {
        BlockHeader {
            version: header.version,
            prev_blockhash: header.prev_blockhash,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        }
    }
}

//--------------------------- BLOCK -------------------------------------------
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txdata: Vec<Transaction>,
}

impl Block {
    pub fn count_bytes(&self) -> usize {
        self.header.count_bytes() + self.txdata.iter().map(|tx| tx.count_bytes()).sum::<usize>()
    }
}

impl From<&Block> for v1::Block {
    fn from(block: &Block) -> v1::Block {
        v1::Block {
            header: Some(v1::BlockHeader::from(&block.header)),
            txdata: block
                .txdata
                .iter()
                .map(|x| v1::Transaction {
                    version: x.version,
                    lock_time: x.lock_time,
                    input: x.input.iter().map(v1::TxIn::from).collect(),
                    output: x
                        .output
                        .iter()
                        .map(|x| v1::TxOut {
                            value: x.value,
                            script_pubkey: x.script_pubkey.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

fn validate_hash(bytes: Vec<u8>) -> Result<Vec<u8>, ProxyDecodeError> {
    if bytes.len() != HASH_LEN {
        Err(ProxyDecodeError::InvalidDigestLength {
            expected: HASH_LEN,
            actual: bytes.len(),
        })
    } else {
        Ok(bytes)
    }
}

impl TryFrom<v1::Block> for Block {
    type Error = ProxyDecodeError;

    fn try_from(block: v1::Block) -> Result<Block, ProxyDecodeError> {
        let header = match block.header {
            Some(header) => BlockHeader {
                version: header.version,
                prev_blockhash: validate_hash(header.prev_blockhash)?,
                merkle_root: validate_hash(header.merkle_root)?,
                time: header.time,
                bits: header.bits,
                nonce: header.nonce,
            },
            None => return Err(ProxyDecodeError::MissingField("Bitcoin::BlockHeader")),
        };

        let mut txdata: Vec<Transaction> = vec![];
        for tx in block.txdata.into_iter() {
            let mut input = vec![];
            for txin in tx.input.into_iter() {
                input.push(TxIn::try_from(txin)?);
            }
            txdata.push(Transaction {
                version: tx.version,
                lock_time: tx.lock_time,
                input,
                output: tx
                    .output
                    .into_iter()
                    .map(|x| TxOut {
                        value: x.value,
                        script_pubkey: x.script_pubkey,
                    })
                    .collect(),
            });
        }

        Ok(Block { header, txdata })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct Transaction {
    pub version: i32,
    pub lock_time: u32,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
}

impl Transaction {
    pub fn count_bytes(&self) -> usize {
        size_of_val(&self.version)
            + size_of_val(&self.lock_time)
            + self.input.iter().map(|i| i.count_bytes()).sum::<usize>()
            + self.output.iter().map(|o| o.count_bytes()).sum::<usize>()
    }
}

pub const HASH_LEN: usize = 32;

pub type Hash = [u8; HASH_LEN];
pub type Txid = Hash;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn count_bytes(&self) -> usize {
        size_of_val(&self.txid) + size_of_val(&self.vout)
    }
}
//--------------------------- TxIn --------------------------------------------

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct TxIn {
    pub previous_output: OutPoint,
    #[serde(with = "serde_bytes")]
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<serde_bytes::ByteBuf>,
}

impl TxIn {
    pub fn count_bytes(&self) -> usize {
        self.previous_output.count_bytes()
            + self.script_sig.len()
            + size_of_val(&self.sequence)
            + self.witness.iter().map(|w| w.len()).sum::<usize>()
    }
}

impl From<&TxIn> for v1::TxIn {
    fn from(txin: &TxIn) -> v1::TxIn {
        v1::TxIn {
            previous_output: Some(v1::OutPoint {
                txid: txin.previous_output.txid.to_vec(),
                vout: txin.previous_output.vout,
            }),
            script_sig: txin.script_sig.to_vec(),
            sequence: txin.sequence,
            witness: txin.witness.iter().map(|v| v.to_vec()).collect(),
        }
    }
}

impl TryFrom<v1::TxIn> for TxIn {
    type Error = ProxyDecodeError;
    fn try_from(txin: v1::TxIn) -> Result<TxIn, ProxyDecodeError> {
        let previous_output = match txin.previous_output {
            Some(previous_output) => previous_output,
            None => return Err(ProxyDecodeError::MissingField("Bitcoin::OutPoint")),
        };
        Ok(TxIn {
            previous_output: OutPoint {
                txid: Txid::try_from(&previous_output.txid[..])
                    .map_err(|e| ProxyDecodeError::Other(e.to_string()))?,
                vout: previous_output.vout,
            },
            script_sig: txin.script_sig,
            sequence: txin.sequence,
            witness: txin
                .witness
                .into_iter()
                .map(serde_bytes::ByteBuf::from)
                .collect(),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct TxOut {
    pub value: u64,
    #[serde(with = "serde_bytes")]
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    pub fn count_bytes(&self) -> usize {
        size_of_val(&self.value) + self.script_pubkey.len()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct SendTransactionResponse {}

impl From<&SendTransactionResponse> for v1::SendTransactionResponse {
    fn from(_response: &SendTransactionResponse) -> Self {
        v1::SendTransactionResponse {}
    }
}

impl From<v1::SendTransactionResponse> for SendTransactionResponse {
    fn from(_response: v1::SendTransactionResponse) -> Self {
        SendTransactionResponse {}
    }
}

impl SendTransactionResponse {
    /// Returns the size of this `SendTransactionResponse` in bytes.
    pub fn count_bytes(&self) -> usize {
        let SendTransactionResponse {} = &self;
        0
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct BitcoinReject {
    /// The [`RejectCode`] of the request.
    pub reject_code: RejectCode,
    /// Error message to provide additional information.
    pub message: String,
}

impl BitcoinReject {
    /// Returns the size of this `RejectResponse` in bytes.
    pub fn count_bytes(&self) -> usize {
        let BitcoinReject {
            reject_code,
            message,
        } = &self;
        size_of_val(reject_code) + message.len()
    }
}

impl From<&BitcoinReject> for v1::GetSuccessorsReject {
    fn from(reject: &BitcoinReject) -> Self {
        v1::GetSuccessorsReject {
            message: reject.message.clone(),
            reject_code: pbRejectCode::from(reject.reject_code).into(),
        }
    }
}

impl TryFrom<v1::GetSuccessorsReject> for BitcoinReject {
    type Error = ProxyDecodeError;
    fn try_from(reject: v1::GetSuccessorsReject) -> Result<Self, Self::Error> {
        Ok(BitcoinReject {
            reject_code: RejectCode::try_from(
                pbRejectCode::try_from(reject.reject_code).map_err(|_| {
                    ProxyDecodeError::ValueOutOfRange {
                        typ: "GetSuccessorsReject::reject_code",
                        err: format!("value out of range: {}", reject.reject_code),
                    }
                })?,
            )?,
            message: reject.message,
        })
    }
}

impl From<&BitcoinReject> for v1::SendTransactionReject {
    fn from(reject: &BitcoinReject) -> Self {
        v1::SendTransactionReject {
            message: reject.message.clone(),
            reject_code: pbRejectCode::from(reject.reject_code).into(),
        }
    }
}

impl TryFrom<v1::SendTransactionReject> for BitcoinReject {
    type Error = ProxyDecodeError;
    fn try_from(reject: v1::SendTransactionReject) -> Result<Self, Self::Error> {
        Ok(BitcoinReject {
            reject_code: RejectCode::try_from(
                pbRejectCode::try_from(reject.reject_code).map_err(|_| {
                    ProxyDecodeError::ValueOutOfRange {
                        typ: "SendTransactionReject::reject_code",
                        err: format!("value out of range: {}", reject.reject_code),
                    }
                })?,
            )?,
            message: reject.message,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum BitcoinAdapterResponseWrapper {
    GetSuccessorsResponse(GetSuccessorsResponseComplete),
    SendTransactionResponse(SendTransactionResponse),
    GetSuccessorsReject(BitcoinReject),
    SendTransactionReject(BitcoinReject),
}

impl BitcoinAdapterResponseWrapper {
    /// Returns the size of this `BitcoinAdapterResponseWrapper` in bytes.
    fn count_bytes(&self) -> usize {
        match self {
            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r) => r.count_bytes(),
            BitcoinAdapterResponseWrapper::SendTransactionResponse(r) => r.count_bytes(),
            BitcoinAdapterResponseWrapper::GetSuccessorsReject(r) => r.count_bytes(),
            BitcoinAdapterResponseWrapper::SendTransactionReject(r) => r.count_bytes(),
        }
    }
}

impl From<&BitcoinAdapterResponseWrapper> for v1::BitcoinAdapterResponseWrapper {
    fn from(response_wrapper: &BitcoinAdapterResponseWrapper) -> Self {
        match response_wrapper {
            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(response) => {
                v1::BitcoinAdapterResponseWrapper {
                    r: Some(
                        v1::bitcoin_adapter_response_wrapper::R::GetSuccessorsResponse(
                            response.into(),
                        ),
                    ),
                }
            }
            BitcoinAdapterResponseWrapper::SendTransactionResponse(response) => {
                v1::BitcoinAdapterResponseWrapper {
                    r: Some(
                        v1::bitcoin_adapter_response_wrapper::R::SendTransactionResponse(
                            response.into(),
                        ),
                    ),
                }
            }
            BitcoinAdapterResponseWrapper::GetSuccessorsReject(reject) => {
                v1::BitcoinAdapterResponseWrapper {
                    r: Some(
                        v1::bitcoin_adapter_response_wrapper::R::GetSuccessorsReject(reject.into()),
                    ),
                }
            }
            BitcoinAdapterResponseWrapper::SendTransactionReject(reject) => {
                v1::BitcoinAdapterResponseWrapper {
                    r: Some(
                        v1::bitcoin_adapter_response_wrapper::R::SendTransactionReject(
                            reject.into(),
                        ),
                    ),
                }
            }
        }
    }
}

impl TryFrom<v1::BitcoinAdapterResponseWrapper> for BitcoinAdapterResponseWrapper {
    type Error = ProxyDecodeError;
    fn try_from(response_wrapper: v1::BitcoinAdapterResponseWrapper) -> Result<Self, Self::Error> {
        match response_wrapper.r.ok_or(ProxyDecodeError::MissingField(
            "BitcoinAdapterResponseWrapper::r",
        ))? {
            v1::bitcoin_adapter_response_wrapper::R::GetSuccessorsResponse(r) => Ok(
                BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r.try_into()?),
            ),
            v1::bitcoin_adapter_response_wrapper::R::SendTransactionResponse(r) => Ok(
                BitcoinAdapterResponseWrapper::SendTransactionResponse(r.into()),
            ),
            v1::bitcoin_adapter_response_wrapper::R::GetSuccessorsReject(r) => Ok(
                BitcoinAdapterResponseWrapper::GetSuccessorsReject(r.try_into()?),
            ),
            v1::bitcoin_adapter_response_wrapper::R::SendTransactionReject(r) => Ok(
                BitcoinAdapterResponseWrapper::SendTransactionReject(r.try_into()?),
            ),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct BitcoinAdapterResponse {
    pub response: BitcoinAdapterResponseWrapper,
    pub callback_id: u64,
}

impl From<&BitcoinAdapterResponse> for v1::BitcoinAdapterResponse {
    fn from(response: &BitcoinAdapterResponse) -> Self {
        v1::BitcoinAdapterResponse {
            response: Some((&response.response).into()),
            callback_id: response.callback_id,
        }
    }
}

impl TryFrom<v1::BitcoinAdapterResponse> for BitcoinAdapterResponse {
    type Error = ProxyDecodeError;
    fn try_from(response: v1::BitcoinAdapterResponse) -> Result<Self, Self::Error> {
        let wrapped_response =
            try_from_option_field(response.response, "BitcoinAdapterResponse::response")?;
        Ok(BitcoinAdapterResponse {
            response: wrapped_response,
            callback_id: response.callback_id,
        })
    }
}

impl BitcoinAdapterResponse {
    /// Returns the size of this `BitcoinAdapterResponse` in bytes.
    pub fn count_bytes(&self) -> usize {
        let BitcoinAdapterResponse {
            response,
            callback_id,
        } = &self;
        response.count_bytes() + size_of_val(callback_id)
    }
}

// A blob representing a block in the standard bitcoin format.
pub type BlockBlob = Vec<u8>;

// A blob representing a block header in the standard bitcoin format.
type BlockHeaderBlob = Vec<u8>;

type BlockHash = Vec<u8>;

type PageNumber = u8;

/// A request to retrieve more blocks from the Bitcoin network.
///
/// ```text
/// variant {
///   initial : record {
///     network: network;
///     anchor: blob;
///     processed_block_hashes: vec blob;
///   };
///   follow_up : nat8;
/// };
/// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum GetSuccessorsRequest {
    /// A request containing the hashes of blocks we'd like to retrieve succeessors for.
    #[serde(rename = "initial")]
    Initial(GetSuccessorsRequestInitial),

    /// A follow-up request to retrieve the `FollowUp` response associated with the given page.
    #[serde(rename = "follow_up")]
    FollowUp(PageNumber),
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct GetSuccessorsRequestInitial {
    pub network: Network,
    pub anchor: BlockHash,
    pub processed_block_hashes: Vec<BlockHash>,
}

impl From<&GetSuccessorsRequestInitial> for v1::GetSuccessorsRequestInitial {
    fn from(request: &GetSuccessorsRequestInitial) -> Self {
        Self {
            network: request.network.into(),
            anchor: request.anchor.clone(),
            processed_block_hashes: request.processed_block_hashes.clone(),
        }
    }
}

impl TryFrom<v1::GetSuccessorsRequestInitial> for GetSuccessorsRequestInitial {
    type Error = ProxyDecodeError;
    fn try_from(request: v1::GetSuccessorsRequestInitial) -> Result<Self, Self::Error> {
        Ok(GetSuccessorsRequestInitial {
            network: Network::try_from(request.network)?,
            anchor: request.anchor,
            processed_block_hashes: request.processed_block_hashes,
        })
    }
}

/// A response containing new successor blocks from the Bitcoin network.
///
/// ```text
/// variant {
///   complete : record {
///     blocks: vec blob;
///     next: vec blob;
///   };
///
///   partial : record {
///     partial_block: blob;
///     next: vec blob;
///     remaining_follow_ups: nat8;
///   };
///
///   follow_up : blob;
/// };
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub enum GetSuccessorsResponse {
    /// A complete response that doesn't require pagination.
    #[serde(rename = "complete")]
    Complete(GetSuccessorsResponseComplete),

    /// A partial response that requires `FollowUp` responses to get the rest of it.
    #[serde(rename = "partial")]
    Partial(GetSuccessorsResponsePartial),

    /// A follow-up response containing a blob of bytes to be appended to the partial response.
    #[serde(rename = "follow_up")]
    FollowUp(BlockBlob),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct GetSuccessorsResponseComplete {
    pub blocks: Vec<BlockBlob>,
    pub next: Vec<BlockHeaderBlob>,
}

impl GetSuccessorsResponseComplete {
    /// Returns the size of this `SendTransactionResponse` in bytes.
    pub fn count_bytes(&self) -> usize {
        self.count_blocks_bytes() + self.count_next_bytes()
    }

    pub fn count_blocks_bytes(&self) -> usize {
        self.blocks.iter().map(|b| b.len()).sum::<usize>()
    }

    pub fn count_next_bytes(&self) -> usize {
        self.next.iter().map(|n| n.len()).sum::<usize>()
    }
}

impl From<&GetSuccessorsResponseComplete> for v1::GetSuccessorsResponseComplete {
    fn from(request: &GetSuccessorsResponseComplete) -> Self {
        v1::GetSuccessorsResponseComplete {
            blocks: request.blocks.clone(),
            next: request.next.clone(),
        }
    }
}

impl TryFrom<v1::GetSuccessorsResponseComplete> for GetSuccessorsResponseComplete {
    type Error = ProxyDecodeError;
    fn try_from(response: v1::GetSuccessorsResponseComplete) -> Result<Self, Self::Error> {
        Ok(GetSuccessorsResponseComplete {
            blocks: response.blocks,
            next: response.next,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub struct GetSuccessorsResponsePartial {
    /// A block that is partial (i.e. the full blob has not been sent).
    pub partial_block: BlockBlob,

    /// Hashes of next block headers.
    pub next: Vec<BlockHeaderBlob>,

    /// The remaining number of follow ups to this response, which can retrieved
    /// via `FollowUp` requests.
    pub remaining_follow_ups: u8,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_successors_response_complete_count_bytes() {
        assert_eq!(
            GetSuccessorsResponseComplete {
                blocks: vec![],
                next: vec![],
            }
            .count_bytes(),
            0
        );

        assert_eq!(
            GetSuccessorsResponseComplete {
                blocks: vec![vec![1, 2, 3], vec![4, 5, 6]],
                next: vec![vec![7, 8, 9, 10], vec![11, 12]],
            }
            .count_bytes(),
            12
        );
    }
}
