use crate::CountBytes;
use bitcoin::{hashes::Hash, Block, OutPoint, TxOut, Txid};
use ic_protobuf::{
    bitcoin::v1,
    proxy::{try_from_option_field, ProxyDecodeError},
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    hash::Hasher,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetSuccessorsRequest {
    pub processed_block_hashes: Vec<Vec<u8>>,
    pub anchor: Vec<u8>,
}

impl From<&GetSuccessorsRequest> for v1::GetSuccessorsRequest {
    fn from(request: &GetSuccessorsRequest) -> Self {
        v1::GetSuccessorsRequest {
            processed_block_hashes: request.processed_block_hashes.clone(),
            anchor: request.anchor.clone(),
        }
    }
}

impl From<v1::GetSuccessorsRequest> for GetSuccessorsRequest {
    fn from(request: v1::GetSuccessorsRequest) -> Self {
        GetSuccessorsRequest {
            processed_block_hashes: request.processed_block_hashes,
            anchor: request.anchor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendTransactionRequest {
    pub transaction: Vec<u8>,
}

impl From<&SendTransactionRequest> for v1::SendTransactionRequest {
    fn from(request: &SendTransactionRequest) -> Self {
        v1::SendTransactionRequest {
            transaction: request.transaction.clone(),
        }
    }
}

impl From<v1::SendTransactionRequest> for SendTransactionRequest {
    fn from(request: v1::SendTransactionRequest) -> Self {
        SendTransactionRequest {
            transaction: request.transaction,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BitcoinAdapterRequestWrapper {
    GetSuccessorsRequest(GetSuccessorsRequest),
    SendTransactionRequest(SendTransactionRequest),
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, Default, Hash, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_blockhash: Vec<u8>,
    pub merkle_root: Vec<u8>,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl CountBytes for BlockHeader {
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<i32>()
            + self.prev_blockhash.len()
            + self.merkle_root.len()
            + std::mem::size_of::<u32>() * 3
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GetSuccessorsResponse {
    pub blocks: Vec<Block>,
    pub next: Vec<BlockHeader>,
}

impl CountBytes for GetSuccessorsResponse {
    fn count_bytes(&self) -> usize {
        self.blocks.iter().map(|x| x.get_size()).sum::<usize>()
            + self.next.iter().map(|x| x.count_bytes()).sum::<usize>()
    }
}

// Implement `PartialEq` and `Eq` because we need to implement `Hash` as well.
// See below for an explanation why we need to implement `Hash`.
impl PartialEq for GetSuccessorsResponse {
    fn eq(&self, other: &Self) -> bool {
        self.blocks.len() == other.blocks.len()
            && self
                .blocks
                .iter()
                .zip(other.blocks.iter())
                .all(|(a, b)| a == b)
    }
}

impl Eq for GetSuccessorsResponse {}

// Implement `Hash` because it's a requirement for structs stored in a consensus
// block and we can't derive it since `bitcoin::Block` doesn't derive it.
impl std::hash::Hash for GetSuccessorsResponse {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.blocks.iter() {
            b.block_hash().hash(state);
        }
        for h in self.next.iter() {
            h.hash(state);
        }
    }
}

impl From<&GetSuccessorsResponse> for v1::GetSuccessorsResponse {
    fn from(response: &GetSuccessorsResponse) -> Self {
        v1::GetSuccessorsResponse {
            blocks: response.blocks.iter().map(block_to_proto).collect(),
            next: response.next.iter().map(v1::BlockHeader::from).collect(),
        }
    }
}

impl TryFrom<v1::GetSuccessorsResponse> for GetSuccessorsResponse {
    type Error = ProxyDecodeError;
    fn try_from(response: v1::GetSuccessorsResponse) -> Result<Self, Self::Error> {
        let mut blocks = vec![];
        for b in response.blocks.into_iter() {
            blocks.push(block_try_from_proto(b)?);
        }
        Ok(GetSuccessorsResponse {
            blocks,
            next: response.next.into_iter().map(BlockHeader::from).collect(),
        })
    }
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
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

impl CountBytes for SendTransactionResponse {
    fn count_bytes(&self) -> usize {
        0
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitcoinAdapterResponseWrapper {
    GetSuccessorsResponse(GetSuccessorsResponse),
    SendTransactionResponse(SendTransactionResponse),
}

impl CountBytes for BitcoinAdapterResponseWrapper {
    fn count_bytes(&self) -> usize {
        match self {
            BitcoinAdapterResponseWrapper::GetSuccessorsResponse(r) => r.count_bytes(),
            BitcoinAdapterResponseWrapper::SendTransactionResponse(r) => r.count_bytes(),
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
                BitcoinAdapterResponseWrapper::SendTransactionResponse(r.try_into()?),
            ),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
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

impl CountBytes for BitcoinAdapterResponse {
    fn count_bytes(&self) -> usize {
        self.response.count_bytes() + std::mem::size_of::<u64>()
    }
}

// Helper function to convert a `bitcoin::TxIn` to a protobuf `TxIn`.
// The function is needed because both types are defined in different crates
// and we cannot idiomatic `From`, `TryFrom` implementations.
fn txin_to_proto(txin: &bitcoin::TxIn) -> v1::TxIn {
    v1::TxIn {
        previous_output: Some(v1::OutPoint {
            txid: txin.previous_output.txid.to_vec(),
            vout: txin.previous_output.vout,
        }),
        script_sig: txin.script_sig.to_bytes(),
        sequence: txin.sequence,
        witness: txin.witness.to_vec(),
    }
}

// Helper function to convert a protobuf `TxIn` to a `bitcoin::TxIn`.
// The function is needed because both types are defined in different crates
// and we cannot idiomatic `From`, `TryFrom` implementations.
fn txin_try_from_proto(txin: v1::TxIn) -> Result<bitcoin::TxIn, ProxyDecodeError> {
    let previous_output = match txin.previous_output {
        Some(previous_output) => previous_output,
        None => return Err(ProxyDecodeError::MissingField("Bitcoin::OutPoint")),
    };
    Ok(bitcoin::TxIn {
        previous_output: OutPoint {
            txid: Txid::from_hash(
                Hash::from_slice(&previous_output.txid)
                    .map_err(|e| ProxyDecodeError::Other(e.to_string()))?,
            ),
            vout: previous_output.vout,
        },
        script_sig: bitcoin::Script::from(txin.script_sig),
        sequence: txin.sequence,
        witness: txin.witness,
    })
}

// Helper function to convert a `bitcoin::Block` to a protobuf `Block`.
// The function is needed because both types are defined in different crates
// and we cannot idiomatic `From`, `TryFrom` implementations.
fn block_to_proto(block: &Block) -> v1::Block {
    v1::Block {
        header: Some(v1::BlockHeader {
            version: block.header.version,
            prev_blockhash: block.header.prev_blockhash.to_vec(),
            merkle_root: block.header.merkle_root.to_vec(),
            time: block.header.time,
            bits: block.header.bits,
            nonce: block.header.nonce,
        }),
        txdata: block
            .txdata
            .iter()
            .map(|x| v1::Transaction {
                version: x.version,
                lock_time: x.lock_time,
                input: x.input.iter().map(txin_to_proto).collect(),
                output: x
                    .output
                    .iter()
                    .map(|x| v1::TxOut {
                        value: x.value,
                        script_pubkey: x.script_pubkey.to_bytes(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

// Helper function to convert a protobuf `Block` to a protobuf `bitcoin::Block`.
// The function is needed because both types are defined in different crates
// and we cannot idiomatic `From`, `TryFrom` implementations.
fn block_try_from_proto(block: v1::Block) -> Result<Block, ProxyDecodeError> {
    let header = match block.header {
        Some(header) => bitcoin::BlockHeader {
            version: header.version,
            prev_blockhash: bitcoin::BlockHash::from_hash(
                Hash::from_slice(&header.prev_blockhash)
                    .map_err(|e| ProxyDecodeError::Other(e.to_string()))?,
            ),
            merkle_root: bitcoin::TxMerkleNode::from_hash(
                Hash::from_slice(&header.merkle_root)
                    .map_err(|e| ProxyDecodeError::Other(e.to_string()))?,
            ),
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        },
        None => return Err(ProxyDecodeError::MissingField("Bitcoin::BlockHeader")),
    };

    let mut txdata: Vec<bitcoin::Transaction> = vec![];
    for tx in block.txdata.into_iter() {
        let mut input = vec![];
        for txin in tx.input.into_iter() {
            input.push(txin_try_from_proto(txin)?);
        }
        txdata.push(bitcoin::Transaction {
            version: tx.version,
            lock_time: tx.lock_time,
            input,
            output: tx
                .output
                .into_iter()
                .map(|x| TxOut {
                    value: x.value,
                    script_pubkey: bitcoin::Script::from(x.script_pubkey),
                })
                .collect(),
        });
    }

    Ok(Block { header, txdata })
}
