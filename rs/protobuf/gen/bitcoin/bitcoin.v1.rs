#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Transaction {
    #[prost(int32, tag="1")]
    pub version: i32,
    #[prost(uint32, tag="2")]
    pub lock_time: u32,
    #[prost(message, repeated, tag="3")]
    pub input: ::prost::alloc::vec::Vec<TxIn>,
    #[prost(message, repeated, tag="4")]
    pub output: ::prost::alloc::vec::Vec<TxOut>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxIn {
    #[prost(message, optional, tag="1")]
    pub previous_output: ::core::option::Option<OutPoint>,
    #[prost(bytes="vec", tag="2")]
    pub script_sig: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="3")]
    pub sequence: u32,
    #[prost(bytes="vec", repeated, tag="4")]
    pub witness: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxOut {
    #[prost(uint64, tag="1")]
    pub value: u64,
    #[prost(bytes="vec", tag="2")]
    pub script_pubkey: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutPoint {
    #[prost(bytes="vec", tag="1")]
    pub txid: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub vout: u32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockHeader {
    #[prost(int32, tag="1")]
    pub version: i32,
    #[prost(bytes="vec", tag="2")]
    pub prev_blockhash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub merkle_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="4")]
    pub time: u32,
    #[prost(uint32, tag="5")]
    pub bits: u32,
    #[prost(uint32, tag="6")]
    pub nonce: u32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<BlockHeader>,
    #[prost(message, repeated, tag="2")]
    pub txdata: ::prost::alloc::vec::Vec<Transaction>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSuccessorsRequest {
    /// Used by the adapter to filter out previously sent blocks from its
    /// `GetSuccessorsResponse`. 
    #[prost(bytes="vec", repeated, tag="1")]
    pub processed_block_hashes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// The first hash in processed block hashes. This field is used by the adapter
    /// to start a breadth-first search its known headers to determine which blocks
    /// to respond with in `GetSuccessorsResponse::blocks` field.
    #[prost(bytes="vec", tag="2")]
    pub anchor: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSuccessorsResponse {
    #[prost(message, repeated, tag="1")]
    pub blocks: ::prost::alloc::vec::Vec<Block>,
    #[prost(message, repeated, tag="2")]
    pub next: ::prost::alloc::vec::Vec<BlockHeader>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionRequest {
    #[prost(bytes="vec", tag="1")]
    pub raw_tx: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionResponse {
}
