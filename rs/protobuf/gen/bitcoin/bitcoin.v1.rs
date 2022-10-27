#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct Transaction {
    #[prost(int32, tag = "1")]
    pub version: i32,
    #[prost(uint32, tag = "2")]
    pub lock_time: u32,
    #[prost(message, repeated, tag = "3")]
    pub input: ::prost::alloc::vec::Vec<TxIn>,
    #[prost(message, repeated, tag = "4")]
    pub output: ::prost::alloc::vec::Vec<TxOut>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct TxIn {
    #[prost(message, optional, tag = "1")]
    pub previous_output: ::core::option::Option<OutPoint>,
    #[prost(bytes = "vec", tag = "2")]
    pub script_sig: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub sequence: u32,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub witness: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct TxOut {
    #[prost(uint64, tag = "1")]
    pub value: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub script_pubkey: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct OutPoint {
    #[prost(bytes = "vec", tag = "1")]
    pub txid: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub vout: u32,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct BlockHeader {
    #[prost(int32, tag = "1")]
    pub version: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub prev_blockhash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub merkle_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub time: u32,
    #[prost(uint32, tag = "5")]
    pub bits: u32,
    #[prost(uint32, tag = "6")]
    pub nonce: u32,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<BlockHeader>,
    #[prost(message, repeated, tag = "2")]
    pub txdata: ::prost::alloc::vec::Vec<Transaction>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct GetSuccessorsRequest {
    /// Used by the adapter to filter out previously sent blocks from its
    /// `GetSuccessorsResponse`.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub processed_block_hashes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// The first hash in processed block hashes. This field is used by the adapter
    /// to start a breadth-first search its known headers to determine which blocks
    /// to respond with in `GetSuccessorsResponse::blocks` field.
    #[prost(bytes = "vec", tag = "2")]
    pub anchor: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct GetSuccessorsResponse {
    /// The blocks that the adapter has knowledge of based on the anchor and processed
    /// block hashes provided in the `GetSuccessorsRequest`.
    #[prost(message, repeated, tag = "1")]
    pub blocks: ::prost::alloc::vec::Vec<Block>,
    /// The next block headers that used to notify the Bitcoin virtual canister that
    /// more blocks are available.
    #[prost(message, repeated, tag = "2")]
    pub next: ::prost::alloc::vec::Vec<BlockHeader>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub transaction: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionResponse {}
/// Wraps the different types of requests to the Bitcoin Adapter.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct BitcoinAdapterRequestWrapper {
    #[prost(oneof = "bitcoin_adapter_request_wrapper::R", tags = "1, 2, 3")]
    pub r: ::core::option::Option<bitcoin_adapter_request_wrapper::R>,
}
/// Nested message and enum types in `BitcoinAdapterRequestWrapper`.
pub mod bitcoin_adapter_request_wrapper {
    #[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag = "1")]
        GetSuccessorsRequest(super::GetSuccessorsRequest),
        #[prost(message, tag = "2")]
        SendTransactionRequest(super::SendTransactionRequest),
        #[prost(message, tag = "3")]
        CanisterGetSuccessorsRequest(super::CanisterGetSuccessorsRequestInitial),
    }
}
/// Wraps the different types of responses from the Bitcoin Adapter.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct BitcoinAdapterResponseWrapper {
    #[prost(oneof = "bitcoin_adapter_response_wrapper::R", tags = "1, 2, 3")]
    pub r: ::core::option::Option<bitcoin_adapter_response_wrapper::R>,
}
/// Nested message and enum types in `BitcoinAdapterResponseWrapper`.
pub mod bitcoin_adapter_response_wrapper {
    #[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag = "1")]
        GetSuccessorsResponse(super::GetSuccessorsResponse),
        #[prost(message, tag = "2")]
        SendTransactionResponse(super::SendTransactionResponse),
        #[prost(message, tag = "3")]
        CanisterGetSuccessorsResponse(super::CanisterGetSuccessorsResponseComplete),
    }
}
/// A Bitcoin Adapter request, used to store the requests in the
/// `ReplicatedState`.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct BitcoinAdapterRequest {
    /// The wrapped Bitcoin request to the Adapter.
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<BitcoinAdapterRequestWrapper>,
    /// The callback id associated with this request. Useful to match it against
    /// the incoming responses.
    #[prost(uint64, tag = "2")]
    pub callback_id: u64,
}
/// A Bitcoin Adapter response, used to store the responses in the
/// `ReplicatedState`.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct BitcoinAdapterResponse {
    /// The wrapped Bitcoin response from the Adapter.
    #[prost(message, optional, tag = "1")]
    pub response: ::core::option::Option<BitcoinAdapterResponseWrapper>,
    /// The callback id associated with this response. Used to match a response
    /// against its corresponding request.
    #[prost(uint64, tag = "2")]
    pub callback_id: u64,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct AdapterQueues {
    /// Tracks the callback id that will be generated for the next request.
    /// Used to match incoming responses to existing requests.
    #[prost(uint64, tag = "1")]
    pub next_callback_id: u64,
    /// Queue of outgoing requests to the Bitcoin Adapter.
    #[prost(message, repeated, tag = "2")]
    pub requests: ::prost::alloc::vec::Vec<BitcoinAdapterRequest>,
    /// Queue of incoming responses from the Bitcoin Adapter.
    #[prost(message, repeated, tag = "3")]
    pub responses: ::prost::alloc::vec::Vec<BitcoinAdapterResponse>,
    /// Capacity of the queue of outgoing requests.
    #[prost(uint32, tag = "4")]
    pub requests_queue_capacity: u32,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct UnstableBlocks {
    #[prost(uint32, tag = "1")]
    pub stability_threshold: u32,
    #[prost(message, optional, tag = "2")]
    pub tree: ::core::option::Option<BlockTree>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct BlockTree {
    #[prost(message, optional, tag = "1")]
    pub root: ::core::option::Option<Block>,
    #[prost(message, repeated, tag = "2")]
    pub children: ::prost::alloc::vec::Vec<BlockTree>,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct Utxo {
    #[prost(message, optional, tag = "1")]
    pub outpoint: ::core::option::Option<OutPoint>,
    #[prost(message, optional, tag = "2")]
    pub txout: ::core::option::Option<TxOut>,
    #[prost(uint32, tag = "3")]
    pub height: u32,
}
/// A request to retrieve new blocks from the specified Bitcoin network.
/// NOTE: This request is specific to the Bitcoin wasm canister. It supersedes the
/// `GetSuccessorsRequest` above, which will be deleted once the  Bitcoin replica canister is
/// phased out.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct CanisterGetSuccessorsRequestInitial {
    #[prost(enumeration = "Network", tag = "1")]
    pub network: i32,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub processed_block_hashes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub anchor: ::prost::alloc::vec::Vec<u8>,
}
/// A response containing new successor blocks from the Bitcoin network.
/// NOTE: This response is specific to the Bitcoin wasm canister. It supersedes the
/// `GetSuccessorsResponse` above, which will be deleted once the  Bitcoin replica canister is
/// phased out.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct CanisterGetSuccessorsResponseComplete {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub blocks: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub next: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// Represents the Bitcoin state that isn't stored in PageMaps.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct BitcoinStateBits {
    /// The queues that maintain the requests to and responses from the Bitcoin
    /// Adapter.
    #[prost(message, optional, tag = "1")]
    pub adapter_queues: ::core::option::Option<AdapterQueues>,
    #[prost(message, optional, tag = "2")]
    pub unstable_blocks: ::core::option::Option<UnstableBlocks>,
    #[prost(uint32, tag = "3")]
    pub stable_height: u32,
    #[prost(enumeration = "Network", tag = "4")]
    pub network: i32,
    #[prost(message, repeated, tag = "5")]
    pub utxos_large: ::prost::alloc::vec::Vec<Utxo>,
}
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum Network {
    Unspecified = 0,
    Testnet = 1,
    Mainnet = 2,
    Regtest = 3,
}
impl Network {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Network::Unspecified => "NETWORK_UNSPECIFIED",
            Network::Testnet => "NETWORK_TESTNET",
            Network::Mainnet => "NETWORK_MAINNET",
            Network::Regtest => "NETWORK_REGTEST",
        }
    }
}
