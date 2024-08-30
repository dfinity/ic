#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxOut {
    #[prost(uint64, tag = "1")]
    pub value: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub script_pubkey: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutPoint {
    #[prost(bytes = "vec", tag = "1")]
    pub txid: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub vout: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<BlockHeader>,
    #[prost(message, repeated, tag = "2")]
    pub txdata: ::prost::alloc::vec::Vec<Transaction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionRequest {
    #[prost(enumeration = "Network", tag = "1")]
    pub network: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub transaction: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionResponse {}
/// Wraps the different types of requests to the Bitcoin Adapter.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinAdapterRequestWrapper {
    #[prost(oneof = "bitcoin_adapter_request_wrapper::R", tags = "3, 4")]
    pub r: ::core::option::Option<bitcoin_adapter_request_wrapper::R>,
}
/// Nested message and enum types in `BitcoinAdapterRequestWrapper`.
pub mod bitcoin_adapter_request_wrapper {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag = "3")]
        GetSuccessorsRequest(super::GetSuccessorsRequestInitial),
        #[prost(message, tag = "4")]
        SendTransactionRequest(super::SendTransactionRequest),
    }
}
/// Wraps the different types of responses from the Bitcoin Adapter.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinAdapterResponseWrapper {
    #[prost(oneof = "bitcoin_adapter_response_wrapper::R", tags = "3, 4, 5, 6")]
    pub r: ::core::option::Option<bitcoin_adapter_response_wrapper::R>,
}
/// Nested message and enum types in `BitcoinAdapterResponseWrapper`.
pub mod bitcoin_adapter_response_wrapper {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag = "3")]
        GetSuccessorsResponse(super::GetSuccessorsResponseComplete),
        #[prost(message, tag = "4")]
        SendTransactionResponse(super::SendTransactionResponse),
        #[prost(message, tag = "5")]
        GetSuccessorsReject(super::GetSuccessorsReject),
        #[prost(message, tag = "6")]
        SendTransactionReject(super::SendTransactionReject),
    }
}
/// A Bitcoin Adapter request, used to store the requests in the
/// `ReplicatedState`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinAdapterResponse {
    /// The wrapped Bitcoin response from the Adapter.
    #[prost(message, optional, tag = "1")]
    pub response: ::core::option::Option<BitcoinAdapterResponseWrapper>,
    /// The callback id associated with this response. Used to match a response
    /// against its corresponding request.
    #[prost(uint64, tag = "2")]
    pub callback_id: u64,
}
/// A request to retrieve new blocks from the specified Bitcoin network.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSuccessorsRequestInitial {
    #[prost(enumeration = "Network", tag = "1")]
    pub network: i32,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub processed_block_hashes: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub anchor: ::prost::alloc::vec::Vec<u8>,
}
/// A response containing new successor blocks from the Bitcoin network.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSuccessorsResponseComplete {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub blocks: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub next: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// A `GetSucceessors` reject response containing additional information about the rejection.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSuccessorsReject {
    #[prost(enumeration = "super::super::types::v1::RejectCode", tag = "3")]
    pub reject_code: i32,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
/// A `SendTransaction` reject response containing additional information about the rejection.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendTransactionReject {
    #[prost(enumeration = "super::super::types::v1::RejectCode", tag = "3")]
    pub reject_code: i32,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
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
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NETWORK_UNSPECIFIED" => Some(Self::Unspecified),
            "NETWORK_TESTNET" => Some(Self::Testnet),
            "NETWORK_MAINNET" => Some(Self::Mainnet),
            "NETWORK_REGTEST" => Some(Self::Regtest),
            _ => None,
        }
    }
}
