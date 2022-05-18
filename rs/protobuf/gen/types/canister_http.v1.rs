#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpHeader {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpRequest {
    #[prost(string, tag="1")]
    pub url: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="2")]
    pub body: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag="3")]
    pub headers: ::prost::alloc::vec::Vec<HttpHeader>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponse {
    #[prost(uint64, tag="1")]
    pub id: u64,
    #[prost(uint64, tag="2")]
    pub timeout: u64,
    #[prost(message, optional, tag="3")]
    pub content: ::core::option::Option<CanisterHttpResponseContent>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseContent {
    #[prost(oneof="canister_http_response_content::Status", tags="2, 3")]
    pub status: ::core::option::Option<canister_http_response_content::Status>,
}
/// Nested message and enum types in `CanisterHttpResponseContent`.
pub mod canister_http_response_content {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Status {
        #[prost(message, tag="2")]
        Reject(super::CanisterHttpReject),
        #[prost(bytes, tag="3")]
        Success(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpReject {
    #[prost(uint32, tag="1")]
    pub reject_code: u32,
    #[prost(string, tag="2")]
    pub message: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseWithConsensus {
    #[prost(message, optional, tag="1")]
    pub response: ::core::option::Option<CanisterHttpResponse>,
    #[prost(bytes="vec", tag="2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="3")]
    pub registry_version: u64,
    #[prost(bytes="vec", tag="4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", repeated, tag="5")]
    pub signers: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
