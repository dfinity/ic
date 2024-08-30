#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusLogEntry {
    #[prost(message, optional, tag = "1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: ::core::option::Option<u64>,
    #[prost(message, optional, tag = "2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replica_version: ::core::option::Option<::prost::alloc::string::String>,
}
