/// A crypto component log entry.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct CryptoLogEntry {
    #[prost(message, optional, tag = "1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trait_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkg_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "5")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_version: ::core::option::Option<u64>,
    #[prost(message, optional, tag = "6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "7")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "8")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_ok: ::core::option::Option<bool>,
    #[prost(message, optional, tag = "9")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "10")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "11")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkg_config: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "12")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkg_dealing: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "13")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkg_dealer: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "14")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkg_transcript: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "15")]
    pub signed_bytes: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "16")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_tls_clients: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "17")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "18")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dkg_epoch: ::core::option::Option<u32>,
}
