#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct P2pLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: ::core::option::Option<u64>,
    #[prost(message, optional, tag="3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: ::core::option::Option<u64>,
    #[prost(message, optional, tag="4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="5")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advert: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="7")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="8")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="9")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: ::core::option::Option<u64>,
    #[prost(message, optional, tag="10")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_elapsed: ::core::option::Option<u64>,
}
