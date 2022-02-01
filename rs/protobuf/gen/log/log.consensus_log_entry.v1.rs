#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: ::core::option::Option<u64>,
    #[prost(message, optional, tag="2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: ::core::option::Option<::prost::alloc::string::String>,
}
