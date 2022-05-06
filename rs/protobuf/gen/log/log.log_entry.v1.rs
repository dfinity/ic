#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogEntry {
    #[prost(string, tag="1")]
    pub level: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub utc_time: ::prost::alloc::string::String,
    #[prost(string, tag="3")]
    pub message: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub crate_: ::prost::alloc::string::String,
    #[prost(string, tag="5")]
    pub module: ::prost::alloc::string::String,
    #[prost(uint32, tag="6")]
    pub line: u32,
    #[prost(string, tag="7")]
    pub node_id: ::prost::alloc::string::String,
    #[prost(string, tag="8")]
    pub subnet_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag="18")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus: ::core::option::Option<super::super::consensus_log_entry::v1::ConsensusLogEntry>,
    #[prost(message, optional, tag="19")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2p: ::core::option::Option<super::super::p2p_log_entry::v1::P2pLogEntry>,
    #[prost(message, optional, tag="20")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messaging: ::core::option::Option<super::super::messaging_log_entry::v1::MessagingLogEntry>,
    #[prost(message, optional, tag="21")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_message: ::core::option::Option<super::super::ingress_message_log_entry::v1::IngressMessageLogEntry>,
    #[prost(message, optional, tag="22")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: ::core::option::Option<super::super::block_log_entry::v1::BlockLogEntry>,
    #[prost(message, optional, tag="23")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto: ::core::option::Option<super::super::crypto_log_entry::v1::CryptoLogEntry>,
    #[prost(message, optional, tag="25")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malicious_behaviour: ::core::option::Option<super::super::malicious_behaviour_log_entry::v1::MaliciousBehaviourLogEntry>,
}
