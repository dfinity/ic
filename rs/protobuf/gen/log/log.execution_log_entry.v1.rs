#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionLogEntry {
    #[prost(message, optional, tag="1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canister_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration="execution_log_entry::MessageType", tag="2")]
    pub message_type: i32,
}
/// Nested message and enum types in `ExecutionLogEntry`.
pub mod execution_log_entry {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum MessageType {
        Unspecified = 0,
        Ingress = 1,
        CanisterRequest = 2,
        CanisterResponse = 3,
    }
}
