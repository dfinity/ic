#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusUnknown {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusProcessing {
    #[prost(message, optional, tag="1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag="2")]
    pub time_nanos: u64,
    #[prost(message, optional, tag="3")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusReceived {
    #[prost(message, optional, tag="1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag="2")]
    pub time_nanos: u64,
    #[prost(message, optional, tag="3")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusCompleted {
    #[prost(message, optional, tag="1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag="4")]
    pub time_nanos: u64,
    #[prost(message, optional, tag="5")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
    #[prost(oneof="ingress_status_completed::WasmResult", tags="2, 3")]
    pub wasm_result: ::core::option::Option<ingress_status_completed::WasmResult>,
}
/// Nested message and enum types in `IngressStatusCompleted`.
pub mod ingress_status_completed {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WasmResult {
        #[prost(bytes, tag="2")]
        Reply(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag="3")]
        Reject(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusFailed {
    #[prost(message, optional, tag="1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(uint64, tag="2")]
    pub err_code: u64,
    #[prost(string, tag="3")]
    pub err_description: ::prost::alloc::string::String,
    #[prost(uint64, tag="4")]
    pub time_nanos: u64,
    #[prost(message, optional, tag="5")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PruningEntry {
    #[prost(uint64, tag="1")]
    pub time_nanos: u64,
    #[prost(bytes="vec", repeated, tag="2")]
    pub messages: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatus {
    #[prost(oneof="ingress_status::Status", tags="1, 2, 3, 4, 5")]
    pub status: ::core::option::Option<ingress_status::Status>,
}
/// Nested message and enum types in `IngressStatus`.
pub mod ingress_status {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Status {
        #[prost(message, tag="1")]
        Unknown(super::IngressStatusUnknown),
        #[prost(message, tag="2")]
        Processing(super::IngressStatusProcessing),
        #[prost(message, tag="3")]
        Received(super::IngressStatusReceived),
        #[prost(message, tag="4")]
        Completed(super::IngressStatusCompleted),
        #[prost(message, tag="5")]
        Failed(super::IngressStatusFailed),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressStatusEntry {
    #[prost(bytes="vec", tag="1")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="2")]
    pub status: ::core::option::Option<IngressStatus>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressHistoryState {
    #[prost(message, repeated, tag="1")]
    pub statuses: ::prost::alloc::vec::Vec<IngressStatusEntry>,
    #[prost(message, repeated, tag="2")]
    pub pruning_times: ::prost::alloc::vec::Vec<PruningEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ingress {
    #[prost(message, optional, tag="1")]
    pub source: ::core::option::Option<super::super::super::types::v1::UserId>,
    #[prost(message, optional, tag="2")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(string, tag="3")]
    pub method_name: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="4")]
    pub method_payload: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="5")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="6")]
    pub expiry_time_nanos: u64,
}
