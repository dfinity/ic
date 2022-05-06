#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cycles {
    #[prost(bytes="vec", tag="2")]
    pub raw_cycles: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Funds {
    #[prost(uint64, tag="2")]
    pub icp: u64,
    #[prost(message, optional, tag="3")]
    pub cycles_struct: ::core::option::Option<Cycles>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stream {
    #[prost(uint64, tag="1")]
    pub messages_begin: u64,
    #[prost(message, repeated, tag="2")]
    pub messages: ::prost::alloc::vec::Vec<RequestOrResponse>,
    #[prost(uint64, tag="5")]
    pub signals_end: u64,
    #[prost(uint64, repeated, tag="6")]
    pub reject_signals: ::prost::alloc::vec::Vec<u64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamEntry {
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag="2")]
    pub subnet_stream: ::core::option::Option<Stream>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(message, optional, tag="1")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="2")]
    pub sender: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag="3")]
    pub sender_reply_callback: u64,
    #[prost(message, optional, tag="4")]
    pub payment: ::core::option::Option<Funds>,
    #[prost(string, tag="5")]
    pub method_name: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="6")]
    pub method_payload: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="7")]
    pub cycles_payment: ::core::option::Option<Cycles>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectContext {
    #[prost(uint64, tag="1")]
    pub reject_code: u64,
    #[prost(string, tag="2")]
    pub reject_message: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(message, optional, tag="1")]
    pub originator: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="2")]
    pub respondent: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag="3")]
    pub originator_reply_callback: u64,
    #[prost(message, optional, tag="4")]
    pub refund: ::core::option::Option<Funds>,
    #[prost(message, optional, tag="7")]
    pub cycles_refund: ::core::option::Option<Cycles>,
    #[prost(oneof="response::ResponsePayload", tags="5, 6")]
    pub response_payload: ::core::option::Option<response::ResponsePayload>,
}
/// Nested message and enum types in `Response`.
pub mod response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ResponsePayload {
        #[prost(bytes, tag="5")]
        Data(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag="6")]
        Reject(super::RejectContext),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestOrResponse {
    #[prost(oneof="request_or_response::R", tags="1, 2")]
    pub r: ::core::option::Option<request_or_response::R>,
}
/// Nested message and enum types in `RequestOrResponse`.
pub mod request_or_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag="1")]
        Request(super::Request),
        #[prost(message, tag="2")]
        Response(super::Response),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InputOutputQueue {
    #[prost(message, repeated, tag="1")]
    pub queue: ::prost::alloc::vec::Vec<RequestOrResponse>,
    #[prost(uint64, tag="2")]
    pub ind: u64,
    #[prost(uint64, tag="3")]
    pub capacity: u64,
    #[prost(uint64, tag="4")]
    pub num_slots_reserved: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueueEntry {
    #[prost(message, optional, tag="1")]
    pub canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag="2")]
    pub queue: ::core::option::Option<InputOutputQueue>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterQueues {
    #[prost(message, repeated, tag="2")]
    pub ingress_queue: ::prost::alloc::vec::Vec<super::super::ingress::v1::Ingress>,
    #[prost(message, repeated, tag="3")]
    pub input_queues: ::prost::alloc::vec::Vec<QueueEntry>,
    /// Upgrade: input_schedule is mapped to local_subnet_input_schedule
    #[prost(message, repeated, tag="4")]
    pub input_schedule: ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag="5")]
    pub output_queues: ::prost::alloc::vec::Vec<QueueEntry>,
    #[prost(enumeration="canister_queues::NextInputQueue", tag="6")]
    pub next_input_queue: i32,
    /// Downgrade: both queues are mapped back to input_schedule in the current release
    #[prost(message, repeated, tag="7")]
    pub local_subnet_input_schedule: ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag="8")]
    pub remote_subnet_input_schedule: ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
}
/// Nested message and enum types in `CanisterQueues`.
pub mod canister_queues {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum NextInputQueue {
        Unspecified = 0,
        LocalSubnet = 1,
        Ingress = 2,
        RemoteSubnet = 3,
    }
}
