#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cycles {
    #[prost(bytes = "vec", tag = "2")]
    pub raw_cycles: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Funds {
    #[prost(uint64, tag = "2")]
    pub icp: u64,
    #[prost(message, optional, tag = "3")]
    pub cycles_struct: ::core::option::Option<Cycles>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamFlags {
    #[prost(bool, tag = "1")]
    pub deprecated_responses_only: bool,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stream {
    #[prost(uint64, tag = "1")]
    pub messages_begin: u64,
    #[prost(message, repeated, tag = "2")]
    pub messages: ::prost::alloc::vec::Vec<RequestOrResponse>,
    #[prost(uint64, tag = "5")]
    pub signals_end: u64,
    #[prost(uint64, repeated, tag = "6")]
    pub reject_signals: ::prost::alloc::vec::Vec<u64>,
    #[prost(message, optional, tag = "7")]
    pub reverse_stream_flags: ::core::option::Option<StreamFlags>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamEntry {
    #[prost(message, optional, tag = "1")]
    pub subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag = "2")]
    pub subnet_stream: ::core::option::Option<Stream>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestMetadata {
    #[prost(uint64, optional, tag = "1")]
    pub call_tree_depth: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    pub call_tree_start_time_nanos: ::core::option::Option<u64>,
    /// A point in the future vs. `call_tree_start_time` at which a request would ideally have concluded
    /// its lifecycle on the IC. Unlike `call_tree_depth` and `call_tree_start_time`, the deadline
    /// does not have to be a constant for the whole call tree. Rather it's valid only for the subtree of
    /// downstream calls at any point in the tree, i.e. it is allowed and desirable for a subtree to have
    /// a tighter deadline than the tree as whole.
    ///
    /// Reserved for future use (guaranteed replies won't be affected).
    #[prost(uint64, optional, tag = "3")]
    pub call_subtree_deadline_nanos: ::core::option::Option<u64>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(message, optional, tag = "1")]
    pub receiver: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag = "2")]
    pub sender: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag = "3")]
    pub sender_reply_callback: u64,
    #[prost(message, optional, tag = "4")]
    pub payment: ::core::option::Option<Funds>,
    #[prost(string, tag = "5")]
    pub method_name: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "6")]
    pub method_payload: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "7")]
    pub cycles_payment: ::core::option::Option<Cycles>,
    #[prost(message, optional, tag = "8")]
    pub metadata: ::core::option::Option<RequestMetadata>,
    /// If non-zero, this is a best-effort call.
    #[prost(uint32, tag = "9")]
    pub deadline_seconds: u32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectContext {
    #[prost(uint64, tag = "1")]
    pub reject_code: u64,
    #[prost(string, tag = "2")]
    pub reject_message: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(message, optional, tag = "1")]
    pub originator: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag = "2")]
    pub respondent: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag = "3")]
    pub originator_reply_callback: u64,
    #[prost(message, optional, tag = "4")]
    pub refund: ::core::option::Option<Funds>,
    #[prost(message, optional, tag = "7")]
    pub cycles_refund: ::core::option::Option<Cycles>,
    /// If non-zero, this is a best-effort call.
    #[prost(uint32, tag = "8")]
    pub deadline_seconds: u32,
    #[prost(oneof = "response::ResponsePayload", tags = "5, 6")]
    pub response_payload: ::core::option::Option<response::ResponsePayload>,
}
/// Nested message and enum types in `Response`.
pub mod response {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ResponsePayload {
        #[prost(bytes, tag = "5")]
        Data(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "6")]
        Reject(super::RejectContext),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestOrResponse {
    #[prost(oneof = "request_or_response::R", tags = "1, 2")]
    pub r: ::core::option::Option<request_or_response::R>,
}
/// Nested message and enum types in `RequestOrResponse`.
pub mod request_or_response {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag = "1")]
        Request(super::Request),
        #[prost(message, tag = "2")]
        Response(super::Response),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageDeadline {
    #[prost(uint64, tag = "1")]
    pub deadline: u64,
    #[prost(uint64, tag = "2")]
    pub index: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InputOutputQueue {
    #[prost(message, repeated, tag = "1")]
    pub queue: ::prost::alloc::vec::Vec<RequestOrResponse>,
    #[prost(uint64, tag = "2")]
    pub begin: u64,
    #[prost(uint64, tag = "3")]
    pub capacity: u64,
    #[prost(uint64, tag = "4")]
    pub num_slots_reserved: u64,
    /// Ordered ranges of messages having the same request deadline. Each range
    /// is represented as a deadline and its end index (the `QueueIndex` just
    /// past the last request where the deadline applies). Both the deadlines and
    /// queue indices are strictly increasing.
    #[prost(message, repeated, tag = "5")]
    pub deadline_range_ends: ::prost::alloc::vec::Vec<MessageDeadline>,
    /// Queue index from which request timing out will resume.
    #[prost(uint64, tag = "6")]
    pub timeout_index: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueueEntry {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag = "2")]
    pub queue: ::core::option::Option<InputOutputQueue>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterQueues {
    #[prost(message, repeated, tag = "2")]
    pub ingress_queue: ::prost::alloc::vec::Vec<super::super::ingress::v1::Ingress>,
    #[prost(message, repeated, tag = "3")]
    pub input_queues: ::prost::alloc::vec::Vec<QueueEntry>,
    /// Upgrade: input_schedule is mapped to local_subnet_input_schedule.
    #[prost(message, repeated, tag = "4")]
    pub input_schedule: ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag = "5")]
    pub output_queues: ::prost::alloc::vec::Vec<QueueEntry>,
    #[prost(enumeration = "canister_queues::NextInputQueue", tag = "6")]
    pub next_input_queue: i32,
    /// Downgrade: both queues are mapped back to input_schedule in the current
    /// release.
    #[prost(message, repeated, tag = "7")]
    pub local_subnet_input_schedule:
        ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag = "8")]
    pub remote_subnet_input_schedule:
        ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
}
/// Nested message and enum types in `CanisterQueues`.
pub mod canister_queues {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration,
    )]
    #[repr(i32)]
    pub enum NextInputQueue {
        Unspecified = 0,
        LocalSubnet = 1,
        Ingress = 2,
        RemoteSubnet = 3,
    }
    impl NextInputQueue {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                NextInputQueue::Unspecified => "NEXT_INPUT_QUEUE_UNSPECIFIED",
                NextInputQueue::LocalSubnet => "NEXT_INPUT_QUEUE_LOCAL_SUBNET",
                NextInputQueue::Ingress => "NEXT_INPUT_QUEUE_INGRESS",
                NextInputQueue::RemoteSubnet => "NEXT_INPUT_QUEUE_REMOTE_SUBNET",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "NEXT_INPUT_QUEUE_UNSPECIFIED" => Some(Self::Unspecified),
                "NEXT_INPUT_QUEUE_LOCAL_SUBNET" => Some(Self::LocalSubnet),
                "NEXT_INPUT_QUEUE_INGRESS" => Some(Self::Ingress),
                "NEXT_INPUT_QUEUE_REMOTE_SUBNET" => Some(Self::RemoteSubnet),
                _ => None,
            }
        }
    }
}
