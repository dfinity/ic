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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RejectSignal {
    #[prost(enumeration = "RejectReason", tag = "1")]
    pub reason: i32,
    #[prost(uint64, tag = "2")]
    pub index: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamFlags {
    #[prost(bool, tag = "1")]
    pub deprecated_responses_only: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stream {
    #[prost(uint64, tag = "1")]
    pub messages_begin: u64,
    #[prost(message, repeated, tag = "2")]
    pub messages: ::prost::alloc::vec::Vec<RequestOrResponse>,
    #[prost(uint64, tag = "5")]
    pub signals_end: u64,
    /// TODO: MR-577 Remove `deprecated_reject_signals` once all replicas are updated.
    #[prost(uint64, repeated, tag = "6")]
    pub deprecated_reject_signals: ::prost::alloc::vec::Vec<u64>,
    #[prost(message, repeated, tag = "8")]
    pub reject_signals: ::prost::alloc::vec::Vec<RejectSignal>,
    #[prost(message, optional, tag = "7")]
    pub reverse_stream_flags: ::core::option::Option<StreamFlags>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamEntry {
    #[prost(message, optional, tag = "1")]
    pub subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag = "2")]
    pub subnet_stream: ::core::option::Option<Stream>,
}
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
    #[prost(enumeration = "super::super::super::types::v1::RejectCode", tag = "3")]
    pub reject_code: i32,
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestOrResponse {
    #[prost(oneof = "request_or_response::R", tags = "1, 2")]
    pub r: ::core::option::Option<request_or_response::R>,
}
/// Nested message and enum types in `RequestOrResponse`.
pub mod request_or_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum R {
        #[prost(message, tag = "1")]
        Request(super::Request),
        #[prost(message, tag = "2")]
        Response(super::Response),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageDeadline {
    #[prost(uint64, tag = "1")]
    pub deadline: u64,
    #[prost(uint64, tag = "2")]
    pub index: u64,
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueueEntry {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag = "2")]
    pub queue: ::core::option::Option<InputOutputQueue>,
}
/// A pool holding all of a canister's incoming and outgoing canister messages.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessagePool {
    /// Map of messages by message ID.
    #[prost(message, repeated, tag = "1")]
    pub messages: ::prost::alloc::vec::Vec<message_pool::Entry>,
    /// The (implicit) deadlines of all outbound guaranteed response requests (only).
    #[prost(message, repeated, tag = "2")]
    pub outbound_guaranteed_request_deadlines:
        ::prost::alloc::vec::Vec<message_pool::MessageDeadline>,
    /// Strictly monotonically increasing counter used to generate unique message
    /// IDs.
    #[prost(uint64, tag = "3")]
    pub message_id_generator: u64,
}
/// Nested message and enum types in `MessagePool`.
pub mod message_pool {
    /// A pool entry: a message keyed by its ID.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Entry {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(message, optional, tag = "2")]
        pub message: ::core::option::Option<super::RequestOrResponse>,
    }
    /// A message deadline.
    ///
    /// Recorded explicitly for outbound guaranteed response requests only.
    /// Best-effort messages have explicit deadlines.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MessageDeadline {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(uint32, tag = "2")]
        pub deadline_seconds: u32,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterQueue {
    /// FIFO queue of references into the pool and reject response markers.
    #[prost(message, repeated, tag = "1")]
    pub queue: ::prost::alloc::vec::Vec<canister_queue::QueueItem>,
    /// Maximum number of requests or responses that can be enqueued at any one time.
    #[prost(uint64, tag = "2")]
    pub capacity: u64,
    /// Number of slots used by or reserved for responses.
    #[prost(uint64, tag = "3")]
    pub response_slots: u64,
}
/// Nested message and enum types in `CanisterQueue`.
pub mod canister_queue {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct QueueItem {
        #[prost(oneof = "queue_item::R", tags = "1")]
        pub r: ::core::option::Option<queue_item::R>,
    }
    /// Nested message and enum types in `QueueItem`.
    pub mod queue_item {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum R {
            /// A reference into the message pool (a pool assigned ID).
            #[prost(uint64, tag = "1")]
            Reference(u64),
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterQueues {
    #[prost(message, repeated, tag = "2")]
    pub ingress_queue: ::prost::alloc::vec::Vec<super::super::ingress::v1::Ingress>,
    #[prost(message, repeated, tag = "3")]
    pub input_queues: ::prost::alloc::vec::Vec<QueueEntry>,
    #[prost(message, repeated, tag = "5")]
    pub output_queues: ::prost::alloc::vec::Vec<QueueEntry>,
    #[prost(message, repeated, tag = "9")]
    pub canister_queues: ::prost::alloc::vec::Vec<canister_queues::CanisterQueuePair>,
    #[prost(message, optional, tag = "10")]
    pub pool: ::core::option::Option<MessagePool>,
    #[prost(enumeration = "canister_queues::NextInputQueue", tag = "6")]
    pub next_input_queue: i32,
    #[prost(message, repeated, tag = "7")]
    pub local_subnet_input_schedule:
        ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag = "8")]
    pub remote_subnet_input_schedule:
        ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(uint64, tag = "11")]
    pub guaranteed_response_memory_reservations: u64,
}
/// Nested message and enum types in `CanisterQueues`.
pub mod canister_queues {
    /// Input queue from and output queue to `canister_id`.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CanisterQueuePair {
        #[prost(message, optional, tag = "1")]
        pub canister_id: ::core::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(message, optional, tag = "2")]
        pub input_queue: ::core::option::Option<super::CanisterQueue>,
        #[prost(message, optional, tag = "3")]
        pub output_queue: ::core::option::Option<super::CanisterQueue>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RejectReason {
    Unspecified = 0,
    CanisterMigrating = 1,
    CanisterNotFound = 2,
    CanisterStopped = 3,
    CanisterStopping = 4,
    QueueFull = 5,
    OutOfMemory = 6,
    Unknown = 7,
}
impl RejectReason {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RejectReason::Unspecified => "REJECT_REASON_UNSPECIFIED",
            RejectReason::CanisterMigrating => "REJECT_REASON_CANISTER_MIGRATING",
            RejectReason::CanisterNotFound => "REJECT_REASON_CANISTER_NOT_FOUND",
            RejectReason::CanisterStopped => "REJECT_REASON_CANISTER_STOPPED",
            RejectReason::CanisterStopping => "REJECT_REASON_CANISTER_STOPPING",
            RejectReason::QueueFull => "REJECT_REASON_QUEUE_FULL",
            RejectReason::OutOfMemory => "REJECT_REASON_OUT_OF_MEMORY",
            RejectReason::Unknown => "REJECT_REASON_UNKNOWN",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "REJECT_REASON_UNSPECIFIED" => Some(Self::Unspecified),
            "REJECT_REASON_CANISTER_MIGRATING" => Some(Self::CanisterMigrating),
            "REJECT_REASON_CANISTER_NOT_FOUND" => Some(Self::CanisterNotFound),
            "REJECT_REASON_CANISTER_STOPPED" => Some(Self::CanisterStopped),
            "REJECT_REASON_CANISTER_STOPPING" => Some(Self::CanisterStopping),
            "REJECT_REASON_QUEUE_FULL" => Some(Self::QueueFull),
            "REJECT_REASON_OUT_OF_MEMORY" => Some(Self::OutOfMemory),
            "REJECT_REASON_UNKNOWN" => Some(Self::Unknown),
            _ => None,
        }
    }
}
