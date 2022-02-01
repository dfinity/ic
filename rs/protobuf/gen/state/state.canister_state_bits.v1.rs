#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContext {
    #[prost(bool, tag="5")]
    pub responded: bool,
    #[prost(message, optional, tag="6")]
    pub available_funds: ::core::option::Option<super::super::queues::v1::Funds>,
    #[prost(bool, tag="8")]
    pub deleted: bool,
    #[prost(oneof="call_context::CallOrigin", tags="1, 2, 3, 4, 7")]
    pub call_origin: ::core::option::Option<call_context::CallOrigin>,
}
/// Nested message and enum types in `CallContext`.
pub mod call_context {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag="1")]
        pub user_id: ::core::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes="vec", tag="2")]
        pub message_id: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CanisterUpdateOrQuery {
        #[prost(message, optional, tag="1")]
        pub canister_id: ::core::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(uint64, tag="2")]
        pub callback_id: u64,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Heartbeat {
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CallOrigin {
        #[prost(message, tag="1")]
        Ingress(Ingress),
        #[prost(message, tag="2")]
        CanisterUpdate(CanisterUpdateOrQuery),
        #[prost(message, tag="3")]
        Query(super::super::super::super::types::v1::UserId),
        #[prost(message, tag="4")]
        CanisterQuery(CanisterUpdateOrQuery),
        #[prost(message, tag="7")]
        Heartbeat(Heartbeat),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContextEntry {
    #[prost(uint64, tag="1")]
    pub call_context_id: u64,
    #[prost(message, optional, tag="2")]
    pub call_context: ::core::option::Option<CallContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmClosure {
    #[prost(uint32, tag="1")]
    pub func_idx: u32,
    #[prost(uint32, tag="2")]
    pub env: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Callback {
    #[prost(uint64, tag="1")]
    pub call_context_id: u64,
    #[prost(message, optional, tag="2")]
    pub on_reply: ::core::option::Option<WasmClosure>,
    #[prost(message, optional, tag="3")]
    pub on_reject: ::core::option::Option<WasmClosure>,
    #[prost(message, optional, tag="4")]
    pub on_cleanup: ::core::option::Option<WasmClosure>,
    #[prost(message, optional, tag="5")]
    pub cycles_sent: ::core::option::Option<super::super::queues::v1::Cycles>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallbackEntry {
    #[prost(uint64, tag="1")]
    pub callback_id: u64,
    #[prost(message, optional, tag="2")]
    pub callback: ::core::option::Option<Callback>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContextManager {
    #[prost(uint64, tag="1")]
    pub next_call_context_id: u64,
    #[prost(uint64, tag="2")]
    pub next_callback_id: u64,
    #[prost(message, repeated, tag="3")]
    pub call_contexts: ::prost::alloc::vec::Vec<CallContextEntry>,
    #[prost(message, repeated, tag="4")]
    pub callbacks: ::prost::alloc::vec::Vec<CallbackEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CyclesAccount {
    /// Cycle balance is store as u128::to_bytes_le()
    #[prost(bytes="vec", tag="1")]
    pub cycles_balance: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Global {
    #[prost(oneof="global::Global", tags="1, 2, 3, 4")]
    pub global: ::core::option::Option<global::Global>,
}
/// Nested message and enum types in `Global`.
pub mod global {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Global {
        #[prost(int32, tag="1")]
        I32(i32),
        #[prost(int64, tag="2")]
        I64(i64),
        #[prost(float, tag="3")]
        F32(f32),
        #[prost(double, tag="4")]
        F64(f64),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmMethod {
    #[prost(oneof="wasm_method::WasmMethod", tags="1, 2, 3")]
    pub wasm_method: ::core::option::Option<wasm_method::WasmMethod>,
}
/// Nested message and enum types in `WasmMethod`.
pub mod wasm_method {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum SystemMethod {
        Unspecified = 0,
        CanisterStart = 1,
        CanisterInit = 2,
        CanisterPreUpgrade = 3,
        CanisterPostUpgrade = 4,
        CanisterInspectMessage = 5,
        CanisterHeartbeat = 6,
        Empty = 7,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WasmMethod {
        #[prost(string, tag="1")]
        Update(::prost::alloc::string::String),
        #[prost(string, tag="2")]
        Query(::prost::alloc::string::String),
        #[prost(enumeration="SystemMethod", tag="3")]
        System(i32),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmCustomSection {
    #[prost(enumeration="CustomSectionType", tag="1")]
    pub visibility: i32,
    #[prost(bytes="vec", tag="2")]
    pub content: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmMetadata {
    #[prost(btree_map="string, message", tag="1")]
    pub custom_sections: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, WasmCustomSection>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionStateBits {
    #[prost(message, repeated, tag="1")]
    pub exported_globals: ::prost::alloc::vec::Vec<Global>,
    #[prost(uint32, tag="2")]
    pub heap_size: u32,
    #[prost(message, repeated, tag="3")]
    pub exports: ::prost::alloc::vec::Vec<WasmMethod>,
    #[prost(uint64, tag="4")]
    pub last_executed_round: u64,
    #[prost(message, optional, tag="5")]
    pub metadata: ::core::option::Option<WasmMetadata>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopCanisterContext {
    #[prost(oneof="stop_canister_context::Context", tags="1, 2")]
    pub context: ::core::option::Option<stop_canister_context::Context>,
}
/// Nested message and enum types in `StopCanisterContext`.
pub mod stop_canister_context {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag="1")]
        pub sender: ::core::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes="vec", tag="2")]
        pub message_id: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Canister {
        #[prost(message, optional, tag="1")]
        pub sender: ::core::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(uint64, tag="2")]
        pub reply_callback: u64,
        #[prost(message, optional, tag="3")]
        pub funds: ::core::option::Option<super::super::super::queues::v1::Funds>,
        #[prost(message, optional, tag="4")]
        pub cycles: ::core::option::Option<super::super::super::queues::v1::Cycles>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Context {
        #[prost(message, tag="1")]
        Ingress(Ingress),
        #[prost(message, tag="2")]
        Canister(Canister),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusRunning {
    #[prost(message, optional, tag="1")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopping {
    #[prost(message, optional, tag="1")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
    #[prost(message, repeated, tag="2")]
    pub stop_contexts: ::prost::alloc::vec::Vec<StopCanisterContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopped {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStateBits {
    #[prost(uint64, tag="2")]
    pub last_full_execution_round: u64,
    #[prost(message, optional, tag="3")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
    #[prost(uint64, tag="4")]
    pub compute_allocation: u64,
    #[prost(int64, tag="5")]
    pub accumulated_priority: i64,
    #[prost(message, optional, tag="7")]
    pub execution_state_bits: ::core::option::Option<ExecutionStateBits>,
    #[prost(uint64, tag="8")]
    pub memory_allocation: u64,
    #[prost(uint64, tag="15")]
    pub scheduled_as_first: u64,
    #[prost(uint64, tag="17")]
    pub skipped_round_due_to_no_messages: u64,
    /// In how many rounds a canister is executed.
    #[prost(uint64, tag="18")]
    pub executed: u64,
    #[prost(bytes="vec", tag="20")]
    pub certified_data: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="21")]
    pub interruped_during_execution: u64,
    #[prost(message, optional, tag="22")]
    pub consumed_cycles_since_replica_started: ::core::option::Option<super::super::super::types::v1::NominalCycles>,
    #[prost(uint64, tag="23")]
    pub freeze_threshold: u64,
    /// This field is deprecated. Once all subnets in production contain the 64-bit
    /// version of this field, we can mark it reserved (EXC-402).
    #[prost(uint32, tag="24")]
    pub stable_memory_size: u32,
    #[prost(message, repeated, tag="25")]
    pub controllers: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
    #[prost(message, optional, tag="26")]
    pub cycles_balance: ::core::option::Option<super::super::queues::v1::Cycles>,
    /// This replaces `stable_memory_size` so that we can represent the size of
    /// both 32-bit (legacy) and 64-bit stable memories.
    /// On the first upgrade of the replica we have:
    /// - `stable_memory_size` stores the actual size,
    /// - `stable_memory_size64` is 0 (the default value)
    /// After that we have the following invariant:
    /// - `stable_memory_size == min(u32::MAX, stable_memory_size64)`
    /// The values of the two fields are in sync as long as the value fits `u32`.
    #[prost(uint64, tag="27")]
    pub stable_memory_size64: u64,
    /// The memory delta debit of this canister at the last time it ran a full
    /// execution. This is tracked for the purposes of rate limiting the amount
    /// of memory delta generated per round.
    #[prost(uint64, tag="28")]
    pub heap_delta_debit: u64,
    #[prost(oneof="canister_state_bits::CanisterStatus", tags="11, 12, 13")]
    pub canister_status: ::core::option::Option<canister_state_bits::CanisterStatus>,
}
/// Nested message and enum types in `CanisterStateBits`.
pub mod canister_state_bits {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterStatus {
        #[prost(message, tag="11")]
        Running(super::CanisterStatusRunning),
        #[prost(message, tag="12")]
        Stopping(super::CanisterStatusStopping),
        #[prost(message, tag="13")]
        Stopped(super::CanisterStatusStopped),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CustomSectionType {
    Unspecified = 0,
    Public = 1,
    Private = 2,
}
