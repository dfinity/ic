#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContext {
    #[prost(bool, tag = "5")]
    pub responded: bool,
    #[prost(message, optional, tag = "6")]
    pub available_funds: ::core::option::Option<super::super::queues::v1::Funds>,
    #[prost(bool, tag = "8")]
    pub deleted: bool,
    #[prost(uint64, optional, tag = "9")]
    pub time_nanos: ::core::option::Option<u64>,
    #[prost(oneof = "call_context::CallOrigin", tags = "1, 2, 3, 4, 7")]
    pub call_origin: ::core::option::Option<call_context::CallOrigin>,
}
/// Nested message and enum types in `CallContext`.
pub mod call_context {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag = "1")]
        pub user_id: ::core::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes = "vec", tag = "2")]
        pub message_id: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CanisterUpdateOrQuery {
        #[prost(message, optional, tag = "1")]
        pub canister_id: ::core::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(uint64, tag = "2")]
        pub callback_id: u64,
    }
    /// System task is either a Heartbeat or a GlobalTimer.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SystemTask {}
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CallOrigin {
        #[prost(message, tag = "1")]
        Ingress(Ingress),
        #[prost(message, tag = "2")]
        CanisterUpdate(CanisterUpdateOrQuery),
        #[prost(message, tag = "3")]
        Query(super::super::super::super::types::v1::UserId),
        #[prost(message, tag = "4")]
        CanisterQuery(CanisterUpdateOrQuery),
        #[prost(message, tag = "7")]
        SystemTask(SystemTask),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContextEntry {
    #[prost(uint64, tag = "1")]
    pub call_context_id: u64,
    #[prost(message, optional, tag = "2")]
    pub call_context: ::core::option::Option<CallContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmClosure {
    #[prost(uint32, tag = "1")]
    pub func_idx: u32,
    #[prost(uint32, tag = "2")]
    pub env: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Callback {
    #[prost(uint64, tag = "1")]
    pub call_context_id: u64,
    #[prost(message, optional, tag = "2")]
    pub on_reply: ::core::option::Option<WasmClosure>,
    #[prost(message, optional, tag = "3")]
    pub on_reject: ::core::option::Option<WasmClosure>,
    #[prost(message, optional, tag = "4")]
    pub on_cleanup: ::core::option::Option<WasmClosure>,
    #[prost(message, optional, tag = "5")]
    pub cycles_sent: ::core::option::Option<super::super::queues::v1::Cycles>,
    #[prost(message, optional, tag = "6")]
    pub originator: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag = "7")]
    pub respondent: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(message, optional, tag = "8")]
    pub prepayment_for_response_execution: ::core::option::Option<super::super::queues::v1::Cycles>,
    #[prost(message, optional, tag = "9")]
    pub prepayment_for_response_transmission:
        ::core::option::Option<super::super::queues::v1::Cycles>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallbackEntry {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub callback: ::core::option::Option<Callback>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContextManager {
    #[prost(uint64, tag = "1")]
    pub next_call_context_id: u64,
    #[prost(uint64, tag = "2")]
    pub next_callback_id: u64,
    #[prost(message, repeated, tag = "3")]
    pub call_contexts: ::prost::alloc::vec::Vec<CallContextEntry>,
    #[prost(message, repeated, tag = "4")]
    pub callbacks: ::prost::alloc::vec::Vec<CallbackEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CyclesAccount {
    /// Cycle balance is stored as u128::to_bytes_le()
    #[prost(bytes = "vec", tag = "1")]
    pub cycles_balance: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Global {
    #[prost(oneof = "global::Global", tags = "1, 2, 3, 4")]
    pub global: ::core::option::Option<global::Global>,
}
/// Nested message and enum types in `Global`.
pub mod global {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Global {
        #[prost(int32, tag = "1")]
        I32(i32),
        #[prost(int64, tag = "2")]
        I64(i64),
        #[prost(float, tag = "3")]
        F32(f32),
        #[prost(double, tag = "4")]
        F64(f64),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmMethod {
    #[prost(oneof = "wasm_method::WasmMethod", tags = "1, 2, 3, 4")]
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
        CanisterGlobalTimer = 8,
    }
    impl SystemMethod {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                SystemMethod::Unspecified => "SYSTEM_METHOD_UNSPECIFIED",
                SystemMethod::CanisterStart => "SYSTEM_METHOD_CANISTER_START",
                SystemMethod::CanisterInit => "SYSTEM_METHOD_CANISTER_INIT",
                SystemMethod::CanisterPreUpgrade => "SYSTEM_METHOD_CANISTER_PRE_UPGRADE",
                SystemMethod::CanisterPostUpgrade => "SYSTEM_METHOD_CANISTER_POST_UPGRADE",
                SystemMethod::CanisterInspectMessage => "SYSTEM_METHOD_CANISTER_INSPECT_MESSAGE",
                SystemMethod::CanisterHeartbeat => "SYSTEM_METHOD_CANISTER_HEARTBEAT",
                SystemMethod::Empty => "SYSTEM_METHOD_EMPTY",
                SystemMethod::CanisterGlobalTimer => "SYSTEM_METHOD_CANISTER_GLOBAL_TIMER",
            }
        }
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WasmMethod {
        #[prost(string, tag = "1")]
        Update(::prost::alloc::string::String),
        #[prost(string, tag = "2")]
        Query(::prost::alloc::string::String),
        #[prost(enumeration = "SystemMethod", tag = "3")]
        System(i32),
        #[prost(string, tag = "4")]
        CompositeQuery(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmCustomSection {
    #[prost(enumeration = "CustomSectionType", tag = "1")]
    pub visibility: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub content: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmMetadata {
    #[prost(btree_map = "string, message", tag = "1")]
    pub custom_sections:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, WasmCustomSection>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionStateBits {
    #[prost(message, repeated, tag = "1")]
    pub exported_globals: ::prost::alloc::vec::Vec<Global>,
    #[prost(uint32, tag = "2")]
    pub heap_size: u32,
    #[prost(message, repeated, tag = "3")]
    pub exports: ::prost::alloc::vec::Vec<WasmMethod>,
    #[prost(uint64, tag = "4")]
    pub last_executed_round: u64,
    #[prost(message, optional, tag = "5")]
    pub metadata: ::core::option::Option<WasmMetadata>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub binary_hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopCanisterContext {
    #[prost(oneof = "stop_canister_context::Context", tags = "1, 2")]
    pub context: ::core::option::Option<stop_canister_context::Context>,
}
/// Nested message and enum types in `StopCanisterContext`.
pub mod stop_canister_context {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag = "1")]
        pub sender: ::core::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes = "vec", tag = "2")]
        pub message_id: ::prost::alloc::vec::Vec<u8>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Canister {
        #[prost(message, optional, tag = "1")]
        pub sender: ::core::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(uint64, tag = "2")]
        pub reply_callback: u64,
        #[prost(message, optional, tag = "3")]
        pub funds: ::core::option::Option<super::super::super::queues::v1::Funds>,
        #[prost(message, optional, tag = "4")]
        pub cycles: ::core::option::Option<super::super::super::queues::v1::Cycles>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Context {
        #[prost(message, tag = "1")]
        Ingress(Ingress),
        #[prost(message, tag = "2")]
        Canister(Canister),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusRunning {
    #[prost(message, optional, tag = "1")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopping {
    #[prost(message, optional, tag = "1")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
    #[prost(message, repeated, tag = "2")]
    pub stop_contexts: ::prost::alloc::vec::Vec<StopCanisterContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopped {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionTask {
    #[prost(oneof = "execution_task::Task", tags = "1, 2")]
    pub task: ::core::option::Option<execution_task::Task>,
}
/// Nested message and enum types in `ExecutionTask`.
pub mod execution_task {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AbortedExecution {
        /// The execution cost that has already been charged from the canister.
        /// Retried execution does not have to pay for it again.
        #[prost(message, optional, tag = "4")]
        pub prepaid_execution_cycles:
            ::core::option::Option<super::super::super::queues::v1::Cycles>,
        #[prost(oneof = "aborted_execution::Message", tags = "1, 2, 3")]
        pub message: ::core::option::Option<aborted_execution::Message>,
    }
    /// Nested message and enum types in `AbortedExecution`.
    pub mod aborted_execution {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Message {
            #[prost(message, tag = "1")]
            Request(super::super::super::super::queues::v1::Request),
            #[prost(message, tag = "2")]
            Response(super::super::super::super::queues::v1::Response),
            #[prost(message, tag = "3")]
            Ingress(super::super::super::super::ingress::v1::Ingress),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AbortedInstallCode {
        /// The execution cost that has already been charged from the canister.
        /// Retried execution does not have to pay for it again.
        #[prost(message, optional, tag = "3")]
        pub prepaid_execution_cycles:
            ::core::option::Option<super::super::super::queues::v1::Cycles>,
        #[prost(oneof = "aborted_install_code::Message", tags = "1, 2")]
        pub message: ::core::option::Option<aborted_install_code::Message>,
    }
    /// Nested message and enum types in `AbortedInstallCode`.
    pub mod aborted_install_code {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Message {
            #[prost(message, tag = "1")]
            Request(super::super::super::super::queues::v1::Request),
            #[prost(message, tag = "2")]
            Ingress(super::super::super::super::ingress::v1::Ingress),
        }
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Task {
        #[prost(message, tag = "1")]
        AbortedExecution(AbortedExecution),
        #[prost(message, tag = "2")]
        AbortedInstallCode(AbortedInstallCode),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStateBits {
    #[prost(uint64, tag = "2")]
    pub last_full_execution_round: u64,
    #[prost(message, optional, tag = "3")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
    #[prost(uint64, tag = "4")]
    pub compute_allocation: u64,
    #[prost(int64, tag = "5")]
    pub accumulated_priority: i64,
    #[prost(message, optional, tag = "7")]
    pub execution_state_bits: ::core::option::Option<ExecutionStateBits>,
    #[prost(uint64, tag = "8")]
    pub memory_allocation: u64,
    #[prost(uint64, tag = "15")]
    pub scheduled_as_first: u64,
    #[prost(uint64, tag = "17")]
    pub skipped_round_due_to_no_messages: u64,
    /// In how many rounds a canister is executed.
    #[prost(uint64, tag = "18")]
    pub executed: u64,
    #[prost(bytes = "vec", tag = "20")]
    pub certified_data: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "21")]
    pub interruped_during_execution: u64,
    #[prost(message, optional, tag = "22")]
    pub consumed_cycles_since_replica_started:
        ::core::option::Option<super::super::super::types::v1::NominalCycles>,
    #[prost(uint64, tag = "23")]
    pub freeze_threshold: u64,
    #[prost(message, repeated, tag = "25")]
    pub controllers: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
    #[prost(message, optional, tag = "26")]
    pub cycles_balance: ::core::option::Option<super::super::queues::v1::Cycles>,
    /// The size of the canister's stable memory in bytes.
    #[prost(uint64, tag = "27")]
    pub stable_memory_size64: u64,
    /// The memory delta debit of this canister. This is tracked for the purposes
    /// of rate limiting the amount of memory delta generated per round.
    #[prost(uint64, tag = "28")]
    pub heap_delta_debit: u64,
    /// The instruction debit for install_code messages of this canister. This is
    /// tracked for the purposes of rate limiting the install_code messages.
    #[prost(uint64, tag = "29")]
    pub install_code_debit: u64,
    /// Contains tasks that need to be executed before processing any input of the
    /// canister.
    #[prost(message, repeated, tag = "30")]
    pub task_queue: ::prost::alloc::vec::Vec<ExecutionTask>,
    /// Time of last charge for resource allocations.
    #[prost(message, optional, tag = "31")]
    pub time_of_last_allocation_charge_nanos: ::core::option::Option<u64>,
    /// Postponed charges that are not applied to `cycles_balance` yet.
    #[prost(message, optional, tag = "32")]
    pub cycles_debit: ::core::option::Option<super::super::queues::v1::Cycles>,
    /// Canister global timer, in nanoseconds since Unix epoch.
    #[prost(uint64, optional, tag = "33")]
    pub global_timer_nanos: ::core::option::Option<u64>,
    /// Canister version.
    #[prost(uint64, tag = "34")]
    pub canister_version: u64,
    #[prost(oneof = "canister_state_bits::CanisterStatus", tags = "11, 12, 13")]
    pub canister_status: ::core::option::Option<canister_state_bits::CanisterStatus>,
}
/// Nested message and enum types in `CanisterStateBits`.
pub mod canister_state_bits {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterStatus {
        #[prost(message, tag = "11")]
        Running(super::CanisterStatusRunning),
        #[prost(message, tag = "12")]
        Stopping(super::CanisterStatusStopping),
        #[prost(message, tag = "13")]
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
impl CustomSectionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CustomSectionType::Unspecified => "CUSTOM_SECTION_TYPE_UNSPECIFIED",
            CustomSectionType::Public => "CUSTOM_SECTION_TYPE_PUBLIC",
            CustomSectionType::Private => "CUSTOM_SECTION_TYPE_PRIVATE",
        }
    }
}
