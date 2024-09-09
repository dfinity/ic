#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContext {
    #[prost(bool, tag = "5")]
    pub responded: bool,
    #[prost(message, optional, tag = "6")]
    pub available_funds: ::core::option::Option<super::super::queues::v1::Funds>,
    #[prost(bool, tag = "8")]
    pub deleted: bool,
    #[prost(uint64, tag = "9")]
    pub time_nanos: u64,
    #[prost(uint64, tag = "10")]
    pub instructions_executed: u64,
    #[prost(message, optional, tag = "11")]
    pub metadata: ::core::option::Option<super::super::queues::v1::RequestMetadata>,
    #[prost(oneof = "call_context::CallOrigin", tags = "1, 2, 3, 4, 7")]
    pub call_origin: ::core::option::Option<call_context::CallOrigin>,
}
/// Nested message and enum types in `CallContext`.
pub mod call_context {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag = "1")]
        pub user_id: ::core::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes = "vec", tag = "2")]
        pub message_id: ::prost::alloc::vec::Vec<u8>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CanisterUpdateOrQuery {
        #[prost(message, optional, tag = "1")]
        pub canister_id: ::core::option::Option<super::super::super::super::types::v1::CanisterId>,
        #[prost(uint64, tag = "2")]
        pub callback_id: u64,
        /// If non-zero, this originates from a best-effort canister update call.
        #[prost(uint32, tag = "3")]
        pub deadline_seconds: u32,
    }
    /// System task is either a Heartbeat or a GlobalTimer.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SystemTask {}
    #[allow(clippy::derive_partial_eq_without_eq)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallContextEntry {
    #[prost(uint64, tag = "1")]
    pub call_context_id: u64,
    #[prost(message, optional, tag = "2")]
    pub call_context: ::core::option::Option<CallContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmClosure {
    /// The number of functions will never exceed 2^32.
    #[prost(uint32, tag = "1")]
    pub func_idx: u32,
    #[prost(uint64, tag = "2")]
    pub env: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
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
    /// If non-zero, this is a best-effort call.
    #[prost(uint32, tag = "10")]
    pub deadline_seconds: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallbackEntry {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub callback: ::core::option::Option<Callback>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CyclesAccount {
    /// Cycle balance is stored as u128::to_bytes_le()
    #[prost(bytes = "vec", tag = "1")]
    pub cycles_balance: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Global {
    #[prost(oneof = "global::Global", tags = "1, 2, 3, 4, 5")]
    pub global: ::core::option::Option<global::Global>,
}
/// Nested message and enum types in `Global`.
pub mod global {
    #[allow(clippy::derive_partial_eq_without_eq)]
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
        #[prost(bytes, tag = "5")]
        V128(::prost::alloc::vec::Vec<u8>),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
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
        CanisterGlobalTimer = 8,
        CanisterOnLowWasmMemory = 9,
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
                SystemMethod::CanisterGlobalTimer => "SYSTEM_METHOD_CANISTER_GLOBAL_TIMER",
                SystemMethod::CanisterOnLowWasmMemory => {
                    "SYSTEM_METHOD_CANISTER_ON_LOW_WASM_MEMORY"
                }
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "SYSTEM_METHOD_UNSPECIFIED" => Some(Self::Unspecified),
                "SYSTEM_METHOD_CANISTER_START" => Some(Self::CanisterStart),
                "SYSTEM_METHOD_CANISTER_INIT" => Some(Self::CanisterInit),
                "SYSTEM_METHOD_CANISTER_PRE_UPGRADE" => Some(Self::CanisterPreUpgrade),
                "SYSTEM_METHOD_CANISTER_POST_UPGRADE" => Some(Self::CanisterPostUpgrade),
                "SYSTEM_METHOD_CANISTER_INSPECT_MESSAGE" => Some(Self::CanisterInspectMessage),
                "SYSTEM_METHOD_CANISTER_HEARTBEAT" => Some(Self::CanisterHeartbeat),
                "SYSTEM_METHOD_CANISTER_GLOBAL_TIMER" => Some(Self::CanisterGlobalTimer),
                "SYSTEM_METHOD_CANISTER_ON_LOW_WASM_MEMORY" => Some(Self::CanisterOnLowWasmMemory),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmCustomSection {
    #[prost(enumeration = "CustomSectionType", tag = "1")]
    pub visibility: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub content: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmMetadata {
    #[prost(btree_map = "string, message", tag = "1")]
    pub custom_sections:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, WasmCustomSection>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
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
    #[prost(enumeration = "NextScheduledMethod", optional, tag = "7")]
    pub next_scheduled_method: ::core::option::Option<i32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopCanisterContext {
    #[prost(oneof = "stop_canister_context::Context", tags = "1, 2")]
    pub context: ::core::option::Option<stop_canister_context::Context>,
}
/// Nested message and enum types in `StopCanisterContext`.
pub mod stop_canister_context {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ingress {
        #[prost(message, optional, tag = "1")]
        pub sender: ::core::option::Option<super::super::super::super::types::v1::UserId>,
        #[prost(bytes = "vec", tag = "2")]
        pub message_id: ::prost::alloc::vec::Vec<u8>,
        #[prost(uint64, optional, tag = "5")]
        pub call_id: ::core::option::Option<u64>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
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
        #[prost(uint64, optional, tag = "5")]
        pub call_id: ::core::option::Option<u64>,
        /// If non-zero, this is a best-effort canister update call.
        #[prost(uint32, tag = "6")]
        pub deadline_seconds: u32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Context {
        #[prost(message, tag = "1")]
        Ingress(Ingress),
        #[prost(message, tag = "2")]
        Canister(Canister),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusRunning {
    #[prost(message, optional, tag = "1")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopping {
    #[prost(message, optional, tag = "1")]
    pub call_context_manager: ::core::option::Option<CallContextManager>,
    #[prost(message, repeated, tag = "2")]
    pub stop_contexts: ::prost::alloc::vec::Vec<StopCanisterContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterStatusStopped {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionTask {
    #[prost(oneof = "execution_task::Task", tags = "1, 2")]
    pub task: ::core::option::Option<execution_task::Task>,
}
/// Nested message and enum types in `ExecutionTask`.
pub mod execution_task {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AbortedExecution {
        /// The execution cost that has already been charged from the canister.
        /// Retried execution does not have to pay for it again.
        #[prost(message, optional, tag = "4")]
        pub prepaid_execution_cycles:
            ::core::option::Option<super::super::super::queues::v1::Cycles>,
        #[prost(oneof = "aborted_execution::Input", tags = "1, 2, 3, 5")]
        pub input: ::core::option::Option<aborted_execution::Input>,
    }
    /// Nested message and enum types in `AbortedExecution`.
    pub mod aborted_execution {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Input {
            #[prost(message, tag = "1")]
            Request(super::super::super::super::queues::v1::Request),
            #[prost(message, tag = "2")]
            Response(super::super::super::super::queues::v1::Response),
            #[prost(message, tag = "3")]
            Ingress(super::super::super::super::ingress::v1::Ingress),
            #[prost(enumeration = "super::CanisterTask", tag = "5")]
            Task(i32),
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AbortedInstallCode {
        /// The execution cost that has already been charged from the canister.
        /// Retried execution does not have to pay for it again.
        #[prost(message, optional, tag = "3")]
        pub prepaid_execution_cycles:
            ::core::option::Option<super::super::super::queues::v1::Cycles>,
        #[prost(uint64, optional, tag = "4")]
        pub call_id: ::core::option::Option<u64>,
        #[prost(oneof = "aborted_install_code::Message", tags = "1, 2")]
        pub message: ::core::option::Option<aborted_install_code::Message>,
    }
    /// Nested message and enum types in `AbortedInstallCode`.
    pub mod aborted_install_code {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Message {
            #[prost(message, tag = "1")]
            Request(super::super::super::super::queues::v1::Request),
            #[prost(message, tag = "2")]
            Ingress(super::super::super::super::ingress::v1::Ingress),
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum CanisterTask {
        Unspecified = 0,
        Heartbeat = 1,
        Timer = 2,
        OnLowWasmMemory = 3,
    }
    impl CanisterTask {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                CanisterTask::Unspecified => "CANISTER_TASK_UNSPECIFIED",
                CanisterTask::Heartbeat => "CANISTER_TASK_HEARTBEAT",
                CanisterTask::Timer => "CANISTER_TASK_TIMER",
                CanisterTask::OnLowWasmMemory => "CANISTER_TASK_ON_LOW_WASM_MEMORY",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "CANISTER_TASK_UNSPECIFIED" => Some(Self::Unspecified),
                "CANISTER_TASK_HEARTBEAT" => Some(Self::Heartbeat),
                "CANISTER_TASK_TIMER" => Some(Self::Timer),
                "CANISTER_TASK_ON_LOW_WASM_MEMORY" => Some(Self::OnLowWasmMemory),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Task {
        #[prost(message, tag = "1")]
        AbortedExecution(AbortedExecution),
        #[prost(message, tag = "2")]
        AbortedInstallCode(AbortedInstallCode),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsumedCyclesByUseCase {
    #[prost(enumeration = "CyclesUseCase", tag = "1")]
    pub use_case: i32,
    #[prost(message, optional, tag = "2")]
    pub cycles: ::core::option::Option<super::super::super::types::v1::NominalCycles>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterChangeFromUser {
    #[prost(message, optional, tag = "1")]
    pub user_id: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterChangeFromCanister {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
    #[prost(uint64, optional, tag = "2")]
    pub canister_version: ::core::option::Option<u64>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCreation {
    #[prost(message, repeated, tag = "1")]
    pub controllers: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCodeUninstall {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCodeDeployment {
    #[prost(
        enumeration = "super::super::super::types::v1::CanisterInstallMode",
        tag = "1"
    )]
    pub mode: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub module_hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterControllersChange {
    #[prost(message, repeated, tag = "1")]
    pub controllers: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterLoadSnapshot {
    #[prost(uint64, tag = "1")]
    pub canister_version: u64,
    #[prost(uint64, tag = "2")]
    pub taken_at_timestamp: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub snapshot_id: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterChange {
    #[prost(uint64, tag = "1")]
    pub timestamp_nanos: u64,
    #[prost(uint64, tag = "2")]
    pub canister_version: u64,
    #[prost(oneof = "canister_change::ChangeOrigin", tags = "3, 4")]
    pub change_origin: ::core::option::Option<canister_change::ChangeOrigin>,
    #[prost(oneof = "canister_change::ChangeDetails", tags = "5, 6, 7, 8, 9")]
    pub change_details: ::core::option::Option<canister_change::ChangeDetails>,
}
/// Nested message and enum types in `CanisterChange`.
pub mod canister_change {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ChangeOrigin {
        #[prost(message, tag = "3")]
        CanisterChangeFromUser(super::CanisterChangeFromUser),
        #[prost(message, tag = "4")]
        CanisterChangeFromCanister(super::CanisterChangeFromCanister),
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ChangeDetails {
        #[prost(message, tag = "5")]
        CanisterCreation(super::CanisterCreation),
        #[prost(message, tag = "6")]
        CanisterCodeUninstall(super::CanisterCodeUninstall),
        #[prost(message, tag = "7")]
        CanisterCodeDeployment(super::CanisterCodeDeployment),
        #[prost(message, tag = "8")]
        CanisterControllersChange(super::CanisterControllersChange),
        #[prost(message, tag = "9")]
        CanisterLoadSnapshot(super::CanisterLoadSnapshot),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHistory {
    #[prost(message, repeated, tag = "1")]
    pub changes: ::prost::alloc::vec::Vec<CanisterChange>,
    #[prost(uint64, tag = "2")]
    pub total_num_changes: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Unsigned128 {
    #[prost(bytes = "vec", tag = "1")]
    pub raw: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TotalQueryStats {
    #[prost(message, optional, tag = "1")]
    pub num_calls: ::core::option::Option<Unsigned128>,
    #[prost(message, optional, tag = "2")]
    pub num_instructions: ::core::option::Option<Unsigned128>,
    #[prost(message, optional, tag = "3")]
    pub ingress_payload_size: ::core::option::Option<Unsigned128>,
    #[prost(message, optional, tag = "4")]
    pub egress_payload_size: ::core::option::Option<Unsigned128>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmChunkData {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub index: u64,
    #[prost(uint64, tag = "3")]
    pub length: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WasmChunkStoreMetadata {
    #[prost(message, repeated, tag = "1")]
    pub chunks: ::prost::alloc::vec::Vec<WasmChunkData>,
    #[prost(uint64, tag = "2")]
    pub size: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogVisibilityAllowedViewers {
    #[prost(message, repeated, tag = "1")]
    pub principals: ::prost::alloc::vec::Vec<super::super::super::types::v1::PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogVisibilityV2 {
    #[prost(oneof = "log_visibility_v2::LogVisibilityV2", tags = "1, 2, 3")]
    pub log_visibility_v2: ::core::option::Option<log_visibility_v2::LogVisibilityV2>,
}
/// Nested message and enum types in `LogVisibilityV2`.
pub mod log_visibility_v2 {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum LogVisibilityV2 {
        #[prost(int32, tag = "1")]
        Controllers(i32),
        #[prost(int32, tag = "2")]
        Public(i32),
        #[prost(message, tag = "3")]
        AllowedViewers(super::LogVisibilityAllowedViewers),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterLogRecord {
    #[prost(uint64, tag = "1")]
    pub idx: u64,
    #[prost(uint64, tag = "2")]
    pub timestamp_nanos: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub content: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnapshotId {
    #[prost(bytes = "vec", tag = "1")]
    pub content: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
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
    pub interrupted_during_execution: u64,
    #[prost(message, optional, tag = "22")]
    pub consumed_cycles: ::core::option::Option<super::super::super::types::v1::NominalCycles>,
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
    #[prost(message, repeated, tag = "36")]
    pub consumed_cycles_by_use_cases: ::prost::alloc::vec::Vec<ConsumedCyclesByUseCase>,
    #[prost(message, optional, tag = "37")]
    pub canister_history: ::core::option::Option<CanisterHistory>,
    /// Resource reservation cycles.
    #[prost(message, optional, tag = "38")]
    pub reserved_balance: ::core::option::Option<super::super::queues::v1::Cycles>,
    /// The user-specified upper limit on `reserved_balance`.
    #[prost(message, optional, tag = "39")]
    pub reserved_balance_limit: ::core::option::Option<super::super::queues::v1::Cycles>,
    /// Maps tracking chunks in the Wasm chunk store.
    #[prost(message, optional, tag = "40")]
    pub wasm_chunk_store_metadata: ::core::option::Option<WasmChunkStoreMetadata>,
    /// Statistics on query execution for entire lifetime of canister.
    #[prost(message, optional, tag = "41")]
    pub total_query_stats: ::core::option::Option<TotalQueryStats>,
    /// Log visibility for the canister.
    #[prost(message, optional, tag = "51")]
    pub log_visibility_v2: ::core::option::Option<LogVisibilityV2>,
    /// Log records of the canister.
    #[prost(message, repeated, tag = "43")]
    pub canister_log_records: ::prost::alloc::vec::Vec<CanisterLogRecord>,
    /// The index of the next log record to be created.
    #[prost(uint64, tag = "44")]
    pub next_canister_log_record_idx: u64,
    /// The Wasm memory limit. This is a field in developer-visible canister
    /// settings that allows the developer to limit the usage of the Wasm memory
    /// by the canister to leave some room in 4GiB for upgrade calls.
    /// See the interface specification for more information.
    #[prost(uint64, optional, tag = "45")]
    pub wasm_memory_limit: ::core::option::Option<u64>,
    /// The next local snapshot ID.
    #[prost(uint64, tag = "46")]
    pub next_snapshot_id: u64,
    /// Captures the memory usage of all snapshots associated with a canister.
    #[prost(uint64, tag = "52")]
    pub snapshots_memory_usage: u64,
    #[prost(int64, tag = "48")]
    pub priority_credit: i64,
    #[prost(enumeration = "LongExecutionMode", tag = "49")]
    pub long_execution_mode: i32,
    #[prost(uint64, optional, tag = "50")]
    pub wasm_memory_threshold: ::core::option::Option<u64>,
    #[prost(enumeration = "OnLowWasmMemoryHookStatus", optional, tag = "53")]
    pub on_low_wasm_memory_hook_status: ::core::option::Option<i32>,
    #[prost(oneof = "canister_state_bits::CanisterStatus", tags = "11, 12, 13")]
    pub canister_status: ::core::option::Option<canister_state_bits::CanisterStatus>,
}
/// Nested message and enum types in `CanisterStateBits`.
pub mod canister_state_bits {
    #[allow(clippy::derive_partial_eq_without_eq)]
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
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CUSTOM_SECTION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "CUSTOM_SECTION_TYPE_PUBLIC" => Some(Self::Public),
            "CUSTOM_SECTION_TYPE_PRIVATE" => Some(Self::Private),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NextScheduledMethod {
    Unspecified = 0,
    GlobalTimer = 1,
    Heartbeat = 2,
    Message = 3,
}
impl NextScheduledMethod {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NextScheduledMethod::Unspecified => "NEXT_SCHEDULED_METHOD_UNSPECIFIED",
            NextScheduledMethod::GlobalTimer => "NEXT_SCHEDULED_METHOD_GLOBAL_TIMER",
            NextScheduledMethod::Heartbeat => "NEXT_SCHEDULED_METHOD_HEARTBEAT",
            NextScheduledMethod::Message => "NEXT_SCHEDULED_METHOD_MESSAGE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NEXT_SCHEDULED_METHOD_UNSPECIFIED" => Some(Self::Unspecified),
            "NEXT_SCHEDULED_METHOD_GLOBAL_TIMER" => Some(Self::GlobalTimer),
            "NEXT_SCHEDULED_METHOD_HEARTBEAT" => Some(Self::Heartbeat),
            "NEXT_SCHEDULED_METHOD_MESSAGE" => Some(Self::Message),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CyclesUseCase {
    Unspecified = 0,
    Memory = 1,
    ComputeAllocation = 2,
    IngressInduction = 3,
    Instructions = 4,
    RequestAndResponseTransmission = 5,
    Uninstall = 6,
    CanisterCreation = 7,
    EcdsaOutcalls = 8,
    HttpOutcalls = 9,
    DeletedCanisters = 10,
    NonConsumed = 11,
    BurnedCycles = 12,
    SchnorrOutcalls = 13,
}
impl CyclesUseCase {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CyclesUseCase::Unspecified => "CYCLES_USE_CASE_UNSPECIFIED",
            CyclesUseCase::Memory => "CYCLES_USE_CASE_MEMORY",
            CyclesUseCase::ComputeAllocation => "CYCLES_USE_CASE_COMPUTE_ALLOCATION",
            CyclesUseCase::IngressInduction => "CYCLES_USE_CASE_INGRESS_INDUCTION",
            CyclesUseCase::Instructions => "CYCLES_USE_CASE_INSTRUCTIONS",
            CyclesUseCase::RequestAndResponseTransmission => {
                "CYCLES_USE_CASE_REQUEST_AND_RESPONSE_TRANSMISSION"
            }
            CyclesUseCase::Uninstall => "CYCLES_USE_CASE_UNINSTALL",
            CyclesUseCase::CanisterCreation => "CYCLES_USE_CASE_CANISTER_CREATION",
            CyclesUseCase::EcdsaOutcalls => "CYCLES_USE_CASE_ECDSA_OUTCALLS",
            CyclesUseCase::HttpOutcalls => "CYCLES_USE_CASE_HTTP_OUTCALLS",
            CyclesUseCase::DeletedCanisters => "CYCLES_USE_CASE_DELETED_CANISTERS",
            CyclesUseCase::NonConsumed => "CYCLES_USE_CASE_NON_CONSUMED",
            CyclesUseCase::BurnedCycles => "CYCLES_USE_CASE_BURNED_CYCLES",
            CyclesUseCase::SchnorrOutcalls => "CYCLES_USE_CASE_SCHNORR_OUTCALLS",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CYCLES_USE_CASE_UNSPECIFIED" => Some(Self::Unspecified),
            "CYCLES_USE_CASE_MEMORY" => Some(Self::Memory),
            "CYCLES_USE_CASE_COMPUTE_ALLOCATION" => Some(Self::ComputeAllocation),
            "CYCLES_USE_CASE_INGRESS_INDUCTION" => Some(Self::IngressInduction),
            "CYCLES_USE_CASE_INSTRUCTIONS" => Some(Self::Instructions),
            "CYCLES_USE_CASE_REQUEST_AND_RESPONSE_TRANSMISSION" => {
                Some(Self::RequestAndResponseTransmission)
            }
            "CYCLES_USE_CASE_UNINSTALL" => Some(Self::Uninstall),
            "CYCLES_USE_CASE_CANISTER_CREATION" => Some(Self::CanisterCreation),
            "CYCLES_USE_CASE_ECDSA_OUTCALLS" => Some(Self::EcdsaOutcalls),
            "CYCLES_USE_CASE_HTTP_OUTCALLS" => Some(Self::HttpOutcalls),
            "CYCLES_USE_CASE_DELETED_CANISTERS" => Some(Self::DeletedCanisters),
            "CYCLES_USE_CASE_NON_CONSUMED" => Some(Self::NonConsumed),
            "CYCLES_USE_CASE_BURNED_CYCLES" => Some(Self::BurnedCycles),
            "CYCLES_USE_CASE_SCHNORR_OUTCALLS" => Some(Self::SchnorrOutcalls),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum LongExecutionMode {
    Unspecified = 0,
    Opportunistic = 1,
    Prioritized = 2,
}
impl LongExecutionMode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            LongExecutionMode::Unspecified => "LONG_EXECUTION_MODE_UNSPECIFIED",
            LongExecutionMode::Opportunistic => "LONG_EXECUTION_MODE_OPPORTUNISTIC",
            LongExecutionMode::Prioritized => "LONG_EXECUTION_MODE_PRIORITIZED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "LONG_EXECUTION_MODE_UNSPECIFIED" => Some(Self::Unspecified),
            "LONG_EXECUTION_MODE_OPPORTUNISTIC" => Some(Self::Opportunistic),
            "LONG_EXECUTION_MODE_PRIORITIZED" => Some(Self::Prioritized),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OnLowWasmMemoryHookStatus {
    Unspecified = 0,
    ConditionNotSatisfied = 1,
    Ready = 2,
    Executed = 3,
}
impl OnLowWasmMemoryHookStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            OnLowWasmMemoryHookStatus::Unspecified => "ON_LOW_WASM_MEMORY_HOOK_STATUS_UNSPECIFIED",
            OnLowWasmMemoryHookStatus::ConditionNotSatisfied => {
                "ON_LOW_WASM_MEMORY_HOOK_STATUS_CONDITION_NOT_SATISFIED"
            }
            OnLowWasmMemoryHookStatus::Ready => "ON_LOW_WASM_MEMORY_HOOK_STATUS_READY",
            OnLowWasmMemoryHookStatus::Executed => "ON_LOW_WASM_MEMORY_HOOK_STATUS_EXECUTED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ON_LOW_WASM_MEMORY_HOOK_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "ON_LOW_WASM_MEMORY_HOOK_STATUS_CONDITION_NOT_SATISFIED" => {
                Some(Self::ConditionNotSatisfied)
            }
            "ON_LOW_WASM_MEMORY_HOOK_STATUS_READY" => Some(Self::Ready),
            "ON_LOW_WASM_MEMORY_HOOK_STATUS_EXECUTED" => Some(Self::Executed),
            _ => None,
        }
    }
}
