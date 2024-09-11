//! This defines the RPC service methods offered by the sandbox process
//! (used by the controller) as well as the expected replies.

use std::{sync::Arc, time::Duration};

use crate::fdenum::EnumerateInnerFileDescriptors;
use crate::protocol::structs;
use ic_embedders::{CompilationResult, SerializedModule, SerializedModuleBytes};
use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::{
    page_map::{
        BaseFileSerialization, CheckpointSerialization, MappingSerialization,
        OverlayFileSerialization, PageAllocatorSerialization, PageMapSerialization,
        StorageSerialization,
    },
    Global, NumWasmPages,
};
use ic_types::CanisterId;
use ic_utils;
use serde::{Deserialize, Serialize};

use super::{
    id::{ExecId, MemoryId, WasmId},
    structs::{MemoryModifications, SandboxExecInput},
};

/// Instruct sandbox process to terminate: Sandbox process should take
/// all necessary steps for graceful termination (sync all files etc.)
/// and quit voluntarily. It is still expected to generate a reply to
/// this RPC (controller may perform a "hard kill" after timeout).
///
/// We do not implement graceful termination.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct TerminateRequest {}

/// Ack signal to the controller that termination was complete.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct TerminateReply {}

/// Register wasm for a canister that can be executed in the sandbox.
/// Multiple wasms can be registered to the same sandbox (in order to
/// support multiple code states e.g. during upgrades). A single wasm
/// instance can be used concurrently for multiple executions.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OpenWasmRequest {
    /// Id used to later refer to this canister runner. Must be unique
    /// per sandbox instance.
    pub wasm_id: WasmId,

    /// Contains wasm source code as a sequence of bytes.
    /// It would actually be preferable to move the compilation into native
    /// code outside the sandbox itself; this way, the sandbox can be further
    /// constrained such that it is impossible to generate and execute custom
    /// code and will hamper an attackers ability to exploit wasm jailbreak
    /// flaws
    pub wasm_src: Vec<u8>,
}

/// Reply to an `OpenWasmRequest`.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OpenWasmReply(pub HypervisorResult<(CompilationResult, SerializedModule)>);

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OpenWasmSerializedRequest {
    /// Id used to later refer to this canister runner. Must be unique
    /// per sandbox instance.
    pub wasm_id: WasmId,

    /// The serialization of a previously compiled `wasmtime::Module`.
    /// This types in just an `Arc` reference to a vector of bytes and the only
    /// reason it is `Arc` is so that we can cheaply create the
    /// `OpenWasmSerializedRequest` before sending it to the sandbox.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub serialized_module: Arc<SerializedModuleBytes>,
}

/// Reply to an `OpenWasmRequest`.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OpenWasmSerializedReply(pub HypervisorResult<()>);

/// Request to close the indicated wasm object.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CloseWasmRequest {
    pub wasm_id: WasmId,
}

/// Reply to a `CloseWasm` request.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CloseWasmReply {
    pub success: bool,
}

/// We build state on the tip or branch off at some specific round via
/// tagged state.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum StateBranch {
    TipOfTheTip,
    Round(structs::Round),
}

/// Represents a snapshot of a memory that can be sent to the sandbox process.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct MemorySerialization {
    pub page_map: PageMapSerialization,
    pub num_wasm_pages: NumWasmPages,
}

// This trait is implemented here for all `Serialization` structs to avoid dependency of
// the replicated-state module on the canister-sandbox module.
impl EnumerateInnerFileDescriptors for MemorySerialization {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        self.page_map.enumerate_fds(fds);
    }
}

impl EnumerateInnerFileDescriptors for PageMapSerialization {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        self.storage.enumerate_fds(fds);
        self.page_allocator.enumerate_fds(fds);
    }
}

impl EnumerateInnerFileDescriptors for CheckpointSerialization {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        if let Some(mapping) = self.mapping.as_mut() {
            mapping.enumerate_fds(fds)
        }
    }
}

impl EnumerateInnerFileDescriptors for StorageSerialization {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        match self.base {
            BaseFileSerialization::Base(ref mut b) => b.enumerate_fds(fds),
            BaseFileSerialization::Overlay(ref mut overlays) => {
                for o in overlays.iter_mut() {
                    o.enumerate_fds(fds);
                }
            }
        }
        for overlay in &mut self.overlays {
            overlay.enumerate_fds(fds);
        }
    }
}

impl EnumerateInnerFileDescriptors for OverlayFileSerialization {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        self.mapping.enumerate_fds(fds);
    }
}

impl EnumerateInnerFileDescriptors for MappingSerialization {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        fds.push(&mut self.file_descriptor.fd);
    }
}

impl EnumerateInnerFileDescriptors for PageAllocatorSerialization {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        fds.push(&mut self.fd.fd);
    }
}

/// Describe a request to open a particular memory.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OpenMemoryRequest {
    pub memory_id: MemoryId,
    pub memory: MemorySerialization,
}

impl EnumerateInnerFileDescriptors for OpenMemoryRequest {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        self.memory.enumerate_fds(fds);
    }
}

/// Ack to the controller that memory was opened or failed to open. A
/// failure to open will lead to a panic in the controller.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct OpenMemoryReply {
    pub success: bool,
}

/// Request the indicated memory to be purged and dropped.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CloseMemoryRequest {
    pub memory_id: MemoryId,
}

/// Ack memory was successfully closed or not.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CloseMemoryReply {
    pub success: bool,
}

/// Start execution of a canister.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct StartExecutionRequest {
    /// Id of the newly created invocation of this canister. This is
    /// used to identify the running instance in callbacks as well as
    /// other operations (status queries etc.).
    /// Must be unique until this execution is finished.
    pub exec_id: ExecId,

    /// Id of canister to run (see OpenWasm).
    pub wasm_id: WasmId,

    /// Wasm memory to use (see OpenMemory).
    pub wasm_memory_id: MemoryId,

    /// Stable memory to use (see OpenMemory).
    pub stable_memory_id: MemoryId,

    /// Arguments to execution (api type, caller, payload, ...).
    pub exec_input: SandboxExecInput,
}

/// Reply to an `StartExecutionRequest`.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct StartExecutionReply {
    pub success: bool,
}

/// Resume execution.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ResumeExecutionRequest {
    /// Id of the previously paused execution.
    pub exec_id: ExecId,
}

/// Reply to an `ResumeExecutionRequest`.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ResumeExecutionReply {
    pub success: bool,
}

/// Abort execution.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct AbortExecutionRequest {
    /// Id of the previously paused execution.
    pub exec_id: ExecId,
}

/// Reply to an `AbortExecutionRequest`.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct AbortExecutionReply {
    pub success: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CreateExecutionStateRequest {
    pub wasm_id: WasmId,
    #[serde(with = "serde_bytes")]
    pub wasm_binary: Vec<u8>,
    pub wasm_page_map: PageMapSerialization,
    pub next_wasm_memory_id: MemoryId,
    pub canister_id: CanisterId,
    pub stable_memory_page_map: PageMapSerialization,
}

impl EnumerateInnerFileDescriptors for CreateExecutionStateRequest {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        self.wasm_page_map.enumerate_fds(fds);
        self.stable_memory_page_map.enumerate_fds(fds);
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CreateExecutionStateSuccessReply {
    pub wasm_memory_modifications: MemoryModifications,
    pub exported_globals: Vec<Global>,
    pub compilation_result: CompilationResult,
    pub serialized_module: SerializedModule,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CreateExecutionStateReply(pub HypervisorResult<CreateExecutionStateSuccessReply>);

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CreateExecutionStateSerializedRequest {
    pub wasm_id: WasmId,
    /// The serialization of a previously compiled `wasmtime::Module`.
    /// This types in just an `Arc` reference to a vector of bytes and the only
    /// reason it is `Arc` is so that we can cheaply create the
    /// `CreateExecutionStateSerializedRequest` before sending it to the sandbox.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub serialized_module: Arc<SerializedModule>,
    pub wasm_page_map: PageMapSerialization,
    pub next_wasm_memory_id: MemoryId,
    pub canister_id: CanisterId,
    pub stable_memory_page_map: PageMapSerialization,
}

impl EnumerateInnerFileDescriptors for CreateExecutionStateSerializedRequest {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        self.wasm_page_map.enumerate_fds(fds);
        self.stable_memory_page_map.enumerate_fds(fds);
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CreateExecutionStateSerializedSuccessReply {
    pub wasm_memory_modifications: MemoryModifications,
    pub exported_globals: Vec<Global>,
    pub deserialization_time: Duration,
    pub total_sandbox_time: Duration,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CreateExecutionStateSerializedReply(
    pub HypervisorResult<CreateExecutionStateSerializedSuccessReply>,
);

/// All possible requests to a sandboxed process.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum Request {
    Terminate(TerminateRequest),
    OpenWasm(OpenWasmRequest),
    OpenWasmSerialized(OpenWasmSerializedRequest),
    CloseWasm(CloseWasmRequest),
    OpenMemory(OpenMemoryRequest),
    CloseMemory(CloseMemoryRequest),
    StartExecution(StartExecutionRequest),
    ResumeExecution(ResumeExecutionRequest),
    AbortExecution(AbortExecutionRequest),
    CreateExecutionState(CreateExecutionStateRequest),
    CreateExecutionStateSerialized(CreateExecutionStateSerializedRequest),
}

impl EnumerateInnerFileDescriptors for Request {
    fn enumerate_fds<'a>(&'a mut self, fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {
        match self {
            Request::OpenMemory(request) => request.enumerate_fds(fds),
            Request::CreateExecutionState(request) => request.enumerate_fds(fds),
            Request::CreateExecutionStateSerialized(request) => request.enumerate_fds(fds),
            Request::Terminate(_)
            | Request::OpenWasm(_)
            | Request::OpenWasmSerialized(_)
            | Request::CloseWasm(_)
            | Request::CloseMemory(_)
            | Request::StartExecution(_)
            | Request::ResumeExecution(_)
            | Request::AbortExecution(_) => {}
        }
    }
}

/// All ack replies by the sandboxed process to the controller.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum Reply {
    Terminate(TerminateReply),
    OpenWasm(OpenWasmReply),
    OpenWasmSerialized(OpenWasmSerializedReply),
    CloseWasm(CloseWasmReply),
    OpenMemory(OpenMemoryReply),
    CloseMemory(CloseMemoryReply),
    StartExecution(StartExecutionReply),
    ResumeExecution(ResumeExecutionReply),
    AbortExecution(AbortExecutionReply),
    CreateExecutionState(CreateExecutionStateReply),
    CreateExecutionStateSerialized(CreateExecutionStateSerializedReply),
}

impl EnumerateInnerFileDescriptors for Reply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use ic_base_types::NumSeconds;
    use ic_config::{
        embedders::Config as EmbeddersConfig, flag_status::FlagStatus,
        subnet_config::CyclesAccountManagerConfig,
    };
    use ic_cycles_account_manager::{CyclesAccountManager, ResourceSaturation};
    use ic_embedders::{wasm_utils, CompilationResult, SerializedModule, WasmtimeEmbedder};
    use ic_interfaces::execution_environment::{ExecutionMode, SubnetAvailableMemory};
    use ic_logger::no_op_logger;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        Global, Memory, NetworkTopology, NumWasmPages, PageMap, SystemState,
    };
    use ic_system_api::{
        sandbox_safe_system_state::SandboxSafeSystemState, ExecutionParameters, InstructionLimits,
    };
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::{
        messages::{CallContextId, RequestMetadata},
        methods::{FuncRef, WasmMethod},
        ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions, SubnetId, Time,
    };
    use ic_wasm_types::BinaryEncodedWasm;

    use crate::protocol::{
        id::{ExecId, MemoryId, WasmId},
        sbxsvc::{
            AbortExecutionReply, AbortExecutionRequest, CloseMemoryReply, CloseMemoryRequest,
            CloseWasmReply, CloseWasmRequest, CreateExecutionStateReply,
            CreateExecutionStateRequest, CreateExecutionStateSerializedReply,
            CreateExecutionStateSerializedRequest, CreateExecutionStateSerializedSuccessReply,
            CreateExecutionStateSuccessReply, MemorySerialization, OpenMemoryReply,
            OpenMemoryRequest, OpenWasmReply, OpenWasmRequest, OpenWasmSerializedReply,
            OpenWasmSerializedRequest, ResumeExecutionReply, ResumeExecutionRequest,
            StartExecutionReply, StartExecutionRequest, TerminateReply,
        },
        structs::{MemoryModifications, SandboxExecInput},
    };

    use super::{Reply, Request, TerminateRequest};

    fn wasm_module() -> (CompilationResult, SerializedModule) {
        let wat = r#"
            (module
                (func (export "canister_init")
                    (drop (memory.grow (i32.const 160)))
                )
                (memory 1)
            )"#;
        let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());
        let wasm = wat::parse_str(wat).unwrap();

        wasm_utils::compile(&embedder, &BinaryEncodedWasm::new(wasm))
            .1
            .unwrap()
    }

    fn round_trip_request(msg: &Request) -> Request {
        let ser = bincode::serialize(&msg).unwrap();
        bincode::deserialize(&ser).unwrap()
    }

    fn round_trip_reply(msg: &Reply) -> Reply {
        let ser = bincode::serialize(&msg).unwrap();
        bincode::deserialize(&ser).unwrap()
    }

    #[test]
    fn round_trip_terminate_request() {
        let msg = Request::Terminate(TerminateRequest {});
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_terminate_reply() {
        let msg = Reply::Terminate(TerminateReply {});
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_open_wasm_request() {
        let msg = Request::OpenWasm(OpenWasmRequest {
            wasm_id: WasmId::new(),
            wasm_src: vec![1, 2, 3],
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_open_wasm_reply() {
        let msg = Reply::OpenWasm(OpenWasmReply(Ok(wasm_module())));
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_open_wasm_serialized_request() {
        let msg = Request::OpenWasmSerialized(OpenWasmSerializedRequest {
            wasm_id: WasmId::new(),
            serialized_module: wasm_module().1.bytes,
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_open_wasm_serialized_reply() {
        let msg = Reply::OpenWasmSerialized(OpenWasmSerializedReply(Ok(())));
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_close_wasm_request() {
        let msg = Request::CloseWasm(CloseWasmRequest {
            wasm_id: WasmId::new(),
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_close_wasm_reply() {
        let msg = Reply::CloseWasm(CloseWasmReply { success: true });
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_open_memory_request() {
        let memory = Memory::new_for_testing();
        let msg = Request::OpenMemory(OpenMemoryRequest {
            memory_id: MemoryId::new(),
            memory: MemorySerialization {
                page_map: memory.page_map.serialize(),
                num_wasm_pages: memory.size,
            },
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_open_memory_reply() {
        let msg = Reply::OpenMemory(OpenMemoryReply { success: true });
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_close_memory_request() {
        let msg = Request::CloseMemory(CloseMemoryRequest {
            memory_id: MemoryId::new(),
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_close_memory_reply() {
        let msg = Reply::CloseMemory(CloseMemoryReply { success: true });
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_start_execution_request() {
        let system_state = SystemState::new_running_for_testing(
            canister_test_id(10),
            canister_test_id(12).get(),
            Cycles::new(100),
            NumSeconds::new(10),
        );
        let msg = Request::StartExecution(StartExecutionRequest {
            exec_id: ExecId::new(),
            wasm_id: WasmId::new(),
            wasm_memory_id: MemoryId::new(),
            stable_memory_id: MemoryId::new(),
            exec_input: SandboxExecInput {
                func_ref: FuncRef::Method(WasmMethod::Update("test".into())),
                api_type: ic_system_api::ApiType::update(
                    Time::from_nanos_since_unix_epoch(10),
                    vec![1, 2, 3],
                    Cycles::new(100),
                    canister_test_id(1).get(),
                    CallContextId::new(10),
                ),
                globals: vec![
                    Global::I32(10),
                    Global::I64(32),
                    Global::F32(10.5),
                    Global::F64(12.3),
                    Global::V128(123),
                ],
                canister_current_memory_usage: NumBytes::new(100),
                canister_current_message_memory_usage: NumBytes::new(123),
                execution_parameters: ExecutionParameters {
                    instruction_limits: InstructionLimits::new(
                        FlagStatus::Enabled,
                        NumInstructions::new(123),
                        NumInstructions::new(12),
                    ),
                    canister_memory_limit: NumBytes::new(123),
                    wasm_memory_limit: Some(NumBytes::new(123)),
                    memory_allocation: MemoryAllocation::Reserved(NumBytes::new(123)),
                    compute_allocation: ComputeAllocation::zero(),
                    subnet_type: SubnetType::Application,
                    execution_mode: ExecutionMode::Replicated,
                    subnet_memory_saturation: ResourceSaturation::new(8, 5, 10),
                },
                subnet_available_memory: SubnetAvailableMemory::new(123, 12, 1),
                next_wasm_memory_id: MemoryId::new(),
                next_stable_memory_id: MemoryId::new(),
                sandbox_safe_system_state: SandboxSafeSystemState::new(
                    &system_state,
                    CyclesAccountManager::new(
                        NumInstructions::new(10),
                        SubnetType::Application,
                        SubnetId::new(canister_test_id(1).get()),
                        CyclesAccountManagerConfig::application_subnet(),
                    ),
                    &NetworkTopology::default(),
                    NumInstructions::new(42),
                    ComputeAllocation::zero(),
                    RequestMetadata::new(0, Time::from_nanos_since_unix_epoch(10)),
                    Some(canister_test_id(1).get()),
                    Some(CallContextId::new(123)),
                ),
                wasm_reserved_pages: NumWasmPages::new(1),
            },
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_start_execution_reply() {
        let msg = Reply::StartExecution(StartExecutionReply { success: true });
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_resume_execution_request() {
        let msg = Request::ResumeExecution(ResumeExecutionRequest {
            exec_id: ExecId::new(),
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_resume_execution_reply() {
        let msg = Reply::ResumeExecution(ResumeExecutionReply { success: true });
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_abort_execution_request() {
        let msg = Request::AbortExecution(AbortExecutionRequest {
            exec_id: ExecId::new(),
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_abort_execution_reply() {
        let msg = Reply::AbortExecution(AbortExecutionReply { success: true });
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_create_execution_state_request() {
        let msg = Request::CreateExecutionState(CreateExecutionStateRequest {
            wasm_id: WasmId::new(),
            wasm_binary: vec![1, 2, 3],
            wasm_page_map: PageMap::new_for_testing().serialize(),
            next_wasm_memory_id: MemoryId::new(),
            canister_id: canister_test_id(1),
            stable_memory_page_map: PageMap::new_for_testing().serialize(),
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_create_execution_state_reply() {
        let compilation = wasm_module();
        let reply = CreateExecutionStateSuccessReply {
            wasm_memory_modifications: MemoryModifications {
                page_delta: PageMap::new_for_testing().serialize_delta(&[]),
                size: NumWasmPages::new(10),
            },
            exported_globals: vec![
                Global::I32(10),
                Global::I64(32),
                Global::F32(10.5),
                Global::F64(12.3),
                Global::V128(123),
            ],
            compilation_result: compilation.0,
            serialized_module: compilation.1,
        };
        let msg = Reply::CreateExecutionState(CreateExecutionStateReply(Ok(reply)));
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_create_execution_state_serialized_request() {
        let msg = Request::CreateExecutionStateSerialized(CreateExecutionStateSerializedRequest {
            wasm_id: WasmId::new(),
            serialized_module: Arc::new(wasm_module().1),
            wasm_page_map: PageMap::new_for_testing().serialize(),
            next_wasm_memory_id: MemoryId::new(),
            canister_id: canister_test_id(1),
            stable_memory_page_map: PageMap::new_for_testing().serialize(),
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_create_execution_state_serialized_reply() {
        let reply = CreateExecutionStateSerializedSuccessReply {
            wasm_memory_modifications: MemoryModifications {
                page_delta: PageMap::new_for_testing().serialize_delta(&[]),
                size: NumWasmPages::new(10),
            },
            exported_globals: vec![
                Global::I32(10),
                Global::I64(32),
                Global::F32(10.5),
                Global::F64(12.3),
                Global::V128(123),
            ],
            deserialization_time: Duration::from_secs(1),
            total_sandbox_time: Duration::from_secs(2),
        };
        let msg =
            Reply::CreateExecutionStateSerialized(CreateExecutionStateSerializedReply(Ok(reply)));
        assert_eq!(round_trip_reply(&msg), msg);
    }
}
