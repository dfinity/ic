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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TerminateRequest {}

/// Ack signal to the controller that termination was complete.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TerminateReply {}

/// Register wasm for a canister that can be executed in the sandbox.
/// Multiple wasms can be registered to the same sandbox (in order to
/// support multiple code states e.g. during upgrades). A single wasm
/// instance can be used concurrently for multiple executions.
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenWasmReply(pub HypervisorResult<(CompilationResult, SerializedModule)>);

#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenWasmSerializedReply(pub HypervisorResult<()>);

/// Request to close the indicated wasm object.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseWasmRequest {
    pub wasm_id: WasmId,
}

/// Reply to a `CloseWasm` request.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseWasmReply {
    pub success: bool,
}

/// We build state on the tip or branch off at some specific round via
/// tagged state.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum StateBranch {
    TipOfTheTip,
    Round(structs::Round),
}

/// Represents a snapshot of a memory that can be sent to the sandbox process.
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpenMemoryReply {
    pub success: bool,
}

/// Request the indicated memory to be purged and dropped.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseMemoryRequest {
    pub memory_id: MemoryId,
}

/// Ack memory was successfully closed or not.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloseMemoryReply {
    pub success: bool,
}

/// Start execution of a canister.
#[derive(Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StartExecutionReply {
    pub success: bool,
}

/// Resume execution.
#[derive(Serialize, Deserialize, Clone)]
pub struct ResumeExecutionRequest {
    /// Id of the previously paused execution.
    pub exec_id: ExecId,
}

/// Reply to an `ResumeExecutionRequest`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResumeExecutionReply {
    pub success: bool,
}

/// Abort execution.
#[derive(Serialize, Deserialize, Clone)]
pub struct AbortExecutionRequest {
    /// Id of the previously paused execution.
    pub exec_id: ExecId,
}

/// Reply to an `AbortExecutionRequest`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AbortExecutionReply {
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateExecutionStateSuccessReply {
    pub wasm_memory_modifications: MemoryModifications,
    pub exported_globals: Vec<Global>,
    pub compilation_result: CompilationResult,
    pub serialized_module: SerializedModule,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateExecutionStateReply(pub HypervisorResult<CreateExecutionStateSuccessReply>);

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateExecutionStateSerializedSuccessReply {
    pub wasm_memory_modifications: MemoryModifications,
    pub exported_globals: Vec<Global>,
    pub deserialization_time: Duration,
    pub total_sandbox_time: Duration,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateExecutionStateSerializedReply(
    pub HypervisorResult<CreateExecutionStateSerializedSuccessReply>,
);

/// All possible requests to a sandboxed process.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
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
