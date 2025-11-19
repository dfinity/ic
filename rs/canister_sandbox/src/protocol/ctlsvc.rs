use crate::{fdenum::EnumerateInnerFileDescriptors, protocol::logging::LogRequest};
use ic_embedders::wasm_executor::SliceExecutionOutput;
use serde::{Deserialize, Serialize};

use super::{id::ExecId, structs::SandboxExecOutput};

// This defines the RPC service methods offered by the controller process
// (used by the sandbox) as well as the expected replies.

// Notify controller that a canister run has finished.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExecutionFinishedRequest {
    // Id for this run, as set up by controller.
    pub exec_id: ExecId,

    pub exec_output: SandboxExecOutput,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExecutionFinishedReply {}

// Notify controller that a canister run is paused.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExecutionPausedRequest {
    pub exec_id: ExecId,
    pub slice: SliceExecutionOutput,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExecutionPausedReply {}

/// We reply to the replica controller that either the execution was
/// finished or the request failed, or request a system call or a log
/// to be applied.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum Request {
    ExecutionFinished(ExecutionFinishedRequest),
    ExecutionPaused(ExecutionPausedRequest),
    LogViaReplica(LogRequest),
}

impl EnumerateInnerFileDescriptors for Request {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

/// We reply to the replica controller that either the execution was
/// finished or the request failed.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum Reply {
    ExecutionFinished(ExecutionFinishedReply),
    ExecutionPaused(ExecutionPausedReply),
    LogViaReplica(()),
}

impl EnumerateInnerFileDescriptors for Reply {
    fn enumerate_fds<'a>(&'a mut self, _fds: &mut Vec<&'a mut std::os::unix::io::RawFd>) {}
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ic_embedders::{
        wasm_executor::SliceExecutionOutput,
        wasmtime_embedder::system_api::sandbox_safe_system_state::SystemStateModifications,
    };
    use ic_interfaces::execution_environment::{
        InstanceStats, MessageMemoryUsage, SystemApiCallCounters, WasmExecutionOutput,
    };
    use ic_management_canister_types_private::Global;
    use ic_replicated_state::{NumWasmPages, PageMap};
    use ic_types::{NumBytes, NumInstructions, ingress::WasmResult};

    use crate::protocol::{
        ctlsvc::{ExecutionFinishedReply, ExecutionPausedReply, ExecutionPausedRequest, Reply},
        id::ExecId,
        logging::{LogLevel, LogRequest},
        structs::{
            ExecutionStateModifications, MemoryModifications, SandboxExecOutput, StateModifications,
        },
    };

    use super::{ExecutionFinishedRequest, Request};

    fn round_trip_request(msg: &Request) -> Request {
        let ser = bincode::serialize(&msg).unwrap();
        bincode::deserialize(&ser).unwrap()
    }

    fn round_trip_reply(msg: &Reply) -> Reply {
        let ser = bincode::serialize(&msg).unwrap();
        bincode::deserialize(&ser).unwrap()
    }

    #[test]
    fn round_trip_execution_finished_request() {
        let wasm_result = WasmResult::Reply(vec![123]);
        let new_message_memory_usage = MessageMemoryUsage {
            guaranteed_response: NumBytes::new(2000),
            best_effort: NumBytes::new(1000),
        };
        let exec_output = SandboxExecOutput {
            slice: SliceExecutionOutput {
                executed_instructions: NumInstructions::new(123),
            },
            wasm: WasmExecutionOutput {
                wasm_result: Ok(Some(wasm_result)),
                num_instructions_left: NumInstructions::new(1),
                allocated_bytes: NumBytes::new(1000),
                allocated_guaranteed_response_message_bytes: NumBytes::new(2000),
                new_memory_usage: Some(NumBytes::new(2000)),
                new_message_memory_usage: Some(new_message_memory_usage),
                instance_stats: InstanceStats::default(),
                system_api_call_counters: SystemApiCallCounters::default(),
            },
            state: StateModifications {
                execution_state_modifications: Some(ExecutionStateModifications {
                    globals: vec![
                        Global::I32(10),
                        Global::I64(32),
                        Global::F32(10.5),
                        Global::F64(1.1),
                        Global::V128(123),
                    ],
                    wasm_memory: MemoryModifications {
                        page_delta: PageMap::new_for_testing().serialize_delta(&[]),
                        size: NumWasmPages::new(10),
                    },
                    stable_memory: MemoryModifications {
                        page_delta: PageMap::new_for_testing().serialize_delta(&[]),
                        size: NumWasmPages::new(42),
                    },
                }),
                system_state_modifications: SystemStateModifications::default(),
            },
            execute_total_duration: Duration::from_secs(10),
            execute_run_duration: Duration::from_secs(1),
        };
        let msg = Request::ExecutionFinished(ExecutionFinishedRequest {
            exec_id: ExecId::new(),
            exec_output,
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_execution_finished_reply() {
        let msg = Reply::ExecutionFinished(ExecutionFinishedReply {});
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_execution_paused_request() {
        let msg = Request::ExecutionPaused(ExecutionPausedRequest {
            exec_id: ExecId::new(),
            slice: SliceExecutionOutput {
                executed_instructions: NumInstructions::new(123),
            },
        });
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_execution_paused_reply() {
        let msg = Reply::ExecutionPaused(ExecutionPausedReply {});
        assert_eq!(round_trip_reply(&msg), msg);
    }

    #[test]
    fn round_trip_log_via_replica_request() {
        let msg = Request::LogViaReplica(LogRequest(LogLevel::Debug, "test".into()));
        assert_eq!(round_trip_request(&msg), msg);
    }

    #[test]
    fn round_trip_log_via_replica_reply() {
        let msg = Reply::LogViaReplica(());
        assert_eq!(round_trip_reply(&msg), msg);
    }
}
