use std::sync::Arc;

/// This module provides the RPC "glue" code to expose the API
/// functionality of the sandbox towards the controller. There is no
/// actual "logic" in this module, just bridging the interfaces.
use crate::sandbox_manager::SandboxManager;

use ic_canister_sandbox_common::{protocol::sbxsvc::*, rpc, sandbox_service::SandboxService};

/// This is the implementation of the RPC interface exposed by the
/// sandbox process and "binds everything together": All RPCs pass
/// through here and are mapped to the "business" logic code contained
/// in SandboxManager.
pub struct SandboxServer {
    /// The SandboxManager contains the business logic (sets up wasm
    /// runtimes, executes things, ...). RPC calls map to methods in
    /// the manager.
    manager: Arc<SandboxManager>,
}

impl SandboxServer {
    /// Creates new sandbox server, taking constructed sandbox manager.
    pub fn new(manager: SandboxManager) -> Self {
        SandboxServer {
            manager: Arc::new(manager),
        }
    }
}

impl SandboxService for SandboxServer {
    fn terminate(&self, _req: TerminateRequest) -> rpc::Call<TerminateReply> {
        rpc::Call::new_resolved(Ok(TerminateReply {}))
    }

    fn open_wasm(&self, req: OpenWasmRequest) -> rpc::Call<OpenWasmReply> {
        let result = self.manager.open_wasm(req.wasm_id, req.wasm_src);
        rpc::Call::new_resolved(Ok(OpenWasmReply(result)))
    }

    fn close_wasm(&self, req: CloseWasmRequest) -> rpc::Call<CloseWasmReply> {
        self.manager.close_wasm(req.wasm_id);
        rpc::Call::new_resolved(Ok(CloseWasmReply { success: true }))
    }

    fn open_memory(&self, req: OpenMemoryRequest) -> rpc::Call<OpenMemoryReply> {
        self.manager.open_memory(req);
        rpc::Call::new_resolved(Ok(OpenMemoryReply { success: true }))
    }

    fn close_memory(&self, req: CloseMemoryRequest) -> rpc::Call<CloseMemoryReply> {
        self.manager.close_memory(req.memory_id);
        rpc::Call::new_resolved(Ok(CloseMemoryReply { success: true }))
    }

    fn start_execution(&self, req: StartExecutionRequest) -> rpc::Call<StartExecutionReply> {
        let StartExecutionRequest {
            exec_id,
            wasm_id,
            wasm_memory_id,
            stable_memory_id,
            exec_input,
        } = req;
        rpc::Call::new_resolved({
            SandboxManager::start_execution(
                &self.manager,
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input,
            );
            Ok(StartExecutionReply { success: true })
        })
    }

    fn create_execution_state(
        &self,
        req: CreateExecutionStateRequest,
    ) -> rpc::Call<CreateExecutionStateReply> {
        let result = self.manager.create_execution_state(
            req.wasm_id,
            req.wasm_binary,
            req.wasm_page_map,
            req.canister_id,
        );
        rpc::Call::new_resolved(Ok(CreateExecutionStateReply(result)))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ic_canister_sandbox_common::{
        controller_service::ControllerService,
        fdenum::EnumerateInnerFileDescriptors,
        protocol::{
            self,
            id::{ExecId, MemoryId, WasmId},
            structs::SandboxExecInput,
        },
    };
    use ic_interfaces::execution_environment::{
        ExecutionMode, ExecutionParameters, SubnetAvailableMemory,
    };
    use ic_registry_routing_table::RoutingTable;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{Global, NumWasmPages, PageIndex, PageMap};
    use ic_system_api::{ApiType, CanisterStatusView, StaticSystemState};
    use ic_test_utilities::types::ids::{canister_test_id, user_test_id};
    use ic_types::{
        ingress::WasmResult,
        messages::CallContextId,
        methods::{FuncRef, WasmMethod},
        time::Time,
        ComputeAllocation, Cycles, NumBytes, NumInstructions, PrincipalId, SubnetId,
    };
    use mockall::*;
    use std::collections::BTreeMap;
    use std::convert::TryFrom;
    use std::sync::{Arc, Condvar, Mutex};
    use wabt::wat2wasm;

    fn execution_parameters() -> ExecutionParameters {
        ExecutionParameters {
            instruction_limit: NumInstructions::new(1000),
            canister_memory_limit: NumBytes::new(4 << 30),
            subnet_available_memory: SubnetAvailableMemory::new(i64::MAX / 2),
            compute_allocation: ComputeAllocation::default(),
            subnet_type: SubnetType::Application,
            execution_mode: ExecutionMode::Replicated,
        }
    }

    fn static_system_state() -> StaticSystemState {
        StaticSystemState::new_internal(
            canister_test_id(0),
            user_test_id(0).get(),
            CanisterStatusView::Running,
            SubnetType::Application,
        )
    }

    fn serialize_memory(page_map: &PageMap, num_wasm_pages: NumWasmPages) -> MemorySerialization {
        let mut memory = MemorySerialization {
            page_map: page_map.serialize(),
            num_wasm_pages,
        };
        // Duplicate all file descriptors to simulate sending them to another process.
        let mut fds: Vec<&mut std::os::unix::io::RawFd> = vec![];
        memory.enumerate_fds(&mut fds);
        for fd in fds.into_iter() {
            *fd = nix::unistd::dup(*fd).unwrap();
        }
        memory
    }

    fn exec_input_for_update(
        method_name: &str,
        incoming_payload: &[u8],
        globals: Vec<Global>,
        next_wasm_memory_id: MemoryId,
        next_stable_memory_id: MemoryId,
    ) -> SandboxExecInput {
        SandboxExecInput {
            func_ref: FuncRef::Method(WasmMethod::Update(method_name.to_string())),
            api_type: ApiType::update(
                Time::from_nanos_since_unix_epoch(0),
                incoming_payload.to_vec(),
                Cycles::from(0),
                PrincipalId::try_from([0].as_ref()).unwrap(),
                CallContextId::from(0),
                SubnetId::from(PrincipalId::new_subnet_test_id(0)),
                SubnetType::Application,
                Arc::new(RoutingTable::new(BTreeMap::new())),
                Arc::new(BTreeMap::new()),
            ),
            globals,
            canister_current_memory_usage: NumBytes::from(0),
            execution_parameters: execution_parameters(),
            next_wasm_memory_id,
            next_stable_memory_id,
            static_system_state: static_system_state(),
        }
    }

    fn exec_input_for_query(
        method_name: &str,
        incoming_payload: &[u8],
        globals: Vec<Global>,
    ) -> SandboxExecInput {
        SandboxExecInput {
            func_ref: FuncRef::Method(WasmMethod::Query(method_name.to_string())),
            api_type: ApiType::replicated_query(
                Time::from_nanos_since_unix_epoch(0),
                incoming_payload.to_vec(),
                PrincipalId::try_from([0].as_ref()).unwrap(),
                None,
            ),
            globals,
            canister_current_memory_usage: NumBytes::from(0),
            execution_parameters: execution_parameters(),
            next_wasm_memory_id: MemoryId::new(),
            next_stable_memory_id: MemoryId::new(),
            static_system_state: static_system_state(),
        }
    }

    mock! {
        pub ControllerService {
        }

        trait ControllerService {
            fn execution_finished(
                &self, req : protocol::ctlsvc::ExecutionFinishedRequest
            ) -> rpc::Call<protocol::ctlsvc::ExecutionFinishedReply>;

            fn canister_system_call(
                &self, req : protocol::ctlsvc::CanisterSystemCallRequest
            ) -> rpc::Call<protocol::ctlsvc::CanisterSystemCallReply>;

            fn log_via_replica(&self, log: protocol::logging::LogRequest) -> rpc::Call<()>;
        }
    }

    struct SyncCell<T> {
        item: Mutex<Option<T>>,
        cond: Condvar,
    }

    impl<T> SyncCell<T> {
        pub fn new() -> Self {
            Self {
                item: Mutex::new(None),
                cond: Condvar::new(),
            }
        }
        pub fn get(&self) -> T {
            let mut guard = self.item.lock().unwrap();
            loop {
                if let Some(item) = (*guard).take() {
                    break item;
                } else {
                    guard = self.cond.wait(guard).unwrap();
                }
            }
        }
        pub fn put(&self, item: T) {
            let mut guard = self.item.lock().unwrap();
            *guard = Some(item);
            self.cond.notify_one();
        }
    }

    fn make_counter_canister_wasm() -> Vec<u8> {
        let wat_data = r#"
            ;; Counter with global variable ;;
            (module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $read
                (i32.store
                  (i32.const 0)
                  (global.get 0)
                )
                (call $msg_reply_data_append
                  (i32.const 0)
                  (i32.const 4))
                (call $msg_reply))

              (func $write
                (global.set 0
                  (i32.add
                    (global.get 0)
                    (i32.const 1)
                  )
                )
                (call $read)
              )

              (memory $memory 1)
              (export "memory" (memory $memory))
              (global (export "counter_global") (mut i32) (i32.const 0))
              (export "canister_query read" (func $read))
              (export "canister_query inc_read" (func $write))
              (export "canister_update write" (func $write))
            )
            "#;

        wat2wasm(wat_data).unwrap().as_slice().to_vec()
    }

    fn make_memory_canister_wasm() -> Vec<u8> {
        // This canister supports two calls:
        // - write: requires 4 bytes of "address" followed by N bytes of payload; writes
        //   the N payload bytes at given "address" into memory
        // - read: requires 4 bytes of "address" followed by 4 bytes of "size"; reads
        //   "size" bytes from "address" in memory and returns the data as reply
        let wat_data = r#"
            (module
              (import "ic0" "msg_arg_data_size"
                (func $msg_arg_data_size (result i32)))
              (import "ic0" "msg_arg_data_copy"
                (func $msg_arg_data_copy (param i32 i32 i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32)))
              (import "ic0" "stable_write"
                (func $stable_write (param i32 i32 i32)))
              (import "ic0" "stable_read"
                (func $stable_read (param i32 i32 i32)))

              (func $read
                (call $msg_arg_data_copy
                  (i32.const 0) ;; dst
                  (i32.const 0) ;; offset
                  (i32.const 8) ;; size
                )
                (call $msg_reply_data_append
                  (i32.load (i32.const 0)) ;; src
                  (i32.load (i32.const 4)) ;; size
                )
                (call $msg_reply)
              )
              (func $write
                (call $msg_arg_data_copy
                  (i32.const 0) ;; dst ;;
                  (i32.const 0) ;; offset ;;
                  (i32.const 4) ;; size ;;
                )
                (call $msg_arg_data_copy
                  (i32.load (i32.const 0)) ;; dst ;;
                  (i32.const 4) ;; offset ;;
                  (i32.sub (call $msg_arg_data_size) (i32.const 4)) ;; size
                )
                (call $msg_reply)
              )

              (func $read_stable
                (call $msg_arg_data_copy
                  (i32.const 0) ;; dst
                  (i32.const 0) ;; offset
                  (i32.const 8) ;; size
                )
                (call $stable_read
                  (i32.const 8) ;; dst
                  (i32.load (i32.const 0)) ;; offset
                  (i32.load (i32.const 4)) ;; size
                )
                (call $msg_reply_data_append
                  (i32.const 8) ;; src
                  (i32.load (i32.const 4)) ;; size
                )
                (call $msg_reply)
              )

              (func $write_stable
                (call $msg_arg_data_copy ;; copy entire messge ;;
                  (i32.const 0) ;; dst ;;
                  (i32.const 0) ;; offset ;;
                  (call $msg_arg_data_size) ;; size ;;
                )
                (call $stable_write
                  (i32.load (i32.const 0)) ;; stable memory offset ;;
                  (i32.const 4) ;; src (first 4 bytes were offset) ;;
                  (i32.sub (call $msg_arg_data_size) (i32.const 4)) ;; size ;;
                )
                (call $msg_reply)
              )

              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_query read" (func $read))
              (export "canister_update write" (func $write))
              (export "canister_query read_stable" (func $read_stable))
              (export "canister_update write_stable" (func $write_stable))
            )
            "#;

        wat2wasm(wat_data).unwrap().as_slice().to_vec()
    }

    /// Create a "mock" controller service that handles the IPC requests
    /// incoming from sandbox. It will ignore most of them, with the
    /// following important exceptions:
    /// - when receiving "ExecFinished" it will put the result in the given
    ///   SyncCell
    /// - when receiving a "special" syscall, it will pass the number of
    ///   instructions to set up for instrumentation
    fn setup_mock_controller(
        exec_finished_sync: Arc<SyncCell<protocol::ctlsvc::ExecutionFinishedRequest>>,
    ) -> Arc<dyn ControllerService> {
        let mut controller = MockControllerService::new();
        controller
            .expect_execution_finished()
            .returning(move |req| {
                (*exec_finished_sync).put(req);
                rpc::Call::new_resolved(Ok(protocol::ctlsvc::ExecutionFinishedReply {}))
            });
        controller
            .expect_log_via_replica()
            .returning(move |_req| rpc::Call::new_resolved(Ok(())));

        Arc::new(controller)
    }

    fn open_memory(srv: &SandboxServer, page_map: &PageMap, num_pages: usize) -> MemoryId {
        let memory_id = MemoryId::new();
        let rep = srv
            .open_memory(OpenMemoryRequest {
                memory_id,
                memory: serialize_memory(page_map, NumWasmPages::new(num_pages)),
            })
            .sync()
            .unwrap();
        assert!(rep.success);
        memory_id
    }

    fn close_memory(srv: &SandboxServer, memory_id: MemoryId) {
        let rep = srv
            .close_memory(protocol::sbxsvc::CloseMemoryRequest { memory_id })
            .sync()
            .unwrap();
        assert!(rep.success);
    }

    /// Verifies that we can create a simple canister and run something on
    /// it.
    #[test]
    fn test_simple_canister() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());

        let srv = SandboxServer::new(SandboxManager::new(setup_mock_controller(
            exec_finished_sync.clone(),
        )));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_counter_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let wasm_memory = PageMap::default();
        let wasm_memory_id = open_memory(&srv, &wasm_memory, 0);
        let stable_memory = PageMap::default();
        let stable_memory_id = open_memory(&srv, &stable_memory, 0);

        // First time around, issue an update to increase the counter.
        let exec_id_1 = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id: exec_id_1,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_update(
                    "write",
                    &[],
                    vec![],
                    MemoryId::new(),
                    MemoryId::new(),
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.wasm.num_instructions_left < NumInstructions::from(1000));
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let globals = result.exec_output.state.unwrap().globals;
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);

        // Second time around, issue a query to read the counter. We
        // will still read the same value of the counter.
        let exec_id_2 = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id: exec_id_2,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_query("read", &[], globals),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.wasm.num_instructions_left < NumInstructions::from(1000));
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);
    }

    /// Verify that memory writes result in correct page being marked
    /// dirty and passed back.
    #[test]
    fn test_memory_write_dirty() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());

        let srv = SandboxServer::new(SandboxManager::new(setup_mock_controller(
            exec_finished_sync.clone(),
        )));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_memory_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let mut wasm_memory = PageMap::default();
        let wasm_memory_id = open_memory(&srv, &wasm_memory, 0);
        let stable_memory = PageMap::default();
        let stable_memory_id = open_memory(&srv, &stable_memory, 0);

        // Issue a write of bytes [1, 2, 3, 4] at address 16.
        let exec_id = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_update(
                    "write",
                    &[16, 0, 0, 0, 1, 2, 3, 4],
                    vec![],
                    MemoryId::new(),
                    MemoryId::new(),
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let state_modifications = result.exec_output.state.unwrap();
        assert_eq!(WasmResult::Reply([].to_vec()), wasm_result);

        wasm_memory.deserialize_delta(state_modifications.wasm_memory.page_delta);
        assert_eq!(
            vec![1, 2, 3, 4],
            wasm_memory.get_page(PageIndex::new(0))[16..20].to_vec()
        );
    }

    /// Verify that state is set up correctly with given page contents
    /// such that memory reads yield the correct data.
    #[test]
    fn test_memory_read_state() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());

        let srv = SandboxServer::new(SandboxManager::new(setup_mock_controller(
            exec_finished_sync.clone(),
        )));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_memory_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let mut wasm_memory = PageMap::default();
        // Create state setting up initial memory to have a couple
        // bytes set to particular values.
        let mut page_data = [0; 4096];
        page_data[42] = 1;
        page_data[43] = 2;
        wasm_memory.update(&[(PageIndex::from(0), &page_data)]);
        let wasm_memory_id = open_memory(&srv, &wasm_memory, 1);
        let stable_memory = PageMap::default();
        let stable_memory_id = open_memory(&srv, &stable_memory, 0);

        // Issue a read of size 4 against address 40.
        let exec_id = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_query("read", &[40, 0, 0, 0, 4, 0, 0, 0], vec![]),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        assert_eq!(WasmResult::Reply([0, 0, 1, 2].to_vec()), wasm_result);
    }

    /// Verifies that we can create a simple canister and run multiple
    /// queries with the same Wasm cache.
    /// TODO: INF-1653 This code triggers EINVAL from lmdb fairly consistently.
    #[test]
    #[ignore]
    fn test_simple_canister_wasm_cache() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());
        let exec_finished_sync_clone = Arc::clone(&exec_finished_sync);

        let mut controller = MockControllerService::new();
        controller
            .expect_execution_finished()
            .returning(move |req| {
                (*exec_finished_sync_clone).put(req);
                rpc::Call::new_resolved(Ok(protocol::ctlsvc::ExecutionFinishedReply {}))
            });
        controller
            .expect_log_via_replica()
            .returning(move |_req| rpc::Call::new_resolved(Ok(())));

        let controller = Arc::new(controller);

        let srv = SandboxServer::new(SandboxManager::new(controller));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_counter_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let wasm_memory = PageMap::default();
        let wasm_memory_id = open_memory(&srv, &wasm_memory, 0);
        let stable_memory = PageMap::default();
        let stable_memory_id = open_memory(&srv, &stable_memory, 0);

        // First time around, issue an update to increase the counter.
        let exec_id = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_update(
                    "write",
                    &[],
                    vec![],
                    MemoryId::new(),
                    MemoryId::new(),
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.wasm.num_instructions_left < NumInstructions::from(1000));
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let globals = result.exec_output.state.unwrap().globals;
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);
        assert_eq!([Global::I32(1), Global::I64(988)].to_vec(), globals);

        // Ensure we close Wasm and stable memory.
        close_memory(&srv, wasm_memory_id);
        close_memory(&srv, stable_memory_id);

        // Now re-issue the same call but with the previous cache on.

        let wasm_memory = PageMap::default();
        let wasm_memory_id = open_memory(&srv, &wasm_memory, 0);
        let stable_memory = PageMap::default();
        let stable_memory_id = open_memory(&srv, &stable_memory, 0);

        // First time around, issue an update to increase the counter.
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_update(
                    "write",
                    &[],
                    globals,
                    MemoryId::new(),
                    MemoryId::new(),
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.wasm.num_instructions_left < NumInstructions::from(1000));
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let globals = result.exec_output.state.unwrap().globals;
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);

        // Second time around, issue a query to read the counter. We
        // expect to be able to read back the modified counter value
        // (since we committed the previous state).
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_query("read", &[], globals),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        assert!(result.exec_output.wasm.num_instructions_left < NumInstructions::from(500));
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        assert_eq!(WasmResult::Reply([1, 0, 0, 0].to_vec()), wasm_result);
    }

    /// Verify that stable memory writes result in correct page being marked
    /// dirty and passed back.
    #[test]
    fn test_stable_memory_write_dirty() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());

        let srv = SandboxServer::new(SandboxManager::new(setup_mock_controller(
            exec_finished_sync.clone(),
        )));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_memory_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let wasm_memory = PageMap::default();
        let wasm_memory_id = open_memory(&srv, &wasm_memory, 0);
        let mut stable_memory = PageMap::default();
        let stable_memory_id = open_memory(&srv, &stable_memory, 1);

        // Issue a write of bytes [1, 2, 3, 4] at address 16 in stable memory.
        let exec_id = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_update(
                    "write_stable",
                    &[16, 0, 0, 0, 1, 2, 3, 4],
                    vec![],
                    MemoryId::new(),
                    MemoryId::new(),
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let state_modifications = result.exec_output.state.unwrap();
        assert_eq!(WasmResult::Reply([].to_vec()), wasm_result);

        stable_memory.deserialize_delta(state_modifications.stable_memory.page_delta);
        assert_eq!(
            vec![1, 2, 3, 4],
            stable_memory.get_page(PageIndex::new(0))[16..20].to_vec()
        );
    }

    /// Verify that state is set up correctly with given page contents
    /// such that memory reads yield the correct data.
    #[test]
    fn test_stable_memory_read_state() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());

        let srv = SandboxServer::new(SandboxManager::new(setup_mock_controller(
            exec_finished_sync.clone(),
        )));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_memory_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let wasm_memory = PageMap::default();
        let wasm_memory_id = open_memory(&srv, &wasm_memory, 0);
        let mut stable_memory = PageMap::default();
        // Create state setting up initial memory to have a couple
        // bytes set to particular values.
        let mut page_data = [0; 4096];
        page_data[42] = 1;
        page_data[43] = 2;
        stable_memory.update(&[(PageIndex::new(0), &page_data)]);
        let stable_memory_id = open_memory(&srv, &stable_memory, 1);

        // Issue a read of size 4 against address 40.
        let exec_id = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id,
                wasm_id,
                wasm_memory_id,
                stable_memory_id,
                exec_input: exec_input_for_query("read_stable", &[40, 0, 0, 0, 4, 0, 0, 0], vec![]),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        assert_eq!(WasmResult::Reply([0, 0, 1, 2].to_vec()), wasm_result);
    }

    #[test]
    fn test_wasm_memory_delta() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());

        let srv = SandboxServer::new(SandboxManager::new(setup_mock_controller(
            exec_finished_sync.clone(),
        )));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_memory_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let mut wasm_memory = PageMap::default();
        let parent_wasm_memory_id = open_memory(&srv, &wasm_memory, 1);
        let stable_memory = PageMap::default();
        let parent_stable_memory_id = open_memory(&srv, &stable_memory, 0);

        let child_wasm_memory_id = MemoryId::new();
        let child_stable_memory_id = MemoryId::new();

        // Issue a write of bytes [1, 2, 3, 4] at address 16 in Wasm memory.
        let exec_id_1 = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id: exec_id_1,
                wasm_id,
                wasm_memory_id: parent_wasm_memory_id,
                stable_memory_id: parent_stable_memory_id,
                exec_input: exec_input_for_update(
                    "write",
                    &[16, 0, 0, 0, 1, 2, 3, 4],
                    vec![],
                    child_wasm_memory_id,
                    child_stable_memory_id,
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let state_modifications = result.exec_output.state.unwrap();
        assert_eq!(WasmResult::Reply([].to_vec()), wasm_result);

        wasm_memory.deserialize_delta(state_modifications.wasm_memory.page_delta);
        assert_eq!(
            vec![1, 2, 3, 4],
            wasm_memory.get_page(PageIndex::new(0))[16..20].to_vec()
        );

        // Issue a write of bytes [5, 6, 7, 8] at address 32 in stable memory.
        let exec_id_2 = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id: exec_id_2,
                wasm_id,
                wasm_memory_id: child_wasm_memory_id,
                stable_memory_id: child_stable_memory_id,
                exec_input: exec_input_for_update(
                    "write",
                    &[32, 0, 0, 0, 5, 6, 7, 8],
                    vec![],
                    MemoryId::new(),
                    MemoryId::new(),
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let state_modifications = result.exec_output.state.unwrap();
        assert_eq!(WasmResult::Reply([].to_vec()), wasm_result);

        wasm_memory.deserialize_delta(state_modifications.wasm_memory.page_delta);
        assert_eq!(
            vec![5, 6, 7, 8],
            wasm_memory.get_page(PageIndex::new(0))[32..36].to_vec()
        );
        assert_eq!(
            vec![1, 2, 3, 4],
            wasm_memory.get_page(PageIndex::new(0))[16..20].to_vec()
        );

        close_memory(&srv, parent_wasm_memory_id);
        close_memory(&srv, parent_stable_memory_id);
        close_memory(&srv, child_wasm_memory_id);
        close_memory(&srv, child_stable_memory_id);
    }

    #[test]
    fn test_stable_memory_delta() {
        let exec_finished_sync =
            Arc::new(SyncCell::<protocol::ctlsvc::ExecutionFinishedRequest>::new());

        let srv = SandboxServer::new(SandboxManager::new(setup_mock_controller(
            exec_finished_sync.clone(),
        )));

        let wasm_id = WasmId::new();
        let rep = srv
            .open_wasm(OpenWasmRequest {
                wasm_id,
                wasm_src: make_memory_canister_wasm(),
            })
            .sync()
            .unwrap();
        assert!(rep.0.is_ok());

        let wasm_memory = PageMap::default();
        let parent_wasm_memory_id = open_memory(&srv, &wasm_memory, 0);
        let mut stable_memory = PageMap::default();
        let parent_stable_memory_id = open_memory(&srv, &stable_memory, 1);

        let child_wasm_memory_id = MemoryId::new();
        let child_stable_memory_id = MemoryId::new();

        // Issue a write of bytes [1, 2, 3, 4] at address 16 in stable memory.
        let exec_id_1 = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id: exec_id_1,
                wasm_id,
                wasm_memory_id: parent_wasm_memory_id,
                stable_memory_id: parent_stable_memory_id,
                exec_input: exec_input_for_update(
                    "write_stable",
                    &[16, 0, 0, 0, 1, 2, 3, 4],
                    vec![],
                    child_wasm_memory_id,
                    child_stable_memory_id,
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let state_modifications = result.exec_output.state.unwrap();
        assert_eq!(WasmResult::Reply([].to_vec()), wasm_result);

        stable_memory.deserialize_delta(state_modifications.stable_memory.page_delta);
        assert_eq!(
            vec![1, 2, 3, 4],
            stable_memory.get_page(PageIndex::new(0))[16..20].to_vec()
        );

        // Issue a write of bytes [5, 6, 7, 8] at address 32 in stable memory.
        let exec_id_2 = ExecId::new();
        let rep = srv
            .start_execution(protocol::sbxsvc::StartExecutionRequest {
                exec_id: exec_id_2,
                wasm_id,
                wasm_memory_id: child_wasm_memory_id,
                stable_memory_id: child_stable_memory_id,
                exec_input: exec_input_for_update(
                    "write_stable",
                    &[32, 0, 0, 0, 5, 6, 7, 8],
                    vec![],
                    MemoryId::new(),
                    MemoryId::new(),
                ),
            })
            .sync()
            .unwrap();
        assert!(rep.success);

        let result = exec_finished_sync.get();
        let wasm_result = result.exec_output.wasm.wasm_result.unwrap().unwrap();
        let state_modifications = result.exec_output.state.unwrap();
        assert_eq!(WasmResult::Reply([].to_vec()), wasm_result);

        stable_memory.deserialize_delta(state_modifications.stable_memory.page_delta);
        assert_eq!(
            vec![5, 6, 7, 8],
            stable_memory.get_page(PageIndex::new(0))[32..36].to_vec()
        );
        assert_eq!(
            vec![1, 2, 3, 4],
            stable_memory.get_page(PageIndex::new(0))[16..20].to_vec()
        );

        close_memory(&srv, parent_wasm_memory_id);
        close_memory(&srv, parent_stable_memory_id);
        close_memory(&srv, child_wasm_memory_id);
        close_memory(&srv, child_stable_memory_id);
    }
}
