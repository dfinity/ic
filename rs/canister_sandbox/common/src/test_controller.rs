use ic_canister_sandbox_common::protocol::id::WasmId;
use ic_canister_sandbox_common::protocol::logging::LogRequest;
use ic_canister_sandbox_common::protocol::{ctlsvc, sbxsvc};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ic_canister_sandbox_common::{controller_service::ControllerService, process, rpc};

struct DummyControllerService {}

/// RPC interface exposed by sandbox process.
impl ControllerService for DummyControllerService {
    fn execution_finished(
        &self,
        _req: ctlsvc::ExecutionFinishedRequest,
    ) -> rpc::Call<ctlsvc::ExecutionFinishedReply> {
        unimplemented!();
    }

    fn canister_system_call(
        &self,
        _req: ctlsvc::CanisterSystemCallRequest,
    ) -> rpc::Call<ctlsvc::CanisterSystemCallReply> {
        unimplemented!();
    }

    fn log_via_replica(&self, _req: LogRequest) -> rpc::Call<()> {
        unimplemented!();
    }
}

fn main() {
    let controller_service = Arc::new(DummyControllerService {});
    let safe_shutdown = Arc::new(AtomicBool::new(false));

    let executable_path = process::build_sandbox_binary_relative_path("test_sandbox").unwrap();
    let (sbx, _, thread_handle) = process::spawn_canister_sandbox_process(
        &executable_path,
        &[executable_path.clone()],
        controller_service,
        safe_shutdown,
    )
    .unwrap();

    println!("Controller: Sending 'open_wasm' request");
    let wasm_id = WasmId::new();
    sbx.open_wasm(sbxsvc::OpenWasmRequest {
        wasm_id,
        wasm_src: Vec::new(),
    })
    .sync()
    .unwrap();
    println!("Controller: 'open_wasm' request returned");

    std::thread::sleep(std::time::Duration::from_millis(10));

    println!("Controller: Sending 'terminate' request");
    sbx.terminate(sbxsvc::TerminateRequest {}).sync().unwrap();
    println!("Controller: 'terminate' request returned");
    thread_handle.join().unwrap();
}
