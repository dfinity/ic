use ic_canister_sandbox_backend_lib::{
    controller_service::ControllerService,
    process,
    protocol::{ctlsvc, id::WasmId, logging::LogRequest, sbxsvc},
    rpc,
};
use ic_embedders::SerializedModuleBytes;
use std::sync::{atomic::AtomicBool, Arc};

struct DummyControllerService {}

/// RPC interface exposed by sandbox process.
impl ControllerService for DummyControllerService {
    fn execution_finished(
        &self,
        _req: ctlsvc::ExecutionFinishedRequest,
    ) -> rpc::Call<ctlsvc::ExecutionFinishedReply> {
        unimplemented!();
    }

    fn execution_paused(
        &self,
        _req: ctlsvc::ExecutionPausedRequest,
    ) -> rpc::Call<ctlsvc::ExecutionPausedReply> {
        unimplemented!()
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
    sbx.open_wasm_serialized(sbxsvc::OpenWasmSerializedRequest {
        wasm_id,
        serialized_module: Arc::new(SerializedModuleBytes::empty()),
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
