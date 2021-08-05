mod canister_descriptor_table;
pub mod controller;
mod controller_service;
mod process_watcher;
mod sandbox_fsm;
pub mod session_nonce;

use ic_config::embedders::Config;
use ic_embedders::{WasmExecutionInput, WasmExecutionOutput};
use ic_logger::ReplicaLogger;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// An async result of wasm execution.
// Cannot be cloned. Can only be consumed.
pub struct WasmExecutionResult {
    pub output_receiver: crossbeam_channel::Receiver<RunnerOutput>,
}

impl WasmExecutionResult {
    pub fn get(self) -> WasmExecutionOutput {
        let res = self
            .output_receiver
            .recv()
            .expect("Recv failed: WasmRunner apparently died");

        WasmExecutionResult::on_result(res)
    }

    fn on_result(res: RunnerOutput) -> WasmExecutionOutput {
        res.output
    }
}

pub struct ReturnToken {
    pub output_sender: crossbeam_channel::Sender<RunnerOutput>,
    pub output_receiver: crossbeam_channel::Receiver<RunnerOutput>,
    pub num_msgs: Arc<AtomicUsize>,
}

impl ReturnToken {
    pub fn return_result(self, output: WasmExecutionOutput) {
        let runner_output = RunnerOutput { output };
        let n = self.num_msgs.fetch_sub(1, Ordering::SeqCst);
        assert!(n > 0, "num_msgs underflowed");
        self.output_sender
            .send(runner_output)
            .expect("Response ready, but the receiver is gone");
    }
}

pub struct RunnerInput {
    pub input: WasmExecutionInput,
    pub return_token: ReturnToken,
}

pub struct RunnerOutput {
    pub output: WasmExecutionOutput,
}

#[derive(Clone)]
pub struct RunnerConfig {
    pub config: Config,
    pub log: ReplicaLogger,
}

pub struct QueueConfig {
    pub max_num_runners: usize,
    pub num_reusable_runners: usize,
}
