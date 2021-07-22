use crate::{WasmExecutionInput, WasmExecutionOutput};
use ic_config::embedders::Config;
use ic_logger::ReplicaLogger;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct RunnerConfig {
    pub config: Config,
    pub log: ReplicaLogger,
}

pub struct QueueConfig {
    pub max_num_runners: usize,
    pub num_reusable_runners: usize,
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
