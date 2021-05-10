use ic_config::embedders::{Config, EmbedderType};
use ic_embedders::{
    ExecutionResult, ProcessingGroup, QueueConfig, ResumeToken, RunnerConfig, RunnerOutput,
    WasmExecutionInput, WasmExecutionResult,
};
use ic_logger::ReplicaLogger;
use ic_system_api::{ApiType, PauseHandler};
use ic_types::NumInstructions;
use std::sync::Arc;
use std::thread::JoinHandle;

struct PauseHandlerImpl {
    output_sender: crossbeam_channel::Sender<RunnerOutput>,
    output_receiver: crossbeam_channel::Receiver<RunnerOutput>,
}

impl PauseHandler for PauseHandlerImpl {
    fn pause(&self) -> NumInstructions {
        let (resume_sender, receiver) = crossbeam_channel::unbounded();
        let output = ExecutionResult::ResumeToken(ResumeToken {
            resume_sender,
            output_receiver: self.output_receiver.clone(),
        });
        self.output_sender
            .send(RunnerOutput {
                output,
                extra_worker_handle: None,
            })
            .expect("Response ready (pause), but the receiver is gone");
        receiver
            .recv()
            .expect("Recv failed: Resume token was apparently destroyed without resuming")
    }
}

struct JoinHandles {
    join_handles: Vec<JoinHandle<()>>,
}

impl Drop for JoinHandles {
    fn drop(&mut self) {
        while !self.join_handles.is_empty() {
            self.join_handles.pop().unwrap().join().unwrap();
        }
    }
}

// Dispatcher is an entry point for wasm code execution.
// execute() produces an asnyc result.
//
// Internally Dispatcher contains ProcessingGroups and for each message
// makes a decision which processing group should handle the message
//
// Currently, beside general processing group, we have a dedicated
// group for processing queries. In the future we could create
// multiple groups and redirect messages to them based on priority
// CanisterId, or some other condition.
pub struct WasmExecutionDispatcher {
    task_processor: Arc<ProcessingGroup>,
    query_task_processor: Arc<ProcessingGroup>,
}

impl WasmExecutionDispatcher {
    pub fn new(embedder_type: EmbedderType, config: Config, log: ReplicaLogger) -> Self {
        let task_queue_config = QueueConfig {
            max_num_runners: config.num_runtime_generic_threads,
            num_reusable_runners: config.num_runtime_generic_threads,
        };
        let query_queue_config = QueueConfig {
            max_num_runners: config.num_runtime_query_threads,
            num_reusable_runners: config.num_runtime_query_threads,
        };

        let runner_config = RunnerConfig {
            embedder_type,
            config,
            log,
        };

        let task_processor = Arc::new(ProcessingGroup::new(
            runner_config.clone(),
            task_queue_config,
        ));

        let query_task_processor =
            Arc::new(ProcessingGroup::new(runner_config, query_queue_config));

        Self {
            task_processor,
            query_task_processor,
        }
    }

    pub fn execute(&self, input: WasmExecutionInput) -> WasmExecutionResult {
        match input.api_type {
            ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::InspectMessage { .. } => self.query_task_processor.execute(input),

            ApiType::Start
            | ApiType::Init { .. }
            | ApiType::Heartbeat { .. }
            | ApiType::Update { .. }
            | ApiType::Cleanup { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::PreUpgrade { .. } => self.task_processor.execute(input),
        }
    }
}
