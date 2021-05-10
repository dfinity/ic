use crate::cow_memory_creator::CowMemoryCreator;
use crate::{
    Embedder, ExecutionResult, Instance, ResumeToken, WasmExecutionInput, WasmExecutionOutput,
    WasmExecutionResult, WasmtimeEmbedder,
};
use ic_config::embedders::{Config, EmbedderType, PersistenceType};
use ic_cow_state::{CowMemoryManager, MappedState};
use ic_interfaces::execution_environment::{HypervisorError, InstanceStats, SystemApi};
use ic_logger::ReplicaLogger;
use ic_replicated_state::{PageDelta, PageIndex};
use ic_system_api::{PauseHandler, SystemApiImpl, SystemStateAccessorDirect};
use ic_types::{
    methods::{FuncRef, SystemMethod, WasmMethod},
    NumInstructions,
};
use ic_wasm_utils::{
    instrumentation::{instrument, InstructionCostTable},
    validation::{validate_wasm_binary, WasmValidationLimits},
};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use std::thread::JoinHandle;

#[derive(Clone)]
pub struct RunnerConfig {
    pub embedder_type: EmbedderType,
    pub config: Config,
    pub log: ReplicaLogger,
}

pub struct QueueConfig {
    pub max_num_runners: usize,
    pub num_reusable_runners: usize,
}

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

pub struct ReturnToken {
    pub output_sender: crossbeam_channel::Sender<RunnerOutput>,
    pub output_receiver: crossbeam_channel::Receiver<RunnerOutput>,
    pub extra_worker_handle: Option<ExtraWorkerHandle>,
    pub num_msgs: Arc<AtomicUsize>,
}

impl ReturnToken {
    pub fn return_result(self, output: WasmExecutionOutput) {
        let output = ExecutionResult::WasmExecutionOutput(output);
        let runner_output = RunnerOutput {
            output,
            extra_worker_handle: self.extra_worker_handle,
        };
        let n = self.num_msgs.fetch_sub(1, Ordering::SeqCst);
        assert!(n > 0, "num_msgs underflowed");
        self.output_sender
            .send(runner_output)
            .expect("Response ready, but the receiver is gone");
    }
    fn create_pause_handler(&self) -> Box<dyn PauseHandler> {
        Box::new(PauseHandlerImpl {
            output_sender: self.output_sender.clone(),
            output_receiver: self.output_receiver.clone(),
        })
    }
}

pub struct RunnerInput {
    pub input: WasmExecutionInput,
    pub return_token: ReturnToken,
}

pub struct RunnerOutput {
    pub output: ExecutionResult,
    pub extra_worker_handle: Option<ExtraWorkerHandle>,
}

pub struct ExtraWorkerHandle {
    processing_group: Arc<ProcessingGroup>,
    join_handle: JoinHandle<()>,
}

// A message which was processed by an extra worker, will have this handle
// and use it to join with the worker thread when the result is claimed
// as well as possibly spawn next extra worker if there are still messages
// waiting in the main queue.
impl ExtraWorkerHandle {
    pub(crate) fn on_task_finished(self) {
        let pg = self.processing_group;

        self.join_handle
            .join()
            .expect("Join failed, which indicates that WasmRunner thread may have panicked");
        pg.num_runners.fetch_sub(1, Ordering::SeqCst);
        // Here the worker finished and it's considered removed.
        // Now ProcessingGroup::execute has accurate information about
        // the state of things (in case it's executing)
        if let Ok(next_task) = pg.task_queue_recv.try_recv() {
            pg.num_runners.fetch_add(1, Ordering::SeqCst);
            pg.spawn_extra_runner(next_task);
        }
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

// A processing group behaves like a thread pool.
// If max_num_runners == num_reusable_runners its behavior is quite simple.
// There is one task_queue on which all workers are listening.
// When a reusable_worker finishes processing a message it takes the next
// message from the task_queue or waits for a new message to appear if queue is
// empty.
//
// Additionally, we support creation of extra workers.
// If x = max_num_runners - num_reusable_runners, is > 0,
// then x extra new workers can be spawned (in the current
// implementation, in some very rare situations, more workers
// than that may appear (extremely unlikely for +1 worker,
// extremely unlikely squared for +2 and so on).
// Extra workers are not listening on the main queue, but instead
// each has his own dedicated queue.
// After an extra worker finishes processing a message it shuts down
// and the result it generated can act as a seed for the next extra worker.
// When the result is claimed, a check is performed whether there are any
// messages waiting in the main queue. If there is a message, a new extra worker
// is spawned to process it. This situation continues until main queue is
// drained.
pub struct ProcessingGroup {
    runner_config: RunnerConfig,
    task_queue_config: QueueConfig,

    task_queue: crossbeam_channel::Sender<RunnerInput>,
    task_queue_recv: crossbeam_channel::Receiver<RunnerInput>,

    num_runners: Arc<AtomicUsize>,
    num_msgs: Arc<AtomicUsize>, //number of messages in the pipeline

    _join_handles: JoinHandles,
}

impl ProcessingGroup {
    pub fn new(runner_config: RunnerConfig, task_queue_config: QueueConfig) -> Self {
        let mut join_handles = vec![];
        let (task_queue, worker_inbound) = crossbeam_channel::unbounded();
        let num_runners = task_queue_config.num_reusable_runners;
        for _i in 0..num_runners {
            join_handles.push(spawn_new_runner(
                runner_config.clone(),
                worker_inbound.clone(),
            ));
        }
        Self {
            runner_config,
            task_queue_config,
            task_queue,
            task_queue_recv: worker_inbound,
            num_runners: Arc::new(AtomicUsize::new(num_runners)),
            num_msgs: Arc::new(AtomicUsize::new(0)),
            _join_handles: JoinHandles { join_handles },
        }
    }

    pub fn execute(self: &Arc<ProcessingGroup>, input: WasmExecutionInput) -> WasmExecutionResult {
        let (output_sender, output_receiver) = crossbeam_channel::unbounded();
        let return_token = ReturnToken {
            output_sender,
            output_receiver: output_receiver.clone(),
            extra_worker_handle: None,
            num_msgs: self.num_msgs.clone(),
        };
        self.num_msgs.fetch_add(1, Ordering::SeqCst);

        let runner_input = RunnerInput {
            input,
            return_token,
        };

        self.task_queue
            .send(runner_input)
            .expect("No task receivers left");

        let num_msgs = self.num_msgs.load(Ordering::SeqCst);
        let num_workers = self.num_runners.load(Ordering::SeqCst);
        let max_workers = self.task_queue_config.max_num_runners;

        if num_msgs > num_workers && num_workers < max_workers {
            // Either we pick up the task, or Extra worker does.
            // In either case exactly one worker, corresponding to
            // one task will be spawned (only one of them will pick up the task)
            if let Ok(task) = self.task_queue_recv.try_recv() {
                self.num_runners.fetch_add(1, Ordering::SeqCst);
                Arc::clone(self).spawn_extra_runner(task);
            }
        }

        WasmExecutionResult { output_receiver }
    }

    fn spawn_extra_runner(self: Arc<ProcessingGroup>, mut input: RunnerInput) {
        let (task_queue, worker_inbound) = crossbeam_channel::unbounded();
        let join_handle = spawn_new_runner(self.runner_config.clone(), worker_inbound);
        input.return_token.extra_worker_handle = Some(ExtraWorkerHandle {
            processing_group: self,
            join_handle,
        });
        task_queue.send(input).unwrap();
    }
}

// A runner listens on an inbound queue for messages to process
// Runner input contains a return token, used to return the result
// (internally it holds a return queue).
//
// A runner can process any message (query or not)
struct WasmRunner<E: Embedder> {
    wasm_embedder: E,
    inbound: crossbeam_channel::Receiver<RunnerInput>,
    _log: ReplicaLogger,
    config: Config,
}

pub fn spawn_new_runner(
    cfg: RunnerConfig,
    worker_inbound: crossbeam_channel::Receiver<RunnerInput>,
) -> std::thread::JoinHandle<()> {
    match cfg.embedder_type {
        EmbedderType::Wasmtime => {
            let wasm_embedder = WasmtimeEmbedder::new(cfg.config.clone(), cfg.log.clone());
            WasmRunner {
                wasm_embedder,
                inbound: worker_inbound,
                _log: cfg.log,
                config: cfg.config,
            }
            .spawn()
        }
    }
}

impl<E: Embedder + Send + 'static> WasmRunner<E> {
    fn run(&self) {
        while let Ok(msg) = self.inbound.recv() {
            let RunnerInput {
                input,
                return_token,
            } = msg;
            let pause_handler = return_token.create_pause_handler();
            let output = self.process(input, pause_handler);
            return_token.return_result(output);
        }
    }

    fn spawn(self) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("WasmRunner".to_string())
            .spawn(move || self.run())
            .expect("failed to spawn a thread")
    }

    fn process(
        &self,
        WasmExecutionInput {
            api_type,
            system_state,
            instructions_limit,
            canister_memory_limit,
            canister_current_memory_usage,
            subnet_available_memory,
            compute_allocation,
            func_ref,
            mut execution_state,
            cycles_account_manager,
        }: WasmExecutionInput,
        pause_handler: Box<dyn PauseHandler>,
    ) -> WasmExecutionOutput {
        let system_state_accessor =
            SystemStateAccessorDirect::new(system_state, cycles_account_manager);
        let persistence_type = if execution_state.cow_mem_mgr.is_valid() {
            PersistenceType::Pagemap
        } else {
            PersistenceType::Sigsegv
        };
        if execution_state.embedder_cache.is_none() {
            // The wasm_binary stored in the `ExecutionState` is not
            // instrumented so instrument it before compiling. Further, due to
            // IC upgrades, it is possible that the `validate_wasm_binary()`
            // function has changed, so also validate the binary.
            match validate_wasm_binary(
                &execution_state.wasm_binary,
                WasmValidationLimits {
                    max_globals: self.config.max_globals,
                    max_functions: self.config.max_functions,
                },
            )
            .map_err(HypervisorError::from)
            .and_then(|()| {
                instrument(&execution_state.wasm_binary, &InstructionCostTable::new())
                    .map_err(HypervisorError::from)
            })
            .and_then(|output| self.wasm_embedder.compile(persistence_type, &output.binary))
            {
                Ok(cache) => execution_state.embedder_cache = Some(cache),
                Err(err) => {
                    return WasmExecutionOutput {
                        wasm_result: Err(err),
                        num_instructions_left: NumInstructions::from(0),
                        system_state: system_state_accessor.release_system_state(),
                        execution_state,
                        instance_stats: InstanceStats {
                            accessed_pages: 0,
                            dirty_pages: 0,
                        },
                    };
                }
            }
        }

        // TODO(EXC-176): we should combine this with the hypervisor so that
        // we make the decision of whether or not to commit modifications in
        // a single place instead.
        let (memory_creator, commit_dirty_pages) = if execution_state.cow_mem_mgr.is_valid() {
            match &func_ref {
                FuncRef::Method(WasmMethod::Update(_))
                | FuncRef::Method(WasmMethod::System(_))
                | FuncRef::UpdateClosure(_) => {
                    let mapped_state = execution_state.cow_mem_mgr.get_map();
                    execution_state.mapped_state = Some(Arc::new(mapped_state));
                }
                _ => (),
            }

            let commit_dirty_pages = func_ref.to_commit();

            let mapped_state = Arc::as_ref(execution_state.mapped_state.as_ref().unwrap());
            (
                Some(Arc::new(CowMemoryCreator::new(mapped_state))),
                commit_dirty_pages,
            )
        } else {
            (None, false)
        };

        let mut instance = self.wasm_embedder.new_instance(
            &execution_state.embedder_cache.as_ref().unwrap(),
            &execution_state.exported_globals,
            execution_state.heap_size,
            memory_creator,
            Some(execution_state.page_map.clone()),
        );

        if let FuncRef::Method(WasmMethod::System(SystemMethod::Empty)) = func_ref {
            execution_state.heap_size = instance.heap_size();
            execution_state.exported_globals = instance.get_exported_globals();
            return WasmExecutionOutput {
                wasm_result: Ok(None),
                num_instructions_left: NumInstructions::from(0),
                system_state: system_state_accessor.release_system_state(),
                execution_state,
                instance_stats: instance.get_stats(),
            };
        }

        let (execution_result, available_num_instructions, system_state_accessor, instance_stats) = {
            let mut system_api = SystemApiImpl::new(
                api_type,
                system_state_accessor,
                instructions_limit,
                canister_memory_limit,
                canister_current_memory_usage,
                subnet_available_memory,
                compute_allocation,
                pause_handler,
            );
            instance.set_num_instructions(system_api.get_available_num_instructions());
            let run_result = instance.run(&mut system_api, func_ref);
            system_api.set_available_num_instructions(instance.get_num_instructions());
            match run_result {
                Ok(run_result) => {
                    if execution_state.cow_mem_mgr.is_valid() && commit_dirty_pages {
                        let mapped_state = execution_state.mapped_state.take();
                        let pages: Vec<u64> =
                            run_result.dirty_pages.iter().map(|p| p.get()).collect();
                        mapped_state.unwrap().soft_commit(&pages);
                    } else {
                        let page_delta =
                            compute_page_delta(instance.as_ref(), &run_result.dirty_pages);
                        execution_state.page_map.update(page_delta);
                    }
                    execution_state.exported_globals = run_result.exported_globals;
                    execution_state.heap_size = instance.heap_size();
                }
                Err(err) => {
                    system_api.set_execution_error(err);
                }
            };
            let mut instance_stats = instance.get_stats();
            instance_stats.dirty_pages += system_api.get_stable_memory_delta_pages();
            (
                system_api.take_execution_result(),
                system_api.get_available_num_instructions(),
                system_api.release_system_state_accessor(),
                instance_stats,
            )
        };

        WasmExecutionOutput {
            wasm_result: execution_result,
            num_instructions_left: available_num_instructions,
            system_state: system_state_accessor.release_system_state(),
            execution_state,
            instance_stats,
        }
    }
}

// Utility function to compute the page delta. It creates a copy of `Instance`
// dirty pages.
fn compute_page_delta(instance: &dyn Instance, dirty_pages: &[PageIndex]) -> PageDelta {
    // heap pointer is only valid as long as the `Instance` is alive.
    let heap_addr: *const u8 = unsafe { instance.heap_addr() };

    let mut pages = vec![];

    for page_index in dirty_pages {
        let i = page_index.get();
        let page_addr: *const u8 = unsafe {
            let offset: usize = i as usize * *ic_sys::PAGE_SIZE;
            (heap_addr as *mut u8).add(offset)
        };
        let buf = unsafe { std::slice::from_raw_parts(page_addr, *ic_sys::PAGE_SIZE) };
        pages.push((*page_index, buf));
    }

    PageDelta::from(pages.as_slice())
}
