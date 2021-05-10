pub mod cow_memory_creator;
mod dispatcher;
mod signal_handler;
pub mod wasmtime_embedder;

use cow_memory_creator::CowMemoryCreator;
pub use dispatcher::spawn_new_runner;
pub use dispatcher::ExtraWorkerHandle;
pub use dispatcher::ProcessingGroup;
pub use dispatcher::QueueConfig;
pub use dispatcher::ReturnToken;
pub use dispatcher::RunnerConfig;
pub use dispatcher::RunnerInput;
pub use dispatcher::RunnerOutput;
use ic_config::embedders::PersistenceType;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::execution_environment::{
    AsyncResult, ExecResult, ExecResultVariant, HypervisorError, HypervisorResult, InstanceStats,
    InterruptedExec, SubnetAvailableMemory, SystemApi, TrySelect,
};
use ic_replicated_state::{
    canister_state::system_state::SystemState, EmbedderCache, ExecutionState, Global, NumWasmPages,
    PageIndex, PageMap,
};
use ic_system_api::ApiType;
use ic_types::{
    ingress::WasmResult, methods::FuncRef, ComputeAllocation, NumBytes, NumInstructions,
};
use ic_wasm_types::BinaryEncodedWasm;
use std::sync::Arc;
pub use wasmtime_embedder::{WasmtimeEmbedder, WasmtimeMemoryCreator};

pub struct ResumeToken {
    pub resume_sender: crossbeam_channel::Sender<NumInstructions>,
    pub output_receiver: crossbeam_channel::Receiver<RunnerOutput>,
}

impl ResumeToken {
    pub fn resume(self, num_instructions_topup: NumInstructions) -> WasmExecutionResult {
        self.resume_sender
            .send(num_instructions_topup)
            .expect("No receivers left for resume");
        WasmExecutionResult {
            output_receiver: self.output_receiver,
        }
    }

    pub fn cancel(self) -> WasmExecutionResult {
        self.resume_sender
            .send(NumInstructions::from(0))
            .expect("No receivers left for cancel");
        WasmExecutionResult {
            output_receiver: self.output_receiver,
        }
    }
}

impl InterruptedExec<WasmExecutionOutput> for ResumeToken {
    fn resume(
        self: Box<Self>,
        num_instructions_topup: NumInstructions,
    ) -> ExecResult<WasmExecutionOutput> {
        ExecResult::new(Box::new(Self::resume(*self, num_instructions_topup)))
    }

    fn cancel(self: Box<Self>) -> ExecResult<WasmExecutionOutput> {
        ExecResult::new(Box::new(Self::cancel(*self)))
    }
}

// An execution result can either be a finished computation output
// (WasmExecutionOutput) or a ResumeToken, which indicates out_of_instructions
// situation. In the latter case we can top up the instructions by calling
// ResumeToken::resume(extra_instructions) or cancel it with
// ResumeToken::cancel().
//
// In the current implementation resume(0) is equivalent to cancel().
// Resume should be called with an amount of instructions sufficient to do some
// real work.
#[allow(clippy::large_enum_variant)]
pub enum ExecutionResult {
    WasmExecutionOutput(WasmExecutionOutput),
    ResumeToken(ResumeToken),
}

#[allow(clippy::type_complexity)]
pub struct ExecSelect<T> {
    early_results: Vec<T>,
    channels: Vec<(
        crossbeam_channel::Receiver<RunnerOutput>,
        Box<dyn FnOnce(Box<dyn std::any::Any + 'static>) -> T>,
    )>,
}

impl<T: 'static> ExecSelect<T> {
    pub fn new(results: Vec<ExecResult<T>>) -> Self {
        let mut s = Self {
            early_results: Vec::new(),
            channels: Vec::new(),
        };

        for r in results {
            s.add(r);
        }

        s
    }

    pub fn add(&mut self, r: ExecResult<T>) {
        match r.try_select() {
            TrySelect::EarlyResult(x) => self.early_results.push(x),
            TrySelect::Channel(c, f) => {
                let c = c
                    .downcast::<crossbeam_channel::Receiver<RunnerOutput>>()
                    .expect("Failed to downcast to crossbeam::Receiver<RunnerOutput>");
                self.channels.push((*c, f));
            }
        }
    }

    pub fn select(&mut self) -> Option<ExecResultVariant<T>> {
        if let Some(r) = self.early_results.pop() {
            return Some(ExecResultVariant::Completed(r));
        }
        if self.channels.is_empty() {
            return None;
        }

        let mut sel = crossbeam_channel::Select::new();
        for (r, _) in &self.channels {
            sel.recv(r);
        }

        let idx = sel.ready();
        let (c, f) = self.channels.remove(idx);
        let res = c.recv().expect("Recv failed: WasmRunner apparently died");
        let res = WasmExecutionResult::on_result(res);

        let g = |x: WasmExecutionOutput| -> T { f(Box::new(x)) };

        let res = match res {
            ExecutionResult::WasmExecutionOutput(x) => ExecResultVariant::Completed(g(x)),
            ExecutionResult::ResumeToken(rt) => {
                let rt: Box<dyn InterruptedExec<_>> = Box::new(rt);
                ExecResultVariant::Interrupted(rt.and_then(g))
            }
        };
        Some(res)
    }
}

// An async result of wasm execution.
// Cannot be cloned. Can only be consumed.
pub struct WasmExecutionResult {
    pub output_receiver: crossbeam_channel::Receiver<RunnerOutput>,
}

impl WasmExecutionResult {
    pub fn get(self) -> ExecutionResult {
        let res = self
            .output_receiver
            .recv()
            .expect("Recv failed: WasmRunner apparently died");

        WasmExecutionResult::on_result(res)
    }

    fn on_result(mut res: RunnerOutput) -> ExecutionResult {
        if let Some(h) = res.extra_worker_handle.take() {
            if let ExecutionResult::ResumeToken(_) = res.output {
                panic!("There should be no extra worker handle wiht resume token");
            }
            h.on_task_finished();
        }
        res.output
    }
}

impl AsyncResult<WasmExecutionOutput> for WasmExecutionResult {
    fn get(self: Box<Self>) -> ExecResultVariant<WasmExecutionOutput> {
        match Self::get(*self) {
            ExecutionResult::WasmExecutionOutput(x) => ExecResultVariant::Completed(x),
            ExecutionResult::ResumeToken(rt) => ExecResultVariant::Interrupted(Box::new(rt)),
        }
    }
    fn try_select(self: Box<Self>) -> TrySelect<WasmExecutionOutput> {
        let f = |x: Box<dyn std::any::Any + 'static>| -> WasmExecutionOutput {
            let y = x
                .downcast::<WasmExecutionOutput>()
                .expect("Failed to downcast to RunnerOutput");
            *y
        };
        TrySelect::Channel(Box::new(self.output_receiver), Box::new(f))
    }
}

pub struct WasmExecutionInput {
    pub api_type: ApiType,
    pub system_state: SystemState,
    pub instructions_limit: NumInstructions,
    pub canister_memory_limit: NumBytes,
    pub canister_current_memory_usage: NumBytes,
    pub subnet_available_memory: SubnetAvailableMemory,
    pub compute_allocation: ComputeAllocation,
    pub func_ref: FuncRef,
    pub execution_state: ExecutionState,
    pub cycles_account_manager: Arc<CyclesAccountManager>,
}

pub struct WasmExecutionOutput {
    pub wasm_result: Result<Option<WasmResult>, HypervisorError>,
    pub num_instructions_left: NumInstructions,
    pub system_state: SystemState,
    pub execution_state: ExecutionState,
    pub instance_stats: InstanceStats,
}
pub struct InstanceRunResult {
    pub dirty_pages: Vec<PageIndex>,
    pub exported_globals: Vec<Global>,
}

/// Instance trait must be implemented by the wrapper of a concrete Wasm
/// executer to hide all it's dependencies and internal details of its instance.
pub trait Instance {
    /// Executes first exported method on an embedder instance, whose name
    /// consists of one of the prefixes and method_name.
    fn run(
        &mut self,
        api: &mut (dyn SystemApi + 'static),
        func_ref: FuncRef,
    ) -> HypervisorResult<InstanceRunResult>;

    /// Sets the amount of cycles for a method execution.
    fn set_num_instructions(&mut self, cycles: NumInstructions);

    /// Returns the amount of cycles left.
    fn get_num_instructions(&self) -> NumInstructions;

    /// Return the heap size.
    fn heap_size(&self) -> NumWasmPages;

    fn get_exported_globals(&self) -> Vec<Global>;

    /// Return the heap address. If the Instance does not contain any memory,
    /// the pointer is null.
    ///
    /// # Safety
    /// This function returns a pointer to Instance's memory. The pointer is
    /// only valid while the Instance object is kept alive.
    unsafe fn heap_addr(&self) -> *const u8;

    /// Returns execution statistics for this instance.  Note that
    /// stats must be available even if this instance trapped.
    fn get_stats(&self) -> InstanceStats;
}

pub trait Embedder: Sync {
    fn compile(
        &self,
        persistence_type: PersistenceType,
        wasm_binary: &BinaryEncodedWasm,
    ) -> HypervisorResult<EmbedderCache>;
    fn new_instance(
        &self,
        embedder_cache: &EmbedderCache,
        exported_globals: &[Global],
        heap_size: NumWasmPages,
        memory_creator: Option<Arc<CowMemoryCreator>>,
        memory_initializer: Option<PageMap>,
    ) -> Box<dyn Instance>;
}

pub trait LinearMemory {
    fn as_ptr(&self) -> *mut libc::c_void;

    fn grow_mem_to(&self, _new_size: u32) {}
}

pub trait ICMemoryCreator {
    type Mem: LinearMemory;

    fn new_memory(
        &self,
        mem_size: usize,
        guard_size: usize,
        instance_heap_offset: usize,
        min_pages: u32,
        max_pages: Option<u32>,
    ) -> Self::Mem;
}
