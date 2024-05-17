pub mod execution_state;
pub(crate) mod queues;
pub mod system_state;
#[cfg(test)]
mod tests;

use crate::canister_state::queues::CanisterOutputQueuesIterator;
use crate::canister_state::system_state::{CanisterStatus, ExecutionTask, SystemState};
use crate::{InputQueueType, StateError};
pub use execution_state::{EmbedderCache, ExecutionState, ExportedFunctions, Global};
use ic_management_canister_types::{CanisterStatusType, LogVisibility};
use ic_registry_subnet_type::SubnetType;
use ic_types::batch::TotalQueryStats;
use ic_types::methods::SystemMethod;
use ic_types::time::UNIX_EPOCH;
use ic_types::{
    messages::{CanisterMessage, Ingress, Request, RequestOrResponse, Response},
    methods::WasmMethod,
    AccumulatedPriority, CanisterId, CanisterLog, ComputeAllocation, ExecutionRound,
    MemoryAllocation, NumBytes, PrincipalId, Time,
};
use ic_types::{LongExecutionMode, NumInstructions};
use phantom_newtype::AmountOf;
pub use queues::{CanisterQueues, DEFAULT_QUEUE_CAPACITY};
use std::collections::BTreeSet;
use std::convert::From;
use std::sync::Arc;
use std::time::Duration;

use self::execution_state::NextScheduledMethod;

#[derive(Clone, Debug, PartialEq, Eq)]
/// State maintained by the scheduler.
pub struct SchedulerState {
    /// The last full round that a canister got the chance to execute. This
    /// means that the canister was given the first pulse in the round or
    /// consumed its input queue.
    pub last_full_execution_round: ExecutionRound,

    /// A canister's compute allocation. A higher compute allocation corresponds
    /// to higher priority in scheduling.
    pub compute_allocation: ComputeAllocation,

    /// Keeps the current priority of this canister, accumulated during the past
    /// rounds. In the scheduler analysis documentation, this value is the entry
    /// in the vector d that corresponds to this canister.
    pub accumulated_priority: AccumulatedPriority,

    /// Keeps the current priority credit of this Canister, accumulated during the
    /// long execution.
    ///
    /// During the long execution, the Canister is temporarily credited with priority
    /// to slightly boost the long execution priority. Only when the long execution
    /// is done, then the `accumulated_priority` is decreased by the `priority_credit`.
    /// TODO(RUN-305): store priority credit and long execution mode across checkpoints
    pub priority_credit: AccumulatedPriority,

    /// Long execution mode: Opportunistic (default) or Prioritized
    pub long_execution_mode: LongExecutionMode,

    /// The amount of heap delta debit. The canister skips execution of update
    /// messages if this value is non-zero.
    pub heap_delta_debit: NumBytes,

    /// The amount of install_code instruction debit. The canister rejects
    /// install_code messages if this value is non-zero.
    pub install_code_debit: NumInstructions,

    /// The last time when the canister was charged for the resource allocations.
    ///
    /// Charging for compute and storage is done periodically, so this is
    /// needed to calculate how much time should be considered when charging
    /// occurs.
    pub time_of_last_allocation_charge: Time,

    /// Query statistics.
    ///
    /// As queries are executed in non-deterministic fashion state modifications are
    /// disallowed during the query call.
    /// Instead, each node collects statistics about query execution locally and periodically,
    /// once per "epoch", sends those to other machines as part of consensus blocks.
    /// At the end of an "epoch", each node deterministically aggregates all those partial
    /// query statistics received from consensus blocks and mutates these values.
    pub total_query_stats: TotalQueryStats,
}

impl Default for SchedulerState {
    fn default() -> Self {
        Self {
            last_full_execution_round: 0.into(),
            compute_allocation: ComputeAllocation::default(),
            accumulated_priority: AccumulatedPriority::default(),
            priority_credit: AccumulatedPriority::default(),
            long_execution_mode: LongExecutionMode::default(),
            heap_delta_debit: 0.into(),
            install_code_debit: 0.into(),
            time_of_last_allocation_charge: UNIX_EPOCH,
            total_query_stats: TotalQueryStats::default(),
        }
    }
}

impl SchedulerState {
    pub fn new(time: Time) -> Self {
        Self {
            time_of_last_allocation_charge: time,
            ..Default::default()
        }
    }
}

/// The full state of a single canister.
#[derive(Clone, Debug, PartialEq)]
pub struct CanisterState {
    /// See `SystemState` for documentation.
    pub system_state: SystemState,

    /// See `ExecutionState` for documentation.
    ///
    /// This may or may not exist depending on whether or not the canister has
    /// an actual wasm module. A valid canister is not required to contain a
    /// Wasm module. Canisters without Wasm modules can exist as a store of
    /// ICP; temporarily when they are being upgraded, etc.
    pub execution_state: Option<ExecutionState>,

    /// See `SchedulerState` for documentation.
    pub scheduler_state: SchedulerState,
}

impl CanisterState {
    pub fn new(
        system_state: SystemState,
        execution_state: Option<ExecutionState>,
        scheduler_state: SchedulerState,
    ) -> Self {
        Self {
            system_state,
            execution_state,
            scheduler_state,
        }
    }

    /// Apply priority credit
    pub fn apply_priority_credit(&mut self) {
        self.scheduler_state.accumulated_priority -=
            std::mem::take(&mut self.scheduler_state.priority_credit);
    }

    pub fn canister_id(&self) -> CanisterId {
        self.system_state.canister_id()
    }

    pub fn controllers(&self) -> &BTreeSet<PrincipalId> {
        &self.system_state.controllers
    }

    pub fn log_visibility(&self) -> LogVisibility {
        self.system_state.log_visibility
    }

    /// Returns the difference in time since the canister was last charged for resource allocations.
    pub fn duration_since_last_allocation_charge(&self, current_time: Time) -> Duration {
        debug_assert!(
            current_time >= self.scheduler_state.time_of_last_allocation_charge,
            "Expect the time of the current batch to be >= the time of the previous batch"
        );

        Duration::from_nanos(
            current_time.as_nanos_since_unix_epoch().saturating_sub(
                self.scheduler_state
                    .time_of_last_allocation_charge
                    .as_nanos_since_unix_epoch(),
            ),
        )
    }

    pub fn new_local_snapshot_id(&mut self) -> u64 {
        self.system_state.new_local_snapshot_id()
    }

    /// See `SystemState::push_input` for documentation.
    ///
    /// The function is public as we push directly to the Canister state in
    /// `SchedulerImpl::induct_messages_on_same_subnet()`
    pub fn push_input(
        &mut self,
        msg: RequestOrResponse,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.system_state.push_input(
            msg,
            subnet_available_memory,
            own_subnet_type,
            input_queue_type,
        )
    }

    /// See `SystemState::pop_input` for documentation.
    ///
    /// The function is public as we pop directly from the Canister state in
    /// `SchedulerImpl::execute_canisters_on_thread()`
    pub fn pop_input(&mut self) -> Option<CanisterMessage> {
        self.system_state.pop_input()
    }

    /// See `SystemState::has_input` for documentation.
    pub fn has_input(&self) -> bool {
        self.system_state.has_input()
    }

    /// Returns what the canister is going to execute next.
    pub fn next_execution(&self) -> NextExecution {
        let next_task = self.system_state.task_queue.front();
        match (next_task, self.has_input()) {
            (None, false) => NextExecution::None,
            (None, true) => NextExecution::StartNew,
            (Some(ExecutionTask::Heartbeat), _) => NextExecution::StartNew,
            (Some(ExecutionTask::GlobalTimer), _) => NextExecution::StartNew,
            (Some(ExecutionTask::AbortedExecution { .. }), _)
            | (Some(ExecutionTask::PausedExecution { .. }), _) => NextExecution::ContinueLong,
            (Some(ExecutionTask::AbortedInstallCode { .. }), _)
            | (Some(ExecutionTask::PausedInstallCode(..)), _) => NextExecution::ContinueInstallCode,
        }
    }

    /// Returns a reference to the next task in the task queue if any.
    pub fn next_task(&self) -> Option<&ExecutionTask> {
        self.system_state.task_queue.front()
    }

    /// Returns true if the canister has an aborted execution.
    pub fn has_aborted_execution(&self) -> bool {
        match self.system_state.task_queue.front() {
            Some(ExecutionTask::AbortedExecution { .. }) => true,
            None
            | Some(ExecutionTask::Heartbeat)
            | Some(ExecutionTask::GlobalTimer)
            | Some(ExecutionTask::PausedExecution { .. })
            | Some(ExecutionTask::PausedInstallCode(..))
            | Some(ExecutionTask::AbortedInstallCode { .. }) => false,
        }
    }

    /// Returns true if the canister has a paused execution.
    pub fn has_paused_execution(&self) -> bool {
        match self.system_state.task_queue.front() {
            Some(ExecutionTask::PausedExecution { .. }) => true,
            None
            | Some(ExecutionTask::Heartbeat)
            | Some(ExecutionTask::GlobalTimer)
            | Some(ExecutionTask::PausedInstallCode(..))
            | Some(ExecutionTask::AbortedExecution { .. })
            | Some(ExecutionTask::AbortedInstallCode { .. }) => false,
        }
    }

    /// Returns true if the canister has a paused install code.
    pub fn has_paused_install_code(&self) -> bool {
        match self.system_state.task_queue.front() {
            Some(ExecutionTask::PausedInstallCode(..)) => true,
            None
            | Some(ExecutionTask::Heartbeat)
            | Some(ExecutionTask::GlobalTimer)
            | Some(ExecutionTask::PausedExecution { .. })
            | Some(ExecutionTask::AbortedExecution { .. })
            | Some(ExecutionTask::AbortedInstallCode { .. }) => false,
        }
    }

    /// Returns true if the canister has an aborted install code.
    pub fn has_aborted_install_code(&self) -> bool {
        match self.system_state.task_queue.front() {
            Some(ExecutionTask::AbortedInstallCode { .. }) => true,
            None
            | Some(ExecutionTask::Heartbeat)
            | Some(ExecutionTask::GlobalTimer)
            | Some(ExecutionTask::PausedExecution { .. })
            | Some(ExecutionTask::PausedInstallCode(..))
            | Some(ExecutionTask::AbortedExecution { .. }) => false,
        }
    }

    /// Returns true if there is at least one message in the canister's output
    /// queues, false otherwise.
    pub fn has_output(&self) -> bool {
        self.system_state.queues().has_output()
    }

    /// See `SystemState::push_output_request` for documentation.
    pub fn push_output_request(
        &mut self,
        msg: Arc<Request>,
        time: Time,
    ) -> Result<(), (StateError, Arc<Request>)> {
        self.system_state.push_output_request(msg, time)
    }

    /// See `SystemState::push_output_response` for documentation.
    pub fn push_output_response(&mut self, msg: Arc<Response>) {
        self.system_state.push_output_response(msg)
    }

    /// Returns an iterator that loops over the canister's output queues,
    /// popping one message at a time from each in a round robin fashion. The
    /// iterator consumes all popped messages.
    pub fn output_into_iter(&mut self) -> CanisterOutputQueuesIterator {
        self.system_state.output_into_iter(self.canister_id())
    }

    /// Unconditionally pushes an ingress message into the ingress pool of the
    /// canister.
    pub fn push_ingress(&mut self, msg: Ingress) {
        self.system_state.push_ingress(msg)
    }

    /// Inducts messages from the output queue to `self` into the input queue
    /// from `self` while respecting queue capacity and subnet available memory.
    ///
    /// `max_canister_memory_size` is the replica's configured maximum canister
    /// memory usage. The specific canister may have an explicit memory
    /// allocation, which would override this maximum. Based on the canister's
    /// specific memory limit we compute the canister's available memory and
    /// pass that to `SystemState::induct_messages_to_self()` (which doesn't
    /// have all the data necessary to compute it itself).
    ///
    /// `subnet_available_memory` is updated to reflect the change in memory
    /// usage due to inducting the messages.
    pub fn induct_messages_to_self(
        &mut self,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) {
        self.system_state
            .induct_messages_to_self(subnet_available_memory, own_subnet_type)
    }

    pub fn into_parts(self) -> (Option<ExecutionState>, SystemState, SchedulerState) {
        (
            self.execution_state,
            self.system_state,
            self.scheduler_state,
        )
    }

    /// Checks the constraints that a canister should always respect.
    /// These invariants will be verified at the end of each execution round.
    pub fn check_invariants(&self, default_limit: NumBytes) -> Result<(), StateError> {
        let memory_used = self.memory_usage();
        let memory_limit = self.memory_limit(default_limit);

        if memory_used > memory_limit {
            return Err(StateError::InvariantBroken(format!(
                "Memory of canister {} exceeds the limit allowed: used {}, allowed {}",
                self.canister_id(),
                memory_used,
                memory_limit
            )));
        }

        self.system_state.check_invariants()
    }

    /// The amount of memory currently being used by the canister.
    ///
    /// This only includes execution memory (heap, stable, globals, Wasm),
    /// canister history memory and wasm chunk storage.
    pub fn memory_usage(&self) -> NumBytes {
        self.execution_memory_usage()
            + self.canister_history_memory_usage()
            + self.wasm_chunk_store_memory_usage()
    }

    /// Returns the amount of execution memory (heap, stable, globals, Wasm)
    /// currently used by the canister in bytes.
    pub fn execution_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.memory_usage())
    }

    /// Returns the amount of canister message memory used by the canister in bytes.
    pub fn message_memory_usage(&self) -> NumBytes {
        self.system_state.message_memory_usage()
    }

    /// Returns the amount of memory used by canisters that have custom Wasm
    /// sections defined.
    pub fn wasm_custom_sections_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.metadata.memory_usage())
    }

    /// Returns the amount of memory used by canister history in bytes.
    pub fn canister_history_memory_usage(&self) -> NumBytes {
        self.system_state.canister_history_memory_usage()
    }

    /// Returns the memory usage of the wasm chunk store in bytes.
    pub(super) fn wasm_chunk_store_memory_usage(&self) -> NumBytes {
        self.system_state.wasm_chunk_store.memory_usage()
    }

    /// Returns the memory usage of a snapshot created based on the current canister's state.
    pub fn snapshot_memory_usage(&self) -> NumBytes {
        let execution_usage = self
            .execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |execution_snapshot| {
                execution_snapshot.memory_usage()
            });

        execution_usage
            + self.wasm_chunk_store_memory_usage()
            + NumBytes::from(self.system_state.certified_data.len() as u64)
    }

    /// Sets the (transient) size in bytes of responses from this canister
    /// routed into streams and not yet garbage collected.
    pub(super) fn set_stream_responses_size_bytes(&mut self, size_bytes: usize) {
        self.system_state
            .set_stream_responses_size_bytes(size_bytes);
    }

    /// Returns the current memory allocation of the canister.
    pub fn memory_allocation(&self) -> MemoryAllocation {
        self.system_state.memory_allocation
    }

    /// Returns the canister's memory limit: its reservation, if set; else the
    /// provided `default_limit`.
    pub fn memory_limit(&self, default_limit: NumBytes) -> NumBytes {
        match self.memory_allocation() {
            MemoryAllocation::Reserved(bytes) => bytes,
            MemoryAllocation::BestEffort => default_limit,
        }
    }

    /// Returns the Wasm memory limit from the canister settings.
    pub fn wasm_memory_limit(&self) -> Option<NumBytes> {
        self.system_state.wasm_memory_limit
    }

    /// Returns the current compute allocation for the canister.
    pub fn compute_allocation(&self) -> ComputeAllocation {
        self.scheduler_state.compute_allocation
    }

    /// Returns true if the canister exports the `canister_heartbeat` system
    /// method.
    pub fn exports_heartbeat_method(&self) -> bool {
        self.exports_method(&WasmMethod::System(SystemMethod::CanisterHeartbeat))
    }

    /// Returns true if the canister exports the `canister_global_timer`
    /// system method.
    pub fn exports_global_timer_method(&self) -> bool {
        self.exports_method(&WasmMethod::System(SystemMethod::CanisterGlobalTimer))
    }

    /// Returns true if the canister exports the given Wasm method.
    pub fn exports_method(&self, method: &WasmMethod) -> bool {
        match &self.execution_state {
            Some(execution_state) => execution_state.exports_method(method),
            None => false,
        }
    }

    /// Returns the number of global variables in the Wasm module.
    pub fn num_wasm_globals(&self) -> usize {
        match &self.execution_state {
            Some(execution_state) => execution_state.num_wasm_globals(),
            None => 0,
        }
    }

    pub fn status(&self) -> CanisterStatusType {
        match self.system_state.status {
            CanisterStatus::Running { .. } => CanisterStatusType::Running,
            CanisterStatus::Stopping { .. } => CanisterStatusType::Stopping,
            CanisterStatus::Stopped { .. } => CanisterStatusType::Stopped,
        }
    }

    /// Returns next scheduled method.
    pub fn get_next_scheduled_method(&self) -> NextScheduledMethod {
        self.execution_state.as_ref().map_or_else(
            || NextScheduledMethod::Message,
            |execution_state| execution_state.next_scheduled_method,
        )
    }

    /// Increments next scheduled method.
    pub fn inc_next_scheduled_method(&mut self) {
        if let Some(execution_state) = self.execution_state.as_mut() {
            execution_state.next_scheduled_method.inc();
        }
    }

    /// Silently discards in-progress subnet messages being executed by the
    /// canister, in the second phase of a subnet split. This should only be called
    /// on canisters that have migrated to a new subnet (*subnet B*), which does not
    /// have a matching call context.
    ///
    /// The other subnet (which must be *subnet A'*), produces reject responses (for
    /// calls originating from canisters); and fails ingress messages (for calls
    /// originating from ingress messages); for the matching subnet calls. This is
    /// the only way to ensure consistency for messages that would otherwise be
    /// executing on one subnet, but for which a response may only be produced by
    /// another subnet.
    pub fn drop_in_progress_management_calls_after_split(&mut self) {
        // Destructure `self` in order for the compiler to enforce an explicit decision
        // whenever new fields are added.
        //
        // (!) DO NOT USE THE ".." WILDCARD, THIS SERVES THE SAME FUNCTION AS a `match`!
        let CanisterState {
            ref mut system_state,
            execution_state: _,
            scheduler_state: _,
        } = self;

        // Remove aborted install code task.
        system_state.task_queue.retain(|task| match task {
            ExecutionTask::AbortedInstallCode { .. } => false,
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(_)
            | ExecutionTask::AbortedExecution { .. } => true,
        });

        // Roll back `Stopping` canister states to `Running` and drop all their stop
        // contexts (the calls corresponding to the dropped stop contexts will be
        // rejected by subnet A').
        match &system_state.status {
            CanisterStatus::Running { .. } | CanisterStatus::Stopped => {}
            CanisterStatus::Stopping {
                call_context_manager,
                ..
            } => {
                system_state.status = CanisterStatus::Running {
                    call_context_manager: call_context_manager.clone(),
                }
            }
        }
    }

    /// Appends the given log to the canister log.
    pub fn append_log(&mut self, other: &mut CanisterLog) {
        self.system_state.canister_log.append(other);
    }

    /// Clears the canister log.
    pub fn clear_log(&mut self) {
        self.system_state.canister_log.clear();
    }

    /// Sets the new canister log.
    pub fn set_log(&mut self, other: CanisterLog) {
        self.system_state.canister_log = other;
    }
}

/// The result of `next_execution()` function.
/// Describes what the canister is going to execute next:
/// - `None`: the canister is idle.
/// - `StartNew`: the canister has a message or heartbeat to execute.
/// - `ContinueLong`: the canister has a long-running execution and will
///   continue it.
/// - `ContinueInstallCode`: the canister has a long-running execution of
/// `install_code` subnet message and will continue it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextExecution {
    None,
    StartNew,
    ContinueLong,
    ContinueInstallCode,
}

pub struct NumWasmPagesTag;
/// Count of number of Wasm Pages (which can be of different size than host
/// page).
pub type NumWasmPages = AmountOf<NumWasmPagesTag, usize>;

pub const WASM_PAGE_SIZE_IN_BYTES: usize = 64 * 1024; // 64KB

/// A session is represented by an array of bytes and a monotonic
/// offset and is unique for each execution.
pub type SessionNonce = ([u8; 32], u64);

pub fn num_bytes_try_from(pages: NumWasmPages) -> Result<NumBytes, String> {
    let (bytes, overflow) = pages.get().overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
    if overflow {
        return Err("Could not convert from wasm pages to number of bytes".to_string());
    }
    Ok(NumBytes::from(bytes as u64))
}

pub mod testing {
    pub use super::queues::testing::{new_canister_queues_for_test, CanisterQueuesTesting};
}
