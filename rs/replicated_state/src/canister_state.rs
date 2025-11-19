pub mod execution_state;
pub(crate) mod queues;
pub mod system_state;
#[cfg(test)]
mod tests;

use crate::canister_state::execution_state::WasmExecutionMode;
use crate::canister_state::queues::CanisterOutputQueuesIterator;
use crate::canister_state::system_state::{ExecutionTask, SystemState};
use crate::{InputQueueType, StateError};
pub use execution_state::{EmbedderCache, ExecutionState, ExportedFunctions};
use ic_config::embedders::Config as HypervisorConfig;
use ic_interfaces::execution_environment::{
    MessageMemoryUsage, SubnetAvailableExecutionMemoryChange,
};
use ic_management_canister_types_private::{
    CanisterChangeDetails, CanisterChangeOrigin, CanisterStatusType, LogVisibilityV2,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::batch::TotalQueryStats;
use ic_types::methods::SystemMethod;
use ic_types::time::UNIX_EPOCH;
use ic_types::{
    AccumulatedPriority, CanisterId, CanisterLog, ComputeAllocation, ExecutionRound,
    MemoryAllocation, NumBytes, PrincipalId, Time,
    messages::{CanisterMessage, Ingress, Request, RequestOrResponse, Response},
    methods::WasmMethod,
};
use ic_types::{LongExecutionMode, NumInstructions};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use phantom_newtype::AmountOf;
pub use queues::{CanisterQueues, DEFAULT_QUEUE_CAPACITY, refunds::RefundPool};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use self::execution_state::NextScheduledMethod;

#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
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
#[derive(Clone, PartialEq, Debug, ValidateEq)]
pub struct CanisterState {
    /// See `SystemState` for documentation.
    #[validate_eq(CompareWithValidateEq)]
    pub system_state: SystemState,

    /// See `ExecutionState` for documentation.
    ///
    /// This may or may not exist depending on whether or not the canister has
    /// an actual wasm module. A valid canister is not required to contain a
    /// Wasm module. Canisters without Wasm modules can exist as a store of
    /// ICP; temporarily when they are being upgraded, etc.
    #[validate_eq(CompareWithValidateEq)]
    pub execution_state: Option<ExecutionState>,

    /// See `SchedulerState` for documentation.
    #[validate_eq(CompareWithValidateEq)]
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

    pub fn canister_id(&self) -> CanisterId {
        self.system_state.canister_id()
    }

    pub fn controllers(&self) -> &BTreeSet<PrincipalId> {
        &self.system_state.controllers
    }

    pub fn log_visibility(&self) -> &LogVisibilityV2 {
        &self.system_state.log_visibility
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
        subnet_available_guaranteed_response_memory: &mut i64,
        own_subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<bool, (StateError, RequestOrResponse)> {
        self.system_state.push_input(
            msg,
            subnet_available_guaranteed_response_memory,
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
            (Some(ExecutionTask::OnLowWasmMemory), _) => NextExecution::StartNew,
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
            | Some(ExecutionTask::OnLowWasmMemory)
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
            | Some(ExecutionTask::OnLowWasmMemory)
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
            | Some(ExecutionTask::OnLowWasmMemory)
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
            | Some(ExecutionTask::OnLowWasmMemory)
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
    pub fn output_into_iter(&mut self) -> CanisterOutputQueuesIterator<'_> {
        self.system_state.output_into_iter()
    }

    /// Unconditionally pushes an ingress message into the ingress pool of the
    /// canister.
    pub fn push_ingress(&mut self, msg: Ingress) {
        self.system_state.push_ingress(msg)
    }

    /// Inducts messages from the output queue to `self` into the input queue from
    /// `self` while respecting queue capacity and subnet's available guaranteed
    /// response memory.
    ///
    /// `subnet_available_guaranteed_response_memory` is updated to reflect the
    /// change in memory usage due to inducting any guaranteed response messages.
    pub fn induct_messages_to_self(
        &mut self,
        subnet_available_guaranteed_response_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) {
        self.system_state
            .induct_messages_to_self(subnet_available_guaranteed_response_memory, own_subnet_type)
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
    pub fn check_invariants(&self, config: &HypervisorConfig) -> Result<(), String> {
        if let Some(execution_state) = &self.execution_state {
            let wasm_memory_usage = execution_state.wasm_memory_usage();
            let wasm_memory_limit = match execution_state.wasm_execution_mode() {
                WasmExecutionMode::Wasm32 => config.max_wasm_memory_size,
                WasmExecutionMode::Wasm64 => config.max_wasm64_memory_size,
            };
            if wasm_memory_usage > wasm_memory_limit {
                return Err(format!(
                    "Invariant broken: Wasm memory of canister {} exceeds the limit allowed: used {}, allowed {}",
                    self.canister_id(),
                    wasm_memory_usage,
                    wasm_memory_limit
                ));
            }

            let stable_memory_usage = execution_state.stable_memory_usage();
            let stable_memory_limit = config.max_stable_memory_size;
            if stable_memory_usage > stable_memory_limit {
                return Err(format!(
                    "Invariant broken: Stable memory of canister {} exceeds the limit allowed: used {}, allowed {}",
                    self.canister_id(),
                    stable_memory_usage,
                    stable_memory_limit
                ));
            }
        }

        self.system_state.check_invariants()
    }

    /// The amount of memory currently being used by the canister.
    ///
    /// This includes execution memory (heap, stable, globals, Wasm),
    /// canister history memory, wasm chunk storage and snapshots that
    /// belong to this canister.
    ///
    /// This amount is used to periodically charge the canister for the memory
    /// resources it consumes and can be used to calculate the canister's
    /// idle cycles burn rate and freezing threshold in cycles.
    pub fn memory_usage(&self) -> NumBytes {
        self.execution_memory_usage()
            + self.canister_history_memory_usage()
            + self.wasm_chunk_store_memory_usage()
            + self.snapshots_memory_usage()
    }

    /// Returns the amount of Wasm memory currently used by the canister in bytes.
    pub fn wasm_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |es| es.wasm_memory_usage())
    }

    /// Returns the amount of stable memory currently used by the canister in bytes.
    pub fn stable_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.stable_memory_usage())
    }

    /// Returns the amount of memory currently used by global variables of the canister in bytes.
    pub fn global_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.global_memory_usage())
    }

    /// Returns the amount of memory currently used by the wasm binary.
    pub fn wasm_binary_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.wasm_binary_memory_usage())
    }

    /// Returns the amount of execution memory (heap, stable, globals, Wasm)
    /// currently used by the canister in bytes.
    pub fn execution_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |es| es.memory_usage())
    }

    /// Returns the amount of memory used by or reserved for guaranteed response and
    /// best-effort canister messages, in bytes.
    pub fn message_memory_usage(&self) -> MessageMemoryUsage {
        MessageMemoryUsage {
            guaranteed_response: self.system_state.guaranteed_response_message_memory_usage(),
            best_effort: self.system_state.best_effort_message_memory_usage(),
        }
    }

    /// Returns the amount of memory used by canisters that have custom Wasm
    /// sections defined.
    pub fn wasm_custom_sections_memory_usage(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |es| es.metadata.memory_usage())
    }

    /// Returns the amount of memory used by canister history in bytes.
    pub fn canister_history_memory_usage(&self) -> NumBytes {
        self.system_state.canister_history_memory_usage()
    }

    /// Returns the memory usage of the wasm chunk store in bytes.
    pub fn wasm_chunk_store_memory_usage(&self) -> NumBytes {
        self.system_state.wasm_chunk_store.memory_usage()
    }

    pub fn snapshots_memory_usage(&self) -> NumBytes {
        self.system_state.snapshots_memory_usage
    }

    /// Returns the snapshot size estimation in bytes based on the current canister's state.
    ///
    /// It represents the memory usage of a snapshot that would be created at the time of the call
    /// and would return a different value if the canister's state changes after the call.
    pub fn snapshot_size_bytes(&self) -> NumBytes {
        let execution_usage = self
            .execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |execution_state| {
                execution_state.memory_usage_in_snapshot()
            });

        execution_usage
            + self.wasm_chunk_store_memory_usage()
            + NumBytes::new(self.system_state.certified_data.len() as u64)
    }

    /// Returns the current memory allocation of the canister.
    pub fn memory_allocation(&self) -> MemoryAllocation {
        self.system_state.memory_allocation
    }

    /// Returns the actual number of allocated bytes for the canister:
    /// the maximum of its memory allocation and memory usage.
    pub fn memory_allocated_bytes(&self) -> NumBytes {
        self.memory_allocation()
            .allocated_bytes(self.memory_usage())
    }

    /// Returns the current Wasm memory threshold of the canister.
    pub fn wasm_memory_threshold(&self) -> NumBytes {
        self.system_state.wasm_memory_threshold
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

    /// Returns true if the canister exports the `canister_on_low_wasm_memory`
    /// system method.
    pub fn exports_on_low_wasm_memory(&self) -> bool {
        self.exports_method(&WasmMethod::System(SystemMethod::CanisterOnLowWasmMemory))
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
        self.system_state.status()
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
            system_state,
            execution_state: _,
            scheduler_state: _,
        } = self;

        system_state.drop_in_progress_management_calls_after_split();
    }

    /// Clears the canister log.
    pub fn clear_log(&mut self) {
        self.system_state.canister_log.clear();
    }

    /// Sets the new canister log.
    pub fn set_log(&mut self, other: CanisterLog) {
        self.system_state.canister_log = other;
    }

    /// Returns the cumulative amount of heap delta represented by this canister's state.
    /// This is the amount that will need to be persisted during the next
    /// checkpoint and counts the delta since previous checkpoint.
    pub fn heap_delta(&self) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::new(0), |es| es.heap_delta())
            + self.system_state.wasm_chunk_store.heap_delta()
    }

    /// Updates status of `OnLowWasmMemory` hook.
    pub fn update_on_low_wasm_memory_hook_condition(&mut self) {
        self.system_state
            .update_on_low_wasm_memory_hook_status(self.wasm_memory_usage());
    }

    /// Returns the `OnLowWasmMemory` hook status without updating the `task_queue`.
    pub fn is_low_wasm_memory_hook_condition_satisfied(&self) -> bool {
        self.system_state
            .is_low_wasm_memory_hook_condition_satisfied(self.wasm_memory_usage())
    }

    /// Adds a canister change to canister history and returns the change
    /// of subnet available execution memory due to updating canister history.
    #[must_use]
    pub fn add_canister_change(
        &mut self,
        timestamp_nanos: Time,
        change_origin: CanisterChangeOrigin,
        change_details: CanisterChangeDetails,
    ) -> SubnetAvailableExecutionMemoryChange {
        let old_allocated_bytes = self.memory_allocated_bytes();
        self.system_state
            .add_canister_change(timestamp_nanos, change_origin, change_details);
        let new_allocated_bytes = self.memory_allocated_bytes();
        if new_allocated_bytes >= old_allocated_bytes {
            let allocated_bytes = new_allocated_bytes - old_allocated_bytes;
            SubnetAvailableExecutionMemoryChange::Allocated(allocated_bytes)
        } else {
            let deallocated_bytes = old_allocated_bytes - new_allocated_bytes;
            SubnetAvailableExecutionMemoryChange::Deallocated(deallocated_bytes)
        }
    }
}

/// The result of `next_execution()` function.
/// Describes what the canister is going to execute next:
/// - `None`: the canister is idle.
/// - `StartNew`: the canister has a message or heartbeat to execute.
/// - `ContinueLong`: the canister has a long-running execution and will
///   continue it.
/// - `ContinueInstallCode`: the canister has a long-running execution of
///   `install_code` subnet message and will continue it.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
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

pub fn num_bytes_try_from(pages: NumWasmPages) -> Result<NumBytes, String> {
    let (bytes, overflow) = pages.get().overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
    if overflow {
        return Err("Could not convert from wasm pages to number of bytes".to_string());
    }
    Ok(NumBytes::new(bytes as u64))
}

pub mod testing {
    pub use super::queues::testing::{CanisterQueuesTesting, new_canister_output_queues_for_test};
}
