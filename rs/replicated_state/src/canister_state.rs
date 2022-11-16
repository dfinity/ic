pub mod execution_state;
pub(crate) mod queues;
pub mod system_state;
#[cfg(test)]
mod tests;

use crate::canister_state::queues::CanisterOutputQueuesIterator;
use crate::canister_state::system_state::{CanisterStatus, ExecutionTask, SystemState};
use crate::{InputQueueType, StateError};
pub use execution_state::{EmbedderCache, ExecutionState, ExportedFunctions, Global};
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::messages::CanisterInputMessage;
use ic_registry_subnet_type::SubnetType;
use ic_types::methods::SystemMethod;
use ic_types::time::UNIX_EPOCH;
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    methods::WasmMethod,
    AccumulatedPriority, CanisterId, ComputeAllocation, ExecutionRound, MemoryAllocation, NumBytes,
    PrincipalId, Time,
};
use ic_types::{LongExecutionMode, NumInstructions};
use phantom_newtype::AmountOf;
pub use queues::{CanisterQueues, DEFAULT_QUEUE_CAPACITY};
use std::collections::BTreeSet;
use std::convert::From;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
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
        self.scheduler_state.accumulated_priority =
            (self.scheduler_state.accumulated_priority.value()
                - self.scheduler_state.priority_credit.value())
            .into();
        self.scheduler_state.priority_credit = 0.into();
    }

    pub fn canister_id(&self) -> CanisterId {
        self.system_state.canister_id()
    }

    pub fn controllers(&self) -> &BTreeSet<PrincipalId> {
        &self.system_state.controllers
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

    /// See `SystemState::push_input` for documentation.
    ///
    /// `max_canister_memory_size` is the replica's configured maximum canister
    /// memory usage. The specific canister may have an explicit memory
    /// allocation, which would override this maximum. Based on the canister's
    /// specific memory limit we compute the canister's available memory and
    /// pass that to `SystemState::push_input()` (which doesn't have all the
    /// data necessary to compute it itself).
    ///
    /// The function is public as we push directly to the Canister state in
    /// `SchedulerImpl::induct_messages_on_same_subnet()`
    pub fn push_input(
        &mut self,
        msg: RequestOrResponse,
        max_canister_memory_size: NumBytes,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.system_state.push_input(
            msg,
            self.available_message_memory(max_canister_memory_size, own_subnet_type),
            subnet_available_memory,
            own_subnet_type,
            input_queue_type,
        )
    }

    /// Returns the memory available for canister messages based on
    ///  * the maximum canister memory size;
    ///  * the canister's memory allocation (overriding the former) if any; and
    ///  * the subnet type (accounting for execution and message memory usage on
    ///    application subnets; but only for messages and disregarding any
    ///    memory allocation on system subnets).
    fn available_message_memory(
        &self,
        max_canister_memory_size: NumBytes,
        own_subnet_type: SubnetType,
    ) -> i64 {
        if own_subnet_type == SubnetType::System {
            // For system subnets we ignore the canister allocation, if any;
            // and the execution memory usage; and always allow up to
            // `max_canister_memory_size` worth of messages.
            max_canister_memory_size.get() as i64 - self.system_state.memory_usage().get() as i64
        } else {
            // For application subnets allow execution plus messages to use up
            // to the canister's memory allocation, if any; or else
            // `max_canister_memory_size`.
            self.memory_limit(max_canister_memory_size).get() as i64
                - self.memory_usage(own_subnet_type).get() as i64
        }
    }

    /// See `SystemState::pop_input` for documentation.
    ///
    /// The function is public as we pop directly from the Canister state in
    /// `SchedulerImpl::execute_canisters_on_thread()`
    pub fn pop_input(&mut self) -> Option<CanisterInputMessage> {
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
            | (Some(ExecutionTask::PausedExecution(..)), _) => NextExecution::ContinueLong,
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
            | Some(ExecutionTask::PausedExecution(..))
            | Some(ExecutionTask::PausedInstallCode(..))
            | Some(ExecutionTask::AbortedInstallCode { .. }) => false,
        }
    }

    /// Returns true if the canister has a paused execution.
    pub fn has_paused_execution(&self) -> bool {
        match self.system_state.task_queue.front() {
            Some(ExecutionTask::PausedExecution(..)) => true,
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
            | Some(ExecutionTask::PausedExecution(..))
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
            | Some(ExecutionTask::PausedExecution(..))
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
    /// from `self` while respecting queue capacity; the canister's computed
    /// available memory; and subnet available memory.
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
        max_canister_memory_size: NumBytes,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) {
        self.system_state.induct_messages_to_self(
            self.available_message_memory(max_canister_memory_size, own_subnet_type),
            subnet_available_memory,
            own_subnet_type,
        )
    }

    pub fn into_parts(self) -> (Option<ExecutionState>, SystemState, SchedulerState) {
        (
            self.execution_state,
            self.system_state,
            self.scheduler_state,
        )
    }

    pub fn from_parts(
        execution_state: Option<ExecutionState>,
        system_state: SystemState,
        scheduler_state: SchedulerState,
    ) -> Self {
        Self {
            system_state,
            execution_state,
            scheduler_state,
        }
    }

    /// Checks the constraints that a canister should always respect.
    /// These invariants will be verified at the end of each execution round.
    pub fn check_invariants(
        &self,
        own_subnet_type: SubnetType,
        default_limit: NumBytes,
    ) -> Result<(), StateError> {
        let memory_used = self.memory_usage(own_subnet_type);
        let memory_limit = self.memory_limit(default_limit);

        if memory_used > memory_limit {
            return Err(StateError::InvariantBroken(format!(
                "Memory of canister {} exceeds the limit allowed: used {}, allowed {}",
                self.canister_id(),
                memory_used,
                memory_limit
            )));
        }

        let num_callbacks = self
            .system_state
            .call_context_manager()
            .map(|ccm| ccm.callbacks().len())
            .unwrap_or(0);
        let num_responses = self.system_state.queues().input_queues_response_count();
        let num_reservations = self.system_state.queues().input_queues_reservation_count();
        let is_callback_invariant_broken = if num_callbacks == num_reservations + num_responses {
            false
        } else if !self.has_paused_execution() && !self.has_aborted_execution() {
            true
        } else {
            // With a pending DTS execution, the response callback is accounted
            // in `num_callbacks` until the execution finishes. Note that there
            // can be at most one pending DTS execution per canister.
            num_callbacks - 1 != num_reservations + num_responses
        };
        if is_callback_invariant_broken {
            return Err(StateError::InvariantBroken(format!(
                "Canister {}: Number of callbacks ({}) is different than the accumulated number of reservations and responses ({})",
                self.canister_id(),
                num_callbacks,
                num_reservations + num_responses
            )));
        }

        Ok(())
    }

    /// The amount of memory currently being used by the canister.
    ///
    /// This only includes execution memory (heap, stable, globals, Wasm) for
    /// system subnets; and execution memory plus system state memory (canister
    /// messages) for application subnets.
    pub fn memory_usage(&self, own_subnet_type: SubnetType) -> NumBytes {
        self.memory_usage_impl(own_subnet_type != SubnetType::System)
    }

    /// Internal `memory_usage()` implementation that allows the caller to
    /// explicitly select whether message memory usage should be included.
    pub(crate) fn memory_usage_impl(&self, with_messages: bool) -> NumBytes {
        let message_memory_usage = if with_messages {
            self.system_state.memory_usage()
        } else {
            0.into()
        };
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.memory_usage())
            + message_memory_usage
    }

    /// Hack to get the dashboard templating working.
    pub fn memory_usage_ref(&self, own_subnet_type: &SubnetType) -> NumBytes {
        self.memory_usage(*own_subnet_type)
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
}

/// The result of `next_execution()` function.
/// Describes what the canister is going to execute next:
/// - `None`: the canister is idle.
/// - `StartNew`: the canister has a message or heartbeat to execute.
/// - `ContinueLong`: the canister has a long-running execution and will
///   continue it.
/// - `ContinueInstallCode`: the canister has a long-running execution of
/// `install_code` subnet message and will continue it.
#[derive(Clone, Copy, Debug, PartialEq)]
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
    use super::*;

    /// Exposes `CanisterState` internals for use in other crates' unit tests.
    pub trait CanisterStateTesting {
        /// Testing only: Publicly exposes `CanisterState::push_input()`.
        fn push_input(
            &mut self,
            msg: RequestOrResponse,
        ) -> Result<(), (StateError, RequestOrResponse)>;
    }

    impl CanisterStateTesting for CanisterState {
        fn push_input(
            &mut self,
            msg: RequestOrResponse,
        ) -> Result<(), (StateError, RequestOrResponse)> {
            (self as &mut CanisterState).push_input(
                msg,
                (i64::MAX as u64 / 2).into(),
                &mut (i64::MAX / 2),
                SubnetType::Application,
                InputQueueType::RemoteSubnet,
            )
        }
    }
}
