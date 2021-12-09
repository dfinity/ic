pub mod execution_state;
mod queues;
pub mod system_state;
#[cfg(test)]
mod tests;

use crate::canister_state::queues::CanisterOutputQueuesIterator;
use crate::canister_state::system_state::{CanisterStatus, SystemState};
use crate::StateError;
pub use execution_state::{EmbedderCache, ExecutionState, ExportedFunctions, Global};
use ic_interfaces::messages::CanisterInputMessage;
use ic_registry_subnet_type::SubnetType;
use ic_types::methods::SystemMethod;
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    methods::WasmMethod,
    AccumulatedPriority, CanisterId, CanisterStatusType, ComputeAllocation, ExecutionRound,
    MemoryAllocation, NumBytes, PrincipalId, QueueIndex,
};
use phantom_newtype::AmountOf;
pub use queues::{CanisterQueues, DEFAULT_QUEUE_CAPACITY, QUEUE_INDEX_NONE};
use std::collections::BTreeSet;
use std::convert::From;

/// Feature flag controlling whether in-flight canister messages are counted
/// against and limited by a canister's available memory.
///
/// TODO(MR-83) Remove when the feature is deemed stable.
pub const ENFORCE_MESSAGE_MEMORY_USAGE: bool = true;

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

    /// The amount of heap delta debit left from the canister's last full
    /// execution round.
    pub heap_delta_debit: NumBytes,
}

impl Default for SchedulerState {
    fn default() -> Self {
        Self {
            last_full_execution_round: ExecutionRound::from(0),
            compute_allocation: ComputeAllocation::default(),
            accumulated_priority: AccumulatedPriority::default(),
            heap_delta_debit: NumBytes::from(0),
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

    pub fn canister_id(&self) -> CanisterId {
        self.system_state.canister_id()
    }

    pub fn controllers(&self) -> &BTreeSet<PrincipalId> {
        &self.system_state.controllers
    }

    /// See `SystemState::push_input` for documentation.
    ///
    /// `max_canister_memory_size` is the replica's configured maximum canister
    /// memory usage. The specific canister may have an explicit memory
    /// allocation, which would override this maximum. Based on the canister's
    /// specific memory limit we compute the canister's available memory and
    /// pass that to `SystemState::push_input()` (which doesn't have all the
    /// data necessary to compute it itself).
    pub fn push_input(
        &mut self,
        index: QueueIndex,
        msg: RequestOrResponse,
        max_canister_memory_size: NumBytes,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        let canister_available_memory = self.memory_limit(max_canister_memory_size).get() as i64
            - self.memory_usage(own_subnet_type).get() as i64;
        self.system_state.push_input(
            index,
            msg,
            canister_available_memory,
            subnet_available_memory,
            own_subnet_type,
        )
    }

    /// See `SystemState::pop_input` for documentation.
    pub fn pop_input(&mut self) -> Option<CanisterInputMessage> {
        self.system_state.pop_input()
    }

    /// See `SystemState::has_input` for documentation.
    pub fn has_input(&self) -> bool {
        self.system_state.has_input()
    }

    /// Returns true if there is at least one message in the canister's output
    /// queues, false otherwise.
    pub fn has_output(&self) -> bool {
        self.system_state.queues().has_output()
    }

    /// See `SystemState::push_output_request` for documentation.
    pub fn push_output_request(&mut self, msg: Request) -> Result<(), (StateError, Request)> {
        self.system_state.push_output_request(msg)
    }

    /// See `SystemState::push_output_response` for documentation.
    pub fn push_output_response(&mut self, msg: Response) {
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
        let canister_available_memory = self.memory_limit(max_canister_memory_size).get() as i64
            - self.memory_usage(own_subnet_type).get() as i64;
        self.system_state.induct_messages_to_self(
            canister_available_memory,
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

    /// The amount of memory currently being used by the canister.
    pub fn memory_usage(&self, own_subnet_type: SubnetType) -> NumBytes {
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.memory_usage())
            + self.system_state.memory_usage(own_subnet_type)
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
        match &self.execution_state {
            Some(execution_state) => {
                execution_state.exports_method(&WasmMethod::System(SystemMethod::CanisterHeartbeat))
            }
            None => false,
        }
    }

    /// Returns true if the canister contains an exported query method with the
    /// name provided, false otherwise.
    pub fn exports_query_method(&self, method_name: String) -> bool {
        match &self.execution_state {
            Some(execution_state) => {
                execution_state.exports_method(&WasmMethod::Query(method_name))
            }
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
            index: QueueIndex,
            msg: RequestOrResponse,
        ) -> Result<(), (StateError, RequestOrResponse)>;
    }

    impl CanisterStateTesting for CanisterState {
        fn push_input(
            &mut self,
            index: QueueIndex,
            msg: RequestOrResponse,
        ) -> Result<(), (StateError, RequestOrResponse)> {
            (self as &mut CanisterState).push_input(
                index,
                msg,
                (i64::MAX as u64 / 2).into(),
                &mut (i64::MAX / 2),
                SubnetType::Application,
            )
        }
    }
}
