pub mod execution_state;
mod queues;
pub mod system_state;
#[cfg(test)]
mod tests;

use crate::canister_state::system_state::{CanisterStatus, SystemState};
use crate::StateError;
pub use execution_state::{EmbedderCache, ExecutionState, ExportedFunctions, Global};
use ic_interfaces::messages::CanisterInputMessage;
use ic_types::messages::MAX_RESPONSE_COUNT_BYTES;
use ic_types::methods::SystemMethod;
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    methods::WasmMethod,
    xnet::QueueId,
    AccumulatedPriority, CanisterId, CanisterStatusType, ComputeAllocation, ExecutionRound,
    MemoryAllocation, NumBytes, PrincipalId, QueueIndex,
};
use phantom_newtype::AmountOf;
pub use queues::{CanisterQueues, QUEUE_INDEX_NONE};
use std::collections::BTreeSet;
use std::convert::From;

pub const ENFORCE_MESSAGE_MEMORY_USAGE: bool = false;

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
    /// DFNs; temporarily when they are being upgraded, etc.
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
    pub fn push_input(
        &mut self,
        index: QueueIndex,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        self.system_state.push_input(index, msg)
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

    /// Unconditionally pushes an ingress message into the ingress pool of the
    /// canister.
    pub fn push_ingress(&mut self, msg: Ingress) {
        self.system_state.push_ingress(msg)
    }

    /// See `CanisterQueues::output_into_iter` for documentation.
    pub fn output_into_iter(
        &mut self,
    ) -> impl std::iter::Iterator<Item = (QueueId, QueueIndex, RequestOrResponse)> + '_ {
        let canister_id = self.system_state.canister_id;
        self.system_state.output_into_iter(canister_id)
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
    pub fn memory_usage(&self) -> NumBytes {
        let mut memory_usage = self
            .execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.memory_usage())
            + self.system_state.memory_usage();

        if ENFORCE_MESSAGE_MEMORY_USAGE {
            let queues = self.system_state.queues();
            let message_memory_usage =
                queues.responses_size_bytes() + queues.reserved_slots() * MAX_RESPONSE_COUNT_BYTES;
            memory_usage += (message_memory_usage as u64).into();
        }

        memory_usage
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
pub type NumWasmPages = AmountOf<NumWasmPagesTag, u32>;

/// Number of Wasm Pages (which can be of different size than host page).
///
/// Note: Allows for representing larger number of wasm pages, e.g. to support
/// 64 bit memories.
pub type NumWasmPages64 = AmountOf<NumWasmPagesTag, u64>;

const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024; // 64KB

/// A session is represented by an array of bytes and a monotonic
/// offset and is unique for each execution.
pub type SessionNonce = ([u8; 32], u64);

pub fn num_bytes_from(pages: NumWasmPages) -> NumBytes {
    NumBytes::from(pages.get() as u64 * WASM_PAGE_SIZE_IN_BYTES)
}

pub fn num_bytes_try_from64(pages: NumWasmPages64) -> Result<NumBytes, String> {
    let (bytes, overflow) = pages.get().overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
    if overflow {
        return Err("Could not convert from wasm pages to number of bytes".to_string());
    }
    Ok(NumBytes::from(bytes))
}

pub mod testing {
    use ic_types::{messages::RequestOrResponse, QueueIndex};

    use crate::{CanisterState, StateError};

    pub use super::queues::testing::CanisterQueuesTesting;

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
            (self as &mut CanisterState).push_input(index, msg)
        }
    }
}
