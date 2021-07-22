pub mod execution_state;
mod queues;
pub mod system_state;

use crate::canister_state::system_state::{CanisterStatus, SystemState};
use crate::StateError;
pub use execution_state::{EmbedderCache, ExecutionState, ExportedFunctions, Global};
use ic_interfaces::messages::CanisterInputMessage;
use ic_types::methods::SystemMethod;
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response},
    methods::WasmMethod,
    xnet::QueueId,
    AccumulatedPriority, CanisterId, CanisterStatusType, ComputeAllocation, ExecutionRound,
    NumBytes, PrincipalId, QueueIndex,
};
use phantom_newtype::AmountOf;
pub use queues::{CanisterQueues, QUEUE_INDEX_NONE};
use std::collections::BTreeSet;
use std::convert::From;

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
}

impl Default for SchedulerState {
    fn default() -> Self {
        Self {
            last_full_execution_round: ExecutionRound::from(0),
            compute_allocation: ComputeAllocation::default(),
            accumulated_priority: AccumulatedPriority::default(),
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
    ///
    /// Warning! this is only exposed for test purposes and should not be used
    /// outside of this crate.
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
        self.system_state.queues.has_output()
    }

    /// See `SystemState::push_output_request` for documentation.
    pub fn push_output_request(&mut self, msg: Request) -> Result<(), (StateError, Request)> {
        self.system_state.push_output_request(msg)
    }

    /// See `SystemState::push_output_response` for documentation.
    pub fn push_output_response(&mut self, msg: Response) {
        self.system_state.push_output_response(msg)
    }

    /// Unconditionally pushes an ingress message into the input queue of the
    /// canister.
    pub fn push_ingress(&mut self, msg: Ingress) {
        self.system_state.queues.push_ingress(msg)
    }

    /// See `CanisterQueues::output_into_iter` for documentation.
    pub fn output_into_iter(
        &mut self,
    ) -> impl std::iter::Iterator<Item = (QueueId, QueueIndex, RequestOrResponse)> + '_ {
        let canister_id = self.system_state.canister_id;
        self.system_state.queues_mut().output_into_iter(canister_id)
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
        self.execution_state
            .as_ref()
            .map_or(NumBytes::from(0), |es| es.memory_usage())
            + self.system_state.memory_usage()
    }

    /// Returns the current memory allocation of the canister in bytes.
    pub fn memory_allocation(&self) -> Option<NumBytes> {
        self.system_state
            .memory_allocation
            .map(|memory| memory.get())
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

const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024; // 64KB

/// A session is represented by an array of bytes and a monotonic
/// offset and is unique for each execution.
pub type SessionNonce = ([u8; 32], u64);

pub fn num_bytes_from(pages: NumWasmPages) -> NumBytes {
    NumBytes::from(pages.get() as u64 * WASM_PAGE_SIZE_IN_BYTES)
}

pub mod testing {
    pub use super::queues::testing::CanisterQueuesTesting;
    use ic_types::{messages::RequestOrResponse, CanisterId, QueueIndex};

    /// Exposes public testing-only `CanisterState` methods to be used in other
    /// crates' unit tests.
    pub trait CanisterStateTesting {
        /// Returns the number of messages in the ingress queue.
        fn ingress_queue_size(&self) -> usize;

        /// Pops the next message from the output queue associated with
        /// `dst_canister`.
        fn pop_canister_output(
            &mut self,
            dst_canister: &CanisterId,
        ) -> Option<(QueueIndex, RequestOrResponse)>;

        /// Returns the number of output queues, empty or not.
        fn output_queues_len(&self) -> usize;
    }

    impl CanisterStateTesting for super::CanisterState {
        fn ingress_queue_size(&self) -> usize {
            self.system_state.queues.ingress_queue_size()
        }

        fn pop_canister_output(
            &mut self,
            dst_canister: &CanisterId,
        ) -> Option<(QueueIndex, RequestOrResponse)> {
            self.system_state
                .queues_mut()
                .pop_canister_output(dst_canister)
        }

        fn output_queues_len(&self) -> usize {
            self.system_state.queues.output_queues_len()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_base_types::NumSeconds;
    use ic_test_utilities::types::{
        ids::{canister_test_id, user_test_id},
        messages::{RequestBuilder, ResponseBuilder},
    };
    use ic_types::Cycles;
    use ic_wasm_types::BinaryEncodedWasm;

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

    fn canister_state_test<F, R>(f: F) -> R
    where
        F: FnOnce(CanisterState) -> R,
    {
        let scheduler_state = SchedulerState::default();
        let system_state = SystemState::new_running(
            canister_test_id(42),
            user_test_id(24).get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        let canister_state = CanisterState::new(system_state, None, scheduler_state);
        f(canister_state)
    }

    #[test]
    #[should_panic]
    fn canister_state_push_input_request_mismatched_sender() {
        canister_state_test(|mut canister_state| {
            canister_state
                .push_input(
                    QueueIndex::from(0),
                    RequestBuilder::default()
                        .sender(canister_test_id(13))
                        .build()
                        .into(),
                )
                .unwrap();
        })
    }

    #[test]
    #[should_panic]
    fn canister_state_push_input_response_mismatched_respondent() {
        canister_state_test(|mut canister_state| {
            canister_state
                .push_input(
                    QueueIndex::from(0),
                    ResponseBuilder::default()
                        .respondent(canister_test_id(13))
                        .build()
                        .into(),
                )
                .unwrap();
        })
    }

    #[test]
    #[should_panic]
    fn canister_state_push_output_request_mismatched_sender() {
        canister_state_test(|mut canister_state| {
            canister_state
                .push_output_request(
                    RequestBuilder::default()
                        .sender(canister_test_id(13))
                        .build(),
                )
                .unwrap();
        })
    }

    #[test]
    #[should_panic]
    fn canister_state_push_output_response_mismatched_respondent() {
        canister_state_test(|mut canister_state| {
            canister_state.push_output_response(
                ResponseBuilder::default()
                    .respondent(canister_test_id(13))
                    .build(),
            );
        })
    }

    #[test]
    fn wasm_can_be_loaded_from_a_file() {
        use std::io::Write;

        let mut tmp = tempfile::NamedTempFile::new().expect("failed to create a temporary file");
        let wasm_in_memory = BinaryEncodedWasm::new(vec![0x00, 0x61, 0x73, 0x6d]);
        tmp.write_all(wasm_in_memory.as_slice())
            .expect("failed to write Wasm to a temporary file");
        let wasm_on_disk = BinaryEncodedWasm::new_from_file(tmp.path().to_owned())
            .expect("failed to read Wasm from disk");

        assert_eq!(wasm_in_memory.file(), None);
        assert_eq!(wasm_on_disk.file(), Some(tmp.path()));
        assert_eq!(wasm_in_memory, wasm_on_disk);
    }
}
