mod call_context_manager;

use crate::{CanisterQueues, NumWasmPages, PageMap, StateError};
pub use call_context_manager::{CallContext, CallContextAction, CallContextManager, CallOrigin};
use ic_base_types::NumSeconds;
use ic_interfaces::messages::CanisterInputMessage;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::canister_state_bits::v1 as pb,
};
use ic_types::{
    messages::{Ingress, Request, RequestOrResponse, Response, StopCanisterContext},
    nominal_cycles::NominalCycles,
    CanisterId, Cycles, MemoryAllocation, NumBytes, PrincipalId, QueueIndex,
};
use lazy_static::lazy_static;
use maplit::btreeset;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use std::{collections::BTreeSet, sync::Arc};

lazy_static! {
    static ref DEFAULT_PRINCIPAL_MULTIPLE_CONTROLLERS: PrincipalId =
        PrincipalId::from_str("ifxlm-aqaaa-multi-pleco-ntrol-lersa-h3ae").unwrap();
    static ref DEFAULT_PRINCIPAL_ZERO_CONTROLLERS: PrincipalId =
        PrincipalId::from_str("zrl4w-cqaaa-nocon-troll-eraaa-d5qc").unwrap();
}

#[derive(Clone, Debug, Default, PartialEq)]
/// Canister-specific metrics on scheduling, maintained by the scheduler.
// For semantics of the fields please check
// protobuf/def/state/canister_state_bits/v1/canister_state_bits.proto:
// CanisterStateBits
pub struct CanisterMetrics {
    pub scheduled_as_first: u64,
    pub skipped_round_due_to_no_messages: u64,
    pub executed: u64,
    pub interruped_during_execution: u64,
    pub consumed_cycles_since_replica_started: NominalCycles,
}

/// State that is controlled and owned by the system (IC).
///
/// Contains structs needed for running and maintaining the canister on the IC.
/// The state here cannot be directly modified by the Wasm module in the
/// canister but can be indirectly via the SystemApi interface.
#[derive(Clone, Debug, PartialEq)]
pub struct SystemState {
    pub controllers: BTreeSet<PrincipalId>,
    pub canister_id: CanisterId,
    // EXE-92: This should be private
    pub queues: CanisterQueues,
    pub stable_memory_size: NumWasmPages,
    pub stable_memory: PageMap,
    /// The canister's memory allocation.
    pub memory_allocation: MemoryAllocation,
    pub freeze_threshold: NumSeconds,
    /// The status of the canister: Running, Stopping, or Stopped.
    /// Different statuses allow for different behaviors on the SystemState.
    pub status: CanisterStatus,
    /// Certified data blob allows canisters to certify parts of their state to
    /// securely answer queries from a single machine.
    ///
    /// Certified data is set by the canister by calling ic0.certified_data_set.
    ///
    /// It can be at most 32 bytes long.  For fresh canisters, this blob is the
    /// empty blob.
    ///
    /// See also:
    ///   * https://sdk.dfinity.org/docs/interface-spec/index.html#system-api-certified-data
    pub certified_data: Vec<u8>,
    pub canister_metrics: CanisterMetrics,

    /// A canister's state has an associated cycles balance, and may `send` a
    /// part of this cycles balance to another canister.
    /// In addition to sending cycles to another canister, a canister `spend`s
    /// cycles in the following three ways:
    ///     a) executing messages,
    ///     b) sending messages to other canisters,
    ///     c) storing data over time/rounds
    /// Each of the above spending is done in three phases:
    ///     1. reserving maximum cycles the operation can require
    ///     2. executing the operation and return `cycles_spent`
    ///     3. reimburse the canister with `cycles_reserved` - `cycles_spent`
    pub cycles_balance: Cycles,
}

/// A wrapper around the different canister statuses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CanisterStatus {
    Running {
        call_context_manager: CallContextManager,
    },
    Stopping {
        call_context_manager: CallContextManager,
        /// Info about the messages that requested the canister to stop.
        /// The reason this is a vec is because it's possible to receive
        /// multiple requests to stop the canister while it is stopping. All
        /// of them would be tracked here so that they can all get a response.
        stop_contexts: Vec<StopCanisterContext>,
    },
    Stopped,
}

impl CanisterStatus {
    pub fn new_running() -> Self {
        Self::Running {
            call_context_manager: CallContextManager::default(),
        }
    }
}

impl From<&CanisterStatus> for pb::canister_state_bits::CanisterStatus {
    fn from(item: &CanisterStatus) -> Self {
        match item {
            CanisterStatus::Running {
                call_context_manager,
            } => Self::Running(pb::CanisterStatusRunning {
                call_context_manager: Some(call_context_manager.into()),
            }),
            CanisterStatus::Stopped => Self::Stopped(pb::CanisterStatusStopped {}),
            CanisterStatus::Stopping {
                call_context_manager,
                stop_contexts,
            } => Self::Stopping(pb::CanisterStatusStopping {
                call_context_manager: Some(call_context_manager.into()),
                stop_contexts: stop_contexts.iter().map(|context| context.into()).collect(),
            }),
        }
    }
}

impl TryFrom<pb::canister_state_bits::CanisterStatus> for CanisterStatus {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::canister_state_bits::CanisterStatus) -> Result<Self, Self::Error> {
        let canister_status = match value {
            pb::canister_state_bits::CanisterStatus::Running(pb::CanisterStatusRunning {
                call_context_manager,
            }) => Self::Running {
                call_context_manager: try_from_option_field(
                    call_context_manager,
                    "CanisterStatus::Running::call_context_manager",
                )?,
            },
            pb::canister_state_bits::CanisterStatus::Stopped(pb::CanisterStatusStopped {}) => {
                Self::Stopped
            }
            pb::canister_state_bits::CanisterStatus::Stopping(pb::CanisterStatusStopping {
                call_context_manager,
                stop_contexts,
            }) => {
                let mut contexts = Vec::<StopCanisterContext>::with_capacity(stop_contexts.len());
                for context in stop_contexts.into_iter() {
                    contexts.push(context.try_into()?);
                }
                Self::Stopping {
                    call_context_manager: try_from_option_field(
                        call_context_manager,
                        "CanisterStatus::Stopping::call_context_manager",
                    )?,
                    stop_contexts: contexts,
                }
            }
        };
        Ok(canister_status)
    }
}

impl SystemState {
    pub fn new_running(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
    ) -> Self {
        Self::new(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            CanisterStatus::new_running(),
        )
    }

    pub fn new_stopping(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
    ) -> Self {
        Self::new(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            CanisterStatus::Stopping {
                call_context_manager: CallContextManager::default(),
                stop_contexts: Vec::default(),
            },
        )
    }

    pub fn new_stopped(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
    ) -> Self {
        Self::new(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            CanisterStatus::Stopped,
        )
    }

    pub fn new(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
        status: CanisterStatus,
    ) -> Self {
        Self {
            canister_id,
            controllers: btreeset! {controller},
            queues: CanisterQueues::default(),
            stable_memory_size: NumWasmPages::new(0),
            stable_memory: PageMap::default(),
            cycles_balance: initial_cycles,
            memory_allocation: MemoryAllocation::BestEffort,
            freeze_threshold,
            status,
            certified_data: Default::default(),
            canister_metrics: CanisterMetrics::default(),
        }
    }

    /// Create a SystemState only having a canister_id -- this is the
    /// state that is expected when the "start" method of the wasm
    /// module is run. There is nothing interesting in the system state
    /// that can be accessed at that point in time, hence this
    /// "slightly" fake system state.
    pub fn new_for_start(canister_id: CanisterId) -> Self {
        let controller = *canister_id.get_ref();
        Self::new(
            canister_id,
            controller,
            Cycles::from(0),
            NumSeconds::from(0),
            CanisterStatus::Stopped,
        )
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    #[doc(hidden)]
    pub fn set_canister_id(&mut self, canister_id: CanisterId) {
        self.canister_id = canister_id;
    }

    /// This method is used for maintaining the backwards compatibility.
    /// Returns:
    /// - controller id as-is, if there is only one controller.
    /// - DEFAULT_PRINCIPAL_MULTIPLE_CONTROLLERS, if there are multiple
    ///   controllers.
    /// - DEFAULT_PRINCIPAL_ZERO_CONTROLLERS, if there is no controller.
    pub fn controller(&self) -> &PrincipalId {
        if self.controllers.len() < 2 {
            match self.controllers.iter().next() {
                None => &DEFAULT_PRINCIPAL_ZERO_CONTROLLERS,
                Some(controller) => controller,
            }
        } else {
            &DEFAULT_PRINCIPAL_MULTIPLE_CONTROLLERS
        }
    }

    pub fn call_context_manager(&self) -> Option<&CallContextManager> {
        match &self.status {
            CanisterStatus::Running {
                call_context_manager,
            } => Some(call_context_manager),
            CanisterStatus::Stopping {
                call_context_manager,
                ..
            } => Some(call_context_manager),
            CanisterStatus::Stopped => None,
        }
    }

    pub fn call_context_manager_mut(&mut self) -> Option<&mut CallContextManager> {
        match &mut self.status {
            CanisterStatus::Running {
                call_context_manager,
            } => Some(call_context_manager),
            CanisterStatus::Stopping {
                call_context_manager,
                ..
            } => Some(call_context_manager),
            CanisterStatus::Stopped => None,
        }
    }

    /// Pushes a `Request` type message into the relevant output queue.
    /// This is preceded by withdrawing the cycles for sending the `Request` and
    /// receiving and processing the corresponding `Response`.
    /// If cycles withdrawal succeeds, the function also reserves a slot on the
    /// matching input queue for the `Response`.
    ///
    /// # Errors
    ///
    /// Returns a `QueueFull` error along with the provided message if either
    /// the output queue or the matching input queue is full.
    ///
    /// Returns a `CanisterOutOfCycles` error along with the provided message if
    /// the canister's cycles balance is not sufficient to pay for cost of
    /// sending the message.
    pub fn push_output_request(&mut self, msg: Request) -> Result<(), (StateError, Request)> {
        assert_eq!(
            msg.sender, self.canister_id,
            "Expected `Request` to have been sent by canister id {}, but instead got {}",
            self.canister_id, msg.sender
        );
        self.queues.push_output_request(msg)
    }

    /// Pushes a `Response` type message into the relevant output queue. The
    /// protocol should have already reserved a slot, so this cannot fail. The
    /// canister is also refunded the excess cycles that was reserved for
    /// sending this response when the original request was received.
    ///
    /// # Panics
    ///
    /// Panics if the queue does not already exist or there is no reserved slot
    /// to push the `Response` into.
    pub fn push_output_response(&mut self, msg: Response) {
        assert_eq!(
            msg.respondent, self.canister_id,
            "Expected `Response` to have been sent by canister id {}, but instead got {}",
            self.canister_id, msg.respondent
        );
        self.queues.push_output_response(msg)
    }

    /// Extracts the next inter-canister or ingress message (in that order).
    /// If no inter-canister messages are available in the induction pool, we
    /// pop the next ingress message.
    pub fn pop_input(&mut self) -> Option<CanisterInputMessage> {
        self.queues.pop_input()
    }

    /// Returns true if there are messages in the input queues, false otherwise.
    pub fn has_input(&self) -> bool {
        self.queues.has_input()
    }

    /// Pushes a `RequestOrResponse` into the induction pool.
    ///
    /// If the message is a `Request`, reserves a slot in the corresponding
    /// output queue for the eventual response and reserves the maximum cycles
    /// cost for sending the `Response` back. If it is a `Response`, the
    /// protocol should have already reserved a slot for it.
    ///
    /// # Notes
    ///  * `Running` system states accept requests and responses.
    ///  * `Stopping` system states accept responses only.
    ///  * `Stopped` system states accept neither.
    ///
    /// # Errors
    ///
    /// Returns a `StateError` along with the provided message:
    ///  * `QueueFull` if either the input queue or the matching output queue is
    ///    full when pushing a `Request` message.
    ///  * `CanisterOutOfCycles` if the canister does not have enough cycles to
    ///    be
    ///  * `CanisterStopping` if the canister is stopping and inducting a
    ///    `Request` is attempted.
    ///  * `CanisterStopped` if the canister is stopped.
    ///
    /// # Panics
    ///
    /// Panics if a `Response` message is pushed into a queue that does not
    /// already exist or there is no reserved slot in the queue.
    ///
    /// Warning! this is only exposed for test purposes and should not be used
    /// outside of this crate.
    pub fn push_input(
        &mut self,
        index: QueueIndex,
        msg: RequestOrResponse,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        assert_eq!(
            msg.receiver(),
            self.canister_id,
            "Expected `RequestOrResponse` to be targeted to canister id {}, but instead got {}",
            self.canister_id,
            msg.receiver()
        );
        match self.status {
            CanisterStatus::Running { .. } => self.queues.push_input(index, msg),
            CanisterStatus::Stopping { .. } => {
                // Responses are accepted and requests are rejected.
                match msg {
                    RequestOrResponse::Request(req) => Err((
                        StateError::CanisterStopping(self.canister_id()),
                        RequestOrResponse::Request(req),
                    )),
                    RequestOrResponse::Response(response) => self
                        .queues
                        .push_input(index, RequestOrResponse::Response(response)),
                }
            }
            CanisterStatus::Stopped => {
                // Requests and responses are both rejected.
                Err((StateError::CanisterStopped(self.canister_id()), msg))
            }
        }
    }

    pub fn queues_mut(&mut self) -> &mut CanisterQueues {
        &mut self.queues
    }

    /// Returns a boolean whether the system state is ready to be `Stopped`.
    /// Only relevant for a `Stopping` system state.
    pub fn ready_to_stop(&self) -> bool {
        match &self.status {
            CanisterStatus::Running { .. } => false,
            CanisterStatus::Stopping {
                call_context_manager,
                ..
            } => {
                call_context_manager.callbacks().is_empty()
                    && call_context_manager.call_contexts().is_empty()
            }
            CanisterStatus::Stopped => true,
        }
    }

    pub fn status_string(&self) -> &'static str {
        match self.status {
            CanisterStatus::Running { .. } => "Running",
            CanisterStatus::Stopping { .. } => "Stopping",
            CanisterStatus::Stopped => "Stopped",
        }
    }

    /// See IngressQueue::filter_messages() for documentation
    pub fn filter_ingress_messages<F>(&mut self, filter: F)
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.queues.filter_ingress_messages(filter);
    }

    /// Returns the memory that is currently used by the `SystemState`.
    pub fn memory_usage(&self) -> NumBytes {
        crate::num_bytes_from(self.stable_memory_size)
    }

    pub fn add_stop_context(&mut self, stop_context: StopCanisterContext) {
        match &mut self.status {
            CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
                panic!("Should never add_stop_context to a non-stopping canister.")
            }
            CanisterStatus::Stopping { stop_contexts, .. } => stop_contexts.push(stop_context),
        }
    }

    /// Clears stable memory of this canister.
    pub fn clear_stable_memory(&mut self) {
        self.stable_memory = PageMap::default();
        self.stable_memory_size = NumWasmPages::new(0);
    }

    /// Method used only by the dashboard.
    pub fn collect_controllers_as_string(&self) -> String {
        self.controllers
            .iter()
            .map(|id| format!("{}", id))
            .collect::<Vec<String>>()
            .join(" ")
    }
}
