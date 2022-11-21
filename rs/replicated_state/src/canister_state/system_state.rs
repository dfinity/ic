mod call_context_manager;

use super::queues::can_push;
pub use super::queues::memory_required_to_push_request;
pub use crate::canister_state::queues::CanisterOutputQueuesIterator;
use crate::{CanisterQueues, CanisterState, InputQueueType, StateError};
pub use call_context_manager::{CallContext, CallContextAction, CallContextManager, CallOrigin};
use ic_base_types::NumSeconds;
use ic_interfaces::messages::{CanisterInputMessage, RequestOrIngress};
use ic_logger::{error, ReplicaLogger};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::canister_state_bits::v1 as pb,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    messages::{Ingress, RejectContext, Request, RequestOrResponse, Response, StopCanisterContext},
    nominal_cycles::NominalCycles,
    CanisterId, CanisterTimer, Cycles, MemoryAllocation, NumBytes, PrincipalId, Time,
};
use lazy_static::lazy_static;
use maplit::btreeset;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
};
use std::{collections::BTreeSet, sync::Arc};
use std::{collections::VecDeque, str::FromStr};

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
    // This must remain private, in order to properly enforce system states (running, stopping,
    // stopped) when enqueuing inputs; and to ensure message memory reservations are accurate.
    queues: CanisterQueues,
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

    /// Should only be modified through `CyclesAccountManager`.
    ///
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
    cycles_balance: Cycles,

    /// Pending charges to `cycles_balance` that are not applied yet.
    ///
    /// Deterministic time slicing requires that `cycles_balance` remains the
    /// same throughout a multi-round execution. During that time all charges
    /// performed outside of execution (e.g. charging for ingress induction) are
    /// recorded in `cycles_debit`. When the multi-round execution completes,
    /// it will apply `cycles_debit` to `cycles_balance`.
    cycles_debit: Cycles,

    /// Tasks to execute before processing input messages.
    /// Currently the task queue is empty outside of execution rounds.
    pub task_queue: VecDeque<ExecutionTask>,

    /// Canister global timer.
    pub global_timer: CanisterTimer,

    /// Canister version.
    pub canister_version: u64,
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

/// The id of a paused execution stored in the execution environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PausedExecutionId(pub u64);

/// Represents a task that needs to be executed before processing canister
/// inputs.
#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionTask {
    // A heartbeat task exists only within an execution round. It is never
    // serialized.
    Heartbeat,

    /// Canister global timer task.
    /// The task exists only within an execution round, it never gets serialized.
    GlobalTimer,

    // A paused execution task exists only within an epoch (between
    // checkpoints). It is never serialized, and it turns into `AbortedExecution`
    // before the checkpoint or when there are too many long-running executions.
    PausedExecution(PausedExecutionId),

    // A paused `install_code` task exists only within an epoch (between
    // checkpoints). It is never serialized and turns into `AbortedInstallCode`
    // before the checkpoint.
    PausedInstallCode(PausedExecutionId),

    // Any paused execution that doesn't finish until the next checkpoint
    // becomes an aborted execution that should be retried after the checkpoint.
    // A paused execution can also be aborted to keep the memory usage low if
    // there are too many long-running executions.
    AbortedExecution {
        message: CanisterInputMessage,
        // The execution cost that has already been charged from the canister.
        // Retried execution does not have to pay for it again.
        prepaid_execution_cycles: Cycles,
    },

    // Any paused `install_code` that doesn't finish until the next checkpoint
    // becomes an aborted `install_code` that should be retried after the
    // checkpoint. A paused execution can also be aborted to keep the memory
    // usage low if there are too many long-running executions.
    AbortedInstallCode {
        message: RequestOrIngress,
        // The execution cost that has already been charged from the canister.
        // Retried execution does not have to pay for it again.
        prepaid_execution_cycles: Cycles,
    },
}

impl From<&ExecutionTask> for pb::ExecutionTask {
    fn from(item: &ExecutionTask) -> Self {
        match item {
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::PausedExecution(_)
            | ExecutionTask::PausedInstallCode(_) => {
                panic!("Attempt to serialize ephemeral task: {:?}.", item);
            }
            ExecutionTask::AbortedExecution {
                message,
                prepaid_execution_cycles,
            } => {
                use pb::execution_task::aborted_execution::Message;
                let message = match message {
                    CanisterInputMessage::Response(v) => Message::Response(v.as_ref().into()),
                    CanisterInputMessage::Request(v) => Message::Request(v.as_ref().into()),
                    CanisterInputMessage::Ingress(v) => Message::Ingress(v.as_ref().into()),
                };
                Self {
                    task: Some(pb::execution_task::Task::AbortedExecution(
                        pb::execution_task::AbortedExecution {
                            message: Some(message),
                            prepaid_execution_cycles: Some((*prepaid_execution_cycles).into()),
                        },
                    )),
                }
            }
            ExecutionTask::AbortedInstallCode {
                message,
                prepaid_execution_cycles,
            } => {
                use pb::execution_task::aborted_install_code::Message;
                let message = match message {
                    RequestOrIngress::Request(v) => Message::Request(v.as_ref().into()),
                    RequestOrIngress::Ingress(v) => Message::Ingress(v.as_ref().into()),
                };
                Self {
                    task: Some(pb::execution_task::Task::AbortedInstallCode(
                        pb::execution_task::AbortedInstallCode {
                            message: Some(message),
                            prepaid_execution_cycles: Some((*prepaid_execution_cycles).into()),
                        },
                    )),
                }
            }
        }
    }
}

impl TryFrom<pb::ExecutionTask> for ExecutionTask {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::ExecutionTask) -> Result<Self, Self::Error> {
        let task = value
            .task
            .ok_or(ProxyDecodeError::MissingField("ExecutionTask::task"))?;
        let task = match task {
            pb::execution_task::Task::AbortedExecution(aborted) => {
                use pb::execution_task::aborted_execution::Message;
                let message = aborted
                    .message
                    .ok_or(ProxyDecodeError::MissingField("AbortedExecution::message"))?;
                let message = match message {
                    Message::Request(v) => CanisterInputMessage::Request(Arc::new(v.try_into()?)),
                    Message::Response(v) => CanisterInputMessage::Response(Arc::new(v.try_into()?)),
                    Message::Ingress(v) => CanisterInputMessage::Ingress(Arc::new(v.try_into()?)),
                };
                let prepaid_execution_cycles = aborted
                    .prepaid_execution_cycles
                    .map(|c| c.try_into())
                    .transpose()?
                    .unwrap_or_else(Cycles::zero);
                ExecutionTask::AbortedExecution {
                    message,
                    prepaid_execution_cycles,
                }
            }
            pb::execution_task::Task::AbortedInstallCode(aborted) => {
                use pb::execution_task::aborted_install_code::Message;
                let message = aborted.message.ok_or(ProxyDecodeError::MissingField(
                    "AbortedInstallCode::message",
                ))?;
                let message = match message {
                    Message::Request(v) => RequestOrIngress::Request(Arc::new(v.try_into()?)),
                    Message::Ingress(v) => RequestOrIngress::Ingress(Arc::new(v.try_into()?)),
                };
                let prepaid_execution_cycles = aborted
                    .prepaid_execution_cycles
                    .map(|c| c.try_into())
                    .transpose()?
                    .unwrap_or_else(Cycles::zero);
                ExecutionTask::AbortedInstallCode {
                    message,
                    prepaid_execution_cycles,
                }
            }
        };
        Ok(task)
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
            cycles_balance: initial_cycles,
            cycles_debit: Cycles::zero(),
            memory_allocation: MemoryAllocation::BestEffort,
            freeze_threshold,
            status,
            certified_data: Default::default(),
            canister_metrics: CanisterMetrics::default(),
            task_queue: Default::default(),
            global_timer: CanisterTimer::Inactive,
            canister_version: 0,
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
            Cycles::zero(),
            NumSeconds::from(0),
            CanisterStatus::Stopped,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_from_checkpoint(
        controllers: BTreeSet<PrincipalId>,
        canister_id: CanisterId,
        queues: CanisterQueues,
        memory_allocation: MemoryAllocation,
        freeze_threshold: NumSeconds,
        status: CanisterStatus,
        certified_data: Vec<u8>,
        canister_metrics: CanisterMetrics,
        cycles_balance: Cycles,
        cycles_debit: Cycles,
        task_queue: VecDeque<ExecutionTask>,
        global_timer: CanisterTimer,
        canister_version: u64,
    ) -> Self {
        Self {
            controllers,
            canister_id,
            queues,
            memory_allocation,
            freeze_threshold,
            status,
            certified_data,
            canister_metrics,
            cycles_balance,
            cycles_debit,
            task_queue,
            global_timer,
            canister_version,
        }
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    /// Returns a mutable reference to the balance of the canister.
    pub fn balance_mut(&mut self) -> &mut Cycles {
        &mut self.cycles_balance
    }

    /// Returns the amount of cycles that the balance holds.
    pub fn balance(&self) -> Cycles {
        self.cycles_balance
    }

    /// Returns the balance after applying the pending debit.
    /// Returns 0 if the balance is smaller than the pending debit.
    pub fn debited_balance(&self) -> Cycles {
        // We rely on saturating operations of `Cycles` here.
        self.cycles_balance - self.cycles_debit
    }

    /// Returns the pending debit.
    pub fn cycles_debit(&self) -> Cycles {
        self.cycles_debit
    }

    /// Records the given amount as debit that will be charged from the balance
    /// at some point in the future.
    ///
    /// Precondition:
    /// - `charge <= self.debited_balance()`.
    pub fn add_postponed_charge_to_cycles_debit(&mut self, charge: Cycles) {
        assert!(
            charge <= self.debited_balance(),
            "Insufficient cycles for a postponed charge: {} vs {}",
            charge,
            self.debited_balance()
        );
        self.cycles_debit += charge;
    }

    /// Charges the pending debit from the balance.
    ///
    /// Precondition:
    /// - The balance is large enough to cover the debit.
    pub fn apply_cycles_debit(&mut self, canister_id: CanisterId, log: &ReplicaLogger) {
        // We rely on saturating operations of `Cycles` here.
        let remaining_debit = self.cycles_debit - self.cycles_balance;
        debug_assert_eq!(remaining_debit.get(), 0);
        if remaining_debit.get() > 0 {
            // This case is unreachable and may happen only due to a bug: if the
            // caller has reduced the cycles balance below the cycles debit.
            // TODO(RUN-299): Increment a critical error counter here.
            error!(
                log,
                "[EXC-BUG]: Debited cycles exceed the cycles balance of {} by {} in install_code",
                canister_id,
                remaining_debit,
            );
            // Continue the execution by dropping the remaining debit, which makes
            // some of the postponed charges free.
        }
        self.cycles_balance -= self.cycles_debit;
        self.cycles_debit = Cycles::zero();
    }

    /// This method is used for maintaining the backwards compatibility.
    /// Returns:
    /// - controller ID as-is, if there is only one controller.
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
    pub fn push_output_request(
        &mut self,
        msg: Arc<Request>,
        time: Time,
    ) -> Result<(), (StateError, Arc<Request>)> {
        assert_eq!(
            msg.sender, self.canister_id,
            "Expected `Request` to have been sent by canister ID {}, but instead got {}",
            self.canister_id, msg.sender
        );
        self.queues.push_output_request(msg, time)
    }

    /// See documentation for [`CanisterQueues::reject_ic00_output_request`].
    pub fn reject_ic00_output_request(
        &mut self,
        request: Request,
        reject_context: RejectContext,
    ) -> Result<(), StateError> {
        assert_eq!(
            request.sender, self.canister_id,
            "Expected `Request` to have been sent from canister ID {}, but instead got {}",
            self.canister_id, request.sender
        );
        self.queues
            .reject_ic00_output_request(request, reject_context)
    }

    /// Returns the number of output requests that can be pushed onto the queue
    /// before it becomes full. Specifically, this is the number of times
    /// `push_output_request` can be called (assuming the canister has enough
    /// cycles to pay for sending the messages).
    pub fn available_output_request_slots(&self) -> BTreeMap<CanisterId, usize> {
        self.queues.available_output_request_slots()
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
    pub fn push_output_response(&mut self, msg: Arc<Response>) {
        assert_eq!(
            msg.respondent, self.canister_id,
            "Expected `Response` to have been sent by canister ID {}, but instead got {}",
            self.canister_id, msg.respondent
        );
        self.queues.push_output_response(msg)
    }

    /// Extracts the next inter-canister or ingress message (round-robin).
    pub(crate) fn pop_input(&mut self) -> Option<CanisterInputMessage> {
        self.queues.pop_input()
    }

    /// Returns true if there are messages in the input queues, false otherwise.
    pub fn has_input(&self) -> bool {
        self.queues.has_input()
    }

    /// Pushes a `RequestOrResponse` into the induction pool.
    ///
    /// If the message is a `Request`, reserves a slot in the corresponding
    /// output queue for the eventual response; and the maximum memory size and
    /// cycles cost for sending the `Response` back. If it is a `Response`,
    /// the protocol should have already reserved a slot and memory for it.
    ///
    /// Updates `subnet_available_memory` to reflect any change in memory usage.
    ///
    /// # Notes
    ///  * `Running` system states accept requests and responses.
    ///  * `Stopping` system states accept responses only.
    ///  * `Stopped` system states accept neither.
    ///
    /// # Errors
    ///
    /// On failure, returns the provided message along with a `StateError`:
    ///  * `QueueFull` if either the input queue or the matching output queue is
    ///    full when pushing a `Request` message.
    ///  * `CanisterOutOfCycles` if the canister does not have enough cycles.
    ///  * `OutOfMemory` if the necessary memory reservation is larger than the
    ///    canister or subnet available memory.
    ///  * `CanisterStopping` if the canister is stopping and inducting a
    ///    `Request` was attempted.
    ///  * `CanisterStopped` if the canister is stopped.
    ///
    /// # Panics
    ///
    /// Panics if a `Response` message is pushed onto a queue that does not
    /// already exist or does not have a reserved slot.
    pub(crate) fn push_input(
        &mut self,
        msg: RequestOrResponse,
        canister_available_memory: i64,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<(), (StateError, RequestOrResponse)> {
        assert_eq!(
            msg.receiver(),
            self.canister_id,
            "Expected `RequestOrResponse` to be targeted to canister ID {}, but instead got {}",
            self.canister_id,
            msg.receiver()
        );

        match (&msg, &self.status) {
            // Requests and responses are both rejected when stopped.
            (_, CanisterStatus::Stopped { .. }) => {
                Err((StateError::CanisterStopped(self.canister_id()), msg))
            }

            // Requests (only) are rejected while stopping.
            (RequestOrResponse::Request(_), CanisterStatus::Stopping { .. }) => {
                Err((StateError::CanisterStopping(self.canister_id()), msg))
            }

            // Everything else is accepted iff there is available memory and queue slots.
            (
                _,
                CanisterStatus::Running {
                    call_context_manager,
                },
            )
            | (
                RequestOrResponse::Response(_),
                CanisterStatus::Stopping {
                    call_context_manager,
                    ..
                },
            ) => {
                if let RequestOrResponse::Response(response) = &msg {
                    call_context_manager
                        .validate_response(response)
                        .map_err(|err| (err, msg.clone()))?;
                }
                push_input(
                    &mut self.queues,
                    msg,
                    canister_available_memory,
                    subnet_available_memory,
                    own_subnet_type,
                    input_queue_type,
                )
            }
        }
    }

    /// Pushes an ingress message into the induction pool.
    pub(crate) fn push_ingress(&mut self, msg: Ingress) {
        self.queues.push_ingress(msg)
    }

    /// For each output queue, invokes `f` on every message until `f` returns
    /// `Err`; then moves on to the next output queue.
    ///
    /// All messages that `f` returned `Ok` for, are popped. Messages that `f`
    /// returned `Err` for and all those following them in the output queue are
    /// retained.
    pub fn output_queues_for_each<F>(&mut self, f: F)
    where
        F: FnMut(&CanisterId, &RequestOrResponse) -> Result<(), ()>,
    {
        self.queues.output_queues_for_each(f)
    }

    /// Returns an iterator that loops over the canister's output queues,
    /// popping one message at a time from each in a round robin fashion. The
    /// iterator consumes all popped messages.
    pub fn output_into_iter(&mut self, owner: CanisterId) -> CanisterOutputQueuesIterator {
        self.queues.output_into_iter(owner)
    }

    /// Returns an immutable reference to the canister queues.
    pub fn queues(&self) -> &CanisterQueues {
        &self.queues
    }

    /// Returns a boolean whether the system state is ready to be `Stopped`.
    /// Only relevant for a `Stopping` system state.
    pub fn ready_to_stop(&self) -> bool {
        match &self.status {
            CanisterStatus::Running { .. } => false,
            CanisterStatus::Stopping {
                call_context_manager,
                ..
            } => call_context_manager.canister_ready_to_stop(),
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

    /// Returns the memory currently in use by the `SystemState`.
    pub fn memory_usage(&self) -> NumBytes {
        (self.queues.memory_usage() as u64).into()
    }

    /// Sets the (transient) size in bytes of responses from this canister
    /// routed into streams and not yet garbage collected.
    pub(super) fn set_stream_responses_size_bytes(&mut self, size_bytes: usize) {
        self.queues.set_stream_responses_size_bytes(size_bytes);
    }

    pub fn add_stop_context(&mut self, stop_context: StopCanisterContext) {
        match &mut self.status {
            CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
                panic!("Should never add_stop_context to a non-stopping canister.")
            }
            CanisterStatus::Stopping { stop_contexts, .. } => stop_contexts.push(stop_context),
        }
    }

    /// Method used only by the dashboard.
    pub fn collect_controllers_as_string(&self) -> String {
        self.controllers
            .iter()
            .map(|id| format!("{}", id))
            .collect::<Vec<String>>()
            .join(" ")
    }

    /// Inducts messages from the output queue to `self` into the input queue
    /// from `self` while respecting queue capacity and the provided canister
    /// and subnet available memory.
    ///
    /// `subnet_available_memory` is updated to reflect the change in
    /// `self.queues` memory usage.
    ///
    /// Available memory is ignored (but updated) for system subnets, since we
    /// don't want to DoS system canisters due to lots of incoming requests.
    pub fn induct_messages_to_self(
        &mut self,
        canister_available_memory: i64,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) {
        // Bail out if the canister is not running.
        match self.status {
            CanisterStatus::Running { .. } => (),
            CanisterStatus::Stopped | CanisterStatus::Stopping { .. } => return,
        }

        let mut available_memory = canister_available_memory.min(*subnet_available_memory);
        let mut memory_usage = self.queues.memory_usage() as i64;

        while let Some(msg) = self.queues.peek_output(&self.canister_id) {
            // Ensure that enough memory is available for inducting `msg`.
            if own_subnet_type != SubnetType::System && can_push(&*msg, available_memory).is_err() {
                // Bail out if not enough memory available for message.
                return;
            }

            // Attempt inducting `msg`. May fail if the input queue is full.
            if self
                .queues
                .induct_message_to_self(self.canister_id)
                .is_err()
            {
                return;
            }

            // Adjust both `available_memory` and `subnet_available_memory` by
            // `memory_usage_before - memory_usage_after`. Defer the accounting
            // to `CanisterQueues`, to avoid duplication or divergence.
            available_memory += memory_usage;
            *subnet_available_memory += memory_usage;
            memory_usage = self.queues.memory_usage() as i64;
            available_memory -= memory_usage;
            *subnet_available_memory -= memory_usage;
        }
    }

    /// Garbage collects empty input and output queue pairs.
    pub fn garbage_collect_canister_queues(&mut self) {
        self.queues.garbage_collect();
    }

    /// Queries whether any of the `OutputQueues` in `self.queues` have any expired
    /// deadlines in them.
    pub fn has_expired_deadlines(&self, current_time: Time) -> bool {
        self.queues.has_expired_deadlines(current_time)
    }

    /// Times out requests in the `OutputQueues` of `self.queues`.
    ///
    /// See `CanisterQueues::time_out_requests` for further details.
    pub fn time_out_requests(
        &mut self,
        current_time: Time,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) {
        self.queues
            .time_out_requests(current_time, own_canister_id, local_canisters);
    }
}

/// Implements memory limits verification for pushing a canister-to-canister
/// message into the induction pool of `queues`.
///
/// Returns `StateError::OutOfMemory` if pushing the message would require more
/// memory than `queues_available_memory.min(subnet_available_memory)`.
///
/// `subnet_available_memory` is updated to reflect the change in memory usage
/// after a successful push; and left unmodified if the push failed.
///
/// See `CanisterQueues::push_input()` for further details.
pub(crate) fn push_input(
    queues: &mut CanisterQueues,
    msg: RequestOrResponse,
    queues_available_memory: i64,
    subnet_available_memory: &mut i64,
    own_subnet_type: SubnetType,
    input_queue_type: InputQueueType,
) -> Result<(), (StateError, RequestOrResponse)> {
    // Do not enforce limits for local messages on system subnets.
    if own_subnet_type != SubnetType::System || input_queue_type != InputQueueType::LocalSubnet {
        let available_memory = queues_available_memory.min(*subnet_available_memory);
        if let Err(required_memory) = can_push(&msg, available_memory) {
            return Err((
                StateError::OutOfMemory {
                    requested: NumBytes::new(required_memory as u64),
                    available: available_memory,
                },
                msg,
            ));
        }
    }

    // But always adjust `subnet_available_memory` by `memory_usage_before -
    // memory_usage_after`. Defer the accounting to `CanisterQueues`, to avoid
    // duplication (and the possibility of divergence).
    *subnet_available_memory += queues.memory_usage() as i64;
    let res = queues.push_input(msg, input_queue_type);
    *subnet_available_memory -= queues.memory_usage() as i64;
    res
}

pub mod testing {
    use super::SystemState;
    use crate::CanisterQueues;
    use ic_interfaces::messages::CanisterInputMessage;
    use ic_types::CanisterId;

    /// Exposes `SystemState` internals for use in other crates' unit tests.
    pub trait SystemStateTesting {
        /// Testing only: Sets the value of the `canister_id` field.
        fn set_canister_id(&mut self, canister_id: CanisterId);

        /// Testing only: Returns a mutable reference to `self.queues`.
        fn queues_mut(&mut self) -> &mut CanisterQueues;

        /// Testing only: Sets `self.queues` to the given `queues`
        fn put_queues(&mut self, queues: CanisterQueues);

        /// Testing only: pops next input message
        fn pop_input(&mut self) -> Option<CanisterInputMessage>;
    }

    impl SystemStateTesting for SystemState {
        fn set_canister_id(&mut self, canister_id: CanisterId) {
            self.canister_id = canister_id;
        }

        fn queues_mut(&mut self) -> &mut CanisterQueues {
            &mut self.queues
        }

        fn put_queues(&mut self, queues: CanisterQueues) {
            self.queues = queues;
        }

        fn pop_input(&mut self) -> Option<CanisterInputMessage> {
            self.pop_input()
        }
    }
}
