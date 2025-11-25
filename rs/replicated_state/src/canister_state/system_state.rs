mod call_context_manager;
pub mod proto;
mod task_queue;
pub mod wasm_chunk_store;

pub use self::task_queue::{TaskQueue, is_low_wasm_memory_hook_condition_satisfied};

use self::wasm_chunk_store::{WasmChunkStore, WasmChunkStoreMetadata};
use super::queues::refunds::RefundPool;
use super::queues::{CanisterInput, can_push};
pub use super::queues::{CanisterOutputQueuesIterator, memory_usage_of_request};
use crate::metadata_state::subnet_call_context_manager::InstallCodeCallId;
use crate::page_map::PageAllocatorFileDescriptor;
use crate::replicated_state::MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN;
use crate::{
    CanisterQueues, CanisterState, CheckpointLoadingMetrics, DroppedMessageMetrics, InputQueueType,
    PageMap, StateError,
};
pub use call_context_manager::{CallContext, CallContextAction, CallContextManager, CallOrigin};
use ic_base_types::{EnvironmentVariables, NumSeconds};
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::HypervisorError;
use ic_logger::{ReplicaLogger, error};
use ic_management_canister_types_private::{
    CanisterChange, CanisterChangeDetails, CanisterChangeOrigin, CanisterStatusType,
    LogVisibilityV2,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::ingress::WasmResult;
use ic_types::messages::{
    CallContextId, CallbackId, CanisterCall, CanisterMessage, CanisterMessageOrTask, CanisterTask,
    Ingress, NO_DEADLINE, Payload, RejectContext, Request, RequestMetadata, RequestOrResponse,
    Response, StopCanisterContext,
};
use ic_types::methods::Callback;
use ic_types::nominal_cycles::NominalCycles;
use ic_types::time::CoarseTime;
use ic_types::{
    CanisterId, CanisterLog, CanisterTimer, Cycles, MemoryAllocation, NumBytes, NumInstructions,
    PrincipalId, Time, default_aggregate_log_memory_limit,
};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use lazy_static::lazy_static;
use maplit::btreeset;
use prometheus::IntCounter;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use std::sync::Arc;
use strum_macros::EnumIter;

lazy_static! {
    static ref DEFAULT_PRINCIPAL_MULTIPLE_CONTROLLERS: PrincipalId =
        PrincipalId::from_str("ifxlm-aqaaa-multi-pleco-ntrol-lersa-h3ae").unwrap();
    static ref DEFAULT_PRINCIPAL_ZERO_CONTROLLERS: PrincipalId =
        PrincipalId::from_str("zrl4w-cqaaa-nocon-troll-eraaa-d5qc").unwrap();
}

/// Maximum number of canister changes stored in the canister history.
pub const MAX_CANISTER_HISTORY_CHANGES: u64 = 20;

/// Enumerates use cases of consumed cycles.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, EnumIter, Serialize)]
pub enum CyclesUseCase {
    Memory = 1,
    ComputeAllocation = 2,
    IngressInduction = 3,
    Instructions = 4,
    RequestAndResponseTransmission = 5,
    Uninstall = 6,
    CanisterCreation = 7,
    ECDSAOutcalls = 8,
    HTTPOutcalls = 9,
    DeletedCanisters = 10,
    NonConsumed = 11,
    BurnedCycles = 12,
    SchnorrOutcalls = 13,
    VetKd = 14,
    DroppedMessages = 15,
}

impl CyclesUseCase {
    /// Returns a string slice representation of the enum variant name for use
    /// e.g. as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Memory => "Memory",
            Self::ComputeAllocation => "ComputeAllocation",
            Self::IngressInduction => "IngressInduction",
            Self::Instructions => "Instructions",
            Self::RequestAndResponseTransmission => "RequestAndResponseTransmission",
            Self::Uninstall => "Uninstall",
            Self::CanisterCreation => "CanisterCreation",
            Self::ECDSAOutcalls => "ECDSAOutcalls",
            Self::HTTPOutcalls => "HTTPOutcalls",
            Self::DeletedCanisters => "DeletedCanisters",
            Self::NonConsumed => "NonConsumed",
            Self::BurnedCycles => "BurnedCycles",
            Self::SchnorrOutcalls => "SchnorrOutcalls",
            Self::VetKd => "VetKd",
            Self::DroppedMessages => "DroppedMessages",
        }
    }
}

enum ConsumingCycles {
    Yes,
    No,
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
/// Canister-specific metrics on scheduling, maintained by the scheduler.
// For semantics of the fields please check
// protobuf/def/state/canister_state_bits/v1/canister_state_bits.proto:
// CanisterStateBits
pub struct CanisterMetrics {
    pub scheduled_as_first: u64,
    pub skipped_round_due_to_no_messages: u64,
    pub executed: u64,
    pub interrupted_during_execution: u64,
    pub consumed_cycles: NominalCycles,
    consumed_cycles_by_use_cases: BTreeMap<CyclesUseCase, NominalCycles>,
}

impl CanisterMetrics {
    pub fn new(
        scheduled_as_first: u64,
        skipped_round_due_to_no_messages: u64,
        executed: u64,
        interrupted_during_execution: u64,
        consumed_cycles: NominalCycles,
        consumed_cycles_by_use_cases: BTreeMap<CyclesUseCase, NominalCycles>,
    ) -> Self {
        Self {
            scheduled_as_first,
            skipped_round_due_to_no_messages,
            executed,
            interrupted_during_execution,
            consumed_cycles,
            consumed_cycles_by_use_cases,
        }
    }

    pub fn get_consumed_cycles_by_use_cases(&self) -> &BTreeMap<CyclesUseCase, NominalCycles> {
        &self.consumed_cycles_by_use_cases
    }
}

/// Computes the total byte size of the given canister changes. Requires `O(N)` time.
pub fn compute_total_canister_change_size(changes: &VecDeque<Arc<CanisterChange>>) -> NumBytes {
    changes.iter().map(|c| c.count_bytes()).sum()
}

/// The canister history consists of a list of canister changes
/// with the oldest canister changes at lowest indices.
/// The system can drop the oldest canister changes from the list to keep its length bounded
/// (with `20` latest canister changes to always remain in the list).
/// The system also drops all canister changes if the canister runs out of cycles.
#[derive(Clone, Eq, PartialEq, Debug, Default, ValidateEq)]
pub struct CanisterHistory {
    /// The canister changes stored in the order from the oldest to the most recent.
    #[validate_eq(Ignore)]
    changes: Arc<VecDeque<Arc<CanisterChange>>>,
    /// The `total_num_changes` records the total number of canister changes
    /// that have ever been recorded. In particular, if the system drops some canister changes,
    /// `total_num_changes` does not decrease.
    total_num_changes: u64,
    /// Sum over `c.count_bytes()` for all canister changes `c`.
    /// We pre-compute and store the sum in a field to optimize the running time
    /// of computing the sum as the canister history memory usage is requested frequently.
    canister_history_memory_usage: NumBytes,
}

impl CanisterHistory {
    /// Clears all canister changes and their memory usage,
    /// but keeps the total number of changes recorded.
    pub fn clear(&mut self) {
        self.changes = Arc::new(Default::default());
        self.canister_history_memory_usage = NumBytes::new(0);

        debug_assert_eq!(
            self.get_memory_usage(),
            compute_total_canister_change_size(&self.changes),
        );
    }

    /// Adds a canister change to the history, updating the memory usage
    /// of canister history tracked internally and the total number of changes.
    /// It also makes sure that the number of canister changes does not exceed
    /// `MAX_CANISTER_HISTORY_CHANGES` by dropping the oldest entry if necessary.
    pub fn add_canister_change(&mut self, canister_change: CanisterChange) {
        let changes = Arc::make_mut(&mut self.changes);
        if changes.len() >= MAX_CANISTER_HISTORY_CHANGES as usize {
            let change_size = changes
                .pop_front()
                .as_ref()
                .map(|c| c.count_bytes())
                .unwrap_or_default();
            self.canister_history_memory_usage -= change_size;
        }
        self.canister_history_memory_usage += canister_change.count_bytes();
        changes.push_back(Arc::new(canister_change));
        self.total_num_changes += 1;

        debug_assert_eq!(
            self.get_memory_usage(),
            compute_total_canister_change_size(&self.changes),
        );
    }

    /// Returns an iterator over the requested number of most recent canister changes
    /// or, if more changes are requested than available in the history,
    /// an iterator over all canister changes.
    /// The changes are iterated in chronological order, i.e., from the oldest to the most recent.
    pub fn get_changes(
        &self,
        num_requested_changes: usize,
    ) -> impl Iterator<Item = &Arc<CanisterChange>> {
        let num_all_changes = self.changes.len();
        let num_changes = num_requested_changes.min(num_all_changes);
        self.changes.range((num_all_changes - num_changes)..)
    }

    pub fn get_total_num_changes(&self) -> u64 {
        self.total_num_changes
    }

    /// Overwrites the `total_num_changes`, which can happen in the context of canister migration.
    pub fn set_total_num_changes(&mut self, total_num_changes: u64) {
        self.total_num_changes = total_num_changes;
    }

    pub fn get_memory_usage(&self) -> NumBytes {
        self.canister_history_memory_usage
    }
}

/// State that is controlled and owned by the system (IC).
///
/// Contains structs needed for running and maintaining the canister on the IC.
/// The state here cannot be directly modified by the Wasm module in the
/// canister but can be indirectly via the SystemApi interface.
#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct SystemState {
    pub controllers: BTreeSet<PrincipalId>,
    pub canister_id: CanisterId,
    /// Input (canister and ingress) and output (canister) message queues.
    ///
    /// Must remain private, to ensure consistency with the `CallContextManager`; to
    /// properly enforce system states (`Running`, `Stopping`, `Stopped`) when
    /// enqueuing inputs; and to ensure accurate slot and message memory
    /// reservations.
    #[validate_eq(CompareWithValidateEq)]
    queues: CanisterQueues,
    /// The canister's memory allocation.
    pub memory_allocation: MemoryAllocation,
    /// Threshold used for activation of canister_on_low_wasm_memory hook.
    pub wasm_memory_threshold: NumBytes,
    pub freeze_threshold: NumSeconds,
    /// The status of the canister: `Running`, `Stopping`, or `Stopped`.
    /// Different statuses allow for different behaviors on the `SystemState`.
    ///
    /// Must remain private, to ensure that the `CallContextManager` is consistent
    /// with `queues`.
    status: CanisterStatus,
    /// Certified data blob allows canisters to certify parts of their state to
    /// securely answer queries from a single machine.
    ///
    /// Certified data is set by the canister by calling ic0.certified_data_set.
    ///
    /// It can be at most 32 bytes long.  For fresh canisters, this blob is the
    /// empty blob.
    ///
    /// See also:
    ///   * https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-certified-data
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
    /// performed in ingress induction are recorded in
    /// `ingress_induction_cycles_debit`. When the multi-round execution
    /// completes, it will apply `ingress_induction_cycles_debit` to `cycles_balance`.
    ingress_induction_cycles_debit: Cycles,

    /// Resource reservation cycles.
    reserved_balance: Cycles,

    /// The user-specified upper limit on `reserved_balance`.
    ///
    /// A resource allocation operation that attempts to reserve `N` cycles will
    /// fail if `reserved_balance + N` exceeds this limit if the limit is set.
    reserved_balance_limit: Option<Cycles>,

    /// Queue of tasks to be executed next. If a paused or aborted execution task is
    /// present, it must be executed before any other tasks or messages.
    pub task_queue: TaskQueue,

    /// Canister global timer.
    pub global_timer: CanisterTimer,

    /// Canister version.
    pub canister_version: u64,

    /// Canister history.
    #[validate_eq(CompareWithValidateEq)]
    canister_history: CanisterHistory,

    /// Store of Wasm chunks to support installation of large Wasm modules.
    #[validate_eq(CompareWithValidateEq)]
    pub wasm_chunk_store: WasmChunkStore,

    /// Log visibility of the canister.
    pub log_visibility: LogVisibilityV2,

    /// The capacity of the canister log in bytes.
    pub log_memory_limit: NumBytes,

    /// Log records of the canister.
    #[validate_eq(CompareWithValidateEq)]
    pub canister_log: CanisterLog,

    /// The Wasm memory limit. This is a field in developer-visible canister
    /// settings that allows the developer to limit the usage of the Wasm memory
    /// by the canister to leave some room in 4GiB for upgrade calls.
    /// See the interface specification for more information.
    pub wasm_memory_limit: Option<NumBytes>,

    /// Next local snapshot id.
    pub next_snapshot_id: u64,

    /// Cumulative memory usage of all snapshots that belong to this canister.
    ///
    /// This amount contributes to the total `memory_usage` of the canister as
    /// reported by `CanisterState::memory_usage`.
    pub snapshots_memory_usage: NumBytes,

    /// Environment variables.
    pub environment_variables: EnvironmentVariables,
}

/// A wrapper around the different canister statuses.
#[derive(Clone, Eq, PartialEq, Debug)]
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

/// The id of a paused execution stored in the execution environment.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct PausedExecutionId(pub u64);

/// Represents a task that needs to be executed before processing canister
/// inputs.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ExecutionTask {
    /// A heartbeat task exists only within an execution round. It is never
    /// serialized.
    Heartbeat,

    /// Canister global timer task.
    /// The task exists only within an execution round, it never gets serialized.
    GlobalTimer,

    /// On low Wasm memory hook.
    /// The task exists only within an execution round, it never gets serialized.
    OnLowWasmMemory,

    /// A paused execution task exists only within an epoch (between
    /// checkpoints). It is never serialized, and it turns into `AbortedExecution`
    /// before the checkpoint or when there are too many long-running executions.
    PausedExecution {
        id: PausedExecutionId,
        /// A copy of the message or task whose execution is being paused.
        input: CanisterMessageOrTask,
    },

    /// A paused `install_code` task exists only within an epoch (between
    /// checkpoints). It is never serialized and turns into `AbortedInstallCode`
    /// before the checkpoint.
    PausedInstallCode(PausedExecutionId),

    /// Any paused execution that doesn't finish until the next checkpoint
    /// becomes an aborted execution that should be retried after the checkpoint.
    /// A paused execution can also be aborted to keep the memory usage low if
    /// there are too many long-running executions.
    AbortedExecution {
        input: CanisterMessageOrTask,
        /// The execution cost that has already been charged from the canister.
        /// Retried execution does not have to pay for it again.
        prepaid_execution_cycles: Cycles,
    },

    /// Any paused `install_code` that doesn't finish until the next checkpoint
    /// becomes an aborted `install_code` that should be retried after the
    /// checkpoint. A paused execution can also be aborted to keep the memory
    /// usage low if there are too many long-running executions.
    AbortedInstallCode {
        message: CanisterCall,
        /// The call ID used by the subnet to identify long running install
        /// code messages.
        call_id: InstallCodeCallId,
        /// The execution cost that has already been charged from the canister.
        /// Retried execution does not have to pay for it again.
        prepaid_execution_cycles: Cycles,
    },
}

impl ExecutionTask {
    pub fn is_hook(&self) -> bool {
        match self {
            Self::OnLowWasmMemory => true,
            Self::Heartbeat
            | Self::GlobalTimer
            | Self::PausedExecution { .. }
            | Self::PausedInstallCode(_)
            | Self::AbortedExecution { .. }
            | Self::AbortedInstallCode { .. } => false,
        }
    }
}

#[derive(Debug)]
pub enum ReservationError {
    InsufficientCycles {
        requested: Cycles,
        available: Cycles,
    },
    ReservedLimitExceed {
        requested: Cycles,
        limit: Cycles,
    },
}

impl SystemState {
    pub fn new_running(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    ) -> Self {
        Self::new_internal(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            CanisterStatus::new_running(),
            WasmChunkStore::new(fd_factory),
        )
    }

    fn new_internal(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
        status: CanisterStatus,
        wasm_chunk_store: WasmChunkStore,
    ) -> Self {
        Self {
            canister_id,
            controllers: btreeset! {controller},
            queues: CanisterQueues::default(),
            cycles_balance: initial_cycles,
            ingress_induction_cycles_debit: Cycles::zero(),
            reserved_balance: Cycles::zero(),
            reserved_balance_limit: None,
            memory_allocation: MemoryAllocation::default(),
            environment_variables: Default::default(),
            wasm_memory_threshold: NumBytes::new(0),
            freeze_threshold,
            status,
            certified_data: Default::default(),
            canister_metrics: CanisterMetrics::default(),
            task_queue: Default::default(),
            global_timer: CanisterTimer::Inactive,
            canister_version: 0,
            canister_history: CanisterHistory::default(),
            wasm_chunk_store,
            log_visibility: Default::default(),
            log_memory_limit: default_aggregate_log_memory_limit(),
            canister_log: CanisterLog::default_aggregate(),
            wasm_memory_limit: None,
            next_snapshot_id: 0,
            snapshots_memory_usage: NumBytes::new(0),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_from_checkpoint(
        controllers: BTreeSet<PrincipalId>,
        canister_id: CanisterId,
        queues: CanisterQueues,
        memory_allocation: MemoryAllocation,
        wasm_memory_threshold: NumBytes,
        freeze_threshold: NumSeconds,
        status: CanisterStatus,
        certified_data: Vec<u8>,
        canister_metrics: CanisterMetrics,
        cycles_balance: Cycles,
        ingress_induction_cycles_debit: Cycles,
        reserved_balance: Cycles,
        reserved_balance_limit: Option<Cycles>,
        task_queue: TaskQueue,
        global_timer: CanisterTimer,
        canister_version: u64,
        canister_history: CanisterHistory,
        wasm_chunk_store_data: PageMap,
        wasm_chunk_store_metadata: WasmChunkStoreMetadata,
        log_visibility: LogVisibilityV2,
        log_memory_limit: NumBytes,
        canister_log: CanisterLog,
        wasm_memory_limit: Option<NumBytes>,
        next_snapshot_id: u64,
        snapshots_memory_usage: NumBytes,
        environment_variables: BTreeMap<String, String>,
        metrics: &dyn CheckpointLoadingMetrics,
    ) -> Self {
        let system_state = Self {
            controllers,
            canister_id,
            queues,
            memory_allocation,
            wasm_memory_threshold,
            freeze_threshold,
            status,
            certified_data,
            canister_metrics,
            cycles_balance,
            ingress_induction_cycles_debit,
            reserved_balance,
            reserved_balance_limit,
            task_queue,
            global_timer,
            canister_version,
            canister_history,
            wasm_chunk_store: WasmChunkStore::from_checkpoint(
                wasm_chunk_store_data,
                wasm_chunk_store_metadata,
            ),
            log_visibility,
            log_memory_limit,
            canister_log,
            wasm_memory_limit,
            next_snapshot_id,
            snapshots_memory_usage,
            environment_variables: EnvironmentVariables::new(environment_variables),
        };
        system_state.check_invariants().unwrap_or_else(|msg| {
            metrics.observe_broken_soft_invariant(msg);
        });
        system_state
    }

    pub fn new_running_for_testing(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
    ) -> Self {
        Self::new_for_testing(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            CanisterStatus::new_running(),
        )
    }

    pub fn new_stopping_for_testing(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
    ) -> Self {
        Self::new_for_testing(
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

    pub fn new_stopped_for_testing(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
    ) -> Self {
        Self::new_for_testing(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            CanisterStatus::Stopped,
        )
    }

    fn new_for_testing(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
        status: CanisterStatus,
    ) -> Self {
        Self::new_internal(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            status,
            WasmChunkStore::new_for_testing(),
        )
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    /// Returns the amount of cycles that the balance holds.
    pub fn balance(&self) -> Cycles {
        self.cycles_balance
    }

    /// Returns the balance after applying the pending 'ingress_induction_cycles_debit'.
    /// Returns 0 if the balance is smaller than the pending 'ingress_induction_cycles_debit'.
    pub fn debited_balance(&self) -> Cycles {
        // We rely on saturating operations of `Cycles` here.
        self.cycles_balance - self.ingress_induction_cycles_debit
    }

    /// Returns the pending 'ingress_induction_cycles_debit'.
    pub fn ingress_induction_cycles_debit(&self) -> Cycles {
        self.ingress_induction_cycles_debit
    }

    /// Returns resource reservation cycles.
    pub fn reserved_balance(&self) -> Cycles {
        self.reserved_balance
    }

    /// Returns the user-specified upper limit on `reserved_balance`.
    pub fn reserved_balance_limit(&self) -> Option<Cycles> {
        self.reserved_balance_limit
    }

    /// Sets the user-specified upper limit on `reserved_balance()`.
    pub fn set_reserved_balance_limit(&mut self, limit: Cycles) {
        self.reserved_balance_limit = Some(limit);
    }

    /// Get new local snapshot ID.
    pub fn new_local_snapshot_id(&mut self) -> u64 {
        let local_snapshot_id = self.next_snapshot_id;
        self.next_snapshot_id += 1;
        local_snapshot_id
    }

    /// Records the given amount as debit that will be charged from the balance
    /// at some point in the future.
    ///
    /// Precondition:
    /// - `charge <= self.debited_balance()`.
    pub fn add_postponed_charge_to_ingress_induction_cycles_debit(&mut self, charge: Cycles) {
        assert!(
            charge <= self.debited_balance(),
            "Insufficient cycles for a postponed charge: {} vs {}",
            charge,
            self.debited_balance()
        );
        self.ingress_induction_cycles_debit += charge;
    }

    /// Removes a previously postponed charge for ingress messages from the balance
    /// of the canister.
    ///
    /// Note that this will saturate the balance to zero if the charge to remove is
    /// larger than the current debit.
    pub fn remove_charge_from_ingress_induction_cycles_debit(&mut self, charge: Cycles) {
        self.ingress_induction_cycles_debit -= charge;
    }

    /// Charges the pending 'ingress_induction_cycles_debit' from the balance.
    ///
    /// Precondition:
    /// - The balance is large enough to cover the debit.
    pub fn apply_ingress_induction_cycles_debit(
        &mut self,
        canister_id: CanisterId,
        log: &ReplicaLogger,
        charging_from_balance_error: &IntCounter,
    ) {
        // We rely on saturating operations of `Cycles` here.
        let remaining_debit = self.ingress_induction_cycles_debit - self.cycles_balance;
        debug_assert_eq!(remaining_debit.get(), 0);
        if remaining_debit.get() > 0 {
            // This case is unreachable and may happen only due to a bug: if the
            // caller has reduced the cycles balance below the cycles debit.
            charging_from_balance_error.inc();
            error!(
                log,
                "[EXC-BUG]: Debited cycles exceed the cycles balance of {} by {} in install_code",
                canister_id,
                remaining_debit,
            );
            // Continue the execution by dropping the remaining debit, which makes
            // some of the postponed charges free.
        }
        self.remove_cycles(
            self.ingress_induction_cycles_debit,
            CyclesUseCase::IngressInduction,
        );
        self.ingress_induction_cycles_debit = Cycles::zero();
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

    /// Returns a reference to the `CallContextManager` in a `Running` or `Stopping`
    /// canister.
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

    /// Creates a new call context and returns its ID. Returns an error if the
    /// canister is `Stopped`.
    pub fn new_call_context(
        &mut self,
        call_origin: CallOrigin,
        cycles: Cycles,
        time: Time,
        metadata: RequestMetadata,
    ) -> Result<CallContextId, StateError> {
        Ok(call_context_manager_mut(&mut self.status)
            .ok_or(StateError::CanisterStopped(self.canister_id))?
            .new_call_context(call_origin, cycles, time, metadata))
    }

    /// Withdraws cycles from the call context with the given ID.
    ///
    /// Returns a reference to the `CallContext` if successful. Returns an error
    /// message if the canister is `Stopped`; the call context does not exist; or
    /// if the call context does not have enough cycles.
    pub fn withdraw_cycles(
        &mut self,
        call_context_id: CallContextId,
        cycles: Cycles,
    ) -> Result<&CallContext, &str> {
        call_context_manager_mut(&mut self.status)
            .ok_or("Canister is stopped")?
            .withdraw_cycles(call_context_id, cycles)
    }

    /// Accepts a canister result for the given `CallContext` and produces an action
    /// that should be taken by the caller; and the call context, if completed.
    pub fn on_canister_result(
        &mut self,
        call_context_id: CallContextId,
        callback_id: Option<CallbackId>,
        result: Result<Option<WasmResult>, HypervisorError>,
        instructions_used: NumInstructions,
    ) -> Result<(CallContextAction, Option<CallContext>), StateError> {
        Ok(call_context_manager_mut(&mut self.status)
            .ok_or(StateError::CanisterStopped(self.canister_id))?
            .on_canister_result(call_context_id, callback_id, result, instructions_used))
    }

    /// Marks all call contexts as deleted and produces reject responses for the
    /// not yet responded ones. This is called as part of uninstalling a canister.
    ///
    /// Callbacks will be unregistered when responses are received.
    pub fn delete_all_call_contexts<R>(
        &mut self,
        reject: impl Fn(&CallContext) -> Option<R>,
    ) -> Vec<R> {
        call_context_manager_mut(&mut self.status)
            .map(|call_context_manager| call_context_manager.delete_all_call_contexts(reject))
            .unwrap_or_default()
    }

    /// Registers a callback and returns its ID. Returns an error if the canister is
    /// `Stopped`.
    //
    // TODO: Check whether this could be done implicitly, when pushing an outbound
    // request.
    pub fn register_callback(&mut self, callback: Callback) -> Result<CallbackId, StateError> {
        Ok(call_context_manager_mut(&mut self.status)
            .ok_or(StateError::CanisterStopped(self.canister_id))?
            .register_callback(callback))
    }

    /// Unregisters the callback with the given ID (when a response was received for
    /// it) and returns the callback. Returns an error if the canister is `Stopped`.
    pub fn unregister_callback(
        &mut self,
        callback_id: CallbackId,
    ) -> Result<Option<Arc<Callback>>, StateError> {
        Ok(call_context_manager_mut(&mut self.status)
            .ok_or(StateError::CanisterStopped(self.canister_id))?
            .unregister_callback(callback_id))
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

    /// See documentation for [`CanisterQueues::reject_subnet_output_request`].
    pub fn reject_subnet_output_request(
        &mut self,
        request: Request,
        reject_context: RejectContext,
        subnet_ids: &BTreeSet<PrincipalId>,
    ) -> Result<(), StateError> {
        assert_eq!(
            request.sender, self.canister_id,
            "Expected `Request` to have been sent from canister ID {}, but instead got {}",
            self.canister_id, request.sender
        );
        self.queues
            .reject_subnet_output_request(request, reject_context, subnet_ids)
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
    pub(crate) fn pop_input(&mut self) -> Option<CanisterMessage> {
        Some(match self.queues.pop_input()? {
            CanisterInput::Ingress(msg) => CanisterMessage::Ingress(msg),
            CanisterInput::Request(msg) => CanisterMessage::Request(msg),
            CanisterInput::Response(msg) => CanisterMessage::Response(msg),
            CanisterInput::DeadlineExpired(callback_id) => {
                self.to_reject_response(callback_id, "Call deadline has expired.")
            }
            CanisterInput::ResponseDropped(callback_id) => {
                self.to_reject_response(callback_id, "Response was dropped.")
            }
        })
    }

    /// Generates a reject response for the given callback ID with the given
    /// message.
    ///
    /// If the `CallContextManager` does not hold a callback with the given
    /// `CallbackId`, generates a reject response with arbitrary values (but
    /// matching `CallbackId`). The missing callback will generate a critical error
    /// when the response is about to be executed, regardless.
    fn to_reject_response(&self, callback_id: CallbackId, message: &str) -> CanisterMessage {
        const UNKNOWN_CANISTER_ID: CanisterId =
            CanisterId::unchecked_from_principal(PrincipalId::new_anonymous());
        const SOME_DEADLINE: CoarseTime = CoarseTime::from_secs_since_unix_epoch(1);

        let call_context_manager = self.call_context_manager().unwrap();
        let (originator, respondent, deadline) =
            match call_context_manager.callbacks().get(&callback_id) {
                // Populate reject responses from the callback.
                Some(callback) => (callback.originator, callback.respondent, callback.deadline),

                // This should be unreachable, but if we somehow end up here, we can populate
                // the reject response with arbitrary values, as trying to execute it it will
                // fail anyway and produce a critical error. This is safer than panicking.
                None => (UNKNOWN_CANISTER_ID, UNKNOWN_CANISTER_ID, SOME_DEADLINE),
            };

        CanisterMessage::Response(
            Response {
                originator,
                respondent,
                originator_reply_callback: callback_id,
                refund: Cycles::zero(),
                response_payload: Payload::Reject(RejectContext::new_with_message_length_limit(
                    RejectCode::SysUnknown,
                    message,
                    MR_SYNTHETIC_REJECT_MESSAGE_MAX_LEN,
                )),
                deadline,
            }
            .into(),
        )
    }

    /// Returns true if there are messages in the input queues, false otherwise.
    pub fn has_input(&self) -> bool {
        self.queues.has_input()
    }

    /// Pushes a `RequestOrResponse` into the induction pool.
    ///
    /// If the message is a `Request`, reserves a slot in the corresponding output
    /// queue for the eventual response; and guaranteed response memory for the
    /// maximum `Response` size if it's a guaranteed response. If it is a `Response`,
    /// the protocol should have already reserved a slot and memory for it.
    ///
    /// Updates `subnet_available_guaranteed_response_memory` to reflect any change
    /// in memory usage.
    ///
    /// # Notes
    ///  * `Running` system states accept requests and responses.
    ///  * `Stopping` system states accept responses only.
    ///  * `Stopped` system states accept neither.
    ///
    /// # Returns
    ///  * `Ok(true)` on successful induction of a message of any type.
    ///  * `Ok(false)` for a best-effort `Response` that was silently dropped.
    ///  * `Err(_)` on induction failure.
    ///
    /// # Errors
    ///
    /// On failure, returns the provided message along with a `StateError`:
    ///  * `QueueFull` if either the input queue or the matching output queue is
    ///    full when pushing a `Request`;
    ///  * `CanisterOutOfCycles` if the canister does not have enough cycles.
    ///  * `OutOfMemory` if the necessary guaranteed response memory reservation
    ///    is larger than `subnet_available_guaranteed_response_memory`.
    ///  * `CanisterStopping` if the canister is stopping and inducting a
    ///    `Request` was attempted.
    ///  * `CanisterStopped` if the canister is stopped.
    ///  * `NonMatchingResponse` if no response is expected, the callback is not
    ///    found, the respondent does not match or this is a duplicate guaranteed
    ///    response.
    pub(crate) fn push_input(
        &mut self,
        msg: RequestOrResponse,
        subnet_available_guaranteed_response_memory: &mut i64,
        own_subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<bool, (StateError, RequestOrResponse)> {
        #[cfg(debug_assertions)]
        let balance_before = self.balance_with_messages(None, Some(msg.cycles()));

        let res = self.push_input_impl(
            msg,
            subnet_available_guaranteed_response_memory,
            own_subnet_type,
            input_queue_type,
        );

        #[cfg(debug_assertions)]
        self.assert_balance_with_messages(
            balance_before,
            None,
            res.as_ref().err().map(|(_, msg)| msg.cycles()),
        );

        res
    }

    /// Implementation of `push_input`. Separated, to make it easier to write debug
    /// assertions.
    fn push_input_impl(
        &mut self,
        msg: RequestOrResponse,
        subnet_available_guaranteed_response_memory: &mut i64,
        own_subnet_type: SubnetType,
        input_queue_type: InputQueueType,
    ) -> Result<bool, (StateError, RequestOrResponse)> {
        assert_eq!(
            msg.receiver(),
            self.canister_id,
            "Expected `RequestOrResponse` to be targeted to canister ID {}, but instead got {}",
            self.canister_id,
            msg.receiver()
        );

        match (&msg, &self.status) {
            // Best-effort responses are silently dropped when stopped.
            (RequestOrResponse::Response(response), CanisterStatus::Stopped)
                if response.is_best_effort() =>
            {
                self.credit_refund(response);
                Ok(false)
            }

            // Requests and guaranteed responses are both rejected when stopped.
            (_, CanisterStatus::Stopped) => {
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
                if let RequestOrResponse::Response(response) = &msg
                    && !has_callback(
                        response,
                        call_context_manager,
                        self.aborted_or_paused_response(),
                    )
                    .map_err(|err| (err, msg.clone()))?
                {
                    // Best effort response whose callback is gone. Silently drop it.
                    self.credit_refund(response);
                    return Ok(false);
                }
                push_input(
                    &mut self.queues,
                    msg,
                    subnet_available_guaranteed_response_memory,
                    own_subnet_type,
                    input_queue_type,
                )
                .map(|dropped| {
                    if let Some(response) = dropped {
                        // Duplicate best-effort response that was silently dropped.
                        self.credit_refund(&response);
                        false
                    } else {
                        true
                    }
                })
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
    pub fn output_into_iter(&mut self) -> CanisterOutputQueuesIterator<'_> {
        self.queues.output_into_iter()
    }

    /// Returns an immutable reference to the canister queues.
    pub fn queues(&self) -> &CanisterQueues {
        &self.queues
    }

    /// Transitions the canister into `Running` state. Returns the pending stop
    /// contexts if the canister was previously in `Stopping` state.
    pub fn start_canister(&mut self) -> Vec<StopCanisterContext> {
        match &mut self.status {
            CanisterStatus::Running { .. } => Vec::new(),

            CanisterStatus::Stopping {
                call_context_manager,
                stop_contexts,
            } => {
                let stop_contexts = std::mem::take(stop_contexts);
                self.status = CanisterStatus::Running {
                    call_context_manager: std::mem::take(call_context_manager),
                };
                stop_contexts
            }

            CanisterStatus::Stopped => {
                self.status = CanisterStatus::new_running();
                Vec::new()
            }
        }
    }

    /// Transitions the canister into `Stopping` state.
    ///
    /// If the canister was `Running` or `Stopping`, remembers the stop context, so
    /// that it can be responded to once the canister has fully stopped. If the
    /// canister was already `Stopped`, returns the stop context.
    pub fn begin_stopping(
        &mut self,
        stop_context: StopCanisterContext,
    ) -> Option<StopCanisterContext> {
        match &mut self.status {
            // Return the stop context, nothing to do here.
            CanisterStatus::Stopped => Some(stop_context),

            CanisterStatus::Stopping { stop_contexts, .. } => {
                // Add the message so we can respond to it once the canister has fully stopped.
                stop_contexts.push(stop_context);
                None
            }

            CanisterStatus::Running {
                call_context_manager,
            } => {
                // Transition the canister into the stopping state.
                self.status = CanisterStatus::Stopping {
                    call_context_manager: std::mem::take(call_context_manager),
                    // Track the stop message to respond to it once the canister is fully stopped.
                    stop_contexts: vec![stop_context],
                };
                None
            }
        }
    }

    /// Tries to transition a `Stopping` canister into the `Stopped` state. No-op if
    /// the canister is `Running` or already `Stopped`.
    ///
    /// Returns a tuple of:
    ///  * a boolean indicating whether the canister has stopped,
    ///  * all stop contexts if the canister has stopped; or the expired stop
    ///    contexts only if the canister is still stopping.
    #[must_use]
    pub fn try_stop_canister(
        &mut self,
        is_expired: impl Fn(&StopCanisterContext) -> bool,
    ) -> (bool, Vec<StopCanisterContext>) {
        match self.status {
            // Canister is not stopping so we can skip it.
            CanisterStatus::Running { .. } | CanisterStatus::Stopped => (false, Vec::new()),

            // Canister is ready to stop.
            CanisterStatus::Stopping {
                ref call_context_manager,
                ref mut stop_contexts,
            } if call_context_manager.callbacks().is_empty()
                && call_context_manager.call_contexts().is_empty() =>
            {
                let stop_contexts = std::mem::take(stop_contexts);

                // Transition the canister to "stopped".
                self.status = CanisterStatus::Stopped;

                // Reply to all pending stop_canister requests.
                (true, stop_contexts)
            }

            // Canister is stopping, but not yet ready to stop.
            CanisterStatus::Stopping {
                ref mut stop_contexts,
                ..
            } => {
                // Return any stop contexts that have timed out.
                let mut expired_stop_contexts = Vec::new();
                stop_contexts.retain(|stop_context| {
                    if is_expired(stop_context) {
                        expired_stop_contexts.push(stop_context.clone());
                        false
                    } else {
                        true
                    }
                });
                (false, expired_stop_contexts)
            }
        }
    }

    /// Tests whether the system state is ready to transition to `Stopped`.
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

    /// Returns the canister status as a `CanisterStatusType`.
    pub fn status(&self) -> CanisterStatusType {
        match self.status {
            CanisterStatus::Running { .. } => CanisterStatusType::Running,
            CanisterStatus::Stopping { .. } => CanisterStatusType::Stopping,
            CanisterStatus::Stopped => CanisterStatusType::Stopped,
        }
    }

    /// Returns the canister status.
    pub fn get_status(&self) -> &CanisterStatus {
        &self.status
    }

    /// Returns the canister status as a string.
    pub fn status_string(&self) -> &'static str {
        match self.status {
            CanisterStatus::Running { .. } => "Running",
            CanisterStatus::Stopping { .. } => "Stopping",
            CanisterStatus::Stopped => "Stopped",
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
        // Remove aborted install code task.
        self.task_queue.remove_aborted_install_code_task();

        // Roll back `Stopping` canister states to `Running` and drop all their stop
        // contexts (the calls corresponding to the dropped stop contexts will be
        // rejected by subnet A').
        match self.status {
            CanisterStatus::Running { .. } | CanisterStatus::Stopped => {}
            CanisterStatus::Stopping {
                ref mut call_context_manager,
                ..
            } => {
                self.status = CanisterStatus::Running {
                    call_context_manager: std::mem::take(call_context_manager),
                }
            }
        }
    }

    /// See `IngressQueue::filter_messages()` for documentation.
    pub fn filter_ingress_messages<F>(&mut self, filter: F) -> Vec<Arc<Ingress>>
    where
        F: FnMut(&Arc<Ingress>) -> bool,
    {
        self.queues.filter_ingress_messages(filter)
    }

    /// Returns the memory currently used by or reserved for guaranteed response
    /// canister messages.
    pub fn guaranteed_response_message_memory_usage(&self) -> NumBytes {
        (self.queues.guaranteed_response_memory_usage() as u64).into()
    }

    /// Returns the memory currently used by best-effort canister messages.
    ///
    /// This returns zero iff there are zero best-effort messages enqueued.
    pub fn best_effort_message_memory_usage(&self) -> NumBytes {
        (self.queues.best_effort_message_memory_usage() as u64).into()
    }

    /// Returns the memory currently in use by the `SystemState`
    /// for canister history.
    pub fn canister_history_memory_usage(&self) -> NumBytes {
        self.canister_history.get_memory_usage()
    }

    /// Method used only by the dashboard.
    pub fn collect_controllers_as_string(&self) -> String {
        self.controllers
            .iter()
            .map(|id| format!("{id}"))
            .collect::<Vec<String>>()
            .join(" ")
    }

    /// Inducts messages from the output queue to `self` into the input queue
    /// from `self` while respecting queue capacity and the provided subnet
    /// available guaranteed response message memory.
    ///
    /// `subnet_available_guaranteed_response_memory` is updated to reflect the
    /// change in `self.queues` guaranteed response message memory usage.
    ///
    /// Available memory is ignored (but updated) for system subnets, since we
    /// don't want to DoS system canisters due to lots of incoming requests.
    pub fn induct_messages_to_self(
        &mut self,
        subnet_available_guaranteed_response_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) {
        #[cfg(debug_assertions)]
        let balance_before = self.balance_with_messages(None, None);

        self.induct_messages_to_self_impl(
            subnet_available_guaranteed_response_memory,
            own_subnet_type,
        );

        #[cfg(debug_assertions)]
        self.assert_balance_with_messages(balance_before, None, None);
    }

    /// Implementation of `induct_messages_to_self`. Separated, to make it easier to
    /// write debug assertions.
    fn induct_messages_to_self_impl(
        &mut self,
        subnet_available_guaranteed_response_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) {
        // Bail out if the canister is not running.
        let call_context_manager = match &self.status {
            CanisterStatus::Running {
                call_context_manager,
            } => call_context_manager,
            CanisterStatus::Stopped | CanisterStatus::Stopping { .. } => return,
        };

        let mut guaranteed_response_memory_usage =
            self.queues.guaranteed_response_memory_usage() as i64;

        while let Some(msg) = self.queues.peek_output(&self.canister_id) {
            // Ensure that enough memory is available for inducting `msg`.
            if own_subnet_type != SubnetType::System
                && can_push(msg, *subnet_available_guaranteed_response_memory).is_err()
            {
                return;
            }

            // Protect against enqueuing duplicate responses.
            if let RequestOrResponse::Response(response) = &msg {
                match has_callback(
                    response,
                    call_context_manager,
                    self.aborted_or_paused_response(),
                ) {
                    // Safe to induct.
                    Ok(true) => {}

                    // Best effort response whose callback is gone. Silently drop it.
                    Ok(false) => {
                        // Borrow checker does not allow calling `credit_refund()` here.
                        self.cycles_balance += response.refund;
                        self.queues
                            .pop_canister_output(&self.canister_id)
                            .expect("Message peeked above so pop should not fail.");
                        continue;
                    }

                    // This should not happen. Bail out and let Message Routing deal with it.
                    Err(e) => {
                        debug_assert!(false, "Failed to induct message to self: {e:?}");
                        return;
                    }
                }
            }

            match self.queues.induct_message_to_self(self.canister_id) {
                // Message successfully inducted.
                Ok(None) => {}
                // Silently dropped duplicate best-effort response.
                Ok(Some(response)) => {
                    // Borrow checker does not allow calling `credit_refund()` here.
                    self.cycles_balance += response.refund;
                }
                // Full input queue.
                Err(_) => return,
            }

            // Adjust `subnet_available_guaranteed_response_memory` by `memory_usage_before
            // - memory_usage_after`. Defer the accounting to `CanisterQueues`, to avoid
            // duplication or divergence.
            *subnet_available_guaranteed_response_memory += guaranteed_response_memory_usage;
            guaranteed_response_memory_usage =
                self.queues.guaranteed_response_memory_usage() as i64;
            *subnet_available_guaranteed_response_memory -= guaranteed_response_memory_usage;
        }
    }

    /// Garbage collects empty input and output queue pairs.
    pub fn garbage_collect_canister_queues(&mut self) {
        self.queues.garbage_collect();
    }

    /// Queries whether any of the `OutputQueues` in `self.queues` hold messages
    /// with expired deadlines in them.
    pub fn has_expired_message_deadlines(&self, current_time: Time) -> bool {
        self.queues.has_expired_deadlines(current_time)
    }

    /// Drops expired messages given a current time.
    ///
    /// See [`CanisterQueues::time_out_messages`] for further details.
    pub fn time_out_messages(
        &mut self,
        current_time: Time,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
        refunds: &mut RefundPool,
        metrics: &impl DroppedMessageMetrics,
    ) {
        #[cfg(debug_assertions)]
        let balance_before = self.balance_with_messages(Some(refunds), None);

        self.queues.time_out_messages(
            current_time,
            own_canister_id,
            local_canisters,
            refunds,
            metrics,
        );

        #[cfg(debug_assertions)]
        self.assert_balance_with_messages(balance_before, Some(refunds), None);
    }

    /// Queries whether the `CallContextManager` in `self.state` holds any not
    /// previouosly expired (i.e. returned by `time_out_callbacks()`) callbacks with
    /// deadlines `< current_time`.
    pub fn has_expired_callbacks(&self, current_time: CoarseTime) -> bool {
        self.call_context_manager()
            .map(|ccm| ccm.has_expired_callbacks(current_time))
            .unwrap_or(false)
    }

    /// Enqueues "deadline expired" references for all expired best-effort callbacks
    /// without a response.
    ///
    /// Returns the number of expired callbacks; plus one `StateError` for every
    /// instance where a `SystemState` internal inconsistency prevented a "deadline
    /// expired" reference from being enqueued.
    #[must_use]
    pub fn time_out_callbacks(
        &mut self,
        current_time: CoarseTime,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> (usize, Vec<StateError>) {
        if self.status == CanisterStatus::Stopped {
            // Stopped canisters have no call context manager, so no callbacks.
            return (0, Vec::new());
        }

        let aborted_or_paused_callback_id = self
            .aborted_or_paused_response()
            .map(|response| response.originator_reply_callback);

        // Safe to unwrap because we just checked that the status is not `Stopped`.
        let call_context_manager = call_context_manager_mut(&mut self.status).unwrap();

        let mut expired_callback_count = 0;
        let mut errors = Vec::new();
        let expired_callbacks = call_context_manager
            .expire_callbacks(current_time)
            .collect::<Vec<_>>();
        for callback_id in expired_callbacks {
            if Some(callback_id) == aborted_or_paused_callback_id {
                // This callback is already executing, don't produce a second response for it.
                continue;
            }

            // Safe to unwrap because this is a callback ID we just got from the
            // `CallContextManager`.
            let callback = call_context_manager.callbacks().get(&callback_id).unwrap();
            self.queues
                .try_push_deadline_expired_input(
                    callback_id,
                    &callback.respondent,
                    own_canister_id,
                    local_canisters,
                )
                .map(|pushed| {
                    if pushed {
                        expired_callback_count += 1;
                    }
                })
                .unwrap_or_else(|err_str| {
                    errors.push(StateError::NonMatchingResponse {
                        err_str,
                        originator: callback.originator,
                        callback_id,
                        respondent: callback.respondent,
                        deadline: callback.deadline,
                    });
                    expired_callback_count += 1;
                });
        }

        (expired_callback_count, errors)
    }

    /// Removes the largest best-effort message in the underlying pool. Returns
    /// `true` if a message was removed; `false` otherwise.
    ///
    /// Enqueues a refund message if the shed message had attached cycles and no
    /// reject response refunding the cycles was enqueued.
    ///
    /// Time complexity: `O(log(n))`.
    pub fn shed_largest_message(
        &mut self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
        refunds: &mut RefundPool,
        metrics: &impl DroppedMessageMetrics,
    ) -> bool {
        #[cfg(debug_assertions)]
        let balance_before = self.balance_with_messages(Some(refunds), None);

        let message_shed =
            self.queues
                .shed_largest_message(own_canister_id, local_canisters, refunds, metrics);

        #[cfg(debug_assertions)]
        self.assert_balance_with_messages(balance_before, Some(refunds), None);

        message_shed
    }

    /// Re-partitions the local and remote input schedules of `self.queues`
    /// following a canister migration, based on the updated set of local canisters.
    ///
    /// See [`CanisterQueues::split_input_schedules`] for further details.
    pub(crate) fn split_input_schedules(
        &mut self,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) {
        self.queues
            .split_input_schedules(own_canister_id, local_canisters);
    }

    /// Credits the canister with the refund in the inbound `Response`.
    fn credit_refund(&mut self, response: &Response) {
        debug_assert_eq!(
            self.canister_id, response.originator,
            "Can only credit refunds from `Responses` originating from self ({}), got {:?}",
            self.canister_id, response
        );
        debug_assert!(response.is_best_effort());

        if !response.refund.is_zero() {
            self.add_cycles(response.refund, CyclesUseCase::NonConsumed);
        }
    }

    /// Increments 'cycles_balance' and in case of refund for consumed cycles
    /// decrements the metric `consumed_cycles`.
    pub fn add_cycles(&mut self, amount: Cycles, use_case: CyclesUseCase) {
        self.cycles_balance += amount;
        self.observe_consumed_cycles_with_use_case(amount, use_case, ConsumingCycles::No);
    }

    /// Decreases 'cycles_balance' for 'requested_amount'.
    /// The resource use cases first drain the `reserved_balance` and only after
    /// that drain the main `cycles_balance`.
    pub fn remove_cycles(&mut self, requested_amount: Cycles, use_case: CyclesUseCase) {
        let remaining_amount = match use_case {
            CyclesUseCase::Memory | CyclesUseCase::ComputeAllocation | CyclesUseCase::Uninstall => {
                let covered_by_reserved_balance = requested_amount.min(self.reserved_balance);
                self.reserved_balance -= covered_by_reserved_balance;
                requested_amount - covered_by_reserved_balance
            }
            CyclesUseCase::IngressInduction
            | CyclesUseCase::Instructions
            | CyclesUseCase::RequestAndResponseTransmission
            | CyclesUseCase::CanisterCreation
            | CyclesUseCase::ECDSAOutcalls
            | CyclesUseCase::SchnorrOutcalls
            | CyclesUseCase::VetKd
            | CyclesUseCase::HTTPOutcalls
            | CyclesUseCase::DeletedCanisters
            | CyclesUseCase::NonConsumed
            | CyclesUseCase::BurnedCycles
            | CyclesUseCase::DroppedMessages => requested_amount,
        };
        self.cycles_balance -= remaining_amount;
        self.observe_consumed_cycles_with_use_case(
            requested_amount,
            use_case,
            ConsumingCycles::Yes,
        );
    }

    /// Checks if the given amount of cycles from the main balance can be moved to the reserved balance.
    /// The provided `main_balance` might be lower than `self.cycles_balance` when this function is used to perform validation before cycles are actually consumed.
    /// Returns an error if the main balance is lower than the requested amount.
    pub fn can_reserve_cycles(
        &self,
        amount: Cycles,
        main_balance: Cycles,
    ) -> Result<(), ReservationError> {
        if amount == Cycles::zero() {
            return Ok(());
        }

        if let Some(limit) = self.reserved_balance_limit {
            let requested = self.reserved_balance + amount;
            if requested > limit {
                return Err(ReservationError::ReservedLimitExceed { requested, limit });
            }
        }

        if amount > main_balance {
            Err(ReservationError::InsufficientCycles {
                requested: amount,
                available: main_balance,
            })
        } else {
            Ok(())
        }
    }

    /// Moves the given amount of cycles from the main balance to the reserved balance.
    /// Returns an error if the main balance is lower than the requested amount.
    pub fn reserve_cycles(&mut self, amount: Cycles) -> Result<(), ReservationError> {
        self.can_reserve_cycles(amount, self.cycles_balance)?;
        self.cycles_balance -= amount;
        self.reserved_balance += amount;
        Ok(())
    }

    /// Removes all cycles from `cycles_balance` and `reserved_balance` as part
    /// of canister uninstallation due to it running out of cycles.
    pub fn burn_remaining_balance_for_uninstall(&mut self) {
        let balance = self.cycles_balance + self.reserved_balance;
        self.remove_cycles(balance, CyclesUseCase::Uninstall);
    }

    fn observe_consumed_cycles_with_use_case(
        &mut self,
        amount: Cycles,
        use_case: CyclesUseCase,
        consuming_cycles: ConsumingCycles,
    ) {
        // The use cases below are not valid on the canister
        // level, they should only appear on the subnet level.
        debug_assert_ne!(use_case, CyclesUseCase::ECDSAOutcalls);
        debug_assert_ne!(use_case, CyclesUseCase::HTTPOutcalls);
        debug_assert_ne!(use_case, CyclesUseCase::DeletedCanisters);
        debug_assert_ne!(use_case, CyclesUseCase::DroppedMessages);

        if use_case == CyclesUseCase::NonConsumed || amount.is_zero() {
            return;
        }

        let metric: &mut BTreeMap<CyclesUseCase, NominalCycles> =
            &mut self.canister_metrics.consumed_cycles_by_use_cases;

        let use_case_consumption = metric
            .entry(use_case)
            .or_insert_with(|| NominalCycles::from(0));

        let nominal_amount = amount.into();

        match consuming_cycles {
            ConsumingCycles::Yes => {
                *use_case_consumption += nominal_amount;
                self.canister_metrics.consumed_cycles += nominal_amount;
            }
            ConsumingCycles::No => {
                *use_case_consumption -= nominal_amount;
                self.canister_metrics.consumed_cycles -= nominal_amount;
            }
        }
    }

    /// Clears all canister changes and their memory usage,
    /// but keeps the total number of changes recorded.
    pub fn clear_canister_history(&mut self) {
        self.canister_history.clear();
    }

    /// Adds a canister change to canister history.
    /// The canister version of the newly added canister change is
    /// taken directly from the `SystemState`.
    pub fn add_canister_change(
        &mut self,
        timestamp_nanos: Time,
        change_origin: CanisterChangeOrigin,
        change_details: CanisterChangeDetails,
    ) {
        let new_change = CanisterChange::new(
            timestamp_nanos.as_nanos_since_unix_epoch(),
            self.canister_version,
            change_origin,
            change_details,
        );
        self.canister_history.add_canister_change(new_change);
    }

    /// Overwrite the `total_num_changes` of the canister history. This can happen in the context of canister migration.
    pub fn set_canister_history_total_num_changes(&mut self, total_num_changes: u64) {
        self.canister_history
            .set_total_num_changes(total_num_changes);
    }

    pub fn get_canister_history(&self) -> &CanisterHistory {
        &self.canister_history
    }

    /// Checks the invariants that should hold at the end of each consensus round.
    pub fn check_invariants(&self) -> Result<(), String> {
        // Callbacks still awaiting a (potentially already enqueued) response.
        let pending_callbacks = self
            .call_context_manager()
            .map(|ccm| ccm.unresponded_callback_count(self.aborted_or_paused_response()))
            .unwrap_or_default();

        let input_queue_responses = self.queues.input_queues_response_count();
        let input_queue_reserved_slots = self.queues.input_queues_reserved_slots();

        if pending_callbacks != input_queue_reserved_slots + input_queue_responses {
            return Err(format!(
                "Invariant broken: Canister {}: Number of callbacks ({}) is different from the cumulative number of reservations and responses ({})",
                self.canister_id(),
                pending_callbacks,
                input_queue_reserved_slots + input_queue_responses
            ));
        }

        let unresponded_call_contexts = self
            .call_context_manager()
            .map(|ccm| {
                ccm.unresponded_canister_update_call_contexts(self.aborted_or_paused_request())
            })
            .unwrap_or_default();

        let input_queue_requests = self.queues.input_queues_request_count();
        let output_queue_reserved_slots = self.queues.output_queues_reserved_slots();

        if input_queue_requests + unresponded_call_contexts != output_queue_reserved_slots {
            return Err(format!(
                "Invariant broken: Canister {}: Number of output queue reserved slots ({}) is different from the cumulative number of input requests and unresponded call contexts ({})",
                self.canister_id(),
                output_queue_reserved_slots,
                input_queue_requests + unresponded_call_contexts
            ));
        }

        Ok(())
    }

    /// Returns the aborted or paused `Response` at the head of the task queue, if
    /// any.
    fn aborted_or_paused_response(&self) -> Option<&Response> {
        match self.task_queue.front() {
            Some(ExecutionTask::AbortedExecution {
                input: CanisterMessageOrTask::Message(CanisterMessage::Response(response)),
                ..
            })
            | Some(ExecutionTask::PausedExecution {
                input: CanisterMessageOrTask::Message(CanisterMessage::Response(response)),
                ..
            }) => Some(response),
            _ => None,
        }
    }

    /// Returns the aborted or paused `Request` at the head of the task queue, if
    /// any.
    fn aborted_or_paused_request(&self) -> Option<&Request> {
        match self.task_queue.front() {
            Some(ExecutionTask::AbortedExecution {
                input: CanisterMessageOrTask::Message(CanisterMessage::Request(request)),
                ..
            })
            | Some(ExecutionTask::PausedExecution {
                input: CanisterMessageOrTask::Message(CanisterMessage::Request(request)),
                ..
            }) => Some(request),
            _ => None,
        }
    }

    /// Enqueues or removes `OnLowWasmMemory` task from `task_queue`
    /// depending if the condition for `OnLowWasmMemoryHook` is satisfied:
    ///
    ///   `wasm_memory_threshold > wasm_memory_limit - wasm_memory_usage`
    ///
    /// Note: if `wasm_memory_limit` is not set, its default value is 4 GiB.
    pub fn update_on_low_wasm_memory_hook_status(&mut self, wasm_memory_usage: NumBytes) {
        if self.is_low_wasm_memory_hook_condition_satisfied(wasm_memory_usage) {
            self.task_queue.enqueue(ExecutionTask::OnLowWasmMemory);
        } else {
            self.task_queue.remove(ExecutionTask::OnLowWasmMemory);
        }
    }

    /// Returns the `OnLowWasmMemory` hook status without updating the `task_queue`.
    pub fn is_low_wasm_memory_hook_condition_satisfied(&self, wasm_memory_usage: NumBytes) -> bool {
        let wasm_memory_limit = self.wasm_memory_limit;
        let wasm_memory_threshold = self.wasm_memory_threshold;

        is_low_wasm_memory_hook_condition_satisfied(
            wasm_memory_usage,
            wasm_memory_limit,
            wasm_memory_threshold,
        )
    }

    /// Computes the canister's total cycle balance including cycles attached to
    /// messages in queues; pooled refunds; plus any `extra_cycles` (e.g. messages
    /// being enqueued; or returned wrapped in an `Err`).
    ///
    /// To be used together with `assert_balance_with_messages()` to ensure that no
    /// cycles were lost or duplicated while inducting, timing out or shedding
    /// messages.
    #[cfg(debug_assertions)]
    pub(crate) fn balance_with_messages(
        &self,
        refunds: Option<&RefundPool>,
        extra_cycles: Option<Cycles>,
    ) -> Cycles {
        self.cycles_balance
            + self.queues.attached_cycles()
            + refunds.map(RefundPool::compute_total).unwrap_or_default()
            + extra_cycles.unwrap_or_default()
    }

    /// Validates that the canister's total cycle balance including cycles attached
    /// to messages in queues; pooled refunds, plus any cycles being returned is the
    /// same as `balance_before` (computed at the top of the caller function).
    #[cfg(debug_assertions)]
    fn assert_balance_with_messages(
        &self,
        balance_before: Cycles,
        refunds: Option<&RefundPool>,
        returned_cycles: Option<Cycles>,
    ) {
        let balance_after = self.balance_with_messages(refunds, returned_cycles);
        assert_eq!(
            balance_before, balance_after,
            "Cycles lost or duplicated: before = {balance_before}, after = {balance_after}",
        );
    }
}

/// Implements memory limits verification for pushing a canister-to-canister
/// message into the induction pool of `queues`.
///
/// Returns `StateError::OutOfMemory` if pushing the message would require more
/// memory than `subnet_available_guaranteed_response_memory`.
///
/// `subnet_available_guaranteed_response_memory` is updated to reflect the change
/// in guaranteed response message memory usage after a successful push; and left
/// unmodified if the push failed.
///
/// See `CanisterQueues::push_input()` for further details.
pub(crate) fn push_input(
    queues: &mut CanisterQueues,
    msg: RequestOrResponse,
    subnet_available_guaranteed_response_memory: &mut i64,
    own_subnet_type: SubnetType,
    input_queue_type: InputQueueType,
) -> Result<Option<Arc<Response>>, (StateError, RequestOrResponse)> {
    // Do not enforce limits for local messages on system subnets.
    if (own_subnet_type != SubnetType::System || input_queue_type != InputQueueType::LocalSubnet)
        && let Err(required_memory) = can_push(&msg, *subnet_available_guaranteed_response_memory)
    {
        return Err((
            StateError::OutOfMemory {
                requested: NumBytes::new(required_memory as u64),
                available: *subnet_available_guaranteed_response_memory,
            },
            msg,
        ));
    }

    // But always adjust `subnet_available_guaranteed_response_memory` by
    // `memory_usage_before - memory_usage_after`. Defer the accounting to
    // `CanisterQueues`, to avoid duplication (and the possibility of divergence).
    *subnet_available_guaranteed_response_memory +=
        queues.guaranteed_response_memory_usage() as i64;
    let res = queues.push_input(msg, input_queue_type);
    *subnet_available_guaranteed_response_memory -=
        queues.guaranteed_response_memory_usage() as i64;
    res
}

/// Looks up the `Callback` associated with the given response's `callback_id`
/// and verifies that its respondent, originator and deadline match those of the
/// response.
///
/// Returns:
///
///  * `Ok(true)` if a matching callback was found.
///  * `Ok(false)` (drop silently) when a matching `callback_id` was not found
///    for a best-effort response (because the callback might have expired and
///    been closed; or because the callback is executing -- aborted or paused).
///  * `Err(StateError::NonMatchingResponse)` when a matching `callback_id` was
///    not found for a guaranteed response.
///  * `Err(StateError::NonMatchingResponse)` when a matching `callback_id` was
///    found, but the response details do not match those of the callback.
fn has_callback(
    response: &Response,
    call_context_manager: &CallContextManager,
    aborted_or_paused_response: Option<&Response>,
) -> Result<bool, StateError> {
    let callback = match aborted_or_paused_response {
        Some(aborted_or_paused_response)
            if response.originator_reply_callback
                == aborted_or_paused_response.originator_reply_callback =>
        {
            // A response for the same callback as `aborted_or_paused_response`. In other
            // words, it does not match any unresponded callback.
            None
        }
        _ => call_context_manager.callback(response.originator_reply_callback),
    };

    match callback {
        Some(callback)
            if response.respondent != callback.respondent
                || response.originator != callback.originator
                || response.deadline != callback.deadline =>
        {
            Err(StateError::non_matching_response(
                format!(
                    "invalid details, expected => [originator => {}, respondent => {}, deadline => {}], but got response with",
                    callback.originator,
                    callback.respondent,
                    Time::from(callback.deadline)
                ),
                response,
            ))
        }
        Some(_) => Ok(true),
        None => {
            // Received an unknown callback ID.
            if response.deadline == NO_DEADLINE {
                // This is an error for a guaranteed response.
                Err(StateError::non_matching_response(
                    "unknown callback ID",
                    response,
                ))
            } else {
                // But should be ignored in the case of a best-effort response (as the callback
                // may have expired and been dropped in the meantime).
                Ok(false)
            }
        }
    }
}

/// Helper function to get a mutable reference to the `CallContextManager` when
/// `Running` or `Stopping`, `None` if `Stopped`.
fn call_context_manager_mut(status: &mut CanisterStatus) -> Option<&mut CallContextManager> {
    match status {
        CanisterStatus::Running {
            call_context_manager,
        }
        | CanisterStatus::Stopping {
            call_context_manager,
            ..
        } => Some(call_context_manager),

        CanisterStatus::Stopped => None,
    }
}

pub mod testing {
    pub use super::call_context_manager::testing::*;
    use super::*;
    use ic_types::methods::WasmClosure;

    /// Exposes `SystemState` internals for use in other crates' unit tests.
    pub trait SystemStateTesting {
        /// Testing only: Sets the value of the `canister_id` field.
        fn set_canister_id(&mut self, canister_id: CanisterId);

        /// Testing only: Returns a mutable reference to `self.queues`.
        fn queues_mut(&mut self) -> &mut CanisterQueues;

        /// Testing only: Sets `self.queues` to the given `queues`
        fn put_queues(&mut self, queues: CanisterQueues);

        /// Testing only: pops next input message
        fn pop_input(&mut self) -> Option<CanisterMessage>;

        fn with_call_context(&mut self, call_context: CallContext) -> CallContextId;

        /// Registers a callback for the given respondent, with the given deadline.
        fn with_callback(&mut self, respondent: CanisterId, deadline: CoarseTime) -> CallbackId;

        /// Testing only: sets the canister status.
        fn set_status(&mut self, status: CanisterStatus);

        /// Testing only: Adds a stop context to a stopping canister. Panics if the
        /// canister is not `Stopping`.
        fn add_stop_context(&mut self, stop_context: StopCanisterContext);

        /// Testing only: sets the value of 'cycles_balance'.
        fn set_balance(&mut self, balance: Cycles);

        /// Testing only: repartitions the local and remote input schedules after a
        /// subnet split.
        fn split_input_schedules(
            &mut self,
            own_canister_id: &CanisterId,
            local_canisters: &BTreeMap<CanisterId, CanisterState>,
        );
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

        fn pop_input(&mut self) -> Option<CanisterMessage> {
            self.pop_input()
        }

        fn set_status(&mut self, status: CanisterStatus) {
            self.status = status;
        }

        fn with_call_context(&mut self, call_context: CallContext) -> CallContextId {
            call_context_manager_mut(&mut self.status)
                .unwrap()
                .with_call_context(call_context)
        }

        fn with_callback(&mut self, respondent: CanisterId, deadline: CoarseTime) -> CallbackId {
            let call_context_manager = call_context_manager_mut(&mut self.status).unwrap();
            let time = Time::from_nanos_since_unix_epoch(1);
            let call_context_id = call_context_manager.new_call_context(
                CallOrigin::SystemTask,
                Cycles::zero(),
                time,
                RequestMetadata::new(0, time),
            );

            call_context_manager.register_callback(Callback::new(
                call_context_id,
                self.canister_id,
                respondent,
                Cycles::zero(),
                Cycles::new(42),
                Cycles::new(84),
                WasmClosure::new(0, 2),
                WasmClosure::new(0, 2),
                None,
                deadline,
            ))
        }

        fn add_stop_context(&mut self, stop_context: StopCanisterContext) {
            match &mut self.status {
                CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
                    panic!("Should never add_stop_context to a non-stopping canister.")
                }
                CanisterStatus::Stopping { stop_contexts, .. } => stop_contexts.push(stop_context),
            }
        }

        fn set_balance(&mut self, balance: Cycles) {
            self.cycles_balance = balance;
        }

        fn split_input_schedules(
            &mut self,
            own_canister_id: &CanisterId,
            local_canisters: &BTreeMap<CanisterId, CanisterState>,
        ) {
            self.split_input_schedules(own_canister_id, local_canisters)
        }
    }

    /// Early warning system / stumbling block forcing the authors of changes adding
    /// or removing system state fields to think about and/or ask the Execution
    /// team to think about any repercussions to the canister snapshot logic.
    ///
    /// If you do find yourself having to make changes to this function, it is quite
    /// possible that you have not broken anything. But there is a non-zero chance
    /// for changes to the structure of the system state to also require changes
    /// to the canister snapshot logic or risk breaking it. Which is why this brute
    /// force check exists.
    ///
    /// See `CanisterSnapshot::from_canister()` for more context.
    #[allow(dead_code)]
    fn canister_snapshot_change_guard_do_not_modify_without_reading_doc_comment() {
        //
        // DO NOT MODIFY WITHOUT READING DOC COMMENT!
        //
        let _system_state = SystemState {
            controllers: Default::default(),
            canister_id: 0.into(),
            queues: Default::default(),
            memory_allocation: Default::default(),
            wasm_memory_threshold: Default::default(),
            freeze_threshold: Default::default(),
            status: CanisterStatus::Stopped,
            certified_data: Default::default(),
            canister_metrics: Default::default(),
            cycles_balance: Default::default(),
            ingress_induction_cycles_debit: Default::default(),
            reserved_balance: Default::default(),
            reserved_balance_limit: Default::default(),
            task_queue: Default::default(),
            global_timer: CanisterTimer::Inactive,
            canister_version: Default::default(),
            canister_history: Default::default(),
            wasm_chunk_store: WasmChunkStore::new_for_testing(),
            log_visibility: Default::default(),
            log_memory_limit: default_aggregate_log_memory_limit(),
            canister_log: CanisterLog::default_aggregate(),
            wasm_memory_limit: Default::default(),
            next_snapshot_id: Default::default(),
            snapshots_memory_usage: Default::default(),
            environment_variables: Default::default(),
        };
    }
}
