mod call_context_manager;
pub mod wasm_chunk_store;

use self::wasm_chunk_store::{WasmChunkStore, WasmChunkStoreMetadata};
use super::queues::can_push;
pub use super::queues::memory_required_to_push_request;
pub use crate::canister_state::queues::CanisterOutputQueuesIterator;
use crate::metadata_state::subnet_call_context_manager::InstallCodeCallId;
use crate::page_map::PageAllocatorFileDescriptor;
use crate::{
    CanisterQueues, CanisterState, CheckpointLoadingMetrics, InputQueueType, PageMap, StateError,
};
pub use call_context_manager::{CallContext, CallContextAction, CallContextManager, CallOrigin};
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_interfaces::execution_environment::ExecutionRoundType;
use ic_logger::{error, ReplicaLogger};
use ic_management_canister_types::{
    CanisterChange, CanisterChangeDetails, CanisterChangeOrigin, LogVisibilityV2,
};
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_registry_subnet_type::SubnetType;
use ic_types::messages::{
    CanisterCall, CanisterMessage, CanisterMessageOrTask, CanisterTask, Ingress, RejectContext,
    Request, RequestOrResponse, Response, StopCanisterContext,
};
use ic_types::nominal_cycles::NominalCycles;
use ic_types::{
    CanisterId, CanisterLog, CanisterTimer, Cycles, MemoryAllocation, NumBytes, PrincipalId, Time,
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
        }
    }
}

impl From<CyclesUseCase> for pb::CyclesUseCase {
    fn from(item: CyclesUseCase) -> Self {
        match item {
            CyclesUseCase::Memory => pb::CyclesUseCase::Memory,
            CyclesUseCase::ComputeAllocation => pb::CyclesUseCase::ComputeAllocation,
            CyclesUseCase::IngressInduction => pb::CyclesUseCase::IngressInduction,
            CyclesUseCase::Instructions => pb::CyclesUseCase::Instructions,
            CyclesUseCase::RequestAndResponseTransmission => {
                pb::CyclesUseCase::RequestAndResponseTransmission
            }
            CyclesUseCase::Uninstall => pb::CyclesUseCase::Uninstall,
            CyclesUseCase::CanisterCreation => pb::CyclesUseCase::CanisterCreation,
            CyclesUseCase::ECDSAOutcalls => pb::CyclesUseCase::EcdsaOutcalls,
            CyclesUseCase::HTTPOutcalls => pb::CyclesUseCase::HttpOutcalls,
            CyclesUseCase::DeletedCanisters => pb::CyclesUseCase::DeletedCanisters,
            CyclesUseCase::NonConsumed => pb::CyclesUseCase::NonConsumed,
            CyclesUseCase::BurnedCycles => pb::CyclesUseCase::BurnedCycles,
            CyclesUseCase::SchnorrOutcalls => pb::CyclesUseCase::SchnorrOutcalls,
        }
    }
}

impl TryFrom<pb::CyclesUseCase> for CyclesUseCase {
    type Error = ProxyDecodeError;
    fn try_from(item: pb::CyclesUseCase) -> Result<Self, Self::Error> {
        match item {
            pb::CyclesUseCase::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "CyclesUseCase",
                err: format!("Unexpected value of cycles use case: {:?}", item),
            }),
            pb::CyclesUseCase::Memory => Ok(Self::Memory),
            pb::CyclesUseCase::ComputeAllocation => Ok(Self::ComputeAllocation),
            pb::CyclesUseCase::IngressInduction => Ok(Self::IngressInduction),
            pb::CyclesUseCase::Instructions => Ok(Self::Instructions),
            pb::CyclesUseCase::RequestAndResponseTransmission => {
                Ok(Self::RequestAndResponseTransmission)
            }
            pb::CyclesUseCase::Uninstall => Ok(Self::Uninstall),
            pb::CyclesUseCase::CanisterCreation => Ok(Self::CanisterCreation),
            pb::CyclesUseCase::EcdsaOutcalls => Ok(Self::ECDSAOutcalls),
            pb::CyclesUseCase::HttpOutcalls => Ok(Self::HTTPOutcalls),
            pb::CyclesUseCase::DeletedCanisters => Ok(Self::DeletedCanisters),
            pb::CyclesUseCase::NonConsumed => Ok(Self::NonConsumed),
            pb::CyclesUseCase::BurnedCycles => Ok(Self::BurnedCycles),
            pb::CyclesUseCase::SchnorrOutcalls => Ok(Self::SchnorrOutcalls),
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
        self.canister_history_memory_usage = NumBytes::from(0);

        debug_assert_eq!(
            self.get_memory_usage(),
            compute_total_canister_change_size(&self.changes),
        );
    }

    /// Adds a canister change to the history, updating the memory usage
    /// and total number of changes. It also makes sure that the number
    /// of canister changes does not exceed `MAX_CANISTER_HISTORY_CHANGES`
    /// by dropping the oldest entry if necessary.
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

    pub fn get_memory_usage(&self) -> NumBytes {
        self.canister_history_memory_usage
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct TaskQueue {
    /// Tasks to execute before processing input messages.
    /// Currently the task queue is empty outside of execution rounds.
    pub queue: VecDeque<ExecutionTask>,
}

impl TaskQueue {
    pub fn from_checkpoint(queue: VecDeque<ExecutionTask>) -> Self {
        TaskQueue { queue }
    }

    pub fn front(&self) -> Option<&ExecutionTask> {
        self.queue.front()
    }

    pub fn pop_front(&mut self) -> Option<ExecutionTask> {
        self.queue.pop_front()
    }

    pub fn pop_back(&mut self) -> Option<ExecutionTask> {
        self.queue.pop_back()
    }

    pub fn push_front(&mut self, task: ExecutionTask) {
        self.queue.push_front(task);
    }

    pub fn push_back(&mut self, task: ExecutionTask) {
        self.queue.push_back(task);
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn get_queue(&self) -> &VecDeque<ExecutionTask> {
        &self.queue
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    // 1. Heartbeat, GlobalTimer tasks exist only during the round and must not exist after the round.
    // 2. Paused executions can exist only in ordinary rounds (not checkpoint rounds).
    // 3. If deterministic time slicing is disabled, then there are no paused tasks.
    //    Aborted tasks may still exist if DTS was disabled in recent checkpoints.
    pub fn check_dts_invariants(
        &self,
        deterministic_time_slicing: FlagStatus,
        current_round_type: ExecutionRoundType,
        id: &CanisterId,
    ) {
        for task in self.queue.iter() {
            match task {
                ExecutionTask::AbortedExecution { .. }
                | ExecutionTask::AbortedInstallCode { .. } => {}
                ExecutionTask::Heartbeat => {
                    panic!(
                        "Unexpected heartbeat task after a round in canister {:?}",
                        id
                    );
                }
                ExecutionTask::GlobalTimer => {
                    panic!(
                        "Unexpected global timer task after a round in canister {:?}",
                        id
                    );
                }
                // TODO [EXC-1666]
                // For now, since OnLowWasmMemory is not used we will copy behaviour similar
                // to Heartbeat and GlobalTimer, but when the feature is implemented we will
                // come back to it, to revisit if we should keep it after the round ends.
                ExecutionTask::OnLowWasmMemory => {
                    panic!(
                        "Unexpected on low wasm memory task after a round in canister {:?}",
                        id
                    );
                }
                ExecutionTask::PausedExecution { .. } | ExecutionTask::PausedInstallCode(_) => {
                    assert_eq!(
                        deterministic_time_slicing,
                        FlagStatus::Enabled,
                        "Unexpected paused execution {:?} with disabled DTS in canister: {:?}",
                        task,
                        id
                    );
                    assert_eq!(
                        current_round_type,
                        ExecutionRoundType::OrdinaryRound,
                        "Unexpected paused execution {:?} after a checkpoint round in canister {:?}",
                        task,
                        id
                    );
                }
            }
        }

        // There should be at most one paused or aborted task left in the task queue.
        assert!(
            self.queue.len() <= 1,
            "Unexpected tasks left in the task queue of canister {} after a round in canister {:?}",
            id,
            self.queue
        );
    }

    /// Removes aborted install code task.
    pub fn remove_aborted_install_code_task(&mut self) {
        self.queue.retain(|task| match task {
            ExecutionTask::AbortedInstallCode { .. } => false,
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::OnLowWasmMemory
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(_)
            | ExecutionTask::AbortedExecution { .. } => true,
        });
    }

    /// Removes aborted `Heartbeat` and `GlobalTimer` tasks.
    pub fn remove_heartbeat_and_global_timer(&mut self) {
        self.queue.retain(|task| match task {
            ExecutionTask::Heartbeat | ExecutionTask::GlobalTimer => false,
            ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(..)
            | ExecutionTask::AbortedExecution { .. }
            | ExecutionTask::AbortedInstallCode { .. }
            | ExecutionTask::OnLowWasmMemory => true,
        });
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
    // This must remain private, in order to properly enforce system states (running, stopping,
    // stopped) when enqueuing inputs; and to ensure message memory reservations are accurate.
    #[validate_eq(CompareWithValidateEq)]
    queues: CanisterQueues,
    /// The canister's memory allocation.
    pub memory_allocation: MemoryAllocation,
    /// Threshold used for activation of canister_on_low_wasm_memory hook.
    pub wasm_memory_threshold: NumBytes,
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

    /// Tasks to execute before processing input messages.
    /// Currently the task queue is empty outside of execution rounds.
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

    /// Status of low_on_wasm_memory hook execution.
    on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,
}

/// A wrapper around the different canister statuses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum OnLowWasmMemoryHookStatus {
    #[default]
    ConditionNotSatisfied,
    Ready,
    Executed,
}

impl From<&OnLowWasmMemoryHookStatus> for pb::OnLowWasmMemoryHookStatus {
    fn from(item: &OnLowWasmMemoryHookStatus) -> Self {
        match *item {
            OnLowWasmMemoryHookStatus::ConditionNotSatisfied => {
                pb::OnLowWasmMemoryHookStatus::ConditionNotSatisfied
            }
            OnLowWasmMemoryHookStatus::Ready => pb::OnLowWasmMemoryHookStatus::Ready,
            OnLowWasmMemoryHookStatus::Executed => pb::OnLowWasmMemoryHookStatus::Executed,
        }
    }
}

impl TryFrom<pb::OnLowWasmMemoryHookStatus> for OnLowWasmMemoryHookStatus {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::OnLowWasmMemoryHookStatus) -> Result<Self, Self::Error> {
        match value {
            pb::OnLowWasmMemoryHookStatus::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "OnLowWasmMemoryHookStatus",
                err: format!(
                    "Unexpected value of status of on low wasm memory hook: {:?}",
                    value
                ),
            }),
            pb::OnLowWasmMemoryHookStatus::ConditionNotSatisfied => {
                Ok(OnLowWasmMemoryHookStatus::ConditionNotSatisfied)
            }
            pb::OnLowWasmMemoryHookStatus::Ready => Ok(OnLowWasmMemoryHookStatus::Ready),
            pb::OnLowWasmMemoryHookStatus::Executed => Ok(OnLowWasmMemoryHookStatus::Executed),
        }
    }
}

impl OnLowWasmMemoryHookStatus {
    pub fn update(
        &mut self,
        wasm_memory_threshold: NumBytes,
        memory_allocation: Option<NumBytes>,
        wasm_memory_limit: Option<NumBytes>,
        used_stable_memory: NumBytes,
        used_wasm_memory: NumBytes,
    ) {
        // If wasm memory limit is not set, the default is 4 GiB. Wasm memory
        // limit is ignored for query methods, response callback handlers,
        // global timers, heartbeats, and canister pre_upgrade.
        let wasm_memory_limit = if let Some(limit) = wasm_memory_limit {
            limit
        } else {
            NumBytes::new(4 * 1024 * 1024 * 1024)
        };

        // If the canister has memory allocation, then it maximum allowed Wasm memory
        // can be calculated as min(memory_allocation - used_stable_memory, wasm_memory_limit).
        let wasm_capacity = if let Some(memory_allocation) = memory_allocation {
            debug_assert!(
                used_stable_memory <= memory_allocation,
                "Used stable memory: {:?}, is larger than memory allocation: {:?}.",
                used_stable_memory,
                memory_allocation
            );
            std::cmp::min(memory_allocation - used_stable_memory, wasm_memory_limit)
        } else {
            wasm_memory_limit
        };

        // Conceptually we can think that the remaining Wasm memory is
        // equal to `wasm_capacity - used_wasm_memory` and that should
        // be compared with `wasm_memory_threshold` when checking for
        // the condition for the hook. However, since `wasm_memory_limit`
        // is ignored in some executions as stated above it is possible
        // that `used_wasm_memory` is greater than `wasm_capacity` to
        // avoid overflowing subtraction we adopted inequality.
        if wasm_capacity >= used_wasm_memory + wasm_memory_threshold {
            *self = OnLowWasmMemoryHookStatus::ConditionNotSatisfied;
        } else if *self != OnLowWasmMemoryHookStatus::Executed {
            *self = OnLowWasmMemoryHookStatus::Ready;
        }
    }
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

impl From<&ExecutionTask> for pb::ExecutionTask {
    fn from(item: &ExecutionTask) -> Self {
        match item {
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::OnLowWasmMemory
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(_) => {
                panic!("Attempt to serialize ephemeral task: {:?}.", item);
            }
            ExecutionTask::AbortedExecution {
                input,
                prepaid_execution_cycles,
            } => {
                use pb::execution_task::{
                    aborted_execution::Input as PbInput, CanisterTask as PbCanisterTask,
                };
                let input = match input {
                    CanisterMessageOrTask::Message(CanisterMessage::Response(v)) => {
                        PbInput::Response(v.as_ref().into())
                    }
                    CanisterMessageOrTask::Message(CanisterMessage::Request(v)) => {
                        PbInput::Request(v.as_ref().into())
                    }
                    CanisterMessageOrTask::Message(CanisterMessage::Ingress(v)) => {
                        PbInput::Ingress(v.as_ref().into())
                    }
                    CanisterMessageOrTask::Task(task) => {
                        PbInput::Task(PbCanisterTask::from(task).into())
                    }
                };
                Self {
                    task: Some(pb::execution_task::Task::AbortedExecution(
                        pb::execution_task::AbortedExecution {
                            input: Some(input),
                            prepaid_execution_cycles: Some((*prepaid_execution_cycles).into()),
                        },
                    )),
                }
            }
            ExecutionTask::AbortedInstallCode {
                message,
                call_id,
                prepaid_execution_cycles,
            } => {
                use pb::execution_task::aborted_install_code::Message;
                let message = match message {
                    CanisterCall::Request(v) => Message::Request(v.as_ref().into()),
                    CanisterCall::Ingress(v) => Message::Ingress(v.as_ref().into()),
                };
                Self {
                    task: Some(pb::execution_task::Task::AbortedInstallCode(
                        pb::execution_task::AbortedInstallCode {
                            message: Some(message),
                            call_id: Some(call_id.get()),
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
                use pb::execution_task::{
                    aborted_execution::Input as PbInput, CanisterTask as PbCanisterTask,
                };
                let input = aborted
                    .input
                    .ok_or(ProxyDecodeError::MissingField("AbortedExecution::input"))?;
                let input = match input {
                    PbInput::Request(v) => CanisterMessageOrTask::Message(
                        CanisterMessage::Request(Arc::new(v.try_into()?)),
                    ),
                    PbInput::Response(v) => CanisterMessageOrTask::Message(
                        CanisterMessage::Response(Arc::new(v.try_into()?)),
                    ),
                    PbInput::Ingress(v) => CanisterMessageOrTask::Message(
                        CanisterMessage::Ingress(Arc::new(v.try_into()?)),
                    ),
                    PbInput::Task(val) => {
                        let task = CanisterTask::try_from(PbCanisterTask::try_from(val).map_err(
                            |_| ProxyDecodeError::ValueOutOfRange {
                                typ: "CanisterTask",
                                err: format!("Unexpected value of canister task: {}", val),
                            },
                        )?)?;
                        CanisterMessageOrTask::Task(task)
                    }
                };
                let prepaid_execution_cycles = aborted
                    .prepaid_execution_cycles
                    .map(|c| c.into())
                    .unwrap_or_else(Cycles::zero);
                ExecutionTask::AbortedExecution {
                    input,
                    prepaid_execution_cycles,
                }
            }
            pb::execution_task::Task::AbortedInstallCode(aborted) => {
                use pb::execution_task::aborted_install_code::Message;
                let message = aborted.message.ok_or(ProxyDecodeError::MissingField(
                    "AbortedInstallCode::message",
                ))?;
                let message = match message {
                    Message::Request(v) => CanisterCall::Request(Arc::new(v.try_into()?)),
                    Message::Ingress(v) => CanisterCall::Ingress(Arc::new(v.try_into()?)),
                };
                let prepaid_execution_cycles = aborted
                    .prepaid_execution_cycles
                    .map(|c| c.into())
                    .unwrap_or_else(Cycles::zero);
                let call_id = aborted.call_id.ok_or(ProxyDecodeError::MissingField(
                    "AbortedInstallCode::call_id",
                ))?;
                ExecutionTask::AbortedInstallCode {
                    message,
                    call_id: InstallCodeCallId::new(call_id),
                    prepaid_execution_cycles,
                }
            }
        };
        Ok(task)
    }
}

impl From<&CanisterHistory> for pb::CanisterHistory {
    fn from(item: &CanisterHistory) -> Self {
        Self {
            changes: item
                .changes
                .iter()
                .map(|e| (&(**e)).into())
                .collect::<Vec<pb::CanisterChange>>(),
            total_num_changes: item.total_num_changes,
        }
    }
}

impl TryFrom<pb::CanisterHistory> for CanisterHistory {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::CanisterHistory) -> Result<Self, Self::Error> {
        let changes = value
            .changes
            .into_iter()
            .map(|e| Ok(Arc::new(e.try_into()?)))
            .collect::<Result<VecDeque<_>, Self::Error>>()?;
        let canister_history_memory_usage = compute_total_canister_change_size(&changes);
        Ok(Self {
            changes: Arc::new(changes),
            total_num_changes: value.total_num_changes,
            canister_history_memory_usage,
        })
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
        on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,
    ) -> Self {
        Self::new_internal(
            canister_id,
            controller,
            initial_cycles,
            freeze_threshold,
            CanisterStatus::new_running(),
            WasmChunkStore::new(fd_factory),
            on_low_wasm_memory_hook_status,
        )
    }

    fn new_internal(
        canister_id: CanisterId,
        controller: PrincipalId,
        initial_cycles: Cycles,
        freeze_threshold: NumSeconds,
        status: CanisterStatus,
        wasm_chunk_store: WasmChunkStore,
        on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,
    ) -> Self {
        Self {
            canister_id,
            controllers: btreeset! {controller},
            queues: CanisterQueues::default(),
            cycles_balance: initial_cycles,
            ingress_induction_cycles_debit: Cycles::zero(),
            reserved_balance: Cycles::zero(),
            reserved_balance_limit: None,
            memory_allocation: MemoryAllocation::BestEffort,
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
            canister_log: Default::default(),
            wasm_memory_limit: None,
            next_snapshot_id: 0,
            snapshots_memory_usage: NumBytes::from(0),
            on_low_wasm_memory_hook_status,
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
        task_queue: VecDeque<ExecutionTask>,
        global_timer: CanisterTimer,
        canister_version: u64,
        canister_history: CanisterHistory,
        wasm_chunk_store_data: PageMap,
        wasm_chunk_store_metadata: WasmChunkStoreMetadata,
        log_visibility: LogVisibilityV2,
        canister_log: CanisterLog,
        wasm_memory_limit: Option<NumBytes>,
        next_snapshot_id: u64,
        snapshots_memory_usage: NumBytes,
        metrics: &dyn CheckpointLoadingMetrics,
        on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,
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
            task_queue: TaskQueue::from_checkpoint(task_queue),
            global_timer,
            canister_version,
            canister_history,
            wasm_chunk_store: WasmChunkStore::from_checkpoint(
                wasm_chunk_store_data,
                wasm_chunk_store_metadata,
            ),
            log_visibility,
            canister_log,
            wasm_memory_limit,
            next_snapshot_id,
            snapshots_memory_usage,
            on_low_wasm_memory_hook_status,
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
            OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
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

    /// See documentation for [`CanisterQueues::reject_subnet_output_request`].
    pub fn reject_subnet_output_request(
        &mut self,
        request: Request,
        reject_context: RejectContext,
        subnet_ids: &[PrincipalId],
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
    ///    full when pushing a `Request`;
    ///  * `CanisterOutOfCycles` if the canister does not have enough cycles.
    ///  * `OutOfMemory` if the necessary guaranteed response memory reservation
    ///    is larger than `subnet_available_memory`.
    ///  * `CanisterStopping` if the canister is stopping and inducting a
    ///    `Request` was attempted.
    ///  * `CanisterStopped` if the canister is stopped.
    ///  * `NonMatchingResponse` if no response is expected, the callback is not
    ///    found or the respondent does not match.
    pub(crate) fn push_input(
        &mut self,
        msg: RequestOrResponse,
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
    pub fn output_into_iter(&mut self) -> CanisterOutputQueuesIterator {
        self.queues.output_into_iter()
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

    /// Returns the memory currently in use by the `SystemState`
    /// for canister history.
    pub fn canister_history_memory_usage(&self) -> NumBytes {
        self.canister_history.get_memory_usage()
    }

    /// Sets the (transient) size in bytes of guaranteed responses from this
    /// canister routed into streams and not yet garbage collected.
    pub(super) fn set_stream_guaranteed_responses_size_bytes(&mut self, size_bytes: usize) {
        self.queues
            .set_stream_guaranteed_responses_size_bytes(size_bytes);
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
    /// from `self` while respecting queue capacity and the provided subnet
    /// available guaranteed response message memory.
    ///
    /// `subnet_available_memory` (the subnet's available guaranteed response
    /// message memory) is updated to reflect the change in `self.queues` guaranteed
    /// response message memory usage.
    ///
    /// Available memory is ignored (but updated) for system subnets, since we
    /// don't want to DoS system canisters due to lots of incoming requests.
    pub fn induct_messages_to_self(
        &mut self,
        subnet_available_memory: &mut i64,
        own_subnet_type: SubnetType,
    ) {
        // Bail out if the canister is not running.
        match self.status {
            CanisterStatus::Running { .. } => (),
            CanisterStatus::Stopped | CanisterStatus::Stopping { .. } => return,
        }

        let mut memory_usage = self.queues.guaranteed_response_memory_usage() as i64;

        while let Some(msg) = self.queues.peek_output(&self.canister_id) {
            // Ensure that enough memory is available for inducting `msg`.
            if own_subnet_type != SubnetType::System
                && can_push(msg, *subnet_available_memory).is_err()
            {
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

            // Adjust `subnet_available_memory` by `memory_usage_before - memory_usage_after`.
            // Defer the accounting to `CanisterQueues`, to avoid duplication or divergence.
            *subnet_available_memory += memory_usage;
            memory_usage = self.queues.guaranteed_response_memory_usage() as i64;
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

    /// Drops expired messages given a current time. Returns the number of messages
    /// that were timed out.
    ///
    /// See [`CanisterQueues::time_out_messages`] for further details.
    pub fn time_out_messages(
        &mut self,
        current_time: Time,
        own_canister_id: &CanisterId,
        local_canisters: &BTreeMap<CanisterId, CanisterState>,
    ) -> usize {
        self.queues
            .time_out_messages(current_time, own_canister_id, local_canisters)
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
            | CyclesUseCase::HTTPOutcalls
            | CyclesUseCase::DeletedCanisters
            | CyclesUseCase::NonConsumed
            | CyclesUseCase::BurnedCycles => requested_amount,
        };
        self.cycles_balance -= remaining_amount;
        self.observe_consumed_cycles_with_use_case(
            requested_amount,
            use_case,
            ConsumingCycles::Yes,
        );
    }

    /// Moves the given amount of cycles from the main balance to the reserved balance.
    /// Returns an error if the main balance is lower than the requested amount.
    pub fn reserve_cycles(&mut self, amount: Cycles) -> Result<(), ReservationError> {
        if let Some(reserved_balance_limit) = self.reserved_balance_limit {
            if self.reserved_balance + amount > reserved_balance_limit {
                return Err(ReservationError::ReservedLimitExceed {
                    requested: self.reserved_balance + amount,
                    limit: reserved_balance_limit,
                });
            }
        }
        if amount > self.cycles_balance {
            Err(ReservationError::InsufficientCycles {
                requested: amount,
                available: self.cycles_balance,
            })
        } else {
            self.cycles_balance -= amount;
            self.reserved_balance += amount;
            Ok(())
        }
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
        // The three CyclesUseCase below are not valid on the canister
        // level, they should only appear on the subnet level.
        debug_assert_ne!(use_case, CyclesUseCase::ECDSAOutcalls);
        debug_assert_ne!(use_case, CyclesUseCase::HTTPOutcalls);
        debug_assert_ne!(use_case, CyclesUseCase::DeletedCanisters);

        if use_case == CyclesUseCase::NonConsumed || amount == Cycles::from(0u128) {
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

    pub fn set_on_low_wasm_memory_hook_status(&mut self, status: OnLowWasmMemoryHookStatus) {
        self.on_low_wasm_memory_hook_status = status;
    }

    pub fn get_on_low_wasm_memory_hook_status(&self) -> &OnLowWasmMemoryHookStatus {
        &self.on_low_wasm_memory_hook_status
    }
}

/// Implements memory limits verification for pushing a canister-to-canister
/// message into the induction pool of `queues`.
///
/// Returns `StateError::OutOfMemory` if pushing the message would require more
/// memory than `subnet_available_memory`.
///
/// `subnet_available_memory` (the subnet's available guaranteed response
/// message memory) is updated to reflect the change in memory usage after a
/// successful push; and left unmodified if the push failed.
///
/// See `CanisterQueues::push_input()` for further details.
pub(crate) fn push_input(
    queues: &mut CanisterQueues,
    msg: RequestOrResponse,
    subnet_available_memory: &mut i64,
    own_subnet_type: SubnetType,
    input_queue_type: InputQueueType,
) -> Result<(), (StateError, RequestOrResponse)> {
    // Do not enforce limits for local messages on system subnets.
    if own_subnet_type != SubnetType::System || input_queue_type != InputQueueType::LocalSubnet {
        if let Err(required_memory) = can_push(&msg, *subnet_available_memory) {
            return Err((
                StateError::OutOfMemory {
                    requested: NumBytes::new(required_memory as u64),
                    available: *subnet_available_memory,
                },
                msg,
            ));
        }
    }

    // But always adjust `subnet_available_memory` by `memory_usage_before -
    // memory_usage_after`. Defer the accounting to `CanisterQueues`, to avoid
    // duplication (and the possibility of divergence).
    *subnet_available_memory += queues.guaranteed_response_memory_usage() as i64;
    let res = queues.push_input(msg, input_queue_type);
    *subnet_available_memory -= queues.guaranteed_response_memory_usage() as i64;
    res
}

pub mod testing {
    use super::*;

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
}
