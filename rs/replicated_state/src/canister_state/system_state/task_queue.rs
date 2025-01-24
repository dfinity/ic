use crate::ExecutionTask;
use ic_config::flag_status::FlagStatus;
use ic_interfaces::execution_environment::ExecutionRoundType;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_types::CanisterId;
use ic_types::NumBytes;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// A wrapper around the different statuses of `OnLowWasmMemory` hook execution.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub enum OnLowWasmMemoryHookStatus {
    #[default]
    ConditionNotSatisfied,
    Ready,
    Executed,
}

impl OnLowWasmMemoryHookStatus {
    pub(crate) fn update(&mut self, is_hook_condition_satisfied: bool) {
        *self = if is_hook_condition_satisfied {
            match *self {
                Self::ConditionNotSatisfied | Self::Ready => Self::Ready,
                Self::Executed => Self::Executed,
            }
        } else {
            Self::ConditionNotSatisfied
        };
    }

    fn is_ready(&self) -> bool {
        *self == Self::Ready
    }
}

impl From<&OnLowWasmMemoryHookStatus> for pb::OnLowWasmMemoryHookStatus {
    fn from(item: &OnLowWasmMemoryHookStatus) -> Self {
        use OnLowWasmMemoryHookStatus::*;

        match *item {
            ConditionNotSatisfied => Self::ConditionNotSatisfied,
            Ready => Self::Ready,
            Executed => Self::Executed,
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

/// `TaskQueue` represents the implementation of queue structure for canister tasks satisfying the following conditions:
///
/// 1. If there is a `Paused` or `Aborted` task it will be returned first.
/// 2. If an `OnLowWasmMemoryHook` is ready to be executed, it will be returned next.
/// 3. All other tasks will be returned based on the order in which they are added to the queue.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct TaskQueue {
    /// Keeps `PausedExecution`, or `PausedInstallCode`, or `AbortedExecution`,
    /// or `AbortedInstallCode` task if there is one.
    paused_or_aborted_task: Option<ExecutionTask>,

    /// Status of low_on_wasm_memory hook execution.
    on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,

    /// Queue of `Heartbeat` and `GlobalTimer` tasks.
    queue: VecDeque<ExecutionTask>,
}

impl TaskQueue {
    pub fn from_checkpoint(
        queue: VecDeque<ExecutionTask>,
        on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,
        canister_id: &CanisterId,
    ) -> Self {
        let mut mut_queue = queue;

        // Extraction of paused_or_aborted_task from queue will be removed in the follow-up EXC-1752 when
        // we introduce CanisterStateBits version of TaskQueue, so the conversion will be implicit.
        let paused_or_aborted_task = match mut_queue.front() {
            Some(ExecutionTask::AbortedInstallCode { .. })
            | Some(ExecutionTask::PausedExecution { .. })
            | Some(ExecutionTask::PausedInstallCode(_))
            | Some(ExecutionTask::AbortedExecution { .. }) => mut_queue.pop_front(),
            Some(ExecutionTask::OnLowWasmMemory)
            | Some(ExecutionTask::Heartbeat)
            | Some(ExecutionTask::GlobalTimer)
            | None => None,
        };

        let queue = TaskQueue {
            paused_or_aborted_task,
            on_low_wasm_memory_hook_status,
            queue: mut_queue,
        };

        // Because paused tasks are not allowed in checkpoint rounds when
        // checking dts invariants that is equivalent to disabling dts.
        queue.check_dts_invariants(
            FlagStatus::Disabled,
            ExecutionRoundType::CheckpointRound,
            canister_id,
        );

        queue
    }

    pub fn front(&self) -> Option<&ExecutionTask> {
        self.paused_or_aborted_task.as_ref().or_else(|| {
            if self.on_low_wasm_memory_hook_status.is_ready() {
                Some(&ExecutionTask::OnLowWasmMemory)
            } else {
                self.queue.front()
            }
        })
    }

    pub fn pop_front(&mut self) -> Option<ExecutionTask> {
        self.paused_or_aborted_task.take().or_else(|| {
            if self.on_low_wasm_memory_hook_status.is_ready() {
                self.on_low_wasm_memory_hook_status = OnLowWasmMemoryHookStatus::Executed;
                Some(ExecutionTask::OnLowWasmMemory)
            } else {
                self.queue.pop_front()
            }
        })
    }

    pub fn remove(&mut self, task: ExecutionTask) {
        match task {
            ExecutionTask::OnLowWasmMemory => {
                self.on_low_wasm_memory_hook_status.update(false);
            }
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::AbortedInstallCode { .. }
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(_)
            | ExecutionTask::AbortedExecution { .. } => unreachable!(
                "Unsuccessful removal of the task {:?}. Removal of task from TaskQueue is only supported for OnLowWasmMemory type.", task
            ),
        };
    }

    pub fn enqueue(&mut self, task: ExecutionTask) {
        match task {
            ExecutionTask::AbortedInstallCode { .. }
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(_)
            | ExecutionTask::AbortedExecution { .. } => {
                debug_assert!(self.paused_or_aborted_task.is_none());
                self.paused_or_aborted_task = Some(task);
            }
            ExecutionTask::OnLowWasmMemory => {
                self.on_low_wasm_memory_hook_status.update(true);
            }
            ExecutionTask::Heartbeat | ExecutionTask::GlobalTimer => self.queue.push_front(task),
        };
    }

    pub fn is_empty(&self) -> bool {
        self.paused_or_aborted_task.is_none()
            && !self.on_low_wasm_memory_hook_status.is_ready()
            && self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
            + self.paused_or_aborted_task.as_ref().map_or(0, |_| 1)
            + if self.on_low_wasm_memory_hook_status.is_ready() {
                1
            } else {
                0
            }
    }

    /// peek_hook_status will be removed in the follow-up EXC-1752.
    pub fn peek_hook_status(&self) -> OnLowWasmMemoryHookStatus {
        self.on_low_wasm_memory_hook_status
    }

    /// get_queue will be removed in the follow-up EXC-1752.
    pub fn get_queue(&self) -> VecDeque<ExecutionTask> {
        let mut queue = self.queue.clone();
        if let Some(task) = self.paused_or_aborted_task.as_ref() {
            queue.push_front(task.clone());
        }
        queue
    }

    /// `check_dts_invariants` should only be called after round execution.
    ///
    /// It checks that the following properties are satisfied:
    /// 1. Heartbeat, GlobalTimer tasks exist only during the round and must not exist after the round.
    /// 2. Paused executions can exist only in ordinary rounds (not checkpoint rounds).
    /// 3. If deterministic time slicing is disabled, then there are no paused tasks.
    ///    Aborted tasks may still exist if DTS was disabled in recent checkpoints.
    pub fn check_dts_invariants(
        &self,
        deterministic_time_slicing: FlagStatus,
        current_round_type: ExecutionRoundType,
        id: &CanisterId,
    ) {
        if let Some(paused_or_aborted_task) = &self.paused_or_aborted_task {
            match paused_or_aborted_task {
                ExecutionTask::PausedExecution { .. } | ExecutionTask::PausedInstallCode(_) => {
                    assert_eq!(
                    current_round_type,
                    ExecutionRoundType::OrdinaryRound,
                    "Unexpected paused execution {:?} after a checkpoint round in canister {:?}",
                    paused_or_aborted_task,
                    id
                );

                    assert_eq!(
                        deterministic_time_slicing,
                        FlagStatus::Enabled,
                        "Unexpected paused execution {:?} with disabled DTS in canister: {:?}",
                        paused_or_aborted_task,
                        id
                    );
                }
                ExecutionTask::AbortedExecution { .. }
                | ExecutionTask::AbortedInstallCode { .. } => {}
                ExecutionTask::Heartbeat
                | ExecutionTask::GlobalTimer
                | ExecutionTask::OnLowWasmMemory => {
                    unreachable!(
                        "Unexpected on task type {:?} in TaskQueue::paused_or_aborted_task in canister {:?} .", paused_or_aborted_task, id
                    )
                }
            }
        }

        if let Some(task) = self.queue.front() {
            match task {
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
                ExecutionTask::OnLowWasmMemory
                | ExecutionTask::AbortedExecution { .. }
                | ExecutionTask::AbortedInstallCode { .. }
                | ExecutionTask::PausedExecution { .. }
                | ExecutionTask::PausedInstallCode(_) => {
                    unreachable!(
                        "Unexpected task type {:?} in TaskQueue::queue, after a round in canister {:?}", task, id
                    );
                }
            }
        }
    }

    /// Removes aborted install code task.
    pub fn remove_aborted_install_code_task(&mut self) {
        if let Some(ExecutionTask::AbortedInstallCode { .. }) = &self.paused_or_aborted_task {
            self.paused_or_aborted_task = None;
        }
    }

    /// Removes `Heartbeat` and `GlobalTimer` tasks.
    pub fn remove_heartbeat_and_global_timer(&mut self) {
        for task in self.queue.iter() {
            debug_assert!(
                *task == ExecutionTask::Heartbeat || *task == ExecutionTask::GlobalTimer,
                "Unexpected task type {:?} in TaskQueue::queue.",
                task
            );
        }

        self.queue.clear();
    }

    /// Returns `PausedExecution` or `PausedInstallCode` task.
    pub fn get_paused_task(&self) -> Option<&ExecutionTask> {
        if let Some(task) = &self.paused_or_aborted_task {
            match task {
                ExecutionTask::PausedExecution { .. } | ExecutionTask::PausedInstallCode(_) => {
                    Some(task)
                }
                ExecutionTask::AbortedExecution { .. }
                | ExecutionTask::AbortedInstallCode { .. } => None,
                ExecutionTask::Heartbeat
                | ExecutionTask::GlobalTimer
                | ExecutionTask::OnLowWasmMemory => unreachable!(
                    "Unexpected on task type in the in TaskQueue::paused_or_aborted_task."
                ),
            }
        } else {
            None
        }
    }

    /// Replace `PausedExecution` or `PausedInstallCode` with corresponding
    /// `AbortedExecution` or `AbortedInstallCode` respectively.
    pub fn replace_paused_with_aborted_task(&mut self, aborted_task: ExecutionTask) {
        match &aborted_task {
            ExecutionTask::AbortedExecution { .. } => assert!(
                matches!(
                    self.paused_or_aborted_task,
                    Some(ExecutionTask::PausedExecution { .. })
                ),
                "Received aborted task {:?} is not compatible with paused task {:?}.",
                aborted_task,
                self.paused_or_aborted_task
            ),
            ExecutionTask::AbortedInstallCode { .. } => assert!(
                matches!(
                    self.paused_or_aborted_task,
                    Some(ExecutionTask::PausedInstallCode(_))
                ),
                "Received aborted task {:?} is not compatible with paused task {:?}.",
                aborted_task,
                self.paused_or_aborted_task
            ),
            ExecutionTask::Heartbeat
            | ExecutionTask::GlobalTimer
            | ExecutionTask::OnLowWasmMemory
            | ExecutionTask::PausedExecution { .. }
            | ExecutionTask::PausedInstallCode(_) => {
                unreachable!(
                    "Unexpected task type {:?} of the aborted task.",
                    aborted_task
                )
            }
        };

        self.paused_or_aborted_task = Some(aborted_task);
    }
}

/// Condition for `OnLowWasmMemoryHook` is satisfied if the following holds:
///
/// 1. In the case of `memory_allocation`
///     `wasm_memory_threshold >= min(memory_allocation - memory_usage_without_wasm_memory, wasm_memory_limit) - wasm_memory_usage`
/// 2. Without memory allocation
///     `wasm_memory_threshold >= wasm_memory_limit - wasm_memory_usage`
///
/// Note: if `wasm_memory_limit` is not set, its default value is 4 GiB.
pub fn is_low_wasm_memory_hook_condition_satisfied(
    memory_usage: NumBytes,
    wasm_memory_usage: NumBytes,
    memory_allocation: Option<NumBytes>,
    wasm_memory_limit: Option<NumBytes>,
    wasm_memory_threshold: NumBytes,
) -> bool {
    // If wasm memory limit is not set, the default is 4 GiB. Wasm memory
    // limit is ignored for query methods, response callback handlers,
    // global timers, heartbeats, and canister pre_upgrade.
    let wasm_memory_limit =
        wasm_memory_limit.unwrap_or_else(|| NumBytes::new(4 * 1024 * 1024 * 1024));

    debug_assert!(
        wasm_memory_usage <= memory_usage,
        "Wasm memory usage {} is greater that memory usage {}.",
        wasm_memory_usage,
        memory_usage
    );

    let memory_usage_without_wasm_memory =
        NumBytes::new(memory_usage.get().saturating_sub(wasm_memory_usage.get()));

    // If the canister has memory allocation, then it maximum allowed Wasm memory can be calculated
    // as min(memory_allocation - memory_usage_without_wasm_memory, wasm_memory_limit).
    let wasm_capacity = memory_allocation.map_or_else(
        || wasm_memory_limit,
        |memory_allocation| {
            debug_assert!(
                memory_usage_without_wasm_memory <= memory_allocation,
                "Used non-Wasm memory: {:?} is larger than memory allocation: {:?}.",
                memory_usage_without_wasm_memory,
                memory_allocation
            );
            std::cmp::min(
                memory_allocation - memory_usage_without_wasm_memory,
                wasm_memory_limit,
            )
        },
    );

    // Conceptually we can think that the remaining Wasm memory is
    // equal to `wasm_capacity - wasm_memory_usage` and that should
    // be compared with `wasm_memory_threshold` when checking for
    // the condition for the hook. However, since `wasm_memory_limit`
    // is ignored in some executions as stated above it is possible
    // that `wasm_memory_usage` is greater than `wasm_capacity` to
    // avoid overflowing subtraction we adopted inequality.
    wasm_capacity < wasm_memory_usage + wasm_memory_threshold
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        canister_state::system_state::OnLowWasmMemoryHookStatus,
        metadata_state::subnet_call_context_manager::InstallCodeCallId, ExecutionTask,
    };

    use super::TaskQueue;
    use crate::canister_state::system_state::PausedExecutionId;
    use ic_test_utilities_types::messages::IngressBuilder;
    use ic_types::{
        messages::{CanisterCall, CanisterMessageOrTask, CanisterTask},
        Cycles,
    };

    #[test]
    fn test_on_low_wasm_memory_hook_start_status_condition_not_satisfied() {
        let mut status = OnLowWasmMemoryHookStatus::ConditionNotSatisfied;
        status.update(false);
        assert_eq!(status, OnLowWasmMemoryHookStatus::ConditionNotSatisfied);

        let mut status = OnLowWasmMemoryHookStatus::ConditionNotSatisfied;
        status.update(true);
        assert_eq!(status, OnLowWasmMemoryHookStatus::Ready);
    }

    #[test]
    fn test_on_low_wasm_memory_hook_start_status_ready() {
        let mut status = OnLowWasmMemoryHookStatus::Ready;
        status.update(false);
        assert_eq!(status, OnLowWasmMemoryHookStatus::ConditionNotSatisfied);

        let mut status = OnLowWasmMemoryHookStatus::Ready;
        status.update(true);
        assert_eq!(status, OnLowWasmMemoryHookStatus::Ready);
    }

    #[test]
    fn test_on_low_wasm_memory_hook_start_status_executed() {
        let mut status = OnLowWasmMemoryHookStatus::Executed;
        status.update(false);
        assert_eq!(status, OnLowWasmMemoryHookStatus::ConditionNotSatisfied);

        let mut status = OnLowWasmMemoryHookStatus::Executed;
        status.update(true);
        assert_eq!(status, OnLowWasmMemoryHookStatus::Executed);
    }

    #[test]
    #[should_panic(expected = "Unexpected task type")]
    fn test_replace_paused_with_aborted_task_heartbeat() {
        let mut task_queue = TaskQueue::default();
        task_queue.replace_paused_with_aborted_task(ExecutionTask::Heartbeat);
    }

    #[test]
    #[should_panic(expected = "Unexpected task type")]
    fn test_replace_paused_with_aborted_task_global_timer() {
        let mut task_queue = TaskQueue::default();
        task_queue.replace_paused_with_aborted_task(ExecutionTask::GlobalTimer);
    }

    #[test]
    #[should_panic(expected = "Unexpected task type")]
    fn test_replace_paused_with_aborted_task_on_low_wasm_memory() {
        let mut task_queue = TaskQueue::default();
        task_queue.replace_paused_with_aborted_task(ExecutionTask::OnLowWasmMemory);
    }

    #[test]
    #[should_panic(expected = "Unexpected task type")]
    fn test_replace_paused_with_aborted_task_on_paused_execution() {
        let mut task_queue = TaskQueue::default();
        task_queue.replace_paused_with_aborted_task(ExecutionTask::PausedExecution {
            id: PausedExecutionId(0),
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
        });
    }

    #[test]
    #[should_panic(expected = "Unexpected task type")]
    fn test_replace_paused_with_aborted_task_on_paused_install_code() {
        let mut task_queue = TaskQueue::default();
        task_queue.replace_paused_with_aborted_task(ExecutionTask::PausedInstallCode(
            PausedExecutionId(0),
        ));
    }

    #[test]
    #[should_panic(expected = "is not compatible with paused task")]
    fn test_replace_paused_with_aborted_task_on_paused_install_code_aborted_execution() {
        let mut task_queue = TaskQueue::default();
        task_queue.enqueue(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));

        task_queue.replace_paused_with_aborted_task(ExecutionTask::AbortedExecution {
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
            prepaid_execution_cycles: Cycles::zero(),
        });
    }

    #[test]
    #[should_panic(expected = "is not compatible with paused task")]
    fn test_replace_paused_with_aborted_task_on_paused_execution_aborted_install_code() {
        let mut task_queue = TaskQueue::default();
        task_queue.enqueue(ExecutionTask::PausedExecution {
            id: PausedExecutionId(0),
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
        });

        let ingress = Arc::new(IngressBuilder::new().method_name("test_ingress").build());

        let aborted_install_code = ExecutionTask::AbortedInstallCode {
            message: CanisterCall::Ingress(Arc::clone(&ingress)),
            prepaid_execution_cycles: Cycles::new(1),
            call_id: InstallCodeCallId::new(0),
        };

        task_queue.replace_paused_with_aborted_task(aborted_install_code);
    }

    #[test]
    #[should_panic(expected = "Unsuccessful removal of the task")]
    fn test_task_queue_remove_heartbeat() {
        let mut task_queue = TaskQueue::default();
        task_queue.remove(ExecutionTask::Heartbeat);
    }

    #[test]
    #[should_panic(expected = "Unsuccessful removal of the task")]
    fn test_task_queue_remove_global_timer() {
        let mut task_queue = TaskQueue::default();
        task_queue.remove(ExecutionTask::GlobalTimer);
    }

    #[test]
    #[should_panic(expected = "Unsuccessful removal of the task")]
    fn test_task_queue_remove_paused_install_code() {
        let mut task_queue = TaskQueue::default();
        task_queue.remove(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));
    }

    #[test]
    #[should_panic(expected = "Unsuccessful removal of the task")]
    fn test_task_queue_remove_paused_execution() {
        let mut task_queue = TaskQueue::default();
        task_queue.remove(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));
    }

    #[test]
    #[should_panic(expected = "Unsuccessful removal of the task")]
    fn test_task_queue_remove_aborted_install_code() {
        let mut task_queue = TaskQueue::default();

        let ingress = Arc::new(IngressBuilder::new().method_name("test_ingress").build());

        task_queue.remove(ExecutionTask::AbortedInstallCode {
            message: CanisterCall::Ingress(Arc::clone(&ingress)),
            prepaid_execution_cycles: Cycles::new(1),
            call_id: InstallCodeCallId::new(0),
        });
    }

    #[test]
    #[should_panic(expected = "Unsuccessful removal of the task")]
    fn test_task_queue_remove_aborted_execution() {
        let mut task_queue = TaskQueue::default();
        task_queue.remove(ExecutionTask::AbortedExecution {
            input: CanisterMessageOrTask::Task(CanisterTask::Heartbeat),
            prepaid_execution_cycles: Cycles::zero(),
        });
    }

    #[test]
    fn test_task_queue_remove_on_low_wasm_memory_hook() {
        let mut task_queue = TaskQueue::default();
        assert!(task_queue.is_empty());

        // Queue is empty, so remove should be no_op.
        task_queue.remove(ExecutionTask::OnLowWasmMemory);
        assert!(task_queue.is_empty());

        // ExecutionTask::OnLowWasmMemory is added to queue.
        task_queue.enqueue(ExecutionTask::OnLowWasmMemory);
        assert_eq!(task_queue.len(), 1);
        assert_eq!(task_queue.front(), Some(&ExecutionTask::OnLowWasmMemory));

        // After removing queue is empty.
        task_queue.remove(ExecutionTask::OnLowWasmMemory);
        assert!(task_queue.is_empty());

        // ExecutionTask::OnLowWasmMemory can be added to the queue again.
        task_queue.enqueue(ExecutionTask::OnLowWasmMemory);
        assert_eq!(task_queue.len(), 1);
        assert_eq!(task_queue.front(), Some(&ExecutionTask::OnLowWasmMemory));
    }

    #[test]
    fn test_task_queue_pop_front_on_low_wasm_memory() {
        let mut task_queue = TaskQueue::default();

        // `ExecutionTask::OnLowWasmMemory` is added to queue.
        task_queue.enqueue(ExecutionTask::OnLowWasmMemory);
        assert_eq!(task_queue.len(), 1);

        assert_eq!(task_queue.pop_front(), Some(ExecutionTask::OnLowWasmMemory));
        assert!(task_queue.is_empty());

        // After `pop` of `OnLowWasmMemory` from queue `OnLowWasmMemoryHookStatus`
        // will be `Executed` so `enqueue` of `OnLowWasmMemory` is no-op.
        task_queue.enqueue(ExecutionTask::OnLowWasmMemory);
        assert!(task_queue.is_empty());

        // After removing `OnLowWasmMemory` from queue `OnLowWasmMemoryHookStatus`
        // will become `ConditionNotSatisfied`.
        task_queue.remove(ExecutionTask::OnLowWasmMemory);
        assert!(task_queue.is_empty());

        // So now `enqueue` of `OnLowWasmMemory` will set `OnLowWasmMemoryHookStatus`
        // to `Ready`.
        task_queue.enqueue(ExecutionTask::OnLowWasmMemory);
        assert_eq!(task_queue.len(), 1);

        assert_eq!(task_queue.pop_front(), Some(ExecutionTask::OnLowWasmMemory));
    }

    #[test]
    fn test_task_queue_test_enqueue() {
        let mut task_queue = TaskQueue::default();
        assert!(task_queue.is_empty());

        task_queue.enqueue(ExecutionTask::Heartbeat);
        task_queue.enqueue(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));
        task_queue.enqueue(ExecutionTask::GlobalTimer);
        task_queue.enqueue(ExecutionTask::OnLowWasmMemory);

        assert!(!task_queue.is_empty());
        assert_eq!(task_queue.len(), 4);

        // Disregarding order of `enqueue` operations, if there is
        // paused task, it should be returned the first.
        assert_eq!(
            task_queue.pop_front(),
            Some(ExecutionTask::PausedInstallCode(PausedExecutionId(0)))
        );

        // Disregarding order of `enqueue` operations, if there is OnLowWasmMemory
        // task, it should be returned right after paused or aborted task if there is one.
        assert_eq!(task_queue.pop_front(), Some(ExecutionTask::OnLowWasmMemory));

        // The rest of the tasks should be returned in the LIFO order.
        assert_eq!(task_queue.pop_front(), Some(ExecutionTask::GlobalTimer));
        assert_eq!(task_queue.pop_front(), Some(ExecutionTask::Heartbeat));
    }
}
