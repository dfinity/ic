pub mod proto;

use crate::ExecutionTask;
use ic_interfaces::execution_environment::ExecutionRoundType;
use ic_management_canister_types_private::OnLowWasmMemoryHookStatus;
use ic_types::CanisterId;
use ic_types::NumBytes;
use ic_types_cycles::{CompoundCycles, Instructions};
use std::collections::VecDeque;

/// `TaskQueue` represents the implementation of queue structure for canister tasks satisfying the following conditions:
///
/// 1. If there is a `Paused` or `Aborted` task it will be returned first.
/// 2. If an `OnLowWasmMemoryHook` is ready to be executed, it will be returned next.
/// 3. All other tasks will be returned in the order in which they were enqueued.
///
/// # OnLowWasmMemory hook reservation
///
/// The `OnLowWasmMemory` hook costs cycles to execute. Those cycles are prepaid
/// by the replicated message whose execution may grow Wasm memory enough to
/// trigger the hook (request, response, ingress, install_code, heartbeat,
/// global timer). When that message's execution observes the hook condition to
/// be satisfied, it transfers the prepayment into this `TaskQueue` via
/// [`TaskQueue::enqueue_on_low_wasm_memory_hook`]; the hook execution path later
/// reclaims it by popping the `OnLowWasmMemory(reservation)` task from the queue.
///
/// The reservation is conceptually attached to the enqueued `OnLowWasmMemory`
/// task; the corresponding state-level invariant is:
///
/// ```text
///   on_low_wasm_memory_hook_status == Ready
///       ⇔
///   on_low_wasm_memory_hook_task == Some(OnLowWasmMemory(reservation))
/// ```
///
/// This invariant is enforced inside this module; external callers must enqueue
/// and dequeue the hook exclusively through `enqueue_on_low_wasm_memory_hook` /
/// `dequeue_on_low_wasm_memory_hook` (and pop the enqueued task via `pop_front`).
///
/// The reservation is *not* persisted into canister snapshots: snapshots must
/// never carry held cycles, so restoring a snapshot with a `Ready` hook
/// withdraws fresh cycles from the canister balance to fund the reservation
/// (see `CanisterSnapshot::try_load`).
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct TaskQueue {
    /// Keeps `PausedExecution`, or `PausedInstallCode`, or `AbortedExecution`,
    /// or `AbortedInstallCode` task if there is one.
    paused_or_aborted_task: Option<ExecutionTask>,

    /// Status of low_on_wasm_memory hook execution.
    ///
    /// Invariant: `Ready` iff `on_low_wasm_memory_hook_task` is `Some` (i.e.,
    /// the hook has been enqueued with a prepayment). Other states never carry
    /// reserved cycles.
    on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,

    /// The enqueued `OnLowWasmMemory` task with its prepaid execution cycles,
    /// present iff `on_low_wasm_memory_hook_status == Ready`. Stored here so
    /// that `front()` can return a stable reference without synthesizing a
    /// transient value.
    on_low_wasm_memory_hook_task: Option<ExecutionTask>,

    /// Queue of `Heartbeat` and `GlobalTimer` tasks.
    queue: VecDeque<ExecutionTask>,
}

impl TaskQueue {
    /// Asserts the internal invariants relating the hook status and the held
    /// hook task. Called from the bottom of every method that mutates either
    /// field. In release builds the body is compiled away.
    ///
    /// Invariants:
    /// 1. `on_low_wasm_memory_hook_task.is_some() ⇔ status == Ready`.
    /// 2. If `on_low_wasm_memory_hook_task` is `Some`, it is an
    ///    `ExecutionTask::OnLowWasmMemory(_)` variant.
    fn check_invariants(&self) {
        debug_assert_eq!(
            self.on_low_wasm_memory_hook_status == OnLowWasmMemoryHookStatus::Ready,
            self.on_low_wasm_memory_hook_task.is_some(),
            "BUG: `Ready ⇔ on_low_wasm_memory_hook_task.is_some()` invariant violated: \
             status={:?}, task={:?}",
            self.on_low_wasm_memory_hook_status,
            self.on_low_wasm_memory_hook_task,
        );
        if let Some(task) = &self.on_low_wasm_memory_hook_task {
            debug_assert!(
                matches!(task, ExecutionTask::OnLowWasmMemory(_)),
                "BUG: unexpected task stored in `on_low_wasm_memory_hook_task`: {task:?}",
            );
        }
    }

    pub fn front(&self) -> Option<&ExecutionTask> {
        self.paused_or_aborted_task
            .as_ref()
            .or(self.on_low_wasm_memory_hook_task.as_ref())
            .or_else(|| self.queue.front())
    }

    pub fn pop_front(&mut self) -> Option<ExecutionTask> {
        let popped = self.paused_or_aborted_task.take().or_else(|| {
            if let Some(task) = self.on_low_wasm_memory_hook_task.take() {
                self.on_low_wasm_memory_hook_status = OnLowWasmMemoryHookStatus::Executed;
                Some(task)
            } else {
                self.queue.pop_front()
            }
        });
        self.check_invariants();
        popped
    }

    /// Enqueues the `OnLowWasmMemory` hook with the supplied prepayment when
    /// the canister transitions from "below the limit" to "over the limit".
    ///
    /// The hook is meant to fire exactly once per such transition.
    /// `OnLowWasmMemoryHookStatus::update(true)` returns `true` iff the status
    /// just transitioned `ConditionNotSatisfied -> Ready`; we install the
    /// reservation in that case and refund it otherwise (status was already
    /// `Ready`, meaning a previous message has already enqueued and funded the
    /// hook; or `Executed`, meaning the hook already fired for the current
    /// memory-limit crossing and must not fire again).
    ///
    /// In short, the caller can unconditionally hand the hook prepayment to
    /// this method whenever the memory condition is satisfied at the end of a
    /// replicated message execution; this method decides whether the hook
    /// actually needs to be (re-)enqueued and returns any unused cycles for
    /// refund.
    #[must_use = "the returned reservation, if any, must be refunded to the canister balance"]
    pub fn enqueue_on_low_wasm_memory_hook(
        &mut self,
        reservation: CompoundCycles<Instructions>,
    ) -> Option<CompoundCycles<Instructions>> {
        let refund = if self.on_low_wasm_memory_hook_status.update(true) {
            // Status transitioned `ConditionNotSatisfied -> Ready`: hold the
            // prepayment with the enqueued task.
            self.on_low_wasm_memory_hook_task = Some(ExecutionTask::OnLowWasmMemory(reservation));
            None
        } else {
            // No transition (status was `Ready` or `Executed`): refund.
            Some(reservation)
        };
        self.check_invariants();
        refund
    }

    /// Dequeues the `OnLowWasmMemory` hook (if any), transitioning the status
    /// to `ConditionNotSatisfied` and returning the previously held
    /// reservation (if any). The caller must refund the returned cycles to the
    /// canister balance via `system_state.refund_cycles`.
    #[must_use = "the returned reservation, if any, must be refunded to the canister balance"]
    pub fn dequeue_on_low_wasm_memory_hook(&mut self) -> Option<CompoundCycles<Instructions>> {
        // `update(false)` always returns `false` (no `Ready` transition) and
        // resets the status to `ConditionNotSatisfied`; release the held task
        // in lockstep and hand its reservation back to the caller for refund.
        let _ = self.on_low_wasm_memory_hook_status.update(false);
        let refund = match self.on_low_wasm_memory_hook_task.take() {
            Some(ExecutionTask::OnLowWasmMemory(reservation)) => Some(reservation),
            Some(other) => {
                panic!("BUG: unexpected task stored in `on_low_wasm_memory_hook_task`: {other:?}")
            }
            None => None,
        };
        self.check_invariants();
        refund
    }

    /// Returns `true` if the `OnLowWasmMemory` hook is currently enqueued
    /// (status `Ready`, reservation held).
    pub fn is_on_low_wasm_memory_hook_enqueued(&self) -> bool {
        self.on_low_wasm_memory_hook_task.is_some()
    }

    pub fn paused_or_aborted_task(&self) -> &Option<ExecutionTask> {
        &self.paused_or_aborted_task
    }

    pub fn has_paused_or_aborted_task(&self) -> bool {
        self.paused_or_aborted_task.is_some()
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
            ExecutionTask::OnLowWasmMemory(_) => panic!(
                "OnLowWasmMemory must not be enqueued via `TaskQueue::enqueue`. \
                 Use `TaskQueue::enqueue_on_low_wasm_memory_hook(reservation)` instead.",
            ),
            ExecutionTask::Heartbeat | ExecutionTask::GlobalTimer => self.queue.push_front(task),
        };
    }

    pub fn is_empty(&self) -> bool {
        self.paused_or_aborted_task.is_none()
            && self.on_low_wasm_memory_hook_task.is_none()
            && self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
            + self.paused_or_aborted_task.as_ref().map_or(0, |_| 1)
            + if self.on_low_wasm_memory_hook_task.is_some() {
                1
            } else {
                0
            }
    }

    pub fn peek_hook_status(&self) -> OnLowWasmMemoryHookStatus {
        self.on_low_wasm_memory_hook_status
    }

    /// Sets the hook status without a reservation. This should only be used by
    /// the canister snapshot restore path for non-`Ready` statuses; if the
    /// snapshot's status is `Ready`, the caller must instead enqueue the hook
    /// with a reservation withdrawn from the canister balance via
    /// `enqueue_on_low_wasm_memory_hook`.
    pub fn set_on_low_wasm_memory_hook_status_from_snapshot(
        &mut self,
        on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus,
    ) {
        debug_assert!(
            !on_low_wasm_memory_hook_status.is_ready(),
            "`Ready` status must be installed via `enqueue_on_low_wasm_memory_hook`."
        );
        self.on_low_wasm_memory_hook_status = on_low_wasm_memory_hook_status;
        self.check_invariants();
    }

    /// `check_dts_invariants` should only be called after round execution.
    ///
    /// It checks that the following properties are satisfied:
    /// 1. Heartbeat, GlobalTimer tasks exist only during the round and must not exist after the round.
    /// 2. Paused executions can exist only in ordinary rounds (not checkpoint rounds).
    /// 3. If deterministic time slicing is disabled, then there are no paused tasks.
    ///    Aborted tasks may still exist if DTS was disabled in recent checkpoints.
    pub fn check_dts_invariants(&self, current_round_type: ExecutionRoundType, id: &CanisterId) {
        if let Some(paused_or_aborted_task) = &self.paused_or_aborted_task {
            match paused_or_aborted_task {
                ExecutionTask::PausedExecution { .. } | ExecutionTask::PausedInstallCode(_) => {
                    assert_eq!(
                        current_round_type,
                        ExecutionRoundType::OrdinaryRound,
                        "Unexpected paused execution {paused_or_aborted_task:?} after a checkpoint round in canister {id:?}"
                    );
                }
                ExecutionTask::AbortedExecution { .. }
                | ExecutionTask::AbortedInstallCode { .. } => {}
                ExecutionTask::Heartbeat
                | ExecutionTask::GlobalTimer
                | ExecutionTask::OnLowWasmMemory(_) => {
                    unreachable!(
                        "Unexpected on task type {:?} in TaskQueue::paused_or_aborted_task in canister {:?} .",
                        paused_or_aborted_task, id
                    )
                }
            }
        }

        if let Some(task) = self.queue.front() {
            match task {
                ExecutionTask::Heartbeat => {
                    panic!("Unexpected heartbeat task after a round in canister {id:?}");
                }
                ExecutionTask::GlobalTimer => {
                    panic!("Unexpected global timer task after a round in canister {id:?}");
                }
                ExecutionTask::OnLowWasmMemory(_)
                | ExecutionTask::AbortedExecution { .. }
                | ExecutionTask::AbortedInstallCode { .. }
                | ExecutionTask::PausedExecution { .. }
                | ExecutionTask::PausedInstallCode(_) => {
                    unreachable!(
                        "Unexpected task type {:?} in TaskQueue::queue, after a round in canister {:?}",
                        task, id
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

    /// Returns true if the task queue has a `Heartbeat` or `GlobalTimer` task.
    pub fn has_heartbeat_or_global_timer(&self) -> bool {
        self.queue
            .iter()
            .any(|task| *task == ExecutionTask::Heartbeat || *task == ExecutionTask::GlobalTimer)
    }

    /// Removes `Heartbeat` and `GlobalTimer` tasks.
    pub fn remove_heartbeat_and_global_timer(&mut self) {
        for task in self.queue.iter() {
            debug_assert!(
                *task == ExecutionTask::Heartbeat || *task == ExecutionTask::GlobalTimer,
                "Unexpected task type {task:?} in TaskQueue::queue."
            );
        }

        self.queue.retain(|task| {
            *task != ExecutionTask::Heartbeat && *task != ExecutionTask::GlobalTimer
        });
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
                | ExecutionTask::OnLowWasmMemory(_) => unreachable!(
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
            | ExecutionTask::OnLowWasmMemory(_)
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
///   `wasm_memory_threshold > wasm_memory_limit - wasm_memory_usage`
///
/// Note: if `wasm_memory_limit` is not set, its default value is 4 GiB.
pub fn is_low_wasm_memory_hook_condition_satisfied(
    wasm_memory_usage: NumBytes,
    wasm_memory_limit: Option<NumBytes>,
    wasm_memory_threshold: NumBytes,
) -> bool {
    // If wasm memory limit is not set, the default is 4 GiB. Wasm memory
    // limit is ignored for query methods, response callback handlers,
    // global timers, heartbeats, and canister pre_upgrade.
    let wasm_memory_limit =
        wasm_memory_limit.unwrap_or_else(|| NumBytes::new(4 * 1024 * 1024 * 1024));

    // Conceptually we can think that the remaining Wasm memory is
    // equal to `wasm_memory_limit - wasm_memory_usage` and that should
    // be compared with `wasm_memory_threshold` when checking for
    // the condition for the hook. However, since `wasm_memory_limit`
    // is ignored in some executions as stated above it is possible
    // that `wasm_memory_usage` is greater than `wasm_memory_limit` and to
    // avoid overflowing subtraction we adjusted the inequality.
    wasm_memory_limit < wasm_memory_usage + wasm_memory_threshold
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{ExecutionTask, metadata_state::subnet_call_context_manager::InstallCodeCallId};

    use super::TaskQueue;
    use crate::canister_state::system_state::PausedExecutionId;
    use ic_management_canister_types_private::OnLowWasmMemoryHookStatus;
    use ic_test_utilities_types::messages::IngressBuilder;
    use ic_types::messages::{CanisterCall, CanisterMessageOrTask, CanisterTask};
    use ic_types_cycles::{CanisterCyclesCostSchedule, CompoundCycles, Cycles, Instructions};

    fn dummy_reservation() -> CompoundCycles<Instructions> {
        CompoundCycles::new(Cycles::zero(), CanisterCyclesCostSchedule::Normal)
    }

    #[test]
    fn test_on_low_wasm_memory_hook_start_status_condition_not_satisfied() {
        let mut status = OnLowWasmMemoryHookStatus::ConditionNotSatisfied;
        assert!(!status.update(false));
        assert_eq!(status, OnLowWasmMemoryHookStatus::ConditionNotSatisfied);

        // `update(true)` transitions `ConditionNotSatisfied -> Ready` and
        // returns `true` so the caller (`enqueue_on_low_wasm_memory_hook`) knows
        // to hold on to the supplied reservation.
        let mut status = OnLowWasmMemoryHookStatus::ConditionNotSatisfied;
        assert!(status.update(true));
        assert_eq!(status, OnLowWasmMemoryHookStatus::Ready);
    }

    #[test]
    fn test_on_low_wasm_memory_hook_start_status_ready() {
        let mut status = OnLowWasmMemoryHookStatus::Ready;
        assert!(!status.update(false));
        assert_eq!(status, OnLowWasmMemoryHookStatus::ConditionNotSatisfied);

        // Already `Ready`: no transition, no new reservation needed.
        let mut status = OnLowWasmMemoryHookStatus::Ready;
        assert!(!status.update(true));
        assert_eq!(status, OnLowWasmMemoryHookStatus::Ready);
    }

    #[test]
    fn test_on_low_wasm_memory_hook_start_status_executed() {
        let mut status = OnLowWasmMemoryHookStatus::Executed;
        assert!(!status.update(false));
        assert_eq!(status, OnLowWasmMemoryHookStatus::ConditionNotSatisfied);

        // The hook already fired for the current crossing; do not re-enqueue.
        let mut status = OnLowWasmMemoryHookStatus::Executed;
        assert!(!status.update(true));
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
        task_queue
            .replace_paused_with_aborted_task(ExecutionTask::OnLowWasmMemory(dummy_reservation()));
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
            prepaid_execution_cycles: CompoundCycles::new(
                Cycles::zero(),
                CanisterCyclesCostSchedule::Normal,
            ),
            prepaid_hook_reservation: None,
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
            prepaid_execution_cycles: CompoundCycles::new(
                Cycles::new(1),
                CanisterCyclesCostSchedule::Normal,
            ),
            call_id: InstallCodeCallId::new(0),
        };

        task_queue.replace_paused_with_aborted_task(aborted_install_code);
    }

    #[test]
    fn test_task_queue_dequeue_on_low_wasm_memory_hook_empty_is_noop() {
        let mut task_queue = TaskQueue::default();
        assert!(task_queue.is_empty());
        // Dequeueing an empty hook is a no-op and returns no reservation.
        assert!(task_queue.dequeue_on_low_wasm_memory_hook().is_none());
        assert!(task_queue.is_empty());
    }

    #[test]
    fn test_task_queue_enqueue_dequeue_on_low_wasm_memory_hook() {
        let mut task_queue = TaskQueue::default();
        assert!(task_queue.is_empty());

        // Enqueueing with a fresh reservation transitions
        // `ConditionNotSatisfied -> Ready`.
        let reservation = CompoundCycles::new(Cycles::new(123), CanisterCyclesCostSchedule::Normal);
        assert!(
            task_queue
                .enqueue_on_low_wasm_memory_hook(reservation)
                .is_none()
        );
        assert_eq!(task_queue.len(), 1);
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::Ready
        );
        assert!(task_queue.is_on_low_wasm_memory_hook_enqueued());

        // Enqueueing again from `Ready` returns the new reservation unchanged;
        // the existing reservation is kept.
        let second = CompoundCycles::new(Cycles::new(456), CanisterCyclesCostSchedule::Normal);
        let refund = task_queue.enqueue_on_low_wasm_memory_hook(second);
        assert_eq!(refund, Some(second));
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::Ready
        );

        // Dequeueing returns the held reservation and resets the status.
        let refund = task_queue.dequeue_on_low_wasm_memory_hook();
        assert_eq!(refund, Some(reservation));
        assert!(task_queue.is_empty());
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::ConditionNotSatisfied
        );

        // Re-enqueueing is allowed after dequeue.
        let third = CompoundCycles::new(Cycles::new(789), CanisterCyclesCostSchedule::Normal);
        assert!(task_queue.enqueue_on_low_wasm_memory_hook(third).is_none());
        assert_eq!(task_queue.len(), 1);
    }

    #[test]
    fn test_task_queue_enqueue_on_low_wasm_memory_hook_does_not_re_enqueue_executed() {
        let mut task_queue = TaskQueue::default();

        // Enqueue the hook and pop it for execution: status transitions
        // `ConditionNotSatisfied -> Ready -> Executed`.
        let reservation = CompoundCycles::new(Cycles::new(100), CanisterCyclesCostSchedule::Normal);
        assert!(
            task_queue
                .enqueue_on_low_wasm_memory_hook(reservation)
                .is_none()
        );
        assert_eq!(
            task_queue.pop_front(),
            Some(ExecutionTask::OnLowWasmMemory(reservation))
        );
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::Executed
        );

        // The hook fired for the current memory-limit crossing. Subsequent
        // messages that observe the condition is still satisfied must not
        // re-enqueue; their hook prepayment is returned for refund.
        let redundant = CompoundCycles::new(Cycles::new(200), CanisterCyclesCostSchedule::Normal);
        let refund = task_queue.enqueue_on_low_wasm_memory_hook(redundant);
        assert_eq!(refund, Some(redundant));
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::Executed
        );
        assert!(!task_queue.is_on_low_wasm_memory_hook_enqueued());

        // Only when the condition becomes unsatisfied (e.g. memory shrinks
        // or `update_settings` raises the threshold) does `Executed` reset
        // to `ConditionNotSatisfied` via `dequeue_on_low_wasm_memory_hook`,
        // at which point enqueueing is allowed again.
        assert!(task_queue.dequeue_on_low_wasm_memory_hook().is_none());
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::ConditionNotSatisfied
        );
        let next_crossing =
            CompoundCycles::new(Cycles::new(300), CanisterCyclesCostSchedule::Normal);
        assert!(
            task_queue
                .enqueue_on_low_wasm_memory_hook(next_crossing)
                .is_none()
        );
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::Ready
        );
    }

    #[test]
    fn test_task_queue_pop_front_on_low_wasm_memory() {
        let mut task_queue = TaskQueue::default();

        // Enqueue the hook.
        let reservation = CompoundCycles::new(Cycles::new(42), CanisterCyclesCostSchedule::Normal);
        assert!(
            task_queue
                .enqueue_on_low_wasm_memory_hook(reservation)
                .is_none()
        );
        assert_eq!(task_queue.len(), 1);

        // Pop returns the hook task with its reservation; status -> Executed.
        assert_eq!(
            task_queue.pop_front(),
            Some(ExecutionTask::OnLowWasmMemory(reservation))
        );
        assert!(task_queue.is_empty());
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::Executed
        );

        // From `Executed`, dequeueing brings us back to `ConditionNotSatisfied`.
        assert!(task_queue.dequeue_on_low_wasm_memory_hook().is_none());
        assert_eq!(
            task_queue.peek_hook_status(),
            OnLowWasmMemoryHookStatus::ConditionNotSatisfied
        );

        // And we can enqueue again.
        let reservation2 = CompoundCycles::new(Cycles::new(7), CanisterCyclesCostSchedule::Normal);
        assert!(
            task_queue
                .enqueue_on_low_wasm_memory_hook(reservation2)
                .is_none()
        );
        assert_eq!(task_queue.len(), 1);
        assert_eq!(
            task_queue.pop_front(),
            Some(ExecutionTask::OnLowWasmMemory(reservation2))
        );
    }

    #[test]
    fn test_task_queue_test_enqueue() {
        let mut task_queue = TaskQueue::default();
        assert!(task_queue.is_empty());

        task_queue.enqueue(ExecutionTask::Heartbeat);
        task_queue.enqueue(ExecutionTask::PausedInstallCode(PausedExecutionId(0)));
        task_queue.enqueue(ExecutionTask::GlobalTimer);
        let reservation = CompoundCycles::new(Cycles::new(1), CanisterCyclesCostSchedule::Normal);
        assert!(
            task_queue
                .enqueue_on_low_wasm_memory_hook(reservation)
                .is_none()
        );

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
        assert_eq!(
            task_queue.pop_front(),
            Some(ExecutionTask::OnLowWasmMemory(reservation))
        );

        // The rest of the tasks should be returned in the LIFO order.
        assert_eq!(task_queue.pop_front(), Some(ExecutionTask::GlobalTimer));
        assert_eq!(task_queue.pop_front(), Some(ExecutionTask::Heartbeat));
    }

    #[test]
    #[should_panic(expected = "OnLowWasmMemory must not be enqueued")]
    fn test_task_queue_enqueue_on_low_wasm_memory_panics() {
        let mut task_queue = TaskQueue::default();
        task_queue.enqueue(ExecutionTask::OnLowWasmMemory(dummy_reservation()));
    }
}
