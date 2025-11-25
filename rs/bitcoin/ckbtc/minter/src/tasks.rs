#[cfg(test)]
mod tests;
use crate::reimbursement::reimburse_withdrawals;
use crate::{
    CanisterRuntime, consolidate_utxos, estimate_fee_per_vbyte, finalize_requests,
    submit_pending_requests,
};
use scopeguard::guard;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

thread_local! {
    static TASKS: RefCell<TaskQueue> = RefCell::default();
    static LAST_GLOBAL_TIMER: Cell<u64> = Cell::default();
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum TaskType {
    ProcessLogic(bool),
    RefreshFeePercentiles,
    ConsolidateUtxos,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Task {
    pub execute_at: u64,
    pub task_type: TaskType,
}

#[derive(Clone, Debug, Default)]
pub struct TaskQueue {
    queue: BTreeSet<Task>,
    deadline_by_task: BTreeMap<TaskType, u64>,
}

fn set_global_timer<R: CanisterRuntime>(ts: u64, runtime: &R) {
    LAST_GLOBAL_TIMER.with(|v| v.set(ts));
    runtime.global_timer_set(ts);
}

impl TaskQueue {
    /// Schedules the given task at the specified time.  Returns the
    /// time that the caller should pass to the set_global_timer
    /// function.
    ///
    /// NOTE: The queue keeps only one copy of each task. If the
    /// caller submits multiple identical tasks with the same
    /// deadline, the queue keeps the task with the earliest deadline.
    pub fn schedule_at(&mut self, execute_at: u64, task_type: TaskType) -> u64 {
        let old_deadline = self
            .deadline_by_task
            .get(&task_type)
            .cloned()
            .unwrap_or(u64::MAX);

        if execute_at <= old_deadline {
            let old_task = Task {
                execute_at: old_deadline,
                task_type,
            };

            self.queue.remove(&old_task);
            self.deadline_by_task
                .insert(old_task.task_type.clone(), execute_at);
            self.queue.insert(Task {
                execute_at,
                task_type: old_task.task_type,
            });
        }

        self.next_execution_timestamp().unwrap_or(execute_at)
    }

    fn next_execution_timestamp(&self) -> Option<u64> {
        self.queue.first().map(|t| t.execute_at)
    }

    /// Removes the first task from the queue that's ready for
    /// execution.
    pub fn pop_if_ready(&mut self, now: u64) -> Option<Task> {
        if self.queue.first()?.execute_at <= now {
            let task = self
                .queue
                .pop_first()
                .expect("unreachable: couldn't pop from a non-empty queue");
            self.deadline_by_task.remove(&task.task_type);
            Some(task)
        } else {
            None
        }
    }

    /// Returns true if the queue is not empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Returns the number of tasks in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

/// Schedules a task for execution after the given delay.
pub fn schedule_after<R: CanisterRuntime>(delay: Duration, work: TaskType, runtime: &R) {
    let now_nanos = runtime.time();
    let execute_at_ns = now_nanos.saturating_add(delay.as_nanos() as u64);

    let execution_time = TASKS.with(|t| t.borrow_mut().schedule_at(execute_at_ns, work));
    set_global_timer(execution_time, runtime);
}

/// Schedules a task for immediate execution.
pub fn schedule_now<R: CanisterRuntime>(work: TaskType, runtime: &R) {
    schedule_after(Duration::from_secs(0), work, runtime)
}

/// Dequeues the next task ready for execution from the minter task queue.
pub fn pop_if_ready<R: CanisterRuntime>(runtime: &R) -> Option<Task> {
    let now = runtime.time();
    let task = TASKS.with(|t| t.borrow_mut().pop_if_ready(now));
    if let Some(next_execution) = TASKS.with(|t| t.borrow().next_execution_timestamp()) {
        set_global_timer(next_execution, runtime);
    }
    task
}

/// Returns the current value of the global task timer.
pub fn global_timer() -> u64 {
    LAST_GLOBAL_TIMER.with(|v| v.get())
}

pub(crate) async fn run_task<R: CanisterRuntime>(task: Task, runtime: R) {
    match task.task_type {
        TaskType::ProcessLogic(force_resubmit_stuck_transactions) => {
            const INTERVAL_PROCESSING: Duration = Duration::from_secs(5);

            let _enqueue_followup_guard = guard((), |_| {
                schedule_after(INTERVAL_PROCESSING, TaskType::ProcessLogic(false), &runtime)
            });

            let _guard = match crate::guard::TimerLogicGuard::new() {
                Some(guard) => guard,
                None => return,
            };

            submit_pending_requests(&runtime).await;
            finalize_requests(&runtime, force_resubmit_stuck_transactions).await;
            reimburse_withdrawals(&runtime).await;
        }
        TaskType::RefreshFeePercentiles => {
            let _enqueue_followup_guard = guard((), |_| {
                schedule_after(
                    runtime.refresh_fee_percentiles_frequency(),
                    TaskType::RefreshFeePercentiles,
                    &runtime,
                )
            });

            let _guard = match crate::guard::TimerLogicGuard::new() {
                Some(guard) => guard,
                None => return,
            };
            let _ = estimate_fee_per_vbyte(&runtime).await;
        }
        TaskType::ConsolidateUtxos => {
            const INTERVAL_PROCESSING: Duration = Duration::from_secs(3600);
            const MIN_CONSOLIDATION_UTXO_THRESHOLD: usize = 10_000;

            let _enqueue_followup_guard = guard((), |_| {
                schedule_after(INTERVAL_PROCESSING, TaskType::ConsolidateUtxos, &runtime)
            });

            let _guard = match crate::guard::TimerLogicGuard::new() {
                Some(guard) => guard,
                None => return,
            };
            consolidate_utxos(&runtime, MIN_CONSOLIDATION_UTXO_THRESHOLD)
                .await
                .ok();
        }
    }
}
