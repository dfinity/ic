use ic0;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

thread_local! {
    static TASKS: RefCell<TaskQueue> = RefCell::default();
    static LAST_GLOBAL_TIMER: Cell<u64> = Cell::default();
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskType {
    ProcessLogic,
    RefreshFeePercentiles,
    DistributeKytFee,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Task {
    pub execute_at: u64,
    pub task_type: TaskType,
}

#[derive(Clone, Debug, Default)]
pub struct TaskQueue {
    queue: BTreeSet<Task>,
    deadline_by_task: BTreeMap<TaskType, u64>,
}

fn set_global_timer(ts: u64) {
    LAST_GLOBAL_TIMER.with(|v| v.set(ts));

    // SAFETY: setting the global timer is always safe; it does not
    // mutate any canister memory.
    unsafe {
        ic0::global_timer_set(ts as i64);
    }
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
pub fn schedule_after(delay: Duration, work: TaskType) {
    let now_nanos = ic_cdk::api::time();
    let execute_at = now_nanos.saturating_add(delay.as_secs() * crate::SEC_NANOS);

    let execution_time = TASKS.with(|t| t.borrow_mut().schedule_at(execute_at, work));
    set_global_timer(execution_time);
}

/// Schedules a task for immediate execution.
pub fn schedule_now(work: TaskType) {
    schedule_after(Duration::from_secs(0), work)
}

/// Dequeues the next task ready for execution from the minter task queue.
pub fn pop_if_ready() -> Option<Task> {
    let now = ic_cdk::api::time();
    let task = TASKS.with(|t| t.borrow_mut().pop_if_ready(now));
    if let Some(next_execution) = TASKS.with(|t| t.borrow().next_execution_timestamp()) {
        set_global_timer(next_execution);
    }
    task
}

/// Returns the current value of the global task timer.
pub fn global_timer() -> u64 {
    LAST_GLOBAL_TIMER.with(|v| v.get())
}
