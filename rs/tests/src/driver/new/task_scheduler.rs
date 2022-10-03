use std::{
    collections::{BTreeMap, BTreeSet},
    panic::UnwindSafe,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskState {
    Skipped,
    Scheduled,
    Running { pid: u32 },
    Passed,
    Failed { failure_message: String },
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Task {
    name: String,
    state: TaskState,
}

pub trait FilterFn: Fn(&str) -> bool + UnwindSafe + Send + Sync + 'static {}
impl<T: Fn(&str) -> bool + UnwindSafe + Send + Sync + 'static> FilterFn for T {}

pub struct TaskSchedule {
    plan: Vec<BTreeSet<String>>,
    filter: Vec<Box<dyn FilterFn>>,
}

impl Default for TaskSchedule {
    fn default() -> Self {
        Self {
            plan: Default::default(),
            filter: vec![Box::new(|_s| true)],
        }
    }
}

impl TaskSchedule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a set of tasks to the schedule. All tasks in `set` will
    /// (possibly) be executed in parallel.
    ///
    /// Notes:
    ///
    /// * eventually, we will need to add options here (e.g. timeouts)
    pub fn append_set(mut self, set: BTreeSet<String>) -> Self {
        self.plan.push(set);
        self
    }

    /// If a task has a name that does not satify _all_ predicates added with
    /// `include_if`, it will transition to the `Skipped` state immediately.
    pub fn include_if<P: FilterFn>(mut self, p: P) -> Self {
        self.filter.push(Box::new(p));
        self
    }

    /// If this method is not interrupted, every scheduled task is either
    /// `Skipped`, `Failed` or `Passed`.
    ///
    /// Every state change creates an event that is passed to the caller.
    pub fn execute(self) {
        // * turn planned tasks into scheduled tasks
        let should_include = |s: &str| self.filter.iter().all(|p| p(s));

        let mut _schedule: Vec<BTreeSet<Task>> = self
            .plan
            .iter()
            .map(|task_names| {
                task_names
                    .iter()
                    .map(|s| {
                        let state = if !should_include(s) {
                            TaskState::Skipped
                        } else {
                            TaskState::Scheduled
                        };
                        let name = s.clone();
                        Task { name, state }
                    })
                    .collect::<_>()
            })
            .collect::<_>();
        // * emit an event for all skipped tasks
        // * start the execution
        // consecutively pop off a set from the schedule
        // invariant: current_set only contains scheduled/running tasks
        let mut _current_set: BTreeMap<String, Task> = Default::default();
        // invariant: done_set only contains failed/passed tasks
        let mut _done_set: BTreeSet<Task> = Default::default();
        // * for each set
        // *
        todo!()
    }
}
