#[rustfmt::skip]

// TODO: rename this module as task_schedule.rs

use std::{
    collections::BTreeSet,
    panic::UnwindSafe,
};

use crate::driver::new::{
    context::GroupContext,
    task::{Task, TaskState},
    task_executor::TaskExecutor,
};

pub trait FilterFn: Fn(&str) -> bool + UnwindSafe + Send + Sync + 'static {}
impl<T: Fn(&str) -> bool + UnwindSafe + Send + Sync + 'static> FilterFn for T {}

pub struct TaskSchedule {
    plan: Vec<BTreeSet<String>>,
    filter: Vec<Box<dyn FilterFn>>,
    ctx: GroupContext,
}

// impl Default for TaskSchedule {
//     fn default() -> Self {
//         Self {
//             plan: Default::default(),
//             filter: vec![Box::new(|_s| true)],
//         }
//     }
// }

impl TaskSchedule {
    pub fn new(ctx: GroupContext) -> Self {
        Self {
            plan: Default::default(),
            filter: vec![Box::new(|_s| true)],
            ctx,
        }
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

    pub fn append(self, name: &str) -> Self {
        let singleton = |n: &str| vec![n.to_string()].into_iter().collect::<BTreeSet<_>>();
        self.append_set(singleton(name))
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

        let schedule: Vec<BTreeSet<Task>> = self
            .plan
            .iter()
            .map(|task_names| {
                task_names
                    .iter()
                    .map(|s| {
                        let state = if !should_include(s) {
                            // FIXME: use logger
                            println!("Skipping task {}", &s[..]);
                            TaskState::Skipped
                        } else {
                            // FIXME: use logger
                            println!("Scheduled task {}", &s[..]);
                            TaskState::Scheduled
                        };
                        match s.as_str() {
                            "::setup" => Task::Setup(state),
                            _ => Task::Test {
                                name: s.clone(),
                                state,
                            },
                        }
                    })
                    .collect::<_>()
            })
            .collect::<_>();

        println!("Obtained {:?} phases", schedule.len());

        let mut done_set: BTreeSet<Task> = Default::default();

        for (i, mut tasks) in schedule.into_iter().enumerate() {
            println!("Executing phase #{:?}", i);
            let mut processed_tasks = TaskExecutor::execute(&self.ctx, &mut tasks);
            done_set.append(&mut processed_tasks);
        }

        println!("Completed {:?} phases", done_set.len());
    }
}
