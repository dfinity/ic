#![allow(dead_code)]
use std::collections::{BTreeMap, VecDeque};
use std::{collections::BTreeSet, panic::UnwindSafe};

use anyhow::{bail, Result};
use slog::{error, Logger};

use crate::driver::new::{
    context::GroupContext,
    task::{OldTask, OldTaskState},
    task_executor::TaskExecutor,
};

use super::action_graph::{ActionGraph, NodeEvent};
use super::event::{Event, EventPayload, EventSubscriber, TaskId};
use super::task::Task;

pub trait FilterFn: Fn(&str) -> bool + UnwindSafe + Send + Sync + 'static {}
impl<T: Fn(&str) -> bool + UnwindSafe + Send + Sync + 'static> FilterFn for T {}

pub struct TaskSchedule {
    plan: Vec<BTreeSet<String>>,
    filter: Vec<Box<dyn FilterFn>>,
    ctx: GroupContext,
}

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
    pub fn execute(self) -> Result<()> {
        // * turn planned tasks into scheduled tasks
        let should_include = |s: &str| self.filter.iter().all(|p| p(s));

        let schedule: Vec<BTreeSet<OldTask>> = self
            .plan
            .iter()
            .map(|task_names| {
                task_names
                    .iter()
                    .map(|s| {
                        let state = if !should_include(s) {
                            // FIXME: use logger
                            println!("Skipping task {}", &s[..]);
                            OldTaskState::Skipped
                        } else {
                            // FIXME: use logger
                            println!("Scheduled task {}", &s[..]);
                            OldTaskState::Scheduled
                        };
                        match s.as_str() {
                            "::setup" => OldTask::Setup(state),
                            _ => OldTask::Test {
                                name: s.clone(),
                                state,
                            },
                        }
                    })
                    .collect::<_>()
            })
            .collect::<_>();

        println!("Obtained {:?} phases", schedule.len());

        let mut done_set: BTreeSet<OldTask> = Default::default();

        for (i, mut tasks) in schedule.into_iter().enumerate() {
            println!("Executing phase #{:?}", i);
            let mut processed_tasks = TaskExecutor::execute(&self.ctx, &mut tasks);
            done_set.append(&mut processed_tasks);
        }

        println!("Completed {:?} phases", done_set.len());
        let has_execution_succeeded = done_set
            .iter()
            .any(|x| matches!(x.state(), OldTaskState::Failed { failure_message: _ }));
        if has_execution_succeeded {
            bail!("Some tasks in the schedule failed.");
        }
        Ok(())
    }
}

/// Map a task id to a task.
pub type TaskTable = BTreeMap<TaskId, Box<dyn Task>>;

/// A task scheduler is an EventSubscriber that spawns, stops, or fails tasks
/// as a side-effect of processing events.
pub fn new_task_scheduler(
    mut scheduled_tasks: TaskTable,
    mut action_graph: ActionGraph<TaskId>,
    log: Logger,
) -> impl EventSubscriber {
    let mut running_tasks = BTreeMap::new();
    let mut action_graph_events = VecDeque::new();

    move |evt: Event| {
        let mut action_graph_subs = |n: NodeEvent<TaskId>| {
            action_graph_events.push_back(n);
        };
        match &evt.what {
            EventPayload::TaskFailed { task_id, .. } => {
                let (_th, node_handle) = if let Some(item) = running_tasks.remove(task_id) {
                    item
                } else {
                    return;
                };
                action_graph.fail(node_handle, &mut action_graph_subs)
            }
            EventPayload::TaskStopped { task_id } => {
                let (_th, node_handle) = if let Some(item) = running_tasks.remove(task_id) {
                    item
                } else {
                    return;
                };
                action_graph.stop(node_handle, &mut action_graph_subs)
            }
            EventPayload::StartSchedule => {
                // Start the state machine. As a result, in the first loop
                // iteration, only tasks get spawned.
                action_graph.start(&mut action_graph_subs);
            }
            _ => return,
        };

        // Spawn, stop, or fail tasks in the order in which the action graph
        // tells us to do so.
        while let Some(c) = action_graph_events.pop_front() {
            let node_handle = c.handle;
            let tid = node_handle.id();
            let action_type = c.event_type;
            use super::action_graph::NodeEventType::*;
            match action_type {
                Start => {
                    let t = match scheduled_tasks.remove(&tid) {
                        Some(t) => t,
                        None => {
                            error!(log, "No scheduled task '{tid:?}'.");
                            return;
                        }
                    };
                    let th = t.spawn();
                    running_tasks.insert(tid, (th, node_handle));
                }
                Stop => {
                    if let Some((t, _node_handle)) = running_tasks.remove(&tid) {
                        t.stop();
                    }
                }
                Fail => {
                    if let Some((t, _node_handle)) = running_tasks.remove(&tid) {
                        // todo: if this failure is the result of a
                        // received failure event, the failure message
                        // could be propagated here by passing as an
                        // argument: fail(msg)
                        t.fail();
                    }
                }
            }
        }
    }
}
