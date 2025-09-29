#![allow(dead_code)]
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use slog::{Logger, debug, info};

use crate::driver::action_graph::ActionGraph;
use crate::driver::event::TaskId;
use crate::driver::log_events;
use crate::driver::task::Task;

use super::action_graph::Node;
use super::group::is_task_visible_to_user;
use super::report::{SystemGroupSummary, TaskReport};
use super::task::TaskHandle;
// Be mindful when modifying this constant, as the event can be consumed by other parties.
const JSON_REPORT_CREATED_EVENT_NAME: &str = "json_report_created_event";

// trait for report and failure
#[derive(Debug)]
pub enum TaskResult {
    Report(TaskId, String),
    Failure(TaskId, String),
}

/// Map a task id to a task.
pub type TaskTable = BTreeMap<TaskId, Box<dyn Task>>;

pub struct TaskScheduler {
    pub scheduled_tasks: TaskTable,
    pub action_graph: ActionGraph<TaskId>,
    pub running_tasks: BTreeMap<TaskId, (Box<dyn TaskHandle>, usize)>,
    pub start_times: BTreeMap<TaskId, SystemTime>,
    pub end_times: BTreeMap<TaskId, SystemTime>,
    pub log: Logger,
    pub test_name: String,
}

impl TaskScheduler {
    #[allow(clippy::map_entry)]
    pub fn execute(&mut self, dbg_keepalive: bool) {
        #[allow(clippy::disallowed_methods)]
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let log = &self.log;
        self.action_graph.start();
        loop {
            // bring tasks into the state prescribed by action graph
            for (node_index, (node, maybe_task_id)) in self.action_graph.task_iter().enumerate() {
                // debug!(log, "ag: node_index {:?} node {:?} task_id {:?}", node_index, node, maybe_task_id);
                match node {
                    Node::Running { active: 0, .. } => {
                        // stop this task if it is still running
                        if let Some(task_id) = maybe_task_id {
                            let (th, _node_handle) = match self.running_tasks.remove(&task_id) {
                                Some(item) => {
                                    Self::record_time(&mut self.end_times, &task_id);
                                    item
                                }
                                _ => {
                                    continue;
                                }
                            };
                            // debug!(log, "ag: Stopping node {:?} task {}", &node, &task_id);
                            th.cancel();

                            if dbg_keepalive && task_id.to_string() == "report" {
                                let report = self.create_report(self.test_name.clone());
                                let event: log_events::LogEvent<_> = report.clone().into();
                                event.emit_log(log);
                                info!(log, "Report:\n{}", report.pretty_print());
                            }
                        }
                    }
                    Node::Running { .. } => {
                        if let Some(task_id) = maybe_task_id
                            && !self.running_tasks.contains_key(&task_id)
                        {
                            // debug!(log, "ag: Starting node: {:?}, task: {}", &node, &task_id);
                            let task = self.scheduled_tasks.get(&task_id).unwrap();
                            let tx = event_tx.clone();
                            let cb = move |result: TaskResult| {
                                tx.send(result).expect("Failed to send message.")
                            };
                            let th = task.spawn(Box::new(cb));
                            Self::record_time(&mut self.start_times, &task_id);
                            self.running_tasks.insert(task_id, (th, node_index));
                        }
                    }
                    Node::Failed { .. } => {
                        if let Some(task_id) = maybe_task_id {
                            let (th, _node_handle) = match self.running_tasks.remove(&task_id) {
                                Some(item) => {
                                    Self::record_time(&mut self.end_times, &task_id);
                                    item
                                }
                                _ => {
                                    continue;
                                }
                            };
                            // debug!(log, "ag: Failing node {:?} task {}", &node, &task_id);
                            th.cancel();
                        }
                    }
                    _ => {}
                }
            }
            // debug!(log, "running tasks: {:?}", self.running_tasks.keys());

            // handle events and update action graph accordingly
            if self.running_tasks.is_empty() {
                info!(
                    log,
                    "Task scheduler is out of running tasks and will terminate."
                );
                break;
            }
            // wait for running task to send a signal
            let result = event_rx
                .recv()
                .expect("Error while task scheduler tried to receive events.");
            // debug!(log, "ag: received result {:?}", result);
            match result {
                TaskResult::Report(task_id, ref report) => {
                    // debug!(log, "ag: Setting ag node with task_id: {:?} to stop due to result {}", &task_id, &report);
                    debug!(log, "Task {:?} succeeded due to: {}", &task_id, &report);
                    if let Some((_th, node_idx)) = self.running_tasks.get(&task_id) {
                        self.action_graph.stop(*node_idx, report.to_string());
                    } else {
                        debug!(
                            log,
                            "Task id {} not found in running_tasks (report)", task_id
                        );
                    }
                }
                TaskResult::Failure(task_id, ref reason) => {
                    // debug!(log, "ag: Setting ag node with task_id: {:?} to fail due to result {}", &task_id, &reason);
                    debug!(log, "Task {:?} failed due to: {}", &task_id, &reason);
                    if let Some((_th, node_idx)) = self.running_tasks.get(&task_id) {
                        self.action_graph.fail(*node_idx, reason.to_string());
                    } else {
                        debug!(
                            log,
                            "Task id {} not found in running_tasks (failure)", task_id
                        );
                    }
                }
            }
        }
    }

    fn record_time(times: &mut BTreeMap<TaskId, SystemTime>, task_id: &TaskId) {
        times.insert(task_id.clone(), SystemTime::now());
    }

    fn get_duration(&self, task_id: &TaskId) -> Option<Duration> {
        if !self.start_times.contains_key(task_id) || !self.end_times.contains_key(task_id) {
            return None;
        }
        Some(
            self.end_times
                .get(task_id)
                .unwrap()
                .duration_since(*self.start_times.get(task_id).unwrap())
                .expect("Failed to calculate task duration."),
        )
    }

    pub fn create_report(&self, test_name: String) -> SystemGroupSummary {
        let mut success = vec![];
        let mut failure = vec![];
        let mut skipped = vec![];
        for (node, maybe_task_id) in self.action_graph.task_iter() {
            if let Some(task_id) = maybe_task_id {
                if !is_task_visible_to_user(&task_id) {
                    continue;
                }
                let duration = self
                    .get_duration(&task_id)
                    .unwrap_or_else(|| Duration::from_secs(0));
                match node {
                    Node::Running { active: _, message } => {
                        // TODO: handle this with proper message/failure types
                        // println!("message for task id {} {:?}", task_id, message);
                        if message.is_some() && message.clone().unwrap().contains("Task skipped") {
                            skipped.push(TaskReport {
                                name: task_id.to_string(),
                                runtime: duration.as_secs_f64(),
                                message,
                            });
                        } else {
                            success.push(TaskReport {
                                name: task_id.to_string(),
                                runtime: duration.as_secs_f64(),
                                message,
                            });
                        }
                    }
                    Node::Failed { reason } => {
                        failure.push(TaskReport {
                            name: task_id.to_string(),
                            runtime: duration.as_secs_f64(),
                            message: reason,
                        });
                    }
                    _ => {}
                }
            }
        }
        SystemGroupSummary {
            test_name,
            success,
            failure,
            skipped,
        }
    }
}

impl From<SystemGroupSummary> for log_events::LogEvent<SystemGroupSummary> {
    fn from(item: SystemGroupSummary) -> Self {
        log_events::LogEvent::new(JSON_REPORT_CREATED_EVENT_NAME.to_string(), item)
    }
}
