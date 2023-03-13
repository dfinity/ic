#![allow(dead_code)]
use std::collections::{BTreeMap, VecDeque};

use slog::{error, Logger};

use crate::driver::action_graph::{ActionGraph, NodeEvent};
use crate::driver::event::{Event, EventPayload, EventSubscriber, TaskId};
use crate::driver::task::Task;

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
                //println!("Processing event EventPayload::StartSchedule ...");
                std::thread::sleep(std::time::Duration::from_secs(5));
                //println!("(changed) Processing event EventPayload::StartSchedule ...");
                // Start the state machine. As a result, in the first loop
                // iteration, only tasks get spawned.
                //println!("A action_graph: {:?}", action_graph);
                action_graph.start(&mut action_graph_subs);
                //println!("B action_graph: {:?}", action_graph);
            }
            _ => return,
        };

        //println!("C action_graph: {:?}", action_graph);

        // Spawn, stop, or fail tasks in the order in which the action graph
        // tells us to do so.
        while let Some(c) = action_graph_events.pop_front() {
            let node_handle = c.handle;
            let tid = node_handle.id();
            let action_type = c.event_type;
            //println!("Processing {:?} {:?} ...", action_type, tid);
            use crate::driver::action_graph::NodeEventType::*;
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
