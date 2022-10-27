#![allow(dead_code)]
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::{collections::BTreeSet, panic::UnwindSafe};

use anyhow::{bail, Result};

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
        let has_execution_succeeded = done_set
            .iter()
            .any(|x| matches!(x.state(), TaskState::Failed { failure_message: _ }));
        if has_execution_succeeded {
            bail!("Some tasks in the schedule failed.");
        }
        Ok(())
    }
}

pub trait TaskId: Clone + Send + Sync {}
impl<T: Clone + Send + Sync> TaskId for T {}

/// A [Plan] is a tree structure used to bound the set of possible
/// runtime schedules. Interior nodes define a 'supervised' scope. Every node
/// that defines a supervised scope carries a dedicated task called the
/// 'supervisor'.
///
/// * When the supervisor fails, all supervised scopes that are being executed
/// or have not yet started executing are failed immediately.
///
/// * When children have stopped executing (regardless of result), the
/// supervising task is stopped (but not failed).
///
/// * The supervisor is started before the children.
///
/// To execute the plan, the plan is translated into a stateful ActionGraph.
pub enum Plan<T> {
    Supervised {
        // note that this might need to be changed to an Arc
        supervisor: T,
        ordering: EvalOrder,
        children: Vec<Plan<T>>,
    },
    Leaf {
        task: T,
    },
}

impl<T> Plan<T> {
    fn capacity(&self) -> usize {
        match self {
            Plan::Supervised {
                ordering, children, ..
            } => match ordering {
                EvalOrder::Sequential => 1,
                EvalOrder::Parallel => children.len(),
            },
            Plan::Leaf { .. } => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalOrder {
    Sequential,
    Parallel,
}

/// A graph where nodes are stateful objects connected via directed actions.
/// When a node A changes state, every action connecting this node to another
/// node is taken if the state of A meets the condition assocated with that
/// action.
pub struct SharedActionGraph<T> {
    shared_state: SharedState<T>,
}

impl<T: TaskId> SharedActionGraph<T> {
    pub fn from_plan(plan: Plan<T>) -> Self {
        let ag = ActionGraph::<T>::from_plan(plan);

        let shared_state = Arc::new(RwLock::new(ag));
        Self { shared_state }
    }

    pub fn start(&self, sink: impl EventSubscriber<T>) {
        let mut guard = self.shared_state.write().unwrap();

        guard.effect(0, Effect::Start, sink);
    }

    pub fn stop(&self, handle: TaskHandle<T>, sink: impl EventSubscriber<T>) {
        let mut guard = self.shared_state.write().unwrap();

        guard.effect(handle.1, Effect::Decrease, sink);
    }

    pub fn fail(&self, handle: TaskHandle<T>, sink: impl EventSubscriber<T>) {
        let mut guard = self.shared_state.write().unwrap();

        guard.effect(handle.1, Effect::Fail, sink);
    }
}

type SharedState<T> = Arc<RwLock<ActionGraph<T>>>;

struct ActionGraph<T> {
    // invariant: nodes.len() == task_identifiers.len()
    nodes: Vec<Node>,
    task_ids: Vec<Option<T>>,
    /// invariant: Actions are always ordered.
    actions: Vec<Action>,
}

impl<T: TaskId> ActionGraph<T> {
    fn effect(&mut self, node_idx: usize, effect: Effect, sink: impl EventSubscriber<T>) {
        // A fifo queue containing pairs of (node index, condition). Each entry
        // indicates that a node has reached the given condition.
        let mut workset = VecDeque::new();

        // println!("effect({}, {:?}) START", node_idx, effect);
        // self.nodes.iter().for_each(|n| println!("{:?}", n));

        let (new_state, cond) = self.nodes[node_idx].apply_effect(effect);
        self.nodes[node_idx] = new_state;
        if let Some(cond) = cond {
            workset.push_back((node_idx, cond));
        }

        while let Some((node_idx, cond)) = workset.pop_front() {
            // We search for the index of the action with _lowest priority_ that
            // matches the source node and the condition.
            let a_idx = match self
                .actions
                .binary_search_by_key(&(node_idx, &cond, 0), |a| {
                    (a.source, &a.condition, a.priority)
                }) {
                Ok(idx) => idx,
                Err(idx) => idx,
            };

            // While there is an action that matches the source and condition,
            // apply the action. Because the actions are ordered by source,
            // condition and priority first, we are guaranteed to visit actions
            // matching a source and a condition in ascending priority.
            while let Some(a) = self.actions.get(a_idx) {
                let source = a.source;
                let target = a.target;
                if source != node_idx || a.condition != cond {
                    break;
                }
                println!("taking action {:?}", a);
                // Remove the action from the list of actions guarantees that
                // the action is never taken twice.

                // NB: Re-declaring `a` here drops the reference on self.actions
                // from above. Using a different symbol would conflict with
                // owernship semantics as `&a` is borrows self.actions.
                let a = self.actions.remove(a_idx);
                let (new_state, cond) = self.nodes[target].apply_effect(a.effect);
                self.nodes[target] = new_state;
                if let Some(cond) = cond {
                    workset.push_back((target, cond));
                    if let Some(task_id) = self.task_ids[target].clone() {
                        let handle = TaskHandle(task_id, target);
                        let change = match &cond {
                            Cond::Started => TaskEventType::Start,
                            Cond::Stopped => TaskEventType::Stop,
                            Cond::Failed => TaskEventType::Fail,
                        };
                        // println!("Issuing command ({}, {:?})", target, change);
                        sink.event(TaskEvent {
                            handle,
                            event_type: change,
                        });
                    }
                }
            }
        }
        // println!("change() END");
        // self.nodes.iter().for_each(|n| println!("{:?}", n));
    }

    fn from_plan(plan: Plan<T>) -> ActionGraph<T> {
        let mut res = Self {
            nodes: vec![],
            task_ids: vec![],
            actions: vec![],
        };

        Self::add_to_graph(&mut res, plan);
        res.actions.sort();
        res
    }

    fn add_to_graph(graph: &mut ActionGraph<T>, plan: Plan<T>) {
        let capacity = plan.capacity();
        match plan {
            Plan::Supervised {
                supervisor,
                ordering,
                children,
            } => {
                use Effect::*;
                // this node
                let myself = graph.nodes.len();
                graph.nodes.push(Node::scheduled(capacity));
                graph.task_ids.push(None);
                // the supervisor
                let supervisor_idx = graph.nodes.len();
                graph.nodes.push(Node::scheduled(1));
                graph.task_ids.push(Some(supervisor));

                // when we start this node, we also start the supervisor
                Self::start_when_started(graph, myself, supervisor_idx);

                // When the supervisor fails, fail this node. In particular,
                // when the supervisor stops, it does not have any effect.
                Self::fail_when_failed(graph, supervisor_idx, myself);
                // if this node fails, stop the supervisor
                let effect = Effect::Decrease;
                Self::effect_when_finished(graph, myself, supervisor_idx, effect);

                let mut child_idcs = vec![];
                for child in children {
                    let child_idx = graph.nodes.len();
                    child_idcs.push(child_idx);
                    Self::add_to_graph(graph, child);
                }

                // when this node fails, fail all children
                for child_idx in &child_idcs {
                    Self::fail_when_failed(graph, myself, *child_idx);
                }

                if !child_idcs.is_empty() {
                    match ordering {
                        EvalOrder::Sequential => {
                            let first_idx = child_idcs.first().unwrap();
                            let last_idx = child_idcs.last().unwrap();

                            Self::start_when_started(graph, myself, *first_idx);
                            Self::effect_when_finished(graph, *last_idx, myself, Decrease);

                            let shifted = child_idcs.iter().skip(1);
                            let pairs = child_idcs.iter().zip(shifted);
                            for (idx1, idx2) in pairs {
                                Self::effect_when_finished(graph, *idx1, *idx2, Start);
                            }
                        }
                        EvalOrder::Parallel => {
                            for idx in child_idcs.iter() {
                                Self::start_when_started(graph, myself, *idx);
                                Self::effect_when_finished(graph, *idx, myself, Decrease);
                            }
                        }
                    }
                }
            }
            Plan::Leaf { task } => {
                graph.nodes.push(Node::scheduled(1));
                graph.task_ids.push(Some(task));
            }
        }
    }

    fn effect_when_finished(
        graph: &mut ActionGraph<T>,
        source: usize,
        target: usize,
        effect: Effect,
    ) {
        use Cond::*;
        let priority = graph.actions.len();
        graph.actions.push(Action {
            source,
            condition: Stopped,
            priority,
            target,
            effect,
        });

        graph.actions.push(Action {
            source,
            priority,
            condition: Failed,
            target,
            effect,
        });
    }

    fn start_when_started(graph: &mut ActionGraph<T>, source: usize, target: usize) {
        use Cond::*;
        use Effect::*;
        let priority = graph.actions.len();
        graph.actions.push(Action {
            source,
            condition: Started,
            priority,
            target,
            effect: Start,
        });
    }

    fn fail_when_failed(graph: &mut ActionGraph<T>, source: usize, target: usize) {
        use Cond::*;
        use Effect::*;
        let priority = graph.actions.len();
        graph.actions.push(Action {
            source,
            condition: Failed,
            priority,
            target,
            effect: Fail,
        });
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    /// A scheduled Node has a capacity for running `capacity` many children in
    /// parallel at most when being started.
    Scheduled {
        capacity: usize,
    },
    /// Indicates the number of `active` children. Thus, `Running { active: 0 }`
    /// is semantically equivalent to 'Stopped'.
    Running {
        active: usize,
    },
    Failed,
}

impl Node {
    fn scheduled(capacity: usize) -> Self {
        Self::Scheduled { capacity }
    }
}

impl Node {
    /// * A node is failed at most once <= all transitions from failed are
    /// cyclic.
    ///
    /// * A node is stopped at most once <= there is only one transition leading
    /// to Stopped.
    ///
    /// * A node is started at most once <= there is only one transition leading
    /// to the Running state.
    fn apply_effect(&self, action: Effect) -> (Self, Option<Cond>) {
        use Effect::*;
        use Node::*;
        let started = Some(Cond::Started);
        let failed = Some(Cond::Failed);
        let stopped = Some(Cond::Stopped);
        match (self, action) {
            (Scheduled { capacity }, Start) => (Running { active: *capacity }, started),
            (s @ Scheduled { .. }, Decrease) => (s.clone(), None),
            (Scheduled { .. }, Fail) => (Failed, failed),
            (Running { active }, Start) => (Running { active: *active }, None),
            (Running { active }, Decrease) if *active > 1 => (Running { active: active - 1 }, None),
            (Running { active }, Decrease) if *active == 1 => (Running { active: 0 }, stopped),
            (Running { active }, Decrease) => (Running { active: *active }, None),
            (Running { active }, Fail) if *active > 0 => (Failed, failed),
            (Running { active }, Fail) => (Running { active: *active }, None),
            (Failed, Start { .. }) => (Failed, None),
            (Failed, Decrease) => (Failed, None),
            (Failed, Fail) => (Failed, None),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Cond {
    Started,
    Stopped,
    Failed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Effect {
    Start,
    Decrease,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Action {
    source: usize,
    condition: Cond,
    /// If actions that have the same source and condition, the priority defines
    /// the order in which the actions are applied. Priority is always > 0.
    priority: usize,
    target: usize,
    effect: Effect,
}

#[derive(Clone)]
pub struct TaskEvent<T: TaskId> {
    handle: TaskHandle<T>,
    event_type: TaskEventType,
}

impl<T: TaskId> TaskEvent<T> {
    pub fn id(&self) -> T {
        self.handle.id()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TaskEventType {
    Start,
    Stop,
    Fail,
}

#[derive(Clone)]
pub struct TaskHandle<T: TaskId>(T, usize);

impl<T: TaskId> TaskHandle<T> {
    pub fn id(&self) -> T {
        self.0.clone()
    }
}

pub trait EventSubscriber<T: TaskId>: Send + Sync {
    fn event(&self, evt: TaskEvent<T>);
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<T: Clone + Send + Sync> EventSubscriber<T> for Arc<RwLock<Vec<TaskEvent<T>>>> {
        fn event(&self, evt: TaskEvent<T>) {
            let mut guard = self.write().unwrap();

            guard.push(evt);
        }
    }

    type EventSink = Arc<RwLock<Vec<TaskEvent<usize>>>>;

    fn seq<T: Clone>(supervisor: T, children: Vec<Plan<T>>) -> Plan<T> {
        Plan::Supervised {
            supervisor,
            ordering: EvalOrder::Sequential,
            children,
        }
    }

    fn par<T: Clone>(supervisor: T, children: Vec<Plan<T>>) -> Plan<T> {
        Plan::Supervised {
            supervisor,
            ordering: EvalOrder::Parallel,
            children,
        }
    }

    fn t<T: Clone>(task: T) -> Plan<T> {
        Plan::Leaf { task }
    }

    const SUPERVISOR_0: usize = 42;
    const SEQ_1: usize = 43;
    const SEQ_2: usize = 44;
    const SUPERVISOR_1: usize = 45;
    const PAR_1: usize = 46;
    const PAR_2: usize = 47;

    fn simple_ag() -> SharedActionGraph<usize> {
        SharedActionGraph::from_plan(seq(
            SUPERVISOR_0,
            vec![
                t(SEQ_1),
                t(SEQ_2),
                par(SUPERVISOR_1, vec![t(PAR_1), t(PAR_2)]),
            ],
        ))
    }

    fn simple_evts() -> Vec<TaskEvent<usize>> {
        let ag = simple_ag();

        let evt_sink = EventSink::default();
        ag.start(evt_sink.clone());

        let mut res = vec![];
        std::mem::swap(evt_sink.write().unwrap().as_mut(), &mut res);
        res
    }

    #[test]
    fn first_supervisor_is_started_first() {
        let mut evts = simple_evts();
        assert_eq!(evts.remove(0).id(), SUPERVISOR_0);
        assert_eq!(evts.remove(0).id(), SEQ_1);
        assert!(evts.is_empty());
    }

    #[test]
    fn seq_children_executed_in_sequence() {
        use TaskEventType::*;
        let ag = simple_ag();

        let evt_sink = EventSink::default();
        let mut pop_front = make_pop_front(evt_sink.clone());
        // println!("before start");
        ag.start(evt_sink.clone());

        matches_event(pop_front(), SUPERVISOR_0, Start);
        let seq_1 = pop_front();
        matches_event(seq_1.clone(), SEQ_1, Start);
        // println!("before stopping 1");
        ag.stop(seq_1.handle, evt_sink.clone());
        // println!("before stopping 1");

        let seq_2 = pop_front();
        matches_event(seq_2.clone(), SEQ_2, Start);

        ag.stop(seq_2.handle, evt_sink.clone());

        matches_event(pop_front(), SUPERVISOR_1, Start);
        let par_1 = pop_front();
        matches_event(par_1.clone(), PAR_1, Start);
        let par_2 = pop_front();
        matches_event(par_2.clone(), PAR_2, Start);

        ag.stop(par_1.handle, evt_sink.clone());
        ag.stop(par_2.handle, evt_sink);

        matches_event(pop_front(), SUPERVISOR_1, Stop);
        matches_event(pop_front(), SUPERVISOR_0, Stop);
    }

    #[test]
    fn failing_fails_all_children() {
        use TaskEventType::*;
        let ag = simple_ag();

        let evt_sink = EventSink::default();
        let mut pop_front = make_pop_front(evt_sink.clone());

        ag.start(evt_sink.clone());
        let sprvsr_0 = pop_front();
        matches_event(sprvsr_0.clone(), SUPERVISOR_0, Start);
        matches_event(pop_front(), SEQ_1, Start);

        ag.fail(sprvsr_0.handle, evt_sink.clone());
        matches_event(pop_front(), SEQ_1, Fail);
        matches_event(pop_front(), SEQ_2, Fail);
        // matches_command(pop_front(), SUPERVISOR_1, Fail);
        matches_event(pop_front(), PAR_1, Fail);
        matches_event(pop_front(), PAR_2, Fail);

        assert_eq!(evt_sink.read().unwrap().len(), 0);
    }

    fn matches_event(tevt: TaskEvent<usize>, id: usize, event: TaskEventType) {
        let actual_id = tevt.id();
        let actual_event = tevt.event_type;
        assert!(
            actual_id == id && actual_event == event,
            "expected id, change: {id:?}, {event:?} -- actual: {actual_id:?}, {actual_event:?}"
        );
    }

    fn make_pop_front(evt_sink: EventSink) -> impl FnMut() -> TaskEvent<usize> {
        move || evt_sink.write().unwrap().remove(0)
    }
}
