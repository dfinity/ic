use std::collections::VecDeque;

use super::{
    event::Subscriber,
    plan::{EvalOrder, Plan},
    task::TaskIdT,
};

pub trait AgSubscriber<T: TaskIdT>: Subscriber<NodeEvent<T>> {}
impl<I: TaskIdT, T: FnMut(NodeEvent<I>) + Send + Sync> AgSubscriber<I> for T {}

/// A graph where nodes are stateful objects connected via directed actions.
/// When a node A changes state, every action connecting this node to another
/// node is taken if the state of A meets the condition assocated with that
/// action.
pub struct ActionGraph<T> {
    // invariant: nodes.len() == task_identifiers.len()
    nodes: Vec<Node>,
    task_ids: Vec<Option<T>>,
    /// invariant: Actions are always ordered.
    actions: Vec<Action>,
}

impl<T: TaskIdT> ActionGraph<T> {
    pub fn start(&mut self, sink: impl AgSubscriber<T>) {
        self.effect(0, Effect::Start, sink);
    }

    pub fn stop(&mut self, handle: NodeHandle<T>, sink: impl AgSubscriber<T>) {
        self.effect(handle.1, Effect::Decrease, sink);
    }

    pub fn fail(&mut self, handle: NodeHandle<T>, sink: impl AgSubscriber<T>) {
        self.effect(handle.1, Effect::Fail, sink);
    }

    fn effect(&mut self, node_idx: usize, effect: Effect, mut sub: impl AgSubscriber<T>) {
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
                        let handle = NodeHandle(task_id, target);
                        let change = match &cond {
                            Cond::Started => NodeEventType::Start,
                            Cond::Stopped => NodeEventType::Stop,
                            Cond::Failed => NodeEventType::Fail,
                        };
                        // println!("Issuing command ({}, {:?})", target, change);
                        (sub)(NodeEvent {
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

    pub fn from_plan(plan: Plan<T>) -> ActionGraph<T> {
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
            (Scheduled { capacity }, Start) if *capacity > 0 => {
                (Running { active: *capacity }, started)
            }
            (Scheduled { capacity }, Start) => (Running { active: *capacity }, stopped),
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

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEvent<T: TaskIdT> {
    pub handle: NodeHandle<T>,
    pub event_type: NodeEventType,
}

impl<T: TaskIdT> NodeEvent<T> {
    pub fn id(&self) -> T {
        self.handle.id()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeEventType {
    Start,
    Stop,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeHandle<T: TaskIdT>(T, usize);

impl<T: TaskIdT> NodeHandle<T> {
    pub fn id(&self) -> T {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use crossbeam_channel::unbounded;

    use super::*;

    fn create_sub() -> (impl FnMut() -> NodeEvent<usize>, impl AgSubscriber<usize>) {
        let (sender, receiver) = unbounded();
        let sub = move |evt: NodeEvent<usize>| sender.send(evt).unwrap();
        let recv = move || receiver.recv().unwrap();
        (recv, sub)
    }

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

    fn simple_ag() -> ActionGraph<usize> {
        ActionGraph::from_plan(seq(
            SUPERVISOR_0,
            vec![
                t(SEQ_1),
                t(SEQ_2),
                par(SUPERVISOR_1, vec![t(PAR_1), t(PAR_2)]),
            ],
        ))
    }

    fn simple_evts() -> impl FnMut() -> NodeEvent<usize> {
        let mut ag = simple_ag();

        let (recv, mut sub) = create_sub();
        ag.start(&mut sub);
        recv
    }

    #[test]
    fn first_supervisor_is_started_first() {
        let mut recv = simple_evts();
        assert_eq!(recv().id(), SUPERVISOR_0);
        assert_eq!(recv().id(), SEQ_1);
    }

    #[test]
    fn seq_children_executed_in_sequence() {
        use NodeEventType::*;
        let mut ag = simple_ag();

        let (mut recv, mut sub) = create_sub();
        // println!("before start");
        ag.start(&mut sub);

        matches_event(recv(), SUPERVISOR_0, Start);
        let seq_1 = recv();
        matches_event(seq_1.clone(), SEQ_1, Start);
        // println!("before stopping 1");
        ag.stop(seq_1.handle, &mut sub);
        // println!("before stopping 1");

        let seq_2 = recv();
        matches_event(seq_2.clone(), SEQ_2, Start);

        ag.stop(seq_2.handle, &mut sub);

        matches_event(recv(), SUPERVISOR_1, Start);
        let par_1 = recv();
        matches_event(par_1.clone(), PAR_1, Start);
        let par_2 = recv();
        matches_event(par_2.clone(), PAR_2, Start);

        ag.stop(par_1.handle, &mut sub);
        ag.stop(par_2.handle, &mut sub);

        matches_event(recv(), SUPERVISOR_1, Stop);
        matches_event(recv(), SUPERVISOR_0, Stop);
    }

    #[test]
    fn failing_fails_all_children() {
        use NodeEventType::*;
        let mut ag = simple_ag();

        let (mut recv, mut sub) = create_sub();

        ag.start(&mut sub);
        let sprvsr_0 = recv();
        matches_event(sprvsr_0.clone(), SUPERVISOR_0, Start);
        matches_event(recv(), SEQ_1, Start);

        ag.fail(sprvsr_0.handle, &mut sub);
        matches_event(recv(), SEQ_1, Fail);
        matches_event(recv(), SEQ_2, Fail);
        // matches_command(recv(), SUPERVISOR_1, Fail);
        matches_event(recv(), PAR_1, Fail);
        matches_event(recv(), PAR_2, Fail);
    }

    fn matches_event(tevt: NodeEvent<usize>, id: usize, event: NodeEventType) {
        let actual_id = tevt.id();
        let actual_event = tevt.event_type;
        assert!(
            actual_id == id && actual_event == event,
            "expected id, change: {id:?}, {event:?} -- actual: {actual_id:?}, {actual_event:?}"
        );
    }
}
