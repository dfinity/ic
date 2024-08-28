use std::collections::VecDeque;

use crate::driver::{
    plan::{EvalOrder, Plan},
    task::TaskIdT,
};

/// A graph where nodes are stateful objects connected via directed actions.
/// When a node A changes state, every action connecting this node to another
/// node is taken if the state of A meets the condition associated with that
/// action.
#[derive(Debug)]
pub struct ActionGraph<T> {
    // invariant: nodes.len() == task_identifiers.len()
    nodes: Vec<Node>,
    task_ids: Vec<Option<T>>,
    /// invariant: Actions are always ordered.
    actions: Vec<Action>,
    // dirty nodes: temporary solution to prevent reason/report propagation through edges of action graph
    dirty_nodes: Vec<usize>,
    dirty_counter: usize,
}

impl<T: TaskIdT> ActionGraph<T> {
    pub fn task_iter(
        &self,
    ) -> std::iter::Zip<std::vec::IntoIter<Node>, std::vec::IntoIter<std::option::Option<T>>> {
        std::iter::zip(self.nodes.clone(), self.task_ids.clone())
    }

    pub fn start(&mut self) {
        self.effect(0, Effect::Start);
    }

    pub fn stop(&mut self, node_idx: usize, report: String) {
        // reset dirty nodes
        self.dirty_nodes.clear();
        self.dirty_counter = 0;
        self.dirty_nodes.resize(self.nodes.len(), 0);
        self.effect(node_idx, Effect::Decrease);
        // propagate message to all dirty nodes
        self.dirty_nodes
            .iter()
            .enumerate()
            .filter(|(_, v)| **v == 1)
            .for_each(|(i, _)| self.nodes[i].set_stop_msg(report.clone()));
    }

    pub fn fail(&mut self, node_idx: usize, reason: String) {
        // reset dirty nodes
        self.dirty_nodes.clear();
        self.dirty_counter = 0;
        self.dirty_nodes.resize(self.nodes.len(), 0);
        self.effect(node_idx, Effect::Fail);
        // propagate message to all dirty nodes
        self.dirty_nodes
            .iter()
            .enumerate()
            .filter(|(_, v)| **v != 0)
            .for_each(|(i, _)| self.nodes[i].set_fail_msg(reason.clone()));
    }

    fn effect(&mut self, node_idx: usize, effect: Effect) {
        // A fifo queue containing pairs of (node index, condition). Each entry
        // indicates that a node has reached the given condition.
        let mut workset = VecDeque::new();

        // println!("1 effect({}, {:?}) START", node_idx, effect);
        // self.nodes.iter().for_each(|n| println!("{:?}", n));

        let (new_state, cond) = self.nodes[node_idx].apply_effect(effect);
        self.nodes[node_idx] = new_state;
        if let Some(cond) = cond {
            workset.push_back((node_idx, cond));
            // println!("1.1 effect({}, {:?}) START", node_idx, effect);
            // if Stop or Fail, mark node as dirty
            match cond {
                Cond::Started => {}
                _ => {
                    self.dirty_counter += 1;
                    self.dirty_nodes[node_idx] = self.dirty_counter;
                }
            }
        }

        // println!("2 effect({}, {:?}) START", node_idx, effect);

        while let Some((node_idx, cond)) = workset.pop_front() {
            // println!("3 effect({}, {:?}) START", node_idx, cond);

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

            // println!("4 effect({}, {:?}) START", node_idx, cond);

            // While there is an action that matches the source and condition,
            // apply the action. Because the actions are ordered by source,
            // condition and priority first, we are guaranteed to visit actions
            // matching a source and a condition in ascending priority.
            while let Some(a) = self.actions.get(a_idx) {
                let source = a.source;
                let target = a.target;
                // println!("1 taking action {:?}", a);
                if source != node_idx || a.condition != cond {
                    break;
                }
                // println!("2 taking action {:?}", a);
                // Remove the action from the list of actions guarantees that
                // the action is never taken twice.

                // NB: Re-declaring `a` here drops the reference on self.actions
                // from above. Using a different symbol would conflict with
                // ownership semantics as `&a` is borrows self.actions.
                let a = self.actions.remove(a_idx);
                let (new_state, cond) = self.nodes[target].apply_effect(a.effect);
                self.nodes[target] = new_state;
                if let Some(cond) = cond {
                    workset.push_back((target, cond));
                    if self.task_ids[target].is_some() {
                        // if Stop or Fail, mark node as dirty
                        match cond {
                            Cond::Started => {}
                            _ => {
                                self.dirty_counter += 1;
                                self.dirty_nodes[target] = self.dirty_counter;
                            }
                        }
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
            dirty_nodes: vec![],
            dirty_counter: 0,
        };

        Self::add_to_graph(&mut res, plan);
        res.actions.sort();
        res.dirty_nodes.resize(res.nodes.len(), 0);
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
pub enum Node {
    /// A scheduled Node has a capacity for running `capacity` many children in
    /// parallel at most when being started.
    Scheduled {
        capacity: usize,
    },
    /// Indicates the number of `active` children. Thus, `Running { active: 0 }`
    /// is semantically equivalent to 'Stopped'.
    Running {
        active: usize,
        message: Option<String>, //TODO: String or better typed alternative?
    },
    Failed {
        reason: Option<String>,
    },
}

impl Node {
    fn scheduled(capacity: usize) -> Self {
        Self::Scheduled { capacity }
    }
    pub fn set_stop_msg(&mut self, msg: String) {
        if let Node::Running { active: _, message } = self {
            *message = Some(msg);
        }
    }
    pub fn set_fail_msg(&mut self, msg: String) {
        if let Node::Failed { reason } = self {
            *reason = Some(msg);
        }
    }
}

impl Node {
    /// * A node is failed at most once <= all transitions from failed are
    ///   cyclic.
    ///
    /// * A node is stopped at most once <= there is only one transition leading
    ///   to Stopped.
    ///
    /// * A node is started at most once <= there is only one transition leading
    ///   to the Running state.
    #[rustfmt::skip]
    fn apply_effect(&self, action: Effect) -> (Self, Option<Cond>) {
        use Effect::*;
        use Node::*;
        let started = Some(Cond::Started);
        let failed = Some(Cond::Failed);
        let stopped = Some(Cond::Stopped);
        match (self, action) {
            (Scheduled { capacity }, Start) if *capacity > 0        => (Running {active: *capacity, message: None}, started,),
            (Scheduled { capacity }, Start)                         => (Running {active: *capacity, message: Some("Job was scheduled with zero capacity".to_owned())}, stopped),
            (s @ Scheduled { .. }, Decrease)                        => (s.clone(), None),
            (Scheduled { .. }, Fail)                                => (Failed { reason: None }, failed),
            (r @ Running { .. }, Start)                             => (r.clone(), None),
            (Running { active, message }, Decrease) if *active > 1  => (Running {active: active - 1, message: message.clone()}, None),
            (Running { active, message }, Decrease) if *active == 1 => ( Running {active: 0, message: message.clone()}, stopped),
            (r @ Running { .. }, Decrease)                          => (r.clone(), None),
            (Running { active, message: _ }, Fail) if *active > 0   => {(Failed { reason: None }, failed)}
            (f @ Running { .. }, Fail)                              => (f.clone(), None),
            (f @ Failed { .. }, Start { .. })                       => (f.clone(), None),
            (f @ Failed { .. }, Decrease)                           => (f.clone(), None),
            (f @ Failed { .. }, Fail)                               => (f.clone(), None),
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
