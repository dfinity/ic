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
    pub fn capacity(&self) -> usize {
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
