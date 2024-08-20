/// A [Plan] is a tree structure used to bound the set of possible
/// runtime schedules. Interior nodes define a 'supervised' scope. Every node
/// that defines a supervised scope carries a dedicated task called the
/// 'supervisor'.
///
/// * When the supervisor fails, all supervised scopes that are being executed
///   or have not yet started executing are failed immediately.
///
/// * When children have stopped executing (regardless of result), the
///   supervising task is stopped (but not failed).
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

impl<T: Clone> Clone for Plan<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Supervised {
                supervisor,
                ordering,
                children,
            } => Self::Supervised {
                supervisor: supervisor.clone(),
                ordering: ordering.clone(),
                children: children.clone(),
            },
            Self::Leaf { task } => Self::Leaf { task: task.clone() },
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Plan<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Plan::Supervised {
                supervisor,
                ordering,
                children,
            } => write!(
                f,
                "Plan::Supervised< supervisor={:?}, ordering={:?}, children={:?} >",
                supervisor, ordering, children
            ),
            Plan::Leaf { task } => write!(f, "Plan::Leaf< task={:?} >", task),
        }
    }
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

    pub fn map<S, F>(&self, f: &F) -> Plan<S>
    where
        F: Fn(&T) -> S,
    {
        match self {
            Plan::Supervised {
                supervisor,
                ordering,
                children,
            } => Plan::Supervised {
                supervisor: f(supervisor),
                ordering: ordering.clone(),
                children: children
                    .iter()
                    .map(|ch| ch.map(f))
                    .collect::<Vec<Plan<S>>>(),
            },
            Plan::Leaf { task } => Plan::Leaf { task: f(task) },
        }
    }

    pub fn find_by_supervisor<F>(&self, f: &F) -> Option<&Plan<T>>
    where
        F: Fn(&T) -> bool,
    {
        match self {
            Plan::Supervised { supervisor, .. } if f(supervisor) => Some(self),
            Plan::Supervised {
                supervisor: _,
                ordering: _,
                children,
            } => children
                .iter()
                .find(|ch| ch.find_by_supervisor(f).is_some()),
            _ => None,
        }
    }

    fn flatten_rec(self, buf: &mut Vec<T>) {
        match self {
            Plan::Supervised {
                supervisor,
                ordering: _,
                children,
            } => {
                buf.push(supervisor);
                children
                    .into_iter()
                    .for_each(move |child| child.flatten_rec(buf));
            }
            Plan::Leaf { task } => buf.push(task),
        }
    }

    pub fn flatten(self) -> Vec<T> {
        let mut buf: Vec<T> = Vec::new();
        self.flatten_rec(&mut buf);
        buf
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalOrder {
    Sequential,
    Parallel,
}
