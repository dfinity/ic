#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskState {
    Skipped,
    Scheduled,
    Running { pid: u32 },
    Passed,
    Failed { failure_message: String },
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Task {
    Setup(TaskState),
    Test { name: String, state: TaskState },
}

impl Task {
    pub fn name(&self) -> String {
        match self {
            Self::Setup(_) => String::from("::setup"),
            Self::Test { name, state: _ } => name.clone(),
        }
    }

    pub fn state(&self) -> TaskState {
        (match self {
            Self::Setup(state) => state,
            Self::Test { name: _, state } => state,
        })
        .clone()
    }

    fn finalize(&self, final_state: TaskState) -> Self {
        // use move semantics (self)
        match final_state {
            TaskState::Passed => {}
            TaskState::Failed { failure_message: _ } => {}
            _ => {
                panic!(
                    "state {:?} cannot be the state of a finalized task",
                    final_state
                )
            }
        }

        match self {
            Self::Setup(_) => Self::Setup(final_state),
            Self::Test { name, state: _ } => Self::Test {
                name: name.clone(),
                state: final_state,
            },
        }
    }

    pub fn mk_passed(&self) -> Self {
        println!("Task {:?} succeeded", self.name());
        self.finalize(TaskState::Passed)
    }

    pub fn mk_failed(&self, failure_message: String) -> Self {
        println!(
            "Task {:?} failed with message: {:?}",
            self.name(),
            failure_message
        );
        self.finalize(TaskState::Failed { failure_message })
    }
}
