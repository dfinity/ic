use crate::protocol::id::ExecId;
use crate::protocol::structs::SandboxExecOutput;
use ic_embedders::wasm_executor::SliceExecutionOutput;
/// Execution state registry for sandbox processes.
///
/// This tracks the "active" executions on a sandbox process and
/// associates them with their execution ID. When starting a wasm
/// execution on a sandbox process, an entry is created in the registry,
/// and information required for resolution of "upward" IPCs from this
/// execution are also deposited in the registry.
///
/// The IPC glue uses the registry to look up information in order to
/// resolve calls from the sandbox process (e.g. find the completion
/// closure to notify when the sandbox tells us that an execution has
/// finished, or system state access for resolving system calls).
///
/// The controller uses the registry to register/unregister executions.
/// The registry also assists with allocating unique "execution ids"
/// to ensure multiple executions on a single sandbox process can be
/// told apart and addressed individually.
///
/// There is one "ActiveExecutionStateRegistry" object per sandbox process,
/// and one "ActiveExecutionState" object per ongoing execution in a specific
/// sandbox process.
use std::collections::HashMap;
use std::sync::Mutex;

#[allow(clippy::large_enum_variant)]
pub enum CompletionResult {
    Paused(SliceExecutionOutput),
    Finished(SandboxExecOutput),
}

type CompletionFunction = Box<dyn FnOnce(ExecId, CompletionResult) + Sync + Send + 'static>;

/// Represents an execution in progress on the sandbox process.
///
/// While an ActiveExecutionState instance is registered with the
/// ActiveExecutionStateRegistry (see below), an execution with matching ID
/// is presumed to be in progress on the sandbox process (it could
/// be that it is "about to be started" or that we have not received
/// and processed its completion yet).
pub(crate) struct ActiveExecutionState {
    /// Closure to call on completing execution. This will be set
    /// on initialization, and cleared once the completion for this
    /// execution has been called (it is not legal to receive two
    /// completions for the same execution).
    completion: Option<CompletionFunction>,
}

/// Multiple execution states, keyed by the unique ID used to identify
/// it across processes.
pub struct ActiveExecutionStateRegistry {
    states: Mutex<HashMap<ExecId, ActiveExecutionState>>,
}

/// All active executions on a sandbox process.
impl ActiveExecutionStateRegistry {
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Registers an execution, allocates a unique ID for it, and
    /// registers system state accessor + completion closure for it.
    ///
    /// Returns the id to be used to refer to the execution. The
    /// returned id should generally be identical to the id_hint passed
    /// in, except when there is a possible collision.
    pub fn register_execution<F>(&self, completion: F) -> ExecId
    where
        F: FnOnce(ExecId, CompletionResult) + Send + Sync + 'static,
    {
        let exec_id = ExecId::new();
        self.register_execution_with_id(exec_id, completion);
        exec_id
    }

    /// Registers an execution with the given id.
    pub fn register_execution_with_id<F>(&self, exec_id: ExecId, completion: F)
    where
        F: FnOnce(ExecId, CompletionResult) + Send + Sync + 'static,
    {
        let completion = Box::new(completion);
        let state = ActiveExecutionState {
            completion: Some(Box::new(completion)),
        };
        let mut mut_states = self.states.lock().unwrap();
        mut_states.insert(exec_id, state);
    }

    /// Removes the given [`ExecId`] and returns its [`CompletionFunction`].
    pub fn take(&self, exec_id: ExecId) -> Option<CompletionFunction> {
        let mut mut_states = self.states.lock().unwrap();
        if let Some(entry) = mut_states.remove(&exec_id) {
            entry.completion
        } else {
            None
        }
    }

    pub(crate) fn take_all(&self) -> HashMap<ExecId, ActiveExecutionState> {
        let mut mut_states = self.states.lock().unwrap();
        std::mem::take(&mut *mut_states)
    }
}

impl Default for ActiveExecutionStateRegistry {
    fn default() -> Self {
        Self::new()
    }
}
