use ic_canister_sandbox_common::protocol::structs;
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
use ic_system_api::SystemStateAccessorDirect;

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

type CompletionFunction =
    Box<dyn FnOnce(&String, Option<structs::ExecOutput>) + Sync + Send + 'static>;

/// Represents an execution in progress on the sandbox process.
///
/// While an ActiveExecutionState instance is registered with the
/// ActiveExecutionStateRegistry (see below), an execution with matching ID
/// is presumed to be in progress on the sandbox process (it could
/// be that it is "about to be started" or that we have not received
/// and processed its completion yet).
///
/// An execution may either be ongoing or held in a sys API callback.
/// If it is in sys API callback, then the state_accessor will be
/// temporarily borrowed for the time that it takes the replica to
/// service the call, and returned as soon as the call is completed.
struct ActiveExecutionState {
    /// Accessor to system state, possibly used by system API callbacks.
    /// Logically, the system state accessor always "exists", but it
    /// may temporarily be "borrowed" in order to fulfill a call.
    /// If this is None, then it is in "borrowed" state and will be
    /// returned later.
    ///
    /// XXX: actually this is not ideal that this "object" itself is
    /// moved in/out on borrow. Probably should be a box (does this work
    /// correctly with deconstructing at the end, though?).
    system_state_accessor: Option<SystemStateAccessorDirect>,

    /// Closure to call on completing execution. This will be set
    /// on initialization, and cleared once the completion for this
    /// execution has been called (it is not legal to receive two
    /// completions for the same execution).
    completion: Option<CompletionFunction>,
}

/// Multiple execution states, keyed by the unique ID used to identify
/// it across processes.
pub struct ActiveExecutionStateRegistry {
    states: Mutex<HashMap<String, ActiveExecutionState>>,
    state_accessor_cond: Condvar,
}

/// All active executions on a sandbox process.
impl ActiveExecutionStateRegistry {
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            state_accessor_cond: Condvar::new(),
        }
    }

    /// Registers an execution, allocates a unique ID for it, and
    /// registers system state accessor + completion closure for it.
    ///
    /// Returns the id to be used to refer to the execution. The
    /// returned id should generally be identical to the id_hint passed
    /// in, except when there is a possible collision.
    pub fn register_execution<F>(
        &self,
        system_state_accessor: SystemStateAccessorDirect,
        completion: F,
        id_hint: &str,
    ) -> String
    where
        F: FnOnce(&String, Option<structs::ExecOutput>) + Send + Sync + 'static,
    {
        let completion = Box::new(completion);
        let state = ActiveExecutionState {
            system_state_accessor: Some(system_state_accessor),
            completion: Some(Box::new(completion)),
        };

        // Try to use the given id, but ultimately ensure that the id
        // is unique by appending a numeric suffix.
        let exec_id = {
            let mut suffix: u64 = 0;
            let mut mut_states = self.states.lock().unwrap();
            loop {
                let id: String = {
                    if suffix == 0 {
                        id_hint.to_owned()
                    } else {
                        id_hint.to_owned() + &suffix.to_string()
                    }
                };
                if mut_states.contains_key(&id) {
                    suffix += 1;
                } else {
                    mut_states.insert(id.to_string(), state);
                    break id;
                }
            }
        };

        exec_id
    }

    /// Unregisters the specified execution state and extracts its
    /// system state accessor.
    /// This "should" be called after the sandbox has reported
    /// completion of execution. It is legal (and possible) to call
    /// it before, it will then cause the sandboxed execution to
    /// fail eventually. Also, completion of the sandbox execution
    /// will not be triggered.
    pub fn unregister_execution(&self, exec_id: &str) -> Option<SystemStateAccessorDirect> {
        let mut mut_states = self.states.lock().unwrap();
        loop {
            let maybe_state = mut_states.remove(exec_id);
            if let Some(state) = maybe_state {
                if let Some(system_state_accessor) = state.system_state_accessor {
                    break Some(system_state_accessor);
                } else {
                    mut_states.insert(exec_id.to_string(), state);
                    mut_states = self.state_accessor_cond.wait(mut_states).unwrap();
                }
            } else {
                break None;
            }
        }
    }
    fn internal_borrow_system_state_accessor(
        &self,
        exec_id: &str,
    ) -> Option<SystemStateAccessorDirect> {
        let mut mut_states = self.states.lock().unwrap();
        loop {
            let mut maybe_entry = mut_states.get_mut(exec_id);
            if let Some(state) = maybe_entry.as_mut() {
                let system_state_accessor = state.system_state_accessor.take();
                if system_state_accessor.is_none() {
                    mut_states = self.state_accessor_cond.wait(mut_states).unwrap();
                } else {
                    break system_state_accessor;
                }
            } else {
                break None;
            }
        }
    }

    fn internal_return_system_state_accessor(
        &self,
        exec_id: &str,
        system_state_accessor: SystemStateAccessorDirect,
    ) {
        let mut mut_states = self.states.lock().unwrap();
        let mut maybe_entry = mut_states.get_mut(exec_id);
        if let Some(state) = maybe_entry.as_mut() {
            state.system_state_accessor = Some(system_state_accessor);
            self.state_accessor_cond.notify_all();
        }
    }

    /// Borrows the system state accessor associated with an execution
    /// state ID. If the accessor is presently borrowed otherwise,
    /// will wait until it becomes available.
    pub fn borrow_system_state_accessor(
        self: &Arc<Self>,
        exec_id: &str,
    ) -> Option<BorrowedSystemStateAccessor> {
        self.internal_borrow_system_state_accessor(exec_id)
            .map(|system_state_accessor| BorrowedSystemStateAccessor {
                registry: self.clone(),
                system_state_accessor: Some(system_state_accessor),
                exec_id: exec_id.to_string(),
            })
    }

    /// Extracts the completion closure for this execution.
    pub fn extract_completion(&self, exec_id: &str) -> Option<CompletionFunction> {
        let mut mut_states = self.states.lock().unwrap();
        if let Some(entry) = mut_states.get_mut(exec_id) {
            entry.completion.take()
        } else {
            None
        }
    }
}

impl Default for ActiveExecutionStateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII helper class to manage "borrowing" of system state accessor:
/// Wraps (and allows access to) a system state accessor, returns it
/// to the place it was borrowed from on drop.
pub struct BorrowedSystemStateAccessor {
    // The system state accessor presently borrowed. This will always
    // be valid except during "drop".
    system_state_accessor: Option<SystemStateAccessorDirect>,

    // Registry to which the system state accessor will be returned
    // on drop.
    registry: Arc<ActiveExecutionStateRegistry>,

    // Execution ID to which the system state accessor will be returned
    // on drop.
    exec_id: String,
}

impl Drop for BorrowedSystemStateAccessor {
    fn drop(&mut self) {
        // This looks like it "conditionally" moves back the
        // system state accessor, but in reality this must always
        // move due to struct invariants.
        if let Some(system_state_accessor) = self.system_state_accessor.take() {
            self.registry
                .internal_return_system_state_accessor(&self.exec_id, system_state_accessor);
        }
    }
}

impl BorrowedSystemStateAccessor {
    pub fn access(&mut self) -> &SystemStateAccessorDirect {
        // Unwrap safe due to struct invariant (see comment in struct
        // declaration).
        self.system_state_accessor.as_mut().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_replicated_state::Memory;
    use ic_test_utilities::{
        cycles_account_manager::CyclesAccountManagerBuilder, state::SystemStateBuilder,
    };

    struct SyncCell<T> {
        item: Mutex<Option<T>>,
        cond: Condvar,
    }

    impl<T> SyncCell<T> {
        pub fn new() -> Self {
            Self {
                item: Mutex::new(None),
                cond: Condvar::new(),
            }
        }
        pub fn try_get(&self) -> Option<T> {
            let mut guard = self.item.lock().unwrap();
            (*guard).take()
        }
        pub fn get(&self) -> T {
            let mut guard = self.item.lock().unwrap();
            loop {
                if let Some(item) = (*guard).take() {
                    break item;
                } else {
                    guard = self.cond.wait(guard).unwrap();
                }
            }
        }
        pub fn put(&self, item: T) {
            let mut guard = self.item.lock().unwrap();
            *guard = Some(item);
            self.cond.notify_one();
        }
    }

    /// Validate that concurrency between "borrow" and "unregister"
    /// operations is handled correctly:
    /// - when a system_state is borrowed, then unregistering the execution will
    ///   temporarily block until it is returned
    /// - as soon as it is returned, unregistration succeeds
    #[test]
    fn borrow_unregister_concurrency() {
        let reg = Arc::new(ActiveExecutionStateRegistry::new());

        let exec1_finished = Arc::new(SyncCell::<String>::new());
        let exec1_finished_copy = Arc::clone(&exec1_finished);
        let exec1_id = reg.register_execution(
            SystemStateAccessorDirect::new(
                SystemStateBuilder::default().build(),
                Arc::new(CyclesAccountManagerBuilder::new().build()),
                &Memory::default(),
            ),
            move |id, _exec_out| {
                exec1_finished_copy.put(id.to_string());
            },
            "exec",
        );

        let borrow = reg.borrow_system_state_accessor(&exec1_id);

        // Start another thread that "concurrently" tries to unregister
        // the execution in question. This is forced to wait until the
        // borrowed system state accessor is returned (which in practice
        // happens after the system call that it was temporarily
        // borrowed for returns).
        let reg = Arc::clone(&reg);
        let exec1_id_copy = exec1_id.to_string();
        let t1 = std::thread::spawn(move || {
            let completion = reg.extract_completion(&exec1_id_copy);
            reg.unregister_execution(&exec1_id_copy);
            completion.unwrap()(&exec1_id_copy, None);
        });

        // Execution cannot have been unregistered yet, so the
        // completion function cannot have been called yet. This is
        // effectively validating a "race" (i.e. that the other thread
        // has NOT progressed to a specific point yet) and can therefore
        // not be 100% reliably tested. Add a small sleep such that
        // there is a "vanishingly small" probability that other thread
        // has not run yet.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(exec1_finished.try_get().is_none());

        // Drop the borrow, returns the system state accessor.
        drop(borrow);
        assert!(t1.join().is_ok());

        assert_eq!(exec1_id, exec1_finished.get());
    }
}
