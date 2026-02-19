use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::Future,
    mem::take,
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll, Wake, Waker},
};

use slotmap::{Key, SecondaryMap, SlotMap, new_key_type};
use smallvec::SmallVec;

/// Represents an active canister method.
#[derive(Clone, Debug)]
pub(crate) struct MethodContext {
    /// Whether this method is an update or a query.
    pub(crate) kind: ContextKind,
    /// The number of handles to this method context. When this drops to zero, the method context gets deleted.
    /// The refcount is managed by `MethodHandle`.
    pub(crate) handles: usize,
    /// An index for Task.method_binding; all protected tasks attached to this method.
    pub(crate) tasks: SmallVec<[TaskId; 4]>,
}

impl MethodContext {
    pub(crate) fn new_update() -> Self {
        Self {
            kind: ContextKind::Update,
            handles: 0,
            tasks: SmallVec::new(),
        }
    }
    pub(crate) fn new_query() -> Self {
        Self {
            kind: ContextKind::Query,
            handles: 0,
            tasks: SmallVec::new(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum ContextKind {
    Update,
    Query,
}

// Null method ID corresponds to 'null context', used for migratory tasks.
// Null task ID is an error.
new_key_type! {
    pub(crate) struct MethodId;
    pub(crate) struct TaskId;
}

thread_local! {
    // global: list of all method contexts currently active
    pub(crate) static METHODS: RefCell<SlotMap<MethodId, MethodContext>> = RefCell::default();
    // global: list of all tasks currently spawned
    pub(crate) static TASKS: RefCell<SlotMap<TaskId, Task>> = RefCell::default();
    // global: map of methods to their protected tasks that have been woken up
    pub(crate) static PROTECTED_WAKEUPS: RefCell<SecondaryMap<MethodId, VecDeque<TaskId>>> = RefCell::default();
    // global: list of migratory tasks that have been woken up
    pub(crate) static MIGRATORY_WAKEUPS: RefCell<VecDeque<TaskId>> = const { RefCell::new(VecDeque::new()) };
    // dynamically scoped: the current method context. None means a context function was not called (which is a user error),
    // vs null which means no method in particular.
    pub(crate) static CURRENT_METHOD: Cell<Option<MethodId>> = const { Cell::new(None) };
    // dynamically scoped: whether we are currently recovering from a trap
    pub(crate) static RECOVERING: Cell<bool> = const { Cell::new(false) };
    // dynamically scoped: the current task ID, or None if a task is not running
    pub(crate) static CURRENT_TASK_ID: Cell<Option<TaskId>> = const { Cell::new(None) };
}

/// A registered task in the executor.
pub(crate) struct Task {
    /// Should be `TaskFuture` in all cases
    future: Pin<Box<dyn Future<Output = ()>>>,
    /// If Some, this task will always resume during that method, regardless of where the waker is woken from.
    /// If None, this task will resume wherever it is awoken from.
    method_binding: Option<MethodId>,
    // While this task is executing, `CURRENT_METHOD` will be set to this value.
    set_current_method_var: MethodId,
}

// Actually using the default value would be a memory leak. This only exists for `take`.
impl Default for Task {
    fn default() -> Self {
        Self {
            future: Box::pin(std::future::pending()),
            method_binding: None,
            set_current_method_var: MethodId::null(),
        }
    }
}

/// Execute an update function in a context that allows calling [`spawn_protected`] and [`spawn_migratory`].
pub fn in_tracking_executor_context<R>(f: impl FnOnce() -> R) -> R {
    setup_panic_hook();
    let method = METHODS.with_borrow_mut(|methods| methods.insert(MethodContext::new_update()));
    let guard = MethodHandle::for_method(method);
    enter_current_method(guard, || {
        let res = f();
        poll_all();
        res
    })
}

/// Execute a function in a context that is not tracked across callbacks, able to call [`spawn_migratory`]
/// but not [`spawn_protected`].
#[expect(dead_code)] // not used in current null context code but may be used for other things in the future
pub(crate) fn in_null_context<R>(f: impl FnOnce() -> R) -> R {
    setup_panic_hook();
    let guard = MethodHandle::for_method(MethodId::null());
    enter_current_method(guard, || {
        let res = f();
        poll_all();
        res
    })
}

/// Execute a query function in a context that allows calling [`spawn_protected`] but not [`spawn_migratory`].
pub fn in_tracking_query_executor_context<R>(f: impl FnOnce() -> R) -> R {
    setup_panic_hook();
    let method = METHODS.with_borrow_mut(|methods| methods.insert(MethodContext::new_query()));
    let guard = MethodHandle::for_method(method);
    enter_current_method(guard, || {
        let res = f();
        poll_all();
        res
    })
}

/// Execute an inter-canister call callback in the context of the method that made it.
pub fn in_callback_executor_context_for<R>(
    method_handle: MethodHandle,
    f: impl FnOnce() -> R,
) -> R {
    setup_panic_hook();
    enter_current_method(method_handle, || {
        let res = f();
        poll_all();
        res
    })
}

/// Enters a trap/panic recovery context for calling [`cancel_all_tasks_attached_to_current_method`] in.
pub fn in_trap_recovery_context_for<R>(method: MethodHandle, f: impl FnOnce() -> R) -> R {
    setup_panic_hook();
    enter_current_method(method, || {
        RECOVERING.set(true);
        let res = f();
        RECOVERING.set(false);
        res
    })
}

/// Cancels all tasks made with [`spawn_protected`] attached to the current method.
pub fn cancel_all_tasks_attached_to_current_method() {
    let Some(method_id) = CURRENT_METHOD.get() else {
        panic!(
            "`cancel_all_tasks_attached_to_current_method` can only be called within a method context"
        );
    };
    cancel_all_tasks_attached_to_method(method_id);
}

/// Cancels all tasks made with [`spawn_protected`] attached to the given method.
fn cancel_all_tasks_attached_to_method(method_id: MethodId) {
    let Some(to_cancel) = METHODS.with_borrow_mut(|methods| {
        methods
            .get_mut(method_id)
            .map(|method| take(&mut method.tasks))
    }) else {
        return; // method context null or already deleted
    };
    let _tasks = TASKS.with(|tasks| {
        let Ok(mut tasks) = tasks.try_borrow_mut() else {
            panic!(
                "`cancel_all_tasks_attached_to_current_method` cannot be called from an async task"
            );
        };
        let mut canceled = Vec::with_capacity(to_cancel.len());
        for task_id in to_cancel {
            canceled.push(tasks.remove(task_id));
        }
        canceled
    });
    drop(_tasks); // always run task destructors outside of a refcell borrow
}

/// Removes a specific task. Use this instead of `remove` for guaranteed drop order.
pub(crate) fn delete_task(task_id: TaskId) {
    let _task = TASKS.with_borrow_mut(|tasks| tasks.remove(task_id));
    drop(_task); // always run task destructors outside of a refcell borrow
}

/// Cancels a specific task by its handle.
pub fn cancel_task(task_handle: &TaskHandle) {
    delete_task(task_handle.task_id);
}

/// Returns true if tasks are being canceled due to a trap or panic.
pub fn is_recovering_from_trap() -> bool {
    RECOVERING.get()
}

/// Produces a handle to the current method context.
///
/// The method is active as long as the handle is alive.
pub fn extend_current_method_context() -> MethodHandle {
    setup_panic_hook();
    let Some(method_id) = CURRENT_METHOD.get() else {
        panic!("`extend_method_context` can only be called within a tracking executor context");
    };
    MethodHandle::for_method(method_id)
}

/// Polls all tasks that have been woken up. Called after all context closures besides cancelation.
///
/// Should never be called inside a task, because it should only be called inside a context closure, and context closures
/// should only be at the top level of an entrypoint.
pub(crate) fn poll_all() {
    let Some(method_id) = CURRENT_METHOD.get() else {
        panic!("tasks can only be polled within an executor context");
    };
    let kind = METHODS
        .with_borrow(|methods| methods.get(method_id).map(|m| m.kind))
        .unwrap_or(ContextKind::Update);
    fn pop_wakeup(method_id: MethodId, update: bool) -> Option<TaskId> {
        if let Some(task_id) = PROTECTED_WAKEUPS.with_borrow_mut(|wakeups| {
            wakeups
                .get_mut(method_id)
                .and_then(|queue| queue.pop_front())
        }) {
            Some(task_id)
        } else if update {
            MIGRATORY_WAKEUPS.with_borrow_mut(|unattached| unattached.pop_front())
        } else {
            None
        }
    }
    while let Some(task_id) = pop_wakeup(method_id, kind == ContextKind::Update) {
        // Temporarily remove the task from the table. We need to execute it while `TASKS` is not borrowed, because it may schedule more tasks.
        let Some(mut task) = TASKS.with_borrow_mut(|tasks| tasks.get_mut(task_id).map(take)) else {
            // This waker handle appears to be dead. The most likely cause is that the method returned before
            // a canceled call came back.
            continue;
            // In the case that a task panicked and that's why it's missing, but it was in an earlier callback so a later
            // one tries to re-wake, the responsibility for re-trapping lies with CallFuture.
        };
        let waker = Waker::from(Arc::new(TaskWaker { task_id }));
        let prev_current_method_var = CURRENT_METHOD.replace(Some(task.set_current_method_var));
        CURRENT_TASK_ID.set(Some(task_id));
        let poll = task.future.as_mut().poll(&mut Context::from_waker(&waker));
        CURRENT_TASK_ID.set(None);
        CURRENT_METHOD.set(prev_current_method_var);
        match poll {
            Poll::Pending => {
                // more to do, put the task back in the table
                TASKS.with_borrow_mut(|tasks| {
                    if let Some(t) = tasks.get_mut(task_id) {
                        *t = task;
                    }
                });
            }
            Poll::Ready(()) => {
                // task complete, remove its entry from the table fully
                delete_task(task_id);
            }
        }
    }
}

/// Begin a context closure for the given method. Destroys the method afterwards if there are no outstanding handles.
pub(crate) fn enter_current_method<R>(method_guard: MethodHandle, f: impl FnOnce() -> R) -> R {
    CURRENT_METHOD.with(|context_var| {
        assert!(
            context_var.get().is_none(),
            "in_*_context called within an existing async context"
        );
        context_var.set(Some(method_guard.method_id));
    });
    let r = f();
    drop(method_guard); // drop the guard *before* the method freeing logic, but *after* the in-context code
    let method_id = CURRENT_METHOD.replace(None);
    if let Some(method_id) = method_id {
        let handles = METHODS.with_borrow_mut(|methods| methods.get(method_id).map(|m| m.handles));
        if handles == Some(0) {
            cancel_all_tasks_attached_to_method(method_id);
            METHODS.with_borrow_mut(|methods| methods.remove(method_id));
        }
    }
    r
}

/// A handle to a method context. If the function returns and all handles have been dropped, the method is considered returned.
///
/// This should be created before performing an inter-canister call via [`extend_current_method_context`],
/// threaded through the `env` parameter, and then used when calling [`in_callback_executor_context_for`] or
/// [`in_trap_recovery_context_for`]. Failure to track this properly may result in unexpected cancellation of tasks.
#[derive(Debug)]
pub struct MethodHandle {
    method_id: MethodId,
}

impl MethodHandle {
    /// Creates a live handle for the given method.
    pub(crate) fn for_method(method_id: MethodId) -> Self {
        if method_id.is_null() {
            return Self { method_id };
        }
        METHODS.with_borrow_mut(|methods| {
            let Some(method) = methods.get_mut(method_id) else {
                panic!("internal error: method context deleted while in use (for_method)");
            };
            method.handles += 1;
        });
        Self { method_id }
    }
}

impl Drop for MethodHandle {
    fn drop(&mut self) {
        METHODS.with_borrow_mut(|methods| {
            if let Some(method) = methods.get_mut(self.method_id) {
                method.handles -= 1;
            }
        })
    }
}

/// A handle to a spawned task.
#[derive(Debug)]
pub struct TaskHandle {
    task_id: TaskId,
}

impl TaskHandle {
    /// A handle to the task currently executing, or None if no task is executing.
    pub fn current() -> Option<Self> {
        let task_id = CURRENT_TASK_ID.get()?;
        Some(Self { task_id })
    }
}

pub(crate) struct TaskWaker {
    pub(crate) task_id: TaskId,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        TASKS.with_borrow_mut(|tasks| {
            if let Some(task) = tasks.get(self.task_id) {
                if let Some(method_id) = task.method_binding {
                    PROTECTED_WAKEUPS.with_borrow_mut(|wakeups| {
                        if let Some(entry) = wakeups.entry(method_id) {
                            entry.or_default().push_back(self.task_id);
                        }
                    });
                } else {
                    MIGRATORY_WAKEUPS.with_borrow_mut(|unattached| {
                        unattached.push_back(self.task_id);
                    });
                }
            }
        })
    }
}

/// Spawns a task that can migrate between methods.
///
/// When the task is awoken, it will run in the context of the method that woke it.
pub fn spawn_migratory(f: impl Future<Output = ()> + 'static) -> TaskHandle {
    setup_panic_hook();
    let Some(method_id) = CURRENT_METHOD.get() else {
        panic!("`spawn_*` can only be called within an executor context");
    };
    if is_recovering_from_trap() {
        panic!("tasks cannot be spawned while recovering from a trap");
    }
    let kind = METHODS
        .with_borrow(|methods| methods.get(method_id).map(|m| m.kind))
        .unwrap_or(ContextKind::Update);
    if kind == ContextKind::Query {
        panic!("unprotected spawns cannot be made within a query context");
    }
    let task = Task {
        future: Box::pin(f),
        method_binding: None,
        set_current_method_var: MethodId::null(),
    };
    let task_id = TASKS.with_borrow_mut(|tasks| tasks.insert(task));
    MIGRATORY_WAKEUPS.with_borrow_mut(|unattached| {
        unattached.push_back(task_id);
    });
    TaskHandle { task_id }
}

/// Spawns a task attached to the current method.
///
/// When the task is awoken, if a different method is currently running, the task will not run until the method
/// it is attached to continues. If the attached method returns before the task completes, the task will be canceled.
pub fn spawn_protected(f: impl Future<Output = ()> + 'static) -> TaskHandle {
    setup_panic_hook();
    if is_recovering_from_trap() {
        panic!("tasks cannot be spawned while recovering from a trap");
    }
    let Some(method_id) = CURRENT_METHOD.get() else {
        panic!("`spawn_*` can only be called within an executor context");
    };
    if method_id.is_null() {
        panic!("`spawn_protected` cannot be called outside of a tracked method context");
    }
    let task = Task {
        future: Box::pin(f),
        method_binding: Some(method_id),
        set_current_method_var: method_id,
    };
    let task_id = TASKS.with_borrow_mut(|tasks| tasks.insert(task));
    METHODS.with_borrow_mut(|methods| {
        let Some(method) = methods.get_mut(method_id) else {
            panic!("internal error: method context deleted while in use (spawn_protected)");
        };
        method.tasks.push(task_id);
    });
    PROTECTED_WAKEUPS.with_borrow_mut(|wakeups| {
        let Some(entry) = wakeups.entry(method_id) else {
            panic!("internal error: method context deleted while in use (spawn_protected)");
        };
        entry.or_default().push_back(task_id);
    });
    TaskHandle { task_id }
}

fn setup_panic_hook() {
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let file = info.location().unwrap().file();
            let line = info.location().unwrap().line();
            let col = info.location().unwrap().column();

            let msg = match info.payload().downcast_ref::<&'static str>() {
                Some(s) => *s,
                None => match info.payload().downcast_ref::<String>() {
                    Some(s) => &s[..],
                    None => "Box<Any>",
                },
            };

            let err_info = format!("Panicked at '{msg}', {file}:{line}:{col}");
            ic0::debug_print(err_info.as_bytes());
            ic0::trap(err_info.as_bytes());
        }));
    });
}
