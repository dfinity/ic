//! Internals used by the attribute macros.
//!
//! You do not need to use this module unless you are deliberately avoiding the attribute macros.

/// Execute an update function in a context that allows calling [`spawn`](super::spawn).
///
/// You do not need to worry about this function unless you are avoiding the attribute macros.
///
/// Background tasks will be polled in the process (and will not be run otherwise).
/// Panics if called inside an existing executor context.
pub fn in_executor_context<R>(f: impl FnOnce() -> R) -> R {
    ic_cdk_executor::in_tracking_executor_context(f)
}

/// Execute a composite query function in a context that allows calling [`spawn`](super::spawn).
///
/// You do not need to worry about this function unless you are avoiding the attribute macros.
///
/// Background composite query tasks will be polled in the process (and will not be run otherwise).
/// Panics if called inside an existing executor context.
pub fn in_query_executor_context<R>(f: impl FnOnce() -> R) -> R {
    ic_cdk_executor::in_tracking_query_executor_context(f)
}
