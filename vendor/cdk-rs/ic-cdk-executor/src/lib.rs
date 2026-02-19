//! An async executor for [`ic-cdk`](https://docs.rs/ic-cdk). Most users should not use this crate directly. It is useful
//! primarily for those who are writing their own CDK or a runtime host for non-Rust languages.
//!
//! ## Contexts
//!
//! The expected boilerplate for a canister method or other entrypoint (*not* including callbacks) looks like this:
//!
//! ```
//! # use ic_cdk_executor::*;
//! pub extern "C" fn function() {
//!     in_tracking_executor_context(|| {
//!         // method goes here
//!     });
//! }
//! ```
//!
//! The [`in_tracking_executor_context`] function permits you to call `spawn_*` functions. As little code as possible
//! should exist outside the block, because [`in_tracking_executor_context`] additionally sets up the panic handler.
//!
//! The above applies to update contexts. Query contexts, including `canister_inspect_message`, should use
//! [`in_tracking_query_executor_context`].
//!
//! The expected boilerplate for an inter-canister call callback looks like this:
//!
//! ```
//! # use ic_cdk_executor::*;
//! # fn unpack_env(env: usize) -> MethodHandle { unimplemented!() }
//! unsafe extern "C" fn callback(env: usize) {
//!     let method = unpack_env(env);
//!     in_callback_executor_context_for(method, || {
//!        // wake the call future
//!     });
//! }
//! unsafe extern "C" fn cleanup(env: usize) {
//!     let method = unpack_env(env);
//!     in_trap_recovery_context_for(method, || {
//!         cancel_all_tasks_attached_to_current_method();
//!     });
//! }
//! ```
//!
//! In async contexts, all scheduled tasks are run *after* the closure passed to the context function
//! returns, but *before* the context function itself returns.
//!
//! The `method` parameter must be retrieved *before* making inter-canister calls via the [`extend_current_method_context`]
//! function. Calling this function from the callback instead will trap.
//!
//! ## Protection
//!
//! Tasks can be either *protected* or *migratory*. Protected tasks are attached to the method that spawned them,
//! when awoken will not resume until that method continues, and will be canceled if the method returns before they complete.
//! Migratory tasks are not attached to any method, and will resume in whatever method wakes them.
mod machinery;

#[doc(inline)]
pub use machinery::{
    MethodHandle, TaskHandle, cancel_all_tasks_attached_to_current_method, cancel_task,
    extend_current_method_context, in_callback_executor_context_for, in_tracking_executor_context,
    in_tracking_query_executor_context, in_trap_recovery_context_for, is_recovering_from_trap,
    spawn_migratory, spawn_protected,
};
