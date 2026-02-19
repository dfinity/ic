//! This library implements multiple and periodic timers on the Internet Computer.
//!
//! # Example
//!
//! ```rust,no_run
//! # use std::time::Duration;
//! # fn main() {
//! ic_cdk_timers::set_timer(Duration::from_secs(1), async { ic_cdk::println!("Hello from the future!") });
//! # }
//! ```
//!
//! # Details
//!
//! Timers internally use a bounded-wait self-call for error handling purposes. This is not guaranteed to
//! remain the case in the future, but means that if the system is under heavy load, timers may begin to
//! slow down by a lot as the self-calls begin to time out and the timers are rescheduled for the next global
//! timer tick. This also means that each executed timer incurs the cycle cost of a canister call.
//!
//! <div class="warning">
//!
//! Timers are not persisted across canister upgrades.
//!
//! </div>

#![warn(
    elided_lifetimes_in_paths,
    missing_debug_implementations,
    missing_docs,
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc
)]

use std::{future::Future, time::Duration};

use crate::state::{TASKS, TIMERS, Task, Timer};

mod global_timer;
mod state;
mod timer_executor;

/// Type returned by the [`set_timer`] and [`set_timer_interval`] functions. Pass to [`clear_timer`] to remove the timer.
#[doc(inline)]
pub use crate::state::TaskId as TimerId;

/// Sets `future` to be executed later, after `delay`. Panics if `delay` + [`time()`] is more than [`u64::MAX`] nanoseconds.
///
/// To cancel the timer before it executes, pass the returned `TimerId` to [`clear_timer`].
///
/// <div class="warning">
///
/// Timers are not persisted across canister upgrades.
///
/// </div>
///
/// # Examples
///
/// ```no_run
/// # use std::time::Duration;
/// ic_cdk_timers::set_timer(Duration::from_secs(1), async {
///     ic_cdk::println!("Hello from the future!");
/// });
/// ```
///
/// [`time()`]: https://docs.rs/ic-cdk/0.18.5/ic_cdk/api/fn.time.html
pub fn set_timer(delay: Duration, future: impl Future<Output = ()> + 'static) -> TimerId {
    let scheduled_time = get_scheduled_time(delay);
    let key = TASKS.with_borrow_mut(|tasks| tasks.insert(Task::Once(Box::pin(future))));
    TIMERS.with_borrow_mut(|timers| {
        timers.push(Timer {
            task: key,
            time: scheduled_time,
            counter: state::next_counter(),
        })
    });
    state::update_ic0_timer();
    key
}

/// Sets `func` to be executed every `interval`. Panics if `interval` + [`time()`] is more than [`u64::MAX`] nanoseconds.
///
/// To cancel the interval timer, pass the returned `TimerId` to [`clear_timer`].
///
/// This is a closure returning a future (`|| async {`), not an async closure (`async || {`). The two syntaxes
/// are interchangeable *if* the closure does not capture anything. If it does, you will need the former syntax,
/// and it is almost certain that either your captures must be Copy or you must use e.g. Rc to share them, because
/// you cannot capture by reference, and referencing an owned capture in a returned async block is not possible.
///
/// <div class="warning">
///
/// Interval timers should be *idempotent* with respect to the canister's state, as during heavy network load,
/// timeouts may result in duplicate execution.
///
/// </div>
///
/// <div class="warning">
///
/// Timers are not persisted across canister upgrades.
///
/// </div>
///
/// # Examples
///
/// ```no_run
/// # use std::time::Duration;
/// ic_cdk_timers::set_timer_interval(Duration::from_secs(5), || async {
///     ic_cdk::println!("This will run every five seconds forever!");
/// });
/// ```
///
/// [`time()`]: https://docs.rs/ic-cdk/0.18.5/ic_cdk/api/fn.time.html
pub fn set_timer_interval<Fut>(interval: Duration, func: impl FnMut() -> Fut + 'static) -> TimerId
where
    Fut: Future<Output = ()> + 'static,
{
    let mut func = func;
    let scheduled_time = get_scheduled_time(interval);
    let key = TASKS.with_borrow_mut(|tasks| {
        tasks.insert(Task::Repeated {
            func: Box::new(move || Box::pin(func())),
            interval,
            concurrent_calls: 0,
        })
    });
    TIMERS.with_borrow_mut(|timers| {
        timers.push(Timer {
            task: key,
            time: scheduled_time,
            counter: state::next_counter(),
        });
    });
    state::update_ic0_timer();
    key
}

/// Sets `func` to be executed every `interval`. Panics if `interval` + [`time()`] is more than [`u64::MAX`] nanoseconds.
///
/// To cancel the interval timer, pass the returned `TimerId` to [`clear_timer`].
///
/// Unlike [`set_timer_interval`], this function takes an async closure (`async || {`). This is simpler to use
/// with captured variables, but also means that invocations cannot be run concurrently; if the interval is up
/// but the previous invocation is still running, the new invocation will be skipped.
///
/// <div class="warning">
///
/// Interval timers should be *idempotent* with respect to the canister's state, as during heavy network load,
/// timeouts may result in duplicate execution.
///
/// </div>
///
/// <div class="warning">
///
/// Timers are not persisted across canister upgrades.
///
/// </div>
///
/// # Examples
///
/// ```no_run
/// # use std::time::Duration;
/// ic_cdk_timers::set_timer_interval_serial(Duration::from_secs(5), async || {
///     ic_cdk::println!("This will run every five seconds forever!");
/// });
/// ```
///
/// [`time()`]: https://docs.rs/ic-cdk/0.18.5/ic_cdk/api/fn.time.html
pub fn set_timer_interval_serial(interval: Duration, func: impl AsyncFnMut() + 'static) -> TimerId {
    let scheduled_time = get_scheduled_time(interval);
    let key = TASKS.with_borrow_mut(|tasks| {
        tasks.insert(Task::RepeatedSerial {
            func: Box::new(func),
            interval,
        })
    });
    TIMERS.with_borrow_mut(|timers| {
        timers.push(Timer {
            task: key,
            time: scheduled_time,
            counter: state::next_counter(),
        });
    });
    state::update_ic0_timer();
    key
}

/// Cancels an existing timer. Does nothing if the timer has already been canceled.
///
/// # Examples
///
/// ```no_run
/// # use std::time::Duration;
/// let timer_id = ic_cdk_timers::set_timer(Duration::from_secs(60), async {
///     ic_cdk::println!("This will never run, because we cancel it!");
/// });
/// ic_cdk_timers::clear_timer(timer_id);
/// ```
pub fn clear_timer(id: TimerId) {
    TASKS.with_borrow_mut(|tasks| tasks.remove(id));
}

fn get_scheduled_time(delay: Duration) -> u64 {
    let delay_ns = u64::try_from(delay.as_nanos()).expect(
        "delay out of bounds (must be within `u64::MAX - ic_cdk::api::time()` nanoseconds)",
    );
    ic0::time()
        .checked_add(delay_ns)
        .expect("delay out of bounds (must be within `u64::MAX - ic_cdk::api::time()` nanoseconds)")
}
