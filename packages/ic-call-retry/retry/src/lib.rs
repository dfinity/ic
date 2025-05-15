//! A library for retrying calls to the Internet Computer with configurable retry policies.
//!
//! This library provides utilities for retrying calls to the Internet Computer with different
//! retry policies. It supports both idempotent and non-idempotent calls, though you must
//! decide yourself which calls are idempotent and which are not.
//!
//! Note that retries are always executed immediately, there is no backoff strategy. This is
//! because the Internet Computer doesn't (yet?) support "pausing" a call context. Retries
//! with backoffs would have to be implemented as background tasks.
//!
//! # Features
//!
//! - Support for both idempotent and non-idempotent calls
//! - Configurable retry policies with deadlines
//! - Detailed error reporting
//!
//! # Examples
//!
//! ```rust
//! use ic_call_retry::{call_idempotent_method_with_retry, when_out_of_time_or_stopping, Deadline};
//! use ic_cdk::api::time;
//! use ic_cdk::call::Call;
//!
//! async fn example_retry_call() -> Result<(), String> {
//!     // Set a deadline 5 seconds in the future
//!     let deadline = time() + 5_000_000_000; // 5 seconds in nanoseconds
//!     let deadline = Deadline::TimeOrStopping(deadline);
//!
//!     // Create a call to some canister
//!     let call = Call::bounded_wait(canister_id, "some_method")
//!         .with_arg(&arg);
//!
//!     // Retry the call until either:
//!     // 1. The call succeeds
//!     // 2. The deadline is reached
//!     // 3. The caller canister enters the stopping state
//!     // 4. A non-retryable error occurs
//!     call_idempotent_method_with_retry(
//!         call,
//!         &mut when_out_of_time_or_stopping(&deadline),
//!     )
//!     .await
//!     .map_err(|e| format!("Call failed: {:?}", e))?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Note
//!
//! Retrying indefinitely is not recommended, as this can make your canister unupgradable.
//! For example, the following are safe to use:
//!
//! - A time-based deadline (`Deadline::TimeOrStopping`)
//! - A stopping-based deadline (`Deadline::Stopping`)
//! - A maximum number of retries (`max_retries`)

#[cfg(feature = "use_call_chaos")]
use ic_call_chaos::Call;
use ic_cdk::api::{canister_status, time, CanisterStatusCode};
#[cfg(not(feature = "use_call_chaos"))]
use ic_cdk::call::Call;
use ic_cdk::call::{CallErrorExt, CallFailed, Response};

/// Represents a deadline for retrying calls.
///
/// The deadline can be based on:
/// - The stopping state of the caller canister
/// - A combination of time and stopping state
#[derive(Debug, Clone)]
pub enum Deadline {
    /// Retry until the caller canister enters the stopping state.
    ///
    /// Note that, since there is no backoff, this caries a risk of burning
    /// the caller's cycles, potentially quickly, until the caller is stopped.
    /// Upstream callers may also be blocked until the caller is stopped.
    Stopping,
    /// Retry until either the specified time is reached or the caller canister enters the stopping state
    TimeOrStopping(u64),
}

/// Represents the cause of a retry error.
#[derive(Debug, Clone)]
pub enum ErrorCause {
    /// The call failed with a specific error
    CallFailed(CallFailed),
    /// The retry was abandoned due to the retry policy
    GaveUpRetrying,
}

/// An error type for retried calls.
///
/// This enum distinguishes between cases where we know the call failed
/// and cases where we cannot determine the final status of the call.
#[derive(Clone, Debug)]
pub enum RetryError {
    /// We know that the call failed, and there is no point in retrying
    CallFailed(ErrorCause),
    /// A fatal error. We don't know whether the call failed, but there is no point in retrying.
    StatusUnknown(ErrorCause),
}

/// Makes and, in case of failure, retries an idempotent call until instructed otherwise
///
/// This function is suitable for calls that can be safely retried without side effects.
/// It will retry the call until either:
/// - The call succeeds
/// - The retry condition returns false
/// - A non-retryable error occurs
///
/// # Arguments
///
/// * `call` - The (idempotent) call to execute and retry if needed
/// * `stop_trying` - A function that determines when to stop (re)trying the call
///
/// # Returns
///
/// * `Ok(Response)` if the call succeeds
/// * `Err(RetryError)` if the call fails and cannot be retried
pub async fn call_idempotent_method_with_retry<'a, 'm, P>(
    call: Call<'a, 'm>,
    stop_trying: &mut P,
) -> Result<Response, RetryError>
where
    P: FnMut() -> bool,
{
    let mut no_unknown_results = true;

    loop {
        if stop_trying() {
            return Err(if no_unknown_results {
                RetryError::CallFailed(ErrorCause::GaveUpRetrying)
            } else {
                RetryError::StatusUnknown(ErrorCause::GaveUpRetrying)
            });
        }

        match call.clone().await {
            Ok(result) => return Ok(result),
            Err(e) if !e.is_immediately_retryable() => {
                if no_unknown_results {
                    return Err(RetryError::CallFailed(ErrorCause::CallFailed(e)));
                } else {
                    return Err(RetryError::StatusUnknown(ErrorCause::CallFailed(e)));
                }
            }
            Err(e) if !e.is_clean_reject() => {
                no_unknown_results = false;
                continue;
            }
            // The only remaining option is a non-sync SysTransient => retry
            Err(_e) => continue,
        }
    }
}

/// Makes and, in case of failure, retries a non-idempotent call until instructed otherwise
///
/// This function is suitable for calls that may have side effects and should be
/// retried with caution. It will retry the call until either:
/// - The call succeeds
/// - The retry condition returns false
/// - A non-retryable error occurs
/// - An error occurs where we cannot determine the final status of the call
///
/// # Arguments
///
/// * `call` - The call to retry
/// * `stop_trying` - A function that determines whether to stop (re)trying the call
///
/// # Returns
///
/// * `Ok(Response)` if the call succeeds
/// * `Err(RetryError)` if the call fails and cannot be retried
pub async fn call_nonidempotent_method_with_retry<'m, 'a, P>(
    call: Call<'m, 'a>,
    stop_trying: &mut P,
) -> Result<Response, RetryError>
where
    P: FnMut() -> bool,
{
    loop {
        if stop_trying() {
            return Err(RetryError::CallFailed(ErrorCause::GaveUpRetrying));
        }

        match call.clone().await {
            Ok(res) => return Ok(res),
            Err(e) if !e.is_immediately_retryable() => {
                return Err(RetryError::CallFailed(ErrorCause::CallFailed(e)))
            }
            Err(e) if !e.is_clean_reject() => {
                return Err(RetryError::StatusUnknown(ErrorCause::CallFailed(e)))
            }
            // Non-sync SysTransient => retry
            Err(_e) => {
                continue
            },
        }
    }
}

/// Returns a function that determines whether to stop retrying based on the deadline.
///
/// This function returns a closure that can be used directly with the retry functions.
///
/// # Arguments
///
/// * `deadline` - The deadline to check against
///
/// # Returns
///
/// A closure that returns `true` if we should continue retrying
pub fn when_out_of_time_or_stopping(deadline: &Deadline) -> impl FnMut() -> bool {
    let deadline = deadline.clone();
    move || match &deadline {
        Deadline::Stopping => canister_status() == CanisterStatusCode::Stopping,
        Deadline::TimeOrStopping(dl) => {
            canister_status() == CanisterStatusCode::Stopping || time() >= *dl
        }
    }
}

/// Returns a function that retries up to the specified number of times.
///
/// This function returns a closure that can be used directly with the retry functions.
///
/// # Arguments
///
/// * `max_retries` - The maximum number of retries
///
/// # Returns
///
/// A closure that returns `true` if we should continue retrying
pub fn when_max_retries_reached(max_retries: u32) -> impl FnMut() -> bool {
    let mut retries = 0;
    move || {
        retries += 1;
        retries > max_retries
    }
}
