//! Chaos testing library for Internet Computer inter-canister calls
//!
//! `ic_call_chaos` is a small library to enable testing the resilience of Internet Computer canisters to inter-canister call failures.
//! It allows you to simulate various failure scenarios, such as dropped, timed out, or rejected calls, to ensure that your canisters
//! can handle these situations gracefully.
//!
//! It is designed to be used in conjunction with the `ic-cdk` library, which provides the necessary tools for building canisters on
//! the Internet Computer.
//!
//! ## Usage
//!
//! 1. Import `Call` and friends from `ic_call_chaos` instead of `ic_cdk::call`. The provided interface is the
//!    same as `ic_cdk::call`, but with additional functionality to simulate failures. The default policy is
//!    `AllowAll`, which means that all calls will be passed to the underlying `ic_cdk` library.
//!    You likely want to make the replacement import conditional on a feature flag, so that you don't inherit
//!    the overhead of (or any bugs in) the wrapper in production.
//! 1. Provide a way to change the failure policy from tests.
//! 1. In your tests, apply the desired policy.
//!
//! For examples, look at the source of this library, and in particular `canister/src/lib.rs` for an example of how to
//! add `ic_call_chaos` to your canister code, and `pocket_ic_test/tests/integration_test.rs` for an example of how to
//! use it in your tests.

use candid::utils::ArgumentEncoder;
use candid::{CandidType, Principal};
use ic_cdk::call::{
    Call as CdkCall, CallFailed, CallFuture as CdkCallFuture, CallPerformFailed, CallRejected,
    OnewayError, RejectCode, Response,
};
use lazy_static::lazy_static;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::future::IntoFuture;
use std::mem;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::Poll;

/// A trait that defines a policy for allowing or rejecting calls.
pub trait Policy: Send + Sync {
    /// Whether to allow a call.
    ///
    /// If the call is allowed, the ic_cdk call will be executed. This still doesn't mean that the
    /// call will succeed, as it might actually fail for an arbitrary reason (e.g., not having enough cycles,
    /// system being under load, etc).
    ///
    /// If the call is not allowed, the ic_cdk call will not be executed. The policy can, however,
    /// execute the call under the hood and still return an error. For example, for bounded-wait
    /// calls, you may return `RejectCode::SysUnknown` and still issue the call, simulating a
    /// timeout in production. Returning a `CallFailed::CallRejected` will cause the chaos library
    /// to actually delay producing the rejection, by calling a no-op on the management canister.
    /// This is done in order to simulate the time it would take for the call to be rejected in
    /// production.
    ///
    /// Note that this takes a mutable reference to the policy, so it can be used to maintain state
    /// if needed (e.g., drop the first `N` calls, and then allow all calls to go through)
    fn allow(&mut self, call: &Call) -> Result<(), CallFailed>;

    /// Whether to allow a one-way call.
    ///
    /// If the call is allowed, the ic_cdk call will be executed. This still doesn't mean that the
    /// call will succeed, as it might fail for an arbitrary reason (e.g., not having enough cycles,
    /// system being under load, etc).
    ///
    /// If the call is not allowed, the ic_cdk call will not be executed. To allow simulating the
    /// call failing silently, the error is returned as an `Option<OnewayError>`. An error of
    /// `None` means that the call shouldn't be executed but no error should be returned either. An
    /// error of `Some(OnewayError)` means that the call shouldn't be executed and the error should
    /// be returned to the caller.
    ///
    /// Note that this takes a mutable reference to the policy, so it can be used to maintain state
    /// if needed (e.g., drop the first `N` calls, and then allow all calls to go through)
    fn allow_oneway(&mut self, call: &Call) -> Result<(), Option<OnewayError>>;
}

/// A simple policy that allows all calls.
#[derive(Default)]
pub struct AllowAll {}

impl Policy for AllowAll {
    fn allow(&mut self, _call: &Call) -> Result<(), CallFailed> {
        Ok(())
    }

    fn allow_oneway(&mut self, _call: &Call) -> Result<(), Option<OnewayError>> {
        Ok(())
    }
}

/// A simple policy that denies all calls, returning a `SysTransient` reject code.
#[derive(Default)]
pub struct DenyAll {}

impl Policy for DenyAll {
    fn allow(&mut self, _call: &Call) -> Result<(), CallFailed> {
        Err(CallFailed::CallRejected(CallRejected::with_rejection(
            RejectCode::SysTransient as u32,
            "Chaos testing: call rejected".to_string(),
        )))
    }

    fn allow_oneway(&mut self, _call: &Call) -> Result<(), Option<OnewayError>> {
        Err(Some(CallPerformFailed.into()))
    }
}

/// A simple policy that fails every other call with a `SysTransient` reject code.
#[derive(Default)]
pub struct AllowEveryOther {
    pub allow_next: bool,
}

impl Policy for AllowEveryOther {
    fn allow(&mut self, _call: &Call) -> Result<(), CallFailed> {
        self.allow_next = !self.allow_next;
        if !self.allow_next {
            Ok(())
        } else {
            Err(CallFailed::CallRejected(CallRejected::with_rejection(
                RejectCode::SysTransient as u32,
                "Chaos testing: call rejected".to_string(),
            )))
        }
    }

    fn allow_oneway(&mut self, _call: &Call) -> Result<(), Option<OnewayError>> {
        self.allow_next = !self.allow_next;
        if !self.allow_next {
            Ok(())
        } else {
            Err(Some(CallPerformFailed.into()))
        }
    }
}

/// A policy that allows calls with a given probability. The probability is a float between 0 and 1.
/// For bounded wait calls, if `silently_perform_bounded_wait_calls` is set to true, bounded-wat calls
/// A will be executed though a reject code (`SysUnknown`) will be returned. This is useful for
/// simulating timeouts in production.
pub struct WithProbability {
    probability: f32,
    silently_perform_bounded_wait_calls: bool,
    rng: ChaCha8Rng,
}

impl WithProbability {
    /// Create a new `WithProbability` policy with the given probability and seed.
    ///
    /// # Arguments
    ///
    /// * `probability` - A float between 0 and 1 representing the probability of allowing calls.
    /// * `seed` - A u64 seed for the random number generator.
    /// * `silently_perform_bounded_wait_calls` - A boolean indicating whether to silently perform bounded-wait calls even if they are reported as rejected (with a `SysUnknown` reject code).
    pub fn new(probability: f32, seed: u64, silently_perform_bounded_wait_calls: bool) -> Self {
        assert!(probability >= 0.0, "Probability should be >= 0");
        assert!(probability <= 1.0, "Probability should be <= 1");
        Self {
            probability,
            silently_perform_bounded_wait_calls,
            rng: ChaCha8Rng::seed_from_u64(seed),
        }
    }
}

impl Policy for WithProbability {
    fn allow(&mut self, call: &Call) -> Result<(), CallFailed> {
        let allow = (self.rng.next_u32() as f32) < self.probability * u32::MAX as f32;
        if allow {
            Ok(())
        } else if call.call_type == CallType::BoundedWait
            && self.silently_perform_bounded_wait_calls
        {
            let _res = call.call.oneway();
            Err(CallFailed::CallRejected(CallRejected::with_rejection(
                RejectCode::SysUnknown as u32,
                "Chaos testing: timing call out".to_string(),
            )))
        } else {
            Err(CallFailed::CallRejected(CallRejected::with_rejection(
                RejectCode::SysTransient as u32,
                "Chaos testing: call rejected".to_string(),
            )))
        }
    }

    fn allow_oneway(&mut self, call: &Call) -> Result<(), Option<OnewayError>> {
        let allow = (self.rng.next_u32() as f32) < self.probability * u32::MAX as f32;
        if allow {
            Ok(())
        } else if call.call_type == CallType::BoundedWait
            && self.silently_perform_bounded_wait_calls
        {
            Err(None)
        } else {
            Err(Some(CallPerformFailed.into()))
        }
    }
}

lazy_static! {
    static ref POLICY: Mutex<Box<dyn Policy>> = Mutex::new(Box::new(AllowAll::default()));
}

pub fn set_policy<P: Policy + 'static>(policy: P) -> () {
    let mut guard = POLICY
        .lock()
        .expect("Couldn't lock the policy mutex when setting the policy");
    *guard = Box::new(policy);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallType {
    BoundedWait,
    UnboundedWait,
}

/// A wrapper around `ic_cdk::call::Call` that enables "chaos testing" by failing calls
/// according to a policy set by `set_policy`. It's implemented as a drop-in replacement
/// for `ic_cdk::call::Call`, so it can be used in lieu of it by simple changing imports.
/// See the documentation on `ic_cdk::call::Call` for more details on the individual methods.
#[derive(Clone, Debug)]
pub struct Call<'m, 'a> {
    pub canister_id: Principal,
    pub method: &'m str,
    pub call_type: CallType,
    call: CdkCall<'m, 'a>,
}

impl<'m> Call<'m, '_> {
    pub fn bounded_wait(canister_id: Principal, method: &'m str) -> Self {
        Call {
            canister_id,
            method,
            call_type: CallType::BoundedWait,
            call: CdkCall::bounded_wait(canister_id, method),
        }
    }

    pub fn unbounded_wait(canister_id: Principal, method: &'m str) -> Self {
        Call {
            canister_id,
            method,
            call_type: CallType::UnboundedWait,
            call: CdkCall::unbounded_wait(canister_id, method),
        }
    }
}

impl<'a> Call<'_, 'a> {
    pub fn with_arg<T: CandidType>(self, arg: &T) -> Self {
        Self {
            call: self.call.with_arg(arg),
            ..self
        }
    }

    pub fn with_args<A: ArgumentEncoder>(self, args: &A) -> Self {
        Self {
            call: self.call.with_args(args),
            ..self
        }
    }

    pub fn with_raw_args(self, raw_args: &'a [u8]) -> Self {
        Self {
            call: self.call.with_raw_args(raw_args),
            ..self
        }
    }

    pub fn with_cycles(mut self, cycles: u128) -> Self {
        self.call = self.call.with_cycles(cycles);
        self
    }

    pub fn change_timeout(mut self, timeout_seconds: u32) -> Self {
        self.call = self.call.change_timeout(timeout_seconds);
        self
    }

    pub fn get_cost(&self) -> u128 {
        self.call.get_cost()
    }
}

impl Call<'_, '_> {
    /// Sends the call and ignores the reply.
    pub fn oneway(&self) -> Result<(), OnewayError> {
        let mut policy = POLICY
            .lock()
            .expect("Couldn't lock the policy mutex when sending a one-way call");
        match policy.allow_oneway(self) {
            Ok(_) => self.call.oneway(),
            Err(None) =>
            // Don't execute the call, but don't return an error either
            {
                Ok(())
            }
            Err(Some(err)) => Err(err),
        }
    }
}

enum CallFutureState<'m, 'a> {
    // The call has been rejected, however, we're waiting for a dummy management canister call
    // to finish, in order to simulate the passage of time that would happen when an asynchronous
    // reject happens in reality.
    Rejected(CallFailed),
    // The call has been allowed, and we're waiting for the result.
    Allowed(CdkCallFuture<'m, 'a>),
    // The policy hasn't been applied yet, so this is before awaiting
    Outstanding(Call<'m, 'a>),
    // We've already returned a `Poll::Ready`. We shouldn't get polled again.
    Completed,
}

pub struct CallFuture<'m, 'a> {
    state: CallFutureState<'m, 'a>,
}

impl<'m, 'a> IntoFuture for Call<'m, 'a> {
    type IntoFuture = CallFuture<'m, 'a>;
    type Output = Result<Response, CallFailed>;

    fn into_future(self) -> Self::IntoFuture {
        CallFuture {
            state: CallFutureState::Outstanding(self),
        }
    }
}

impl std::future::Future for CallFuture<'_, '_> {
    type Output = Result<Response, CallFailed>;

    fn poll(
        self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let fut = Pin::into_inner(self);
        let (mut cdk_fut, opt_err) = match fut.state {
            CallFutureState::Completed => {
                panic!("CallFuture is already completed, it shouldn't be polled again")
            }
            CallFutureState::Outstanding(ref mut call) => {
                let mut policy = POLICY
                    .lock()
                    .expect("Couldn't lock the policy mutex when sending a call");
                match policy.allow(&call) {
                    Ok(()) => {
                        let call = call.clone();
                        (call.call.into_future(), None)
                    }
                    Err(call_failed) => {
                        match call_failed {
                            CallFailed::CallRejected(_) => {
                                // If the call was rejected, we need to wait for a dummy management canister call
                                // to finish, in order to simulate the passage of time in the current call context.
                                let err = call_failed.clone();
                                let cdk_fut = CdkCall::bounded_wait(
                                    Principal::management_canister(),
                                    "canister_info",
                                )
                                .with_arg(ic_cdk::management_canister::CanisterInfoArgs {
                                    canister_id: ic_cdk::api::canister_self(),
                                    num_requested_changes: None,
                                })
                                .into_future();
                                (cdk_fut, Some(err))
                            }
                            _ => {
                                // The policy failed the call synchronously, just return the result
                                let err = call_failed.clone();
                                fut.state = CallFutureState::Completed;
                                return Poll::Ready(Err(err));
                            }
                        }
                    }
                }
            }
            CallFutureState::Allowed(ref mut cdk_fut) => {
                // Replace with something dummy to take ownership
                let mut cdk_fut = mem::replace(
                    cdk_fut,
                    CdkCall::bounded_wait(Principal::anonymous(), "nothing").into_future(),
                );
                fut.state = CallFutureState::Completed;
                return Pin::new(&mut cdk_fut).poll(context);
            }
            CallFutureState::Rejected(ref call_failed) => {
                let err = call_failed.clone();
                fut.state = CallFutureState::Completed;
                return Poll::Ready(Err(err));
            }
        };
        let res = Pin::new(&mut cdk_fut).poll(context);
        match opt_err {
            Some(err) => fut.state = CallFutureState::Rejected(err),
            None => fut.state = CallFutureState::Allowed(cdk_fut),
        }
        res
    }
}
