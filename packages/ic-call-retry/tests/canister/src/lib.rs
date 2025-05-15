use ic_call_chaos::{set_policy as call_chaos_set_policy, Call};
use ic_call_retry::{call_idempotent_method_with_retry, when_out_of_time_or_stopping, Deadline};
use ic_cdk::api::canister_self;
use ic_cdk::call::{CallFailed, CallPerformFailed, CallRejected, OnewayError};
use ic_cdk::{query, update};
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::sync::Mutex;

struct State {
    stored_ids: HashSet<u64>,
}

impl State {
    fn new() -> Self {
        Self {
            stored_ids: HashSet::new(),
        }
    }
}

lazy_static! {
    static ref STATE: Mutex<State> = Mutex::new(State::new());
    static ref COUNTER: Mutex<u64> = Mutex::new(0);
}

#[update]
fn idempotent(id: u64) -> u64 {
    let mut state = STATE.lock().expect("Couldn't obtain the lock on the state");
    state.stored_ids.insert(id);
    state.stored_ids.len() as u64
}

#[update]
fn non_idempotent() -> u64 {
    let mut counter = COUNTER
        .lock()
        .expect("Couldn't obtain the lock on the counter");
    *counter += 1;
    *counter
}

#[update]
async fn call_idempotent(id: u64, deadline: u64, use_unbounded_wait: bool) -> Result<u64, String> {
    let call = if use_unbounded_wait {
        Call::unbounded_wait(canister_self(), "idempotent")
    } else {
        Call::bounded_wait(canister_self(), "idempotent")
    }
    .with_arg(&id);

    let res = call_idempotent_method_with_retry(
        call,
        &mut when_out_of_time_or_stopping(&Deadline::TimeOrStopping(deadline)),
    )
    .await
    .map(|resp| {
        resp.candid::<u64>()
            .expect("Couldn't decode response from idempotent")
    })
    .map_err(|e| format!("Error: {:?}", e));
    res
}

struct DenyAllSynchronously;
impl ic_call_chaos::Policy for DenyAllSynchronously {
    fn allow(&mut self, _call: &Call) -> Result<(), CallFailed> {
        Err(CallPerformFailed.into())
    }

    fn allow_oneway(&mut self, _call: &Call) -> Result<(), Option<OnewayError>> {
        Err(Some(CallPerformFailed.into()))
    }
}

struct DenyWithCanisterReject;
impl ic_call_chaos::Policy for DenyWithCanisterReject {
    fn allow(&mut self, _call: &Call) -> Result<(), CallFailed> {
        Err(CallRejected::with_rejection(4, "Injected a canister reject".to_string()).into())
    }

    fn allow_oneway(&mut self, _call: &Call) -> Result<(), Option<OnewayError>> {
        todo!()
    }
}

struct DenyWithSysnUnknown;
impl ic_call_chaos::Policy for DenyWithSysnUnknown {
    fn allow(&mut self, _call: &Call) -> Result<(), CallFailed> {
        Err(CallRejected::with_rejection(6, "Injected a sys_unknown".to_string()).into())
    }

    fn allow_oneway(&mut self, _call: &Call) -> Result<(), Option<OnewayError>> {
        todo!()
    }
}

#[update]
async fn set_policy(policy: String) {
    match policy.as_str() {
        "AllowAll" => call_chaos_set_policy(ic_call_chaos::AllowAll::default()),
        "AllowEveryOther" => call_chaos_set_policy(ic_call_chaos::AllowEveryOther::default()),
        "DenyAll" => call_chaos_set_policy(ic_call_chaos::DenyAll::default()),
        "WithProbability" => {
            call_chaos_set_policy(ic_call_chaos::WithProbability::new(0.1, 1337, true))
        }
        "DenyAllSynchronously" => call_chaos_set_policy(DenyAllSynchronously),
        "DenyWithCanisterReject" => call_chaos_set_policy(DenyWithCanisterReject),
        "DenyWithSysUnknown" => call_chaos_set_policy(DenyWithSysnUnknown),
        _ => panic!("Unknown policy: {}", policy),
    }
}

#[update]
async fn call_non_idempotent(use_unbounded_wait: bool) -> Result<u64, String> {
    let call = if use_unbounded_wait {
        Call::unbounded_wait(canister_self(), "non_idempotent")
    } else {
        Call::bounded_wait(canister_self(), "non_idempotent")
    };
    let res = call
        .await
        .map(|resp| {
            resp.candid::<u64>()
                .expect("Couldn't decode response from non_idempotent")
        })
        .map_err(|e| format!("Error: {:?}", e));
    res
}

#[query]
fn get_counter() -> u64 {
    let counter = COUNTER
        .lock()
        .expect("Couldn't obtain the lock on the counter");
    *counter
}

fn main() {}
