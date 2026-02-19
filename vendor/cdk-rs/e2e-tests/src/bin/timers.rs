use futures::{stream::FuturesUnordered, StreamExt};
use ic_cdk::{
    api::canister_self,
    call::Call,
    futures::spawn,
    management_canister::{HttpMethod, HttpRequestArgs},
    query, update,
};
use ic_cdk_timers::{clear_timer, set_timer, set_timer_interval, TimerId};
use std::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

thread_local! {
    static EVENTS: RefCell<Vec<String>> = RefCell::default();
    static LONG: Cell<TimerId> = Cell::default();
    static REPEATING: Cell<TimerId> = Cell::default();
}

static EXECUTED_TIMERS: AtomicU32 = AtomicU32::new(0);

#[query]
fn get_events() -> Vec<String> {
    EVENTS.with(|events| events.borrow().clone())
}

#[update]
fn clear_events() {
    EVENTS.with(|events| events.borrow_mut().clear());
}

#[update]
fn schedule() {
    set_timer(Duration::from_secs(2), async {
        add_event("2");
    });
    set_timer(Duration::from_secs(1), async {
        add_event("1");
        set_timer(Duration::from_secs(2), async { add_event("3") });
    });
    set_timer(Duration::from_secs(4), async {
        add_event("4");
    });
}

#[update]
fn schedule_n_timers(n: u32) {
    for i in 0..n {
        ic_cdk_timers::set_timer(Duration::from_nanos(i.into()), async move {
            EXECUTED_TIMERS.fetch_add(1, Ordering::Relaxed);
        });
    }
}

#[query]
fn executed_timers() -> u32 {
    EXECUTED_TIMERS.load(Ordering::Relaxed)
}

#[update]
fn schedule_long() {
    let id = set_timer(Duration::from_secs(9), async { add_event("long") });
    LONG.with(|long| long.set(id));
}

#[update]
fn set_self_cancelling_timer() {
    let id = set_timer(Duration::from_secs(0), async {
        cancel_long();
        add_event("timer cancelled self");
    });
    LONG.with(|long| long.set(id));
}

#[update]
fn cancel_long() {
    LONG.with(|long| clear_timer(long.get()));
}

#[update]
fn start_repeating() {
    let id = set_timer_interval(Duration::from_secs(1), async || {
        add_event("repeat");
    });
    REPEATING.with(|repeating| repeating.set(id));
}

#[update]
fn start_repeating_async() {
    let id = set_timer_interval(Duration::from_secs(1), async || {
        Call::bounded_wait(canister_self(), "add_event_method")
            .with_arg("repeat")
            .await
            .unwrap();
    });
    REPEATING.with(|repeating| repeating.set(id));
}

#[update]
fn start_repeating_serial() {
    let id = ic_cdk_timers::set_timer_interval_serial(Duration::from_secs(1), async || {
        Call::bounded_wait(canister_self(), "add_event_method")
            .with_arg("repeat serial")
            .await
            .unwrap();
        // best way of sleeping is a mocked http outcall
        ic_cdk::management_canister::http_request_with_closure(
            &HttpRequestArgs {
                url: "http://mock".to_string(),
                method: HttpMethod::GET,
                headers: vec![],
                body: None,
                max_response_bytes: None,
                transform: None,
                is_replicated: None,
            },
            |resp| resp,
        )
        .await
        .unwrap();
    });
    REPEATING.with(|repeating| repeating.set(id));
}

#[update]
fn set_self_cancelling_periodic_timer() {
    let id = set_timer_interval(Duration::from_secs(1), async || {
        stop_repeating();
        add_event("periodic timer cancelled self");
    });
    REPEATING.with(|repeating| repeating.set(id));
}

#[update]
fn stop_repeating() {
    REPEATING.with(|repeating| clear_timer(repeating.get()));
}

fn add_event(event: &str) {
    EVENTS.with(|events| events.borrow_mut().push(event.to_string()));
}

#[update]
fn global_timer_set(timestamp: u64) -> u64 {
    ic_cdk::api::global_timer_set(timestamp)
}

#[update]
fn add_event_method(name: &str) {
    add_event(&format!("method {name}"));
}

#[update]
fn async_await() {
    set_timer(Duration::from_secs(1), async {
        add_event("1");
        Call::bounded_wait(canister_self(), "add_event_method")
            .with_arg("outer")
            .await
            .unwrap();
        add_event("2");
        spawn(async {
            Call::bounded_wait(canister_self(), "add_event_method")
                .with_arg("spawned")
                .await
                .unwrap();
        });
        let futs = FuturesUnordered::new();
        for _ in 0..3 {
            futs.push(async move {
                Call::bounded_wait(canister_self(), "add_event_method")
                    .with_arg("concurrent")
                    .await
                    .unwrap();
            });
        }
        futs.collect::<()>().await;
    });
    add_event("0")
}

fn main() {}
