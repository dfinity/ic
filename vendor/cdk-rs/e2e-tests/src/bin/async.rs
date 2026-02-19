use async_channel::{Receiver, Sender, TryRecvError};
use candid::Principal;
use core::panic;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ic_cdk::call::Call;
use ic_cdk::futures::{spawn, spawn_017_compat, spawn_migratory};
use ic_cdk::{query, update};
use lazy_static::lazy_static;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::RwLock;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

lazy_static! {
    static ref RESOURCE: RwLock<u64> = RwLock::new(0);
    static ref NOTIFICATIONS_RECEIVED: RwLock<u64> = RwLock::new(0);
    static ref CHANNEL: (Sender<()>, Receiver<()>) = async_channel::unbounded();
}

#[query]
fn inc(n: u64) -> u64 {
    n + 1
}

#[query]
fn get_locked_resource() -> u64 {
    let lock = RESOURCE
        .read()
        .unwrap_or_else(|_| ic_cdk::api::trap("failed to obtain a read lock"));
    *lock
}

#[update]
#[allow(clippy::await_holding_lock)]
async fn panic_after_await() {
    let mut lock = RESOURCE
        .write()
        .unwrap_or_else(|_| ic_cdk::api::trap("failed to obtain a write lock"));
    *lock += 1;
    let value = *lock;
    // Do not drop the lock before the await point.

    Call::bounded_wait(ic_cdk::api::canister_self(), "inc")
        .with_arg(value)
        .await
        .unwrap();
    ic_cdk::api::trap("Goodbye, cruel world.")
}

#[update]
#[allow(clippy::await_holding_lock)]
async fn panic_after_await_in_spawn_migratory() {
    spawn_migratory(async move {
        CHANNEL.1.recv().await.unwrap();
        let mut lock = RESOURCE
            .write()
            .unwrap_or_else(|_| ic_cdk::api::trap("failed to obtain a write lock"));
        *lock += 1;
        let value = *lock;
        Call::bounded_wait(ic_cdk::api::canister_self(), "inc")
            .with_arg(value)
            .await
            .unwrap();
        panic!("Goodbye, cruel world.");
    });
}

#[update]
async fn migratory_resume() {
    CHANNEL.0.send(()).await.unwrap();
}

#[update]
#[allow(clippy::await_holding_lock)]
async fn panic_twice() {
    let _lock = RESOURCE.write().unwrap();
    let fut1 = async_then_panic();
    let fut2 = async_then_panic();
    futures::future::join_all([fut1, fut2]).await;
}

async fn async_then_panic() {
    Call::bounded_wait(ic_cdk::api::canister_self(), "on_notify")
        .await
        .unwrap();
    panic!();
}

#[update]
async fn panic_then_continue() {
    let cell = Rc::new(Cell::new(true));
    let fut1 = async_then_panic_if_first(cell.clone());
    let fut2 = async_then_panic_if_first(cell);
    let mut coll = FuturesUnordered::from_iter([fut1, fut2]);
    while (coll.next().await).is_some() {}
}

async fn async_then_panic_if_first(cell: Rc<Cell<bool>>) {
    Call::bounded_wait(ic_cdk::api::canister_self(), "on_notify")
        .await
        .unwrap();
    if cell.replace(false) {
        panic!("first");
    }
}

#[query]
fn notifications_received() -> u64 {
    *NOTIFICATIONS_RECEIVED.read().unwrap()
}

#[update]
fn on_notify() {
    *NOTIFICATIONS_RECEIVED.write().unwrap() += 1;
}

#[update]
fn notify(whom: Principal, method: String) {
    Call::bounded_wait(whom, method.as_str())
        .oneway()
        .unwrap_or_else(|reject| {
            ic_cdk::api::trap(format!(
                "failed to notify (callee={whom}, method={method}): {reject:?}"
            ))
        });
}

#[query]
fn greet(name: String) -> String {
    format!("Hello, {name}")
}

#[query(composite = true)]
async fn greet_self(greeter: Principal) -> String {
    Call::bounded_wait(greeter, "greet")
        .with_arg("myself")
        .await
        .unwrap()
        .candid()
        .unwrap()
}

#[update]
async fn invalid_reply_payload_does_not_trap() -> String {
    // We're decoding an integer instead of a string, decoding must fail.
    let result = Call::bounded_wait(ic_cdk::api::canister_self(), "greet")
        .with_arg("World")
        .await
        .unwrap()
        .candid::<u64>();

    match result {
        Ok(_) => ic_cdk::api::trap("expected the decoding to fail"),
        Err(e) => format!("handled decoding error gracefully: {e}"),
    }
}

#[update]
async fn await_channel_completion() -> String {
    let (tx, rx) = async_channel::bounded(1);
    ic_cdk::futures::spawn(async move {
        let greeting: String = Call::bounded_wait(ic_cdk::api::canister_self(), "greet")
            .with_arg("myself")
            .await
            .unwrap()
            .candid()
            .unwrap();
        tx.send(greeting).await.unwrap();
    });
    let greeting = rx.recv().await;
    greeting.unwrap()
}

#[update]
async fn schedule_on_panic() {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            for _ in 0..3 {
                ic_cdk::futures::spawn(async {
                    on_notify();
                });
            }
        }
    }
    let _guard = Guard;
    Call::bounded_wait(ic_cdk::api::canister_self(), "on_notify")
        .await
        .unwrap();
    ic_cdk::trap("testing");
}

#[update]
async fn timer_on_panic() {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            for _ in 0..3 {
                ic_cdk_timers::set_timer(Duration::ZERO, async {
                    on_notify();
                });
            }
        }
    }
    let _guard = Guard;
    Call::bounded_wait(ic_cdk::api::canister_self(), "on_notify")
        .await
        .unwrap();
    ic_cdk::trap("testing");
}

#[update]
fn spawn_ordering() {
    let notifs = notifications_received();
    spawn_017_compat(async { on_notify() });
    assert_eq!(
        notifications_received(),
        notifs + 1,
        "spawn_017_compat should run immediately"
    );
    spawn(async { on_notify() });
    assert_eq!(notifications_received(), notifs + 1, "spawn should be lazy");
}

#[update]
async fn spawn_protected_with_distant_waker() {
    let caller = ic_cdk::api::msg_caller();
    thread_local! {
        static WAKER: Cell<Option<Waker>> = const { Cell::new(None) };
    }
    struct RemoteFuture(bool);
    impl Future for RemoteFuture {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.0 {
                Poll::Ready(())
            } else {
                WAKER.set(Some(cx.waker().clone()));
                self.as_mut().0 = true;
                Poll::Pending
            }
        }
    }
    // despite the waker being awoken from a timer...
    ic_cdk_timers::set_timer(Duration::from_secs(0), async {
        WAKER.take().unwrap().wake();
    });
    let (tx, rx) = async_channel::bounded(1);
    spawn(async move {
        RemoteFuture(false).await;
        // ... the msg data should still match the original task
        tx.send(ic_cdk::api::msg_caller()).await.unwrap();
    });
    loop {
        match rx.try_recv() {
            Ok(value) => {
                assert_eq!(value, caller);
                break;
            }
            Err(TryRecvError::Empty) => {
                // make calls to keep the method alive while the background task runs
                Call::bounded_wait(ic_cdk::api::canister_self(), "on_notify")
                    .await
                    .unwrap();
            }
            Err(TryRecvError::Closed) => panic!("channel closed unexpectedly"),
        }
    }
}

#[update]
async fn stalled_protected_task() {
    spawn(std::future::pending());
    Call::bounded_wait(ic_cdk::api::canister_self(), "on_notify")
        .await
        .unwrap();
}

#[update]
async fn protected_from_migratory() {
    spawn_migratory(async {
        spawn(async {
            on_notify();
        });
    });
}

fn main() {}
