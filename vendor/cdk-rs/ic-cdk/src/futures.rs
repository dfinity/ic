//! Functions relating to the async executor.
//!
//! ## Running async tasks
//!
//! Most async tasks can be run just by changing your canister entry point to `async`:
//!
//! ```
//! # use ic_cdk::update;
//! # async fn some_other_async_fn() {}
//! #[update]
//! async fn foo() {
//!     some_other_async_fn().await;
//! }
//! ```
//!
//! To run async tasks in the *background*, however, use [`spawn`]:
//!
//! ```
//! # use ic_cdk::{update, futures::spawn};
//! # async fn some_other_async_fn() {}
//! #[update]
//! async fn foo() {
//!     spawn(async { some_other_async_fn().await; });
//!     // do other stuff
//! }
//! ```
//!
//! The spawned future will not be run at the same time as the remaining code, nor will it run immediately. It will start
//! running while `foo` awaits (or after it ends if it does not await). Unlike some other libraries, `spawn` does not
//! return a join-handle; if you want to await multiple results concurrently, use `futures`' [`join_all`] function.
//!
//! ## Method lifetime
//!
//! The default [`spawn`] function will ensure a task does not outlive the canister method it was spawned in. If
//! the method ends, and the task has `await`s that are not completed yet, it will trap. The method's lifetime lasts until
//! it stops making inter-canister calls. What this means is that any await in a task created with `spawn` should be,
//! or be driven by, an inter-canister call. If you instead await something dependent on a
//! different canister method, or a timer, or similar, it is likely to trap. (This is unlikely to impact you if you
//! don't use any 'remote' futures like channels or signals.)
//!
//! Where a task spawned with [`spawn`] will panic if it outlives the canister method, [`spawn_weak`] will simply
//! cancel the task in such a case, dropping it.
//!
//! Note: for purposes of the executor, each invocation of a repeated [timer] is considered a separate canister method.
//!
//! ## `spawn_migratory`
//!
//! The [`spawn_migratory`] function is a little different. Migratory tasks can outlive the canister method they were
//! spawned in, and will migrate between different canister methods as needed; when awoken, they will resume in whatever
//! context they were awoken in, instead of the context they were originally spawned in. Because they can move around,
//! any functions referencing the current method (i.e. `msg_*`) are unreliable and should not be used from these tasks.
//!
//! "Background" is a tricky subject on the IC. Migratory tasks can only run in the context of a canister message.
//! It takes from that call's instruction limit, which can introduce hidden sources of instruction limit based traps;
//! if that call runs multiple concurrent tasks, state changes made by the migratory task may be observable in between them.
//!
//! Most importantly, a migratory task must never trap. When it traps, it will cancel (see below) the execution of the call
//! whose context it's in, even though that call didn't do anything wrong, and it may not undo whatever caused it to trap,
//! meaning the canister could end up bricked.
//!
//! ## Automatic cancellation
//!
//! Asynchronous tasks can be *canceled*, meaning that a partially completed function will halt at an
//! `await` point, never complete, and drop its local variables as though it had returned. Cancellation
//! (not counting [`spawn_weak`]) is caused by panics and traps: if an async function panics, time will be rewound to the
//! previous await as though the code since then never ran, and then the task will be canceled.
//!
//! When a protected task traps, *all* protected tasks in the method will be canceled, as well as any pending migratory tasks.
//! The system cannot know exactly which task panicked, so a conservatively large 'blast radius' is assumed.
//!
//! Use panics sparingly in async functions after the first await, and beware system functions that trap
//! (which is most of them in the right context). Make atomic transactions between awaits wherever
//! possible, and use [`scopeguard`] or a [`Drop`] impl for any cleanup functions that must run no matter what.
//! If an await cannot be removed from the middle of a transaction, and it must be rolled back if it fails,
//! [`is_recovering_from_trap`] can be used to detect when the task is being automatically canceled.
//!
//! [`scopeguard`]: https://docs.rs/scopeguard
//! [`join_all`]: https://docs.rs/futures/latest/futures/future/fn.join_all.html
//! [timer]: https://docs.rs/ic-cdk-timers
//! [`caller`]: crate::api::caller
//! [`in_replicated_execution`]: crate::api::in_replicated_execution
//! [`canister_self`]: crate::api::canister_self

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

pub mod internals;

/// Spawn a protected asynchronous task to run during the current canister method.
///
/// The task will panic if it outlives the canister method. To cancel it instead, use [`spawn_weak`].
pub fn spawn<F: 'static + Future<Output = ()>>(future: F) {
    pin_project_lite::pin_project! {
        struct ProtectedTask<F> {
            #[pin]
            future: F,
            completed: bool,
        }
        impl<F> PinnedDrop for ProtectedTask<F> {
            #[track_caller]
            fn drop(this: Pin<&mut Self>) {
                if !this.completed && !ic_cdk_executor::is_recovering_from_trap() {
                    panic!("protected task outlived its canister method (did you mean to use spawn_weak or spawn_migratory?)")
                }
            }
        }
    }
    impl<F> Future for ProtectedTask<F>
    where
        F: Future<Output = ()>,
    {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.project();
            let res = this.future.poll(cx);
            if res.is_ready() {
                *this.completed = true;
            }
            res
        }
    }
    ic_cdk_executor::spawn_protected(ProtectedTask {
        future,
        completed: false,
    });
}

/// Spawn a weak asynchronous task to run during the current canister method.
///
/// If the task outlives the canister method, it will be dropped.
pub fn spawn_weak<F: 'static + Future<Output = ()>>(future: F) {
    ic_cdk_executor::spawn_protected(future);
}

/// Spawn an asynchronous task that can outlive the current canister method.
pub fn spawn_migratory<F: 'static + Future<Output = ()>>(future: F) {
    ic_cdk_executor::spawn_migratory(future);
}

/// Tells you whether the current async fn is being canceled due to a trap/panic.
///
/// In a destructor, `is_recovering_from_trap` serves the same purpose as
/// [`std::thread::panicking`] - it tells you whether the destructor is executing *because* of a trap,
/// as opposed to just because the scope was exited, so you could e.g. implement mutex poisoning.
///
/// For information about when and how this occurs, see [the module docs](self).
pub fn is_recovering_from_trap() -> bool {
    ic_cdk_executor::is_recovering_from_trap()
}

/// Like `spawn`, but preserves the code ordering behavior of `ic-cdk` 0.17 and before.
///
/// Namely, the spawned future will start executing immediately, with control returning to the surrounding code
/// after the first `await`.
pub fn spawn_017_compat<F: 'static + Future<Output = ()>>(fut: F) {
    struct DummyWaker(AtomicBool);
    impl Wake for DummyWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    // Emulated behavior: A spawned future is polled once immediately, then backgrounded and run at a normal pace.
    // We poll it once with an unimplemented waker, then spawn it, which will poll it again with the real waker.
    // In a correctly implemented future, this second poll should overwrite the fake waker with the real one.
    // If the `poll` function calls `wake`, call it again until it is 'really' pending.
    let mut pin = Box::pin(fut);
    loop {
        let dummy = Arc::new(DummyWaker(AtomicBool::new(false)));
        let poll = pin
            .as_mut()
            .poll(&mut Context::from_waker(&Waker::from(dummy.clone())));
        match poll {
            Poll::Ready(()) => break,
            Poll::Pending => {
                if dummy.0.load(Ordering::SeqCst) {
                    continue;
                } else {
                    spawn(pin);
                    break;
                }
            }
        }
    }
}
