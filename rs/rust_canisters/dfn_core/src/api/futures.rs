//! This module contains all mechanisms required to enable asynchronous
//! programming in Rust, based on native async Rust capabilities:
//!
//!  - the future returned by the asynchronous System API call, and
//!  - the kickstarting/waker implementations to advance top level futures on
//!    every inter-canister callback call.

use std::{
    cell::{Cell, RefCell, RefMut},
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

thread_local! {
    static CURRENT_TOP_LEVEL_FUTURE: Cell<*mut TopLevelFuture> =
        Cell::new(std::ptr::null_mut::<TopLevelFuture>());
}

/// This structure holds a future passed to the spawn() function and metadata
/// required for cleanup.
pub(crate) struct TopLevelFuture {
    // The future passed to spawn() function.
    future: Pin<Box<dyn Future<Output = ()>>>,
    // Number of strong references to this top-level future.
    ref_count: u32,
}

impl TopLevelFuture {
    /// Increments weak reference count.
    pub unsafe fn acquire(p: *mut TopLevelFuture) {
        (*p).ref_count += 1;
    }

    /// Decrements weak reference count.
    pub unsafe fn release(p: *mut TopLevelFuture) {
        (*p).ref_count -= 1;
        if (*p).ref_count == 0 {
            drop_top_level_future(p);
        }
    }

    /// Drops the top-level future if there are is exactly one pending calls
    /// that can resolve it. This should only be called from call cleanup()
    /// because the future should normally be deleted by the waker when it's
    /// ready.
    pub unsafe fn drop_if_last_reference(p: *mut TopLevelFuture) {
        if (*p).ref_count == 1 {
            Self::release(p)
        }
    }
}

/// Returns the pointer to the current top-level future.
pub(crate) fn current_top_level_future() -> *mut TopLevelFuture {
    CURRENT_TOP_LEVEL_FUTURE.with(|p| p.get())
}

/// Sets the pointer to the current top-level future.
fn set_top_level_future(ptr: *mut TopLevelFuture) {
    CURRENT_TOP_LEVEL_FUTURE.with(|p| {
        p.set(ptr);
    });
}

/// Deletes a top level-future.
unsafe fn drop_top_level_future(ptr: *mut TopLevelFuture) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

struct TopLevelFutureGuard(*mut TopLevelFuture);
impl TopLevelFutureGuard {
    pub fn new(p: *mut TopLevelFuture) -> Self {
        let old = current_top_level_future();
        set_top_level_future(p);
        Self(old)
    }
}

impl Drop for TopLevelFutureGuard {
    fn drop(&mut self) {
        set_top_level_future(self.0);
    }
}

/// A reference counter wrapper we use with the CallFuture.
/// This is required, because the future we return from the `call` method can
/// either have two owners (the callback closure and the canister runtime) if
/// the underlying system call succeeded, or just one (the canister runtime) it
/// the system call failed.
pub struct RefCounted<T>(Rc<RefCell<T>>);

/// In order to be able to have an async method that returns the
/// result of a call to another canister, we need that result to
/// be Send + Sync, but Rc and RefCell are not. Since inside
/// a canister there isn't actual concurrent access to the referenced
/// cell or the reference counted container, it is safe to force
/// these to be Send/Sync.
unsafe impl<T> Send for RefCounted<T> {}
unsafe impl<T> Sync for RefCounted<T> {}

impl<T> RefCounted<T> {
    pub fn new(val: T) -> Self {
        RefCounted(Rc::new(RefCell::new(val)))
    }
    pub fn into_raw(self) -> *const RefCell<T> {
        Rc::into_raw(self.0)
    }
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn from_raw(ptr: *const RefCell<T>) -> Self {
        Self(Rc::from_raw(ptr))
    }
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        self.0.borrow_mut()
    }
    pub fn as_ptr(&self) -> *const RefCell<T> {
        self.0.as_ptr() as *const _
    }
}

impl<O, T: Future<Output = O>> Future for RefCounted<T> {
    type Output = O;
    #[allow(unused_mut)]
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { Pin::new_unchecked(&mut *self.0.borrow_mut()) }.poll(ctx)
    }
}

impl<T> Clone for RefCounted<T> {
    fn clone(&self) -> Self {
        RefCounted(Rc::clone(&self.0))
    }
}

/// The result type of the CallFuture.
pub type FutureResult<A> = Result<A, (Option<i32>, String)>;

/// The Future trait implementation, returned by the asynchronous inter-canister
/// call.
pub(super) struct CallFuture {
    /// result of the canister call
    pub result: Option<FutureResult<Vec<u8>>>,
    /// waker (callback)
    pub waker: Option<Waker>,
    /// Top-level future in scope of which poll() was called for the first time.
    pub top_level_future: *mut TopLevelFuture,
}

impl Default for CallFuture {
    fn default() -> Self {
        Self {
            result: None,
            waker: None,
            top_level_future: std::ptr::null_mut(),
        }
    }
}

impl CallFuture {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Future for CallFuture {
    type Output = FutureResult<Vec<u8>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(result) = self.result.take() {
            return Poll::Ready(result);
        } else if self.top_level_future.is_null() {
            // NOTE: we set the top-level future here and not in the constructor
            // because the future can be constructed in one context but actually
            // polled in a different one, like in spawn(call()).
            let top_level_future_ptr = current_top_level_future();
            unsafe {
                TopLevelFuture::acquire(top_level_future_ptr);
            }
            self.top_level_future = top_level_future_ptr;
        }
        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Spawns a future running concurrently with the caller.
///
/// Note: the main purpose of this function is to kick-start top-level canister
/// async method calls.
pub fn spawn<F: 'static + Future<Output = ()>>(future: F) {
    let top_level_future = Box::new(TopLevelFuture {
        future: Box::pin(future),
        ref_count: 1,
    });

    let top_level_future_ptr = Box::into_raw(top_level_future);
    let _guard = TopLevelFutureGuard::new(top_level_future_ptr);

    if let Poll::Ready(_) = unsafe {
        (*top_level_future_ptr)
            .future
            .as_mut()
            .poll(&mut Context::from_waker(&waker::waker(
                top_level_future_ptr as *const (),
            )))
    } {
        unsafe {
            TopLevelFuture::release(top_level_future_ptr);
        }
    }
}

// This module contains the implementation of a waker we're using for waking
// top-level futures (the ones returned by canister methods). The waker waits
// for the future to become ready and deletes it afterwards.
mod waker {
    use super::*;
    use std::task::{RawWaker, RawWakerVTable, Waker};

    static MY_VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

    fn raw_waker(ptr: *const ()) -> RawWaker {
        RawWaker::new(ptr, &MY_VTABLE)
    }

    fn clone(ptr: *const ()) -> RawWaker {
        raw_waker(ptr)
    }

    // Our waker will be called only if one of the response callbacks is triggered.
    // Then, the waker will restore the future from the pointer we passed into the
    // waker inside the `kickstart` method and poll the future again. If the future
    // is pending, we leave it on the heap. If it's ready, we deallocate the
    // pointer.
    unsafe fn wake(ptr: *const ()) {
        let future_ptr = ptr as *mut TopLevelFuture;
        let _guard = TopLevelFutureGuard::new(future_ptr);

        if let Poll::Ready(_) = (*future_ptr)
            .future
            .as_mut()
            .poll(&mut Context::from_waker(&waker::waker(ptr)))
        {
            TopLevelFuture::release(future_ptr);
        }
    }

    fn wake_by_ref(_: *const ()) {}

    fn drop(_: *const ()) {}

    pub fn waker(ptr: *const ()) -> Waker {
        unsafe { Waker::from_raw(raw_waker(ptr)) }
    }
}
