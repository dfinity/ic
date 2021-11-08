use ic_types::canonical_error::CanonicalError;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};

pub struct PendingFutureResultInternal<T> {
    pub result: Option<Result<T, CanonicalError>>,
    pub waker: Option<Waker>,
}

pub struct PendingFutureResult<T> {
    pub inner: Arc<Mutex<PendingFutureResultInternal<T>>>,
}

impl<T> PendingFutureResult<T> {
    pub fn weak(&self) -> Weak<Mutex<PendingFutureResultInternal<T>>> {
        Arc::downgrade(&self.inner)
    }

    pub fn from_weak(weak: Weak<Mutex<PendingFutureResultInternal<T>>>) -> Option<Self> {
        let inner = weak.upgrade()?;
        Some(Self { inner })
    }

    pub fn resolve(&self, result: Result<T, CanonicalError>) {
        let mut inner = self.inner.lock().unwrap();
        inner.result = Some(result);
        if let Some(waker) = inner.waker.take() {
            waker.wake();
        }
    }
}

impl<T> Future for PendingFutureResult<T> {
    type Output = Result<T, CanonicalError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut inner = self.inner.lock().unwrap();
        match inner.result.take() {
            Some(result) => Poll::Ready(result),
            None => {
                inner.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}
