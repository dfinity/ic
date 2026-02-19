use pin_project::pin_project;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;
use tower_layer::Layer;

/// Convert error of a service into another type, where the conversion does *not* fail.
///
/// This [`Layer`] produces instances of the [`ConvertError`] service.
///
/// [`Layer`]: tower::Layer
#[derive(Debug)]
pub struct ConvertErrorLayer<E> {
    _marker: PhantomData<E>,
}

impl<E> ConvertErrorLayer<E> {
    /// Returns a new [`ConvertErrorLayer`]
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<E> Default for ConvertErrorLayer<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> Clone for ConvertErrorLayer<E> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
        }
    }
}

/// Convert the inner service error to another type, where the conversion does *not* fail.
#[derive(Debug)]
pub struct ConvertError<S, E> {
    inner: S,
    _marker: PhantomData<E>,
}

impl<S: Clone, E> Clone for ConvertError<S, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _marker: self._marker,
        }
    }
}

impl<S, E> Layer<S> for ConvertErrorLayer<E> {
    type Service = ConvertError<S, E>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<S, Request, Error, NewError> Service<Request> for ConvertError<S, NewError>
where
    S: Service<Request, Error = Error>,
    Error: Into<NewError>,
{
    type Response = S::Response;
    type Error = NewError;
    type Future = ResponseFuture<S::Future, NewError>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        ResponseFuture {
            response_future: self.inner.call(req),
            _marker: PhantomData,
        }
    }
}

#[pin_project]
pub struct ResponseFuture<F, NewError> {
    #[pin]
    response_future: F,
    _marker: PhantomData<NewError>,
}

impl<F, Response, Error, NewError> Future for ResponseFuture<F, NewError>
where
    F: Future<Output = Result<Response, Error>>,
    Error: Into<NewError>,
{
    type Output = Result<Response, NewError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result_fut = this.response_future.poll(cx);
        match result_fut {
            Poll::Ready(result) => match result {
                Ok(response) => Poll::Ready(Ok(response)),
                Err(e) => Poll::Ready(Err(e.into())),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}
