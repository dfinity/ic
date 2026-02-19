use crate::convert::{Convert, Filter};
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;
use tower_layer::Layer;

/// Convert responses of a service into another type, where the conversion may fail.
///
/// This [`Layer`] produces instances of the [`ConvertResponse`] service.
///
/// [`Layer`]: tower::Layer
#[derive(Debug, Clone)]
pub struct ConvertResponseLayer<C> {
    converter: C,
}

impl<C> ConvertResponseLayer<C> {
    /// Creates a new [`ConvertResponseLayer`]
    pub fn new(converter: C) -> Self {
        Self { converter }
    }
}

/// Convert the inner service response to another type, where the conversion may fail.
#[derive(Debug, Clone)]
pub struct ConvertResponse<S, C> {
    inner: S,
    converter: C,
}

impl<S, C: Clone> Layer<S> for ConvertResponseLayer<C> {
    type Service = ConvertResponse<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            converter: self.converter.clone(),
        }
    }
}

impl<S, Request, Response, NewResponse, Converter> Service<Request>
    for ConvertResponse<S, Converter>
where
    S: Service<Request, Response = Response>,
    Converter: Convert<Response, Output = NewResponse> + Clone,
    Converter::Error: Into<S::Error>,
{
    type Response = NewResponse;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, Converter>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        ResponseFuture {
            response_future: self.inner.call(req),
            converter: self.converter.clone(),
        }
    }
}

#[pin_project]
pub struct ResponseFuture<F, Converter> {
    #[pin]
    response_future: F,
    converter: Converter,
}

impl<F, Filter, Response, NewResponse, Error> Future for ResponseFuture<F, Filter>
where
    F: Future<Output = Result<Response, Error>>,
    Filter: Convert<Response, Output = NewResponse>,
    Filter::Error: Into<Error>,
{
    type Output = Result<NewResponse, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result_fut = this.response_future.poll(cx);
        match result_fut {
            Poll::Ready(result) => match result {
                Ok(response) => {
                    Poll::Ready(this.converter.try_convert(response).map_err(Into::into))
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Create a response filter per request.
///
/// This is useful when response validation depends on some request data.
pub trait CreateResponseFilter<Request, Response> {
    /// The response filter produced.
    type Filter: Filter<Response, Error = Self::Error>;
    /// The type of error returned by the filter.
    type Error;

    /// Return a new filter for this request.
    fn create_filter(&self, request: &Request) -> Self::Filter;
}

/// Filter responses of a service based on the corresponding request.
///
/// This [`Layer`] produces instances of the [`FilterResponse`] service.
///
/// [`Layer`]: tower::Layer
#[derive(Debug, Clone)]
pub struct CreateResponseFilterLayer<C> {
    create_filter: C,
}

impl<C> CreateResponseFilterLayer<C> {
    /// Create a new [`CreateResponseFilterLayer`]
    pub fn new(create_filter: C) -> Self {
        Self { create_filter }
    }
}

impl<S, C: Clone> Layer<S> for CreateResponseFilterLayer<C> {
    type Service = FilterResponse<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        FilterResponse {
            inner,
            create_filter: self.create_filter.clone(),
        }
    }
}

/// Filter the inner service response based on the original request that lead to that response.
#[derive(Debug, Clone)]
pub struct FilterResponse<S, C> {
    inner: S,
    create_filter: C,
}

impl<S, Request, Response, C> Service<Request> for FilterResponse<S, C>
where
    S: Service<Request, Response = Response>,
    C: CreateResponseFilter<Request, Response>,
    C::Error: Into<S::Error>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, C::Filter>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let filter = self.create_filter.create_filter(&req);
        ResponseFuture {
            response_future: self.inner.call(req),
            converter: filter,
        }
    }
}
