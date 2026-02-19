//! Middleware that adds high level observability (e.g., logging, metrics) to a [`Service`].
//!
//! # Comparison with the `Trace` service of the [`tower_http`] crate.
//! This middleware is strongly inspired by the functionality offered by `Trace`.
//! The reason for not using this middleware directly is it cannot be used inside a canister:
//! 1. It measures the latency of a call by calling
//!    [`Instant::now`](https://github.com/tower-rs/tower-http/blob/469bdac3193ed22da9ea524a454d8cda93ffa0d5/tower-http/src/trace/service.rs#L302),
//!    which will fail when run from a canister.
//! 2. It can deal with streaming responses, which is unnecessary for HTTPs outcalls,
//!    since the response is available to a canister at once. This flexibility brings some complexity
//!    (body can only be fetched asynchronously, end of stream errors, etc.) which is not useful in a canister environment.
//!
//! # Examples
//!
//! To add a basic observability layer, for example tracking the number of request and responses/errors inside a canister:
//!
//! ```rust
//! use canhttp::{IcError, observability::ObservabilityLayer};
//! use ic_cdk::management_canister::{HttpRequestArgs as IcHttpRequest, HttpRequestResult as IcHttpResponse};
//! use tower::{Service, ServiceBuilder, ServiceExt};
//! use std::cell::RefCell;
//!
//! async fn handle(request: IcHttpRequest) -> Result<IcHttpResponse, IcError> {
//!    Ok(IcHttpResponse::default())
//! }
//!
//! #[derive(Clone, Debug, Default, PartialEq, Eq)]
//! pub struct Metrics {
//!     pub num_requests: u64,
//!     pub num_responses: u64,
//!     pub num_errors: u64
//! }
//!
//! thread_local! {
//!     static METRICS: RefCell<Metrics> = RefCell::new(Metrics::default())
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let mut service = ServiceBuilder::new()
//!     .layer(ObservabilityLayer::new()
//!         .on_request(|req: &IcHttpRequest| {
//!             METRICS.with_borrow_mut(|m| m.num_requests += 1);
//!         })
//!         .on_response(|req_data: (), response: &IcHttpResponse| {
//!             METRICS.with_borrow_mut(|m| m.num_responses += 1);
//!         })
//!         .on_error(|req_data: (), response: &IcError| {
//!             METRICS.with_borrow_mut(|m| m.num_errors += 1);
//!         })
//!     )
//!     .service_fn(handle);
//!
//! let request = IcHttpRequest::default();
//!
//! let response = service
//! .ready()
//! .await?
//! .call(request)
//! .await?;
//!
//! let metrics = METRICS.with_borrow(|m| m.clone());
//! assert_eq!(
//!     metrics,
//!     Metrics {
//!         num_requests: 1,
//!         num_responses: 1,
//!         num_errors: 0
//!     }
//!  );
//! # Ok(())
//! # }
//! ```
//!
//! The previous example can be refined by extracting request data (such as the request URL) to observe the responses/errors:
//! ```rust
//! use canhttp::{IcError, observability::ObservabilityLayer};
//! use ic_cdk::management_canister::{HttpRequestArgs as IcHttpRequest, HttpRequestResult as IcHttpResponse};
//! use maplit::btreemap;
//! use tower::{Service, ServiceBuilder, ServiceExt};
//! use std::cell::RefCell;
//! use std::collections::BTreeMap;
//!
//! async fn handle(request: IcHttpRequest) -> Result<IcHttpResponse, IcError> {
//!    Ok(IcHttpResponse::default())
//! }
//!
//! pub type Url = String;
//!
//! #[derive(Clone, Debug, Default, PartialEq, Eq)]
//! pub struct Metrics {
//!     pub num_requests: BTreeMap<Url, u64>,
//!     pub num_responses: BTreeMap<Url, u64>,
//!     pub num_errors: BTreeMap<Url, u64>
//! }
//!
//! thread_local! {
//!     static METRICS: RefCell<Metrics> = RefCell::new(Metrics::default())
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let mut service = ServiceBuilder::new()
//!     .layer(
//!         ObservabilityLayer::new()
//!             .on_request(|req: &IcHttpRequest| {
//!                 METRICS.with_borrow_mut(|m| {
//!                     m.num_requests
//!                         .entry(req.url.clone())
//!                         .and_modify(|c| *c += 1)
//!                         .or_insert(1);
//!                 });
//!                 req.url.clone() //First parameter in on_response/on_error
//!             })
//!             .on_response(|req_data: Url, response: &IcHttpResponse| {
//!                 METRICS.with_borrow_mut(|m| {
//!                     m.num_responses
//!                         .entry(req_data)
//!                         .and_modify(|c| *c += 1)
//!                         .or_insert(1);
//!                 });
//!             })
//!             .on_error(|req_data: Url, response: &IcError| {
//!                 METRICS.with_borrow_mut(|m| {
//!                     m.num_errors
//!                         .entry(req_data)
//!                         .and_modify(|c| *c += 1)
//!                         .or_insert(1);
//!                 });
//!             }),
//!     )
//!     .service_fn(handle);
//!
//! let request = IcHttpRequest {
//!     url: "https://internetcomputer.org/".to_string(),
//!     ..Default::default()
//! };
//!
//! let response = service
//! .ready()
//! .await?
//! .call(request)
//! .await?;
//!
//! let metrics = METRICS.with_borrow(|m| m.clone());
//! assert_eq!(
//!     metrics,
//!     Metrics {
//!         num_requests: btreemap! {"https://internetcomputer.org/".to_string() => 1},
//!         num_responses: btreemap! {"https://internetcomputer.org/".to_string() => 1},
//!         num_errors: btreemap! {}
//!     }
//!  );
//! # Ok(())
//! # }
//! ```
//!
//! [`Service`]: tower::Service
//! [`tower_http`]: https://crates.io/crates/tower-http

use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// [`Layer`] that adds high level observability to a [`Service`].
///
/// See the [module docs](crate::observability) for more details.
///
/// [`Layer`]: tower::Layer
/// [`Service`]: tower::Service
#[derive(Clone, Debug)]
pub struct ObservabilityLayer<OnRequest, OnResponse, OnError> {
    on_request: OnRequest,
    on_response: OnResponse,
    on_error: OnError,
}

impl ObservabilityLayer<(), (), ()> {
    /// Creates a new [`ObservabilityLayer`] that does nothing.
    pub fn new() -> Self {
        Self {
            on_request: (),
            on_response: (),
            on_error: (),
        }
    }
}

impl Default for ObservabilityLayer<(), (), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<OnRequest, OnResponse, OnError> ObservabilityLayer<OnRequest, OnResponse, OnError> {
    /// Customize what to do when a request is received.
    ///
    /// `NewOnRequest` is expected to implement [`RequestObserver`].
    pub fn on_request<NewOnRequest>(
        self,
        new_on_request: NewOnRequest,
    ) -> ObservabilityLayer<NewOnRequest, OnResponse, OnError> {
        ObservabilityLayer {
            on_request: new_on_request,
            on_response: self.on_response,
            on_error: self.on_error,
        }
    }

    /// Customize what to do when a response has been produced.
    ///
    /// `NewOnResponse` is expected to implement [`ResponseObserver`].
    pub fn on_response<NewOnResponse>(
        self,
        new_on_response: NewOnResponse,
    ) -> ObservabilityLayer<OnRequest, NewOnResponse, OnError> {
        ObservabilityLayer {
            on_request: self.on_request,
            on_response: new_on_response,
            on_error: self.on_error,
        }
    }

    /// Customize what to do when an error has been produced.
    ///
    /// `NewOnError` is expected to implement [`ResponseObserver`].
    pub fn on_error<NewOnError>(
        self,
        new_on_error: NewOnError,
    ) -> ObservabilityLayer<OnRequest, OnResponse, NewOnError> {
        ObservabilityLayer {
            on_request: self.on_request,
            on_response: self.on_response,
            on_error: new_on_error,
        }
    }
}

impl<S, OnRequest, OnResponse, OnError> Layer<S>
    for ObservabilityLayer<OnRequest, OnResponse, OnError>
where
    OnRequest: Clone,
    OnResponse: Clone,
    OnError: Clone,
{
    type Service = Observability<S, OnRequest, OnResponse, OnError>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            on_request: self.on_request.clone(),
            on_response: self.on_response.clone(),
            on_error: self.on_error.clone(),
        }
    }
}

/// Middleware that adds high level observability to a [`Service`].
///
/// See the [module docs](crate::observability) for an example.
///
/// [`Service`]: tower::Service
#[derive(Clone, Debug)]
pub struct Observability<S, OnRequest, OnResponse, OnError> {
    inner: S,
    on_request: OnRequest,
    on_response: OnResponse,
    on_error: OnError,
}

impl<S, Request, Response, OnRequest, RequestData, OnResponse, OnError> Service<Request>
    for Observability<S, OnRequest, OnResponse, OnError>
where
    S: Service<Request, Response = Response>,
    OnRequest: RequestObserver<Request, ObservableRequestData = RequestData>,
    OnResponse: ResponseObserver<RequestData, S::Response> + Clone,
    OnError: ResponseObserver<RequestData, S::Error> + Clone,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, RequestData, OnResponse, OnError>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let req_data = self.on_request.observe_request(&req);
        ResponseFuture {
            response_future: self.inner.call(req),
            request_data: Some(req_data),
            on_response: self.on_response.clone(),
            on_error: self.on_error.clone(),
        }
    }
}

/// Trait used to tell [`Observability`] what to do when a request is received.
pub trait RequestObserver<Request> {
    /// Type of data that can be observed from the request (e.g., URL, host, etc.)
    /// when the response will be processed.
    type ObservableRequestData;

    /// Observe the given request and produce observable data based on the request.
    /// This observable data will be passed on to the response observer.
    fn observe_request(&self, request: &Request) -> Self::ObservableRequestData;
}

impl<Request> RequestObserver<Request> for () {
    type ObservableRequestData = ();

    fn observe_request(&self, _request: &Request) -> Self::ObservableRequestData {
        //NOP
    }
}

impl<F, Request, RequestData> RequestObserver<Request> for F
where
    F: Fn(&Request) -> RequestData,
{
    type ObservableRequestData = RequestData;

    fn observe_request(&self, request: &Request) -> Self::ObservableRequestData {
        self(request)
    }
}

/// Trait used to tell [`Observability`] what to do when a response is received.
pub trait ResponseObserver<RequestData, Response> {
    /// Observe the response (typically an instance of [`std::result::Result`]) and the request data produced by a [`RequestObserver`].
    fn observe_response(&self, request_data: RequestData, value: &Response);
}

impl<RequestData, Response> ResponseObserver<RequestData, Response> for () {
    fn observe_response(&self, _request_data: RequestData, _value: &Response) {
        //NOP
    }
}

impl<F, RequestData, Response> ResponseObserver<RequestData, Response> for F
where
    F: Fn(RequestData, &Response),
{
    fn observe_response(&self, request_data: RequestData, value: &Response) {
        self(request_data, value);
    }
}

/// Response future for [`Observability`].
#[pin_project]
pub struct ResponseFuture<F, RequestData, OnResponse, OnError> {
    #[pin]
    response_future: F,
    request_data: Option<RequestData>,
    on_response: OnResponse,
    on_error: OnError,
}

impl<F, RequestData, OnResponse, OnError, Response, Error> Future
    for ResponseFuture<F, RequestData, OnResponse, OnError>
where
    F: Future<Output = Result<Response, Error>>,
    OnResponse: ResponseObserver<RequestData, Response>,
    OnError: ResponseObserver<RequestData, Error>,
{
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result_fut = this.response_future.poll(cx);
        match &result_fut {
            Poll::Ready(result) => {
                let request_data = this.request_data.take().unwrap();
                match result {
                    Ok(response) => {
                        this.on_response.observe_response(request_data, response);
                    }
                    Err(error) => {
                        this.on_error.observe_response(request_data, error);
                    }
                }
            }
            Poll::Pending => {}
        }
        result_fut
    }
}
