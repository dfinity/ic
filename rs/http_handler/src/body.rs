use crate::{
    common::make_plaintext_response, MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES,
};
use hyper::{Body, Response, StatusCode};
use ic_async_utils::{receive_body, BodyReceiveError};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Layer, Service};

pub(crate) struct BodyReceiverLayer {
    max_request_receive_duration: Duration,
    max_request_body_size_bytes: usize,
}

impl BodyReceiverLayer {
    pub(crate) fn new(
        max_request_receive_duration: Duration,
        max_request_body_size_bytes: usize,
    ) -> Self {
        Self {
            max_request_receive_duration,
            max_request_body_size_bytes,
        }
    }
}

impl Default for BodyReceiverLayer {
    fn default() -> Self {
        BodyReceiverLayer::new(MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES)
    }
}

impl<S> Layer<S> for BodyReceiverLayer {
    type Service = BodyReceiverService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyReceiverService {
            max_request_receive_duration: self.max_request_receive_duration,
            max_request_body_size_bytes: self.max_request_body_size_bytes,
            inner,
        }
    }
}

#[derive(Clone)]
pub(crate) struct BodyReceiverService<S> {
    max_request_receive_duration: Duration,
    max_request_body_size_bytes: usize,
    inner: S,
}

impl<S, E> Service<Body> for BodyReceiverService<S>
where
    S: Service<
            Vec<u8>,
            Response = Response<Body>,
            Error = E,
            Future = Pin<Box<dyn Future<Output = Result<Response<Body>, E>> + Send>>,
        > + Clone
        + Send
        + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, body: Body) -> Self::Future {
        let inner = self.inner.clone();

        // In case the inner service has state that's driven to readiness and
        // not tracked by clones (such as `Buffer`), pass the version we have
        // already called `poll_ready` on into the future, and leave its clone
        // behind.
        //
        // The types implementing the Service trait are not necessary thread-safe.
        // So the unless the caller is sure that the service implementation is
        // thread-safe we must make sure 'poll_ready' is always called before 'call'
        // on the same object. Hence if 'poll_ready' is called and not tracked by
        // the 'Clone' implementation the following sequence of events may panic.
        //
        //  s1.call_ready()
        //  s2 = s1.clone()
        //  s2.call()
        let mut inner = std::mem::replace(&mut self.inner, inner);

        let max_request_receive_duration = self.max_request_receive_duration;
        let max_request_body_size_bytes = self.max_request_body_size_bytes;
        Box::pin(async move {
            match receive_body(
                body,
                max_request_receive_duration,
                max_request_body_size_bytes,
            )
            .await
            {
                Err(err) => match err {
                    BodyReceiveError::TooLarge(e) => {
                        Ok(make_plaintext_response(StatusCode::PAYLOAD_TOO_LARGE, e))
                    }
                    BodyReceiveError::Timeout(e) => {
                        Ok(make_plaintext_response(StatusCode::REQUEST_TIMEOUT, e))
                    }
                    BodyReceiveError::Unavailable(e) => {
                        Ok(make_plaintext_response(StatusCode::BAD_REQUEST, e))
                    }
                },
                Ok(body) => inner.call(body).await,
            }
        })
    }
}
