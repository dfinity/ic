use crate::{common::make_response, MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES};
use futures_util::StreamExt;
use hyper::{body::HttpBody, Body, Response};
use ic_types::canonical_error::{out_of_range_error, unknown_error, CanonicalError};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::timeout;
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

async fn receive_body_without_timeout(
    mut body: Body,
    max_request_body_size_bytes: usize,
) -> Result<Vec<u8>, CanonicalError> {
    let body_size_hint = body.size_hint().lower() as usize;
    if body_size_hint > max_request_body_size_bytes {
        return Err(out_of_range_error(format!(
            "The request body is bigger than {} bytes.",
            max_request_body_size_bytes
        )));
    }
    let mut received_body = Vec::<u8>::with_capacity(body_size_hint);
    while let Some(chunk) = body.next().await {
        match chunk {
            Err(err) => {
                return Err(unknown_error(format!(
                    "Unexpected error while reading request: {}",
                    err
                )));
            }
            Ok(bytes) => {
                if received_body.len() + bytes.len() > max_request_body_size_bytes {
                    return Err(out_of_range_error(format!(
                        "The request body is bigger than {} bytes.",
                        max_request_body_size_bytes
                    )));
                }
                received_body.append(&mut bytes.to_vec());
            }
        }
    }
    Ok(received_body)
}

async fn receive_body(
    body: Body,
    max_request_receive_duration: Duration,
    max_request_body_size_bytes: usize,
) -> Result<Vec<u8>, CanonicalError> {
    match timeout(
        max_request_receive_duration,
        receive_body_without_timeout(body, max_request_body_size_bytes),
    )
    .await
    {
        Ok(res) => res,
        Err(_err) => Err(out_of_range_error(format!(
            "The request body was not received within {:?} seconds.",
            max_request_receive_duration
        ))),
    }
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
                Err(err) => Ok(make_response(err)),
                Ok(body) => inner.call(body).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    #[tokio::test]
    async fn test_succesfully_parse_small_body() {
        let (mut sender, body) = Body::channel();
        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // We need to drop the channel so the service will know there aren't any new
        // chunks. If we remove this line the test should run forever.
        std::mem::drop(sender);
        assert_eq!(
            receive_body(body, MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES)
                .await
                .ok(),
            Some(Vec::<u8>::from("hello world"))
        );
    }

    #[tokio::test]
    async fn test_stop_and_return_error_when_parsing_big_body() {
        let (mut sender, body) = Body::channel();
        let chunk_size: usize = 1024;
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(chunk_size)
            .map(char::from)
            .collect();

        let jh = tokio::task::spawn(async move {
            receive_body(body, MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES).await
        });
        for _i in 0..(MAX_REQUEST_SIZE_BYTES / chunk_size) {
            assert!(sender
                .send_data(bytes::Bytes::from(rand_string.clone()))
                .await
                .is_ok());
        }
        // We are at the limit, so sending an extra byte will succeed and cause the
        // service to yield.
        assert!(sender.send_data(bytes::Bytes::from("a")).await.is_ok());
        let response = jh
            .await
            .unwrap()
            .expect_err("The service must have returned an Err.");
        assert_eq!(
            response,
            out_of_range_error(format!(
                "The request body is bigger than {} bytes.",
                MAX_REQUEST_SIZE_BYTES
            ))
        );
        // Check we can't send more data. The other end of the channel - the body - is
        // dropped.
        assert!(sender
            .send_data(bytes::Bytes::from(rand_string.clone()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_time_out_while_waiting_for_a_single_chunk() {
        let (mut sender, body) = Body::channel();
        let time_to_wait = Duration::from_secs(5);

        let jh = tokio::task::spawn(async move {
            receive_body(body, time_to_wait, MAX_REQUEST_SIZE_BYTES).await
        });

        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // If we drop the sender here the test will fail because parse_body has all the
        // chunks so it won't timeout.
        tokio::time::sleep(time_to_wait + Duration::from_secs(1)).await;
        let response = jh
            .await
            .unwrap()
            .expect_err("parse_body must have returned an Err.");
        assert_eq!(
            response,
            out_of_range_error(format!(
                "The request body was not received within {:?} seconds.",
                time_to_wait
            ))
        );
    }

    #[tokio::test]
    async fn test_time_out_while_waiting_for_many_chunks() {
        let (mut sender, body) = Body::channel();
        let time_to_wait = Duration::from_secs(5);

        let jh = tokio::task::spawn(async move {
            receive_body(body, time_to_wait, MAX_REQUEST_SIZE_BYTES).await
        });

        let num_chunks = 10;
        let mut chunks_sent = 0;
        for _i in 0..num_chunks {
            if sender
                .send_data(bytes::Bytes::from("hello world"))
                .await
                .is_ok()
            {
                chunks_sent += 1;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        std::mem::drop(sender);
        // We expect the sender to fail because the receiver will be closed once we are
        // pass the timeout.
        assert!(chunks_sent < num_chunks);
        assert!(chunks_sent > 1);
        let response = jh
            .await
            .unwrap()
            .expect_err("parse_body must have returned an Err.");
        assert_eq!(
            response,
            out_of_range_error(format!(
                "The request body was not received within {:?} seconds.",
                time_to_wait
            ))
        );
    }
}
