use futures_util::StreamExt;
use hyper::Body;
use ic_types::canonical_error::{out_of_range_error, unknown_error, CanonicalError};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::timeout;
use tower::Service;

#[derive(Clone)]
pub(crate) struct BodyParserService {
    max_request_receive_duration: Duration,
    max_request_body_size_bytes: usize,
}

impl BodyParserService {
    pub(crate) fn new(
        max_request_body_size_bytes: usize,
        max_request_receive_duration: Duration,
    ) -> Self {
        Self {
            max_request_receive_duration,
            max_request_body_size_bytes,
        }
    }
}

impl Service<Body> for BodyParserService {
    type Response = Vec<u8>;
    type Error = CanonicalError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut body: Body) -> Self::Future {
        let max_request_receive_duration = self.max_request_receive_duration;
        let max_request_body_size_bytes = self.max_request_body_size_bytes;
        Box::pin(async move {
            // Read "content-length" bytes
            // Parse the body only when needed.
            let mut parsed_body = Vec::<u8>::new();
            // Timeout when we are waiting for the next chunk because this wait depends on
            // the user.
            loop {
                match timeout(max_request_receive_duration, body.next()).await {
                    Ok(chunk_option) => match chunk_option {
                        Some(chunk) => match chunk {
                            Err(err) => {
                                return Err(unknown_error(
                                    format!("Unexpected error while reading request: {}", err)
                                        .as_str(),
                                ));
                            }
                            Ok(bytes) => {
                                if parsed_body.len() + bytes.len() > max_request_body_size_bytes {
                                    return Err(out_of_range_error(
                                        format!(
                                            "The request body is bigger than {} bytes.",
                                            max_request_body_size_bytes
                                        )
                                        .as_str(),
                                    ));
                                }
                                parsed_body.append(&mut bytes.to_vec());
                            }
                        },
                        // End of stream.
                        None => {
                            return Ok(parsed_body);
                        }
                    },
                    Err(_err) => {
                        return Err(out_of_range_error(&format!(
                            "The request body was not received within {:?} seconds.",
                            max_request_receive_duration
                        )));
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES};
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_succesfully_parse_small_body() {
        let (mut sender, body) = Body::channel();
        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // We need to drop the channel so the service will know there aren't any new
        // chunks. If we remove this line the test should run forever.
        let body_parser =
            BodyParserService::new(MAX_REQUEST_SIZE_BYTES, MAX_REQUEST_RECEIVE_DURATION);
        std::mem::drop(sender);
        assert_eq!(
            body_parser.oneshot(body).await.ok(),
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
            BodyParserService::new(MAX_REQUEST_SIZE_BYTES, MAX_REQUEST_RECEIVE_DURATION)
                .oneshot(body)
                .await
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
            out_of_range_error(&format!(
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
    async fn test_time_out_during_body_parsing() {
        let (mut sender, body) = Body::channel();
        let time_to_wait = Duration::from_secs(5);

        let jh = tokio::task::spawn(async move {
            BodyParserService::new(MAX_REQUEST_SIZE_BYTES, time_to_wait)
                .oneshot(body)
                .await
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
            out_of_range_error(&format!(
                "The request body was not received within {:?} seconds.",
                time_to_wait
            ))
        );
    }
}
