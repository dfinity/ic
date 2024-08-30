/// This module contains custom code for receiving bodies and adding timeouts.
/// We would ideally use middleware such as `tower_http::limit::RequestBodyLimitLayer`,
/// but the current implementation has poor usability as it changes the request body type.
/// See [issue](https://github.com/tokio-rs/axum/issues/1110) and [PR](https://github.com/tokio-rs/axum/pull/1751)
/// for more detail.
///
/// These issues will be resolved with Axum 0.7 along with Hyper 1.0, as hyper::Body will be going away.
use byte_unit::Byte;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use hyper::{body::HttpBody, Body};
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum BodyReceiveError {
    #[error("body is too large `{0}`")]
    TooLarge(String),
    #[error("receiving body takes too long `{0}`")]
    Timeout(String),
    #[error("body is unavailable `{0}`")]
    Unavailable(String),
}

pub async fn receive_body_without_timeout(
    mut body: Body,
    max_request_body_size: Byte,
) -> Result<Bytes, BodyReceiveError> {
    let body_size_hint = body.size_hint().lower() as usize;
    if Byte::from(body_size_hint) > max_request_body_size {
        return Err(BodyReceiveError::TooLarge(
            "Value of 'Content-length' header exceeds http body size limit.".to_string(),
        ));
    }
    let mut received_body = BytesMut::with_capacity(body_size_hint);
    while let Some(chunk) = body.next().await {
        match chunk {
            Err(err) => {
                return Err(BodyReceiveError::Unavailable(format!(
                    "Failed to read body from connection: {}",
                    err
                )))
            }
            Ok(bytes) => {
                if Byte::from(received_body.len() + bytes.len()) > max_request_body_size {
                    return Err(BodyReceiveError::TooLarge(format!(
                        "Http body exceeds size limit of {} bytes.",
                        max_request_body_size
                    )));
                }
                received_body.extend_from_slice(&bytes);
            }
        }
    }
    Ok(received_body.freeze())
}

pub async fn receive_body(
    body: Body,
    max_request_receive_duration: Duration,
    max_request_body_size: Byte,
) -> Result<Bytes, BodyReceiveError> {
    match timeout(
        max_request_receive_duration,
        receive_body_without_timeout(body, max_request_body_size),
    )
    .await
    {
        Ok(res) => res,
        Err(err) => Err(BodyReceiveError::Timeout(format!(
            "Timeout of {}s reached while receiving http body: {}",
            max_request_receive_duration.as_secs(),
            err
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    #[tokio::test]
    async fn test_successfully_parse_small_body() {
        let (mut sender, body) = Body::channel();
        let time_to_wait = Duration::from_secs(5);
        let max_request_size = Byte::from_bytes(5 * 1024 * 1024);
        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // We need to drop the channel so the service will know there aren't any new
        // chunks. If we remove this line the test should run forever.
        std::mem::drop(sender);
        assert_eq!(
            receive_body(body, time_to_wait, max_request_size)
                .await
                .ok(),
            Some(Bytes::from("hello world"))
        );
    }

    #[tokio::test]
    async fn test_stop_and_return_error_when_parsing_big_body() {
        let (mut sender, body) = Body::channel();
        let chunk_size: usize = 1024;
        let time_to_wait = Duration::from_secs(5);
        let max_request_size = Byte::from_bytes(5 * 1024 * 1024);
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(chunk_size)
            .map(char::from)
            .collect();

        let jh =
            tokio::task::spawn(
                async move { receive_body(body, time_to_wait, max_request_size).await },
            );
        for _i in 0..(max_request_size.get_bytes() / chunk_size as u128) {
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
        assert!(matches!(response, BodyReceiveError::TooLarge { .. }));
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
        let max_request_size = Byte::from_bytes(5 * 1024 * 1024);
        let jh =
            tokio::task::spawn(
                async move { receive_body(body, time_to_wait, max_request_size).await },
            );

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
        assert!(matches!(response, BodyReceiveError::Timeout { .. }));
    }

    #[tokio::test]
    async fn test_time_out_while_waiting_for_many_chunks() {
        let (mut sender, body) = Body::channel();
        let time_to_wait = Duration::from_secs(5);
        let max_request_size = Byte::from_bytes(5 * 1024 * 1024);

        let jh =
            tokio::task::spawn(
                async move { receive_body(body, time_to_wait, max_request_size).await },
            );

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
        assert!(matches!(response, BodyReceiveError::Timeout { .. }));
    }
}
