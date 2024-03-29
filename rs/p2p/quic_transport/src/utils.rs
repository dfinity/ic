//! Quic Transport utilities.
//!
//! Contains the actual wire format used for messages.
//! Request encoding Request<Bytes>:
//!     - Split into header and body.
//!     - Header contains a HeaderMap and the URI
//!     - Body is just the byte vector.
//!     - Both the header and body are encoded with bincode
//!     - At this point both header and body are just a vector of bytes.
//!       The two bytes vector both get length limited encoded and sent.
//!     - Reading a request involves doing two reads from the wire for the
//!       encoded header and body and reconstructing it into a typed request.
//! Response encoding Response<Bytes>:
//!     - Same as request expect that the header contains a HeaderMap and a Statuscode.
use anyhow::Context;
use axum::{
    body::{Body, HttpBody},
    extract::State,
    http::{Request, Response, StatusCode, Uri},
    middleware::Next,
};
use bincode::Options;
use bytes::Bytes;
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::metrics::QuicTransportMetrics;

/// On purpose the value is big, otherwise there is risk of not processing important consensus messages.
/// E.g. summary blocks generated by the consensus protocol for 40 node subnet can be bigger than 5MB.
const MAX_MESSAGE_SIZE_BYTES: usize = 128 * 1024 * 1024;

fn bincode_config() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_MESSAGE_SIZE_BYTES as u64)
}

pub(crate) async fn read_request(
    mut recv_stream: RecvStream,
) -> Result<Request<Body>, anyhow::Error> {
    let raw_msg = recv_stream
        .read_to_end(MAX_MESSAGE_SIZE_BYTES)
        .await
        .with_context(|| "Failed to read request from the stream.")?;

    let msg: WireRequest = bincode_config()
        .deserialize(&raw_msg)
        .with_context(|| "Failed to deserialize the request from the wire.")?;

    let mut request = Request::new(Body::from(Bytes::copy_from_slice(msg.body)));
    let _ = std::mem::replace(request.uri_mut(), msg.uri);
    Ok(request)
}

pub(crate) async fn read_response(
    mut recv_stream: RecvStream,
) -> Result<Response<Bytes>, anyhow::Error> {
    let raw_msg = recv_stream
        .read_to_end(MAX_MESSAGE_SIZE_BYTES)
        .await
        .with_context(|| "Failed to read response from the stream.")?;
    let msg: WireResponse = bincode_config()
        .deserialize(&raw_msg)
        .with_context(|| "Failed to deserialize response.")?;

    let mut response = Response::new(Bytes::copy_from_slice(msg.body));
    let _ = std::mem::replace(response.status_mut(), msg.status);
    Ok(response)
}

pub(crate) async fn write_request(
    send_stream: &mut SendStream,
    request: Request<Bytes>,
) -> Result<(), anyhow::Error> {
    let (parts, body) = request.into_parts();

    let msg = WireRequest {
        uri: parts.uri,
        body: &body,
    };

    let res = bincode_config()
        .serialize(&msg)
        .with_context(|| "Failed to serialize request.")?;
    send_stream
        .write_all(&res)
        .await
        .with_context(|| "Failed to write request to the stream.")
}

pub(crate) async fn write_response(
    send_stream: &mut SendStream,
    response: Response<Body>,
) -> Result<(), anyhow::Error> {
    let (parts, body) = response.into_parts();
    // Check for axum error in body
    // TODO: Think about this. What is the error that can happen here?
    let b = axum::body::to_bytes(body, MAX_MESSAGE_SIZE_BYTES)
        .await
        .with_context(|| "Failed to convert response body to bytes.")?;
    let msg = WireResponse {
        status: parts.status,
        body: &b,
    };
    let res = bincode_config()
        .serialize(&msg)
        .with_context(|| "Failed to serialize response.")?;
    send_stream
        .write_all(&res)
        .await
        .with_context(|| "Failed to write response to the wire.")
}

#[derive(Serialize, Deserialize)]
struct WireResponse<'a> {
    #[serde(with = "http_serde::status_code")]
    status: StatusCode,
    #[serde(with = "serde_bytes")]
    body: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct WireRequest<'a> {
    #[serde(with = "http_serde::uri")]
    uri: Uri,
    #[serde(with = "serde_bytes")]
    body: &'a [u8],
}

/// Axum middleware to collect metrics
pub(crate) async fn collect_metrics(
    State(state): State<QuicTransportMetrics>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    state
        .request_handle_bytes_received_total
        .with_label_values(&[request.uri().path()])
        .inc_by(request.body().size_hint().lower());
    let _timer = state
        .request_handle_duration_seconds
        .with_label_values(&[request.uri().path()])
        .start_timer();
    let out_counter = state
        .request_handle_bytes_sent_total
        .with_label_values(&[request.uri().path()]);
    let response = next.run(request).await;
    out_counter.inc_by(response.body().size_hint().lower());
    response
}
