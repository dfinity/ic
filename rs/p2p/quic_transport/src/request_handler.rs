//! Quic Transport incoming request handler.
//!
//! The handler is an event loop that accepts streams and spawns a tokio task for each stream
//! Each task does the following:
//!     - Reads a request from the stream. (A single stream carries a single request.)
//!     - Adds metadata to the request based on the underlying connection.
//!       E.g. adds the NodeId of the peer as an extension.
//!     - Calls the router.
//!     - Writes the response to the wire.
//!
//! Please note that the connection manager is responsible for closing connections.
//!
use std::time::Duration;

use anyhow::Context;
use axum::{body::Body, Router};
use bytes::Bytes;
use http::{Method, Request, Response, Version};
use ic_base_types::NodeId;
use ic_logger::{info, ReplicaLogger};
use ic_protobuf::transport::v1 as pb;
use prost::Message;
use quinn::RecvStream;
use tower::ServiceExt;
use tracing::instrument;

use crate::{
    connection_handle::ConnectionHandle,
    metrics::{
        observe_conn_error, observe_read_to_end_error, observe_stopped_error, observe_write_error,
        QuicTransportMetrics, ERROR_TYPE_APP, INFALIBBLE, STREAM_TYPE_BIDI,
    },
    ConnId, ResetStreamOnDrop, MAX_MESSAGE_SIZE_BYTES,
};

const QUIC_METRIC_SCRAPE_INTERVAL: Duration = Duration::from_secs(5);

pub async fn run_stream_acceptor(
    log: ReplicaLogger,
    peer_id: NodeId,
    conn_handle: ConnectionHandle,
    metrics: QuicTransportMetrics,
    router: Router,
) {
    let mut inflight_requests = tokio::task::JoinSet::new();
    let mut quic_metrics_scrape = tokio::time::interval(QUIC_METRIC_SCRAPE_INTERVAL);
    // The extreme result of a slow handler is that the stream limit will be reach, hence
    // having buffered up to the stream limit number of messages/requests.
    // A better approach will be to use a router implemented as a tower service and accept
    // streams iff the router is ready. Then the actual number of buffered messages is determined
    // by the handlers instead by the underlying implementation.
    loop {
        tokio::select! {
             _ = quic_metrics_scrape.tick() => {
                metrics.collect_quic_connection_stats(conn_handle.conn(), &peer_id);
            }
            bi = conn_handle.conn().accept_bi() => {
                match bi {
                    Ok((bi_tx, bi_rx)) => {
                        let send_stream = ResetStreamOnDrop::new(bi_tx);
                        inflight_requests.spawn(
                            metrics.request_task_monitor.instrument(
                                handle_bi_stream(
                                    peer_id,
                                    conn_handle.conn_id(),
                                    metrics.clone(),
                                    router.clone(),
                                    send_stream,
                                    bi_rx
                                )
                            )
                        );
                    }
                    Err(err) => {
                        info!(log, "Error accepting bi stream {:?}", err.to_string());
                        observe_conn_error(&err, "accept_bi", &metrics.request_handle_errors_total);
                        break;
                    }
                }
            },
            _ = conn_handle.conn().accept_uni() => {},
            _ = conn_handle.conn().read_datagram() => {},
            Some(completed_request) = inflight_requests.join_next() => {
                match completed_request {
                    Ok(res) => {
                        let _ = res.inspect_err(|err| info!(every_n_seconds => 60, log, "{:?}", err));
                    }
                    Err(err) => {
                        // Cancelling tasks is ok. Panicking tasks are not.
                        if err.is_panic() {
                            std::panic::resume_unwind(err.into_panic());
                        }
                    }
                }
            },
        }
    }
    info!(log, "Shutting down request handler for peer {:?}", peer_id);

    inflight_requests.shutdown().await;
}

#[instrument(skip(metrics, router, send_stream_guard, recv_stream))]
/// Note: The method is cancel-safe.
async fn handle_bi_stream(
    peer_id: NodeId,
    conn_id: ConnId,
    metrics: QuicTransportMetrics,
    router: Router,
    mut send_stream_guard: ResetStreamOnDrop,
    recv_stream: RecvStream,
) -> Result<(), anyhow::Error> {
    // Note that the 'recv_stream' is dropped before we call any method on the 'send_stream'
    let mut request = read_request(recv_stream, &metrics).await?;
    request.extensions_mut().insert::<NodeId>(peer_id);
    request.extensions_mut().insert::<ConnId>(conn_id);

    let send_stream = &mut send_stream_guard.send_stream;
    let svc = router.oneshot(request);
    let stopped = send_stream.stopped();
    let response = tokio::select! {
        response = svc => response.expect("Infallible"),
        stopped_res = stopped => {
            return stopped_res.map(|_| ()).with_context(|| "stopped.");
        }
    };

    // Record application level errors.
    if !response.status().is_success() {
        metrics
            .request_handle_errors_total
            .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_APP])
            .inc();
    }

    // We can ignore the errors because if both peers follow the protocol an errors will only occur
    // if the other peer has closed the connection. In this case `accept_bi` in the peer event
    // loop will close this connection.
    let response_bytes = to_response_bytes(response).await?;
    send_stream
        .write_all(&response_bytes)
        .await
        .inspect_err(|err| {
            observe_write_error(err, "write_all", &metrics.request_handle_errors_total);
        })?;
    send_stream.finish().inspect_err(|_| {
        metrics
            .request_handle_errors_total
            .with_label_values(&["finish", INFALIBBLE])
            .inc();
    })?;
    send_stream.stopped().await.inspect_err(|err| {
        observe_stopped_error(err, "stopped", &metrics.request_handle_errors_total);
    })?;
    Ok(())
}

// The function returns infallible error.
async fn read_request(
    mut recv_stream: RecvStream,
    metrics: &QuicTransportMetrics,
) -> Result<Request<Body>, anyhow::Error> {
    let request_bytes = recv_stream
        .read_to_end(MAX_MESSAGE_SIZE_BYTES)
        .await
        .inspect_err(|err| {
            observe_read_to_end_error(err, "read_to_end", &metrics.request_handle_errors_total)
        })?;

    let request_proto = pb::HttpRequest::decode(request_bytes.as_slice())?;
    let pb_http_method = pb::HttpMethod::try_from(request_proto.method)?;
    let http_method = match pb_http_method {
        pb::HttpMethod::Get => Some(Method::GET),
        pb::HttpMethod::Post => Some(Method::POST),
        pb::HttpMethod::Put => Some(Method::PUT),
        pb::HttpMethod::Delete => Some(Method::DELETE),
        pb::HttpMethod::Head => Some(Method::HEAD),
        pb::HttpMethod::Options => Some(Method::OPTIONS),
        pb::HttpMethod::Connect => Some(Method::CONNECT),
        pb::HttpMethod::Patch => Some(Method::PATCH),
        pb::HttpMethod::Trace => Some(Method::TRACE),
        pb::HttpMethod::Unspecified => None,
    };
    let mut request_builder = Request::builder();
    if let Some(http_method) = http_method {
        request_builder = request_builder.method(http_method);
    }
    request_builder = request_builder
        .version(Version::HTTP_3)
        .uri(request_proto.uri);
    for h in request_proto.headers {
        let pb::HttpHeader { key, value } = h;
        request_builder = request_builder.header(key, value);
    }
    // This consumes the body without requiring allocation or cloning the whole content.
    let body_bytes = Bytes::from(request_proto.body);
    request_builder
        .body(Body::from(body_bytes))
        .with_context(|| "Failed to build request.")
}

async fn to_response_bytes(response: Response<Body>) -> Result<Vec<u8>, anyhow::Error> {
    let (parts, body) = response.into_parts();
    // Check for axum error in body
    // TODO: Think about this. What is the error that can happen here?
    let body = axum::body::to_bytes(body, MAX_MESSAGE_SIZE_BYTES)
        .await
        .with_context(|| "Failed to read response from body.")?;
    let response_proto = pb::HttpResponse {
        status_code: parts.status.as_u16().into(),
        headers: parts
            .headers
            .into_iter()
            .filter_map(|(k, v)| {
                k.map(|k| ic_protobuf::transport::v1::HttpHeader {
                    key: k.to_string(),
                    value: v.as_bytes().to_vec(),
                })
            })
            .collect(),
        body: body.into(),
    };
    Ok(response_proto.encode_to_vec())
}
