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

use axum::{body::Body, Router}; // TODO: try to remove the axum dep here
use bytes::Bytes;
use http::{Method, Request, Response, Version};
use ic_base_types::NodeId;
use ic_logger::{warn, ReplicaLogger};
use ic_protobuf::transport::v1 as pb;
use prost::Message;
use quinn::RecvStream;
use tower::ServiceExt;

use crate::{
    connection_handle::ConnectionHandle,
    metrics::{observe_transport_error, QuicTransportMetrics},
    ConnId, ResetStreamOnDrop, TransportError, MAX_MESSAGE_SIZE_BYTES,
};

const QUIC_METRIC_SCRAPE_INTERVAL: Duration = Duration::from_secs(5);

/// Note: The event loop is cancel-safe.
pub async fn start_stream_acceptor(
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
                                    router.clone(),
                                    send_stream,
                                    bi_rx
                                )
                            )
                        );
                    }
                    Err(err) => {
                        let counter = &metrics.request_handle_errors_total;
                        let transport_err = err.clone().into();
                        observe_transport_error(&transport_err, counter);
                        if let TransportError::Internal(internal_err) = &transport_err {
                            warn!(log, "{:?}", internal_err);
                        }
                        break;
                    }
                }
            },
            _ = conn_handle.conn().accept_uni() => {},
            _ = conn_handle.conn().read_datagram() => {},
            Some(completed_request) = inflight_requests.join_next() => {
                match completed_request {
                    Ok(Ok(())) => (),
                    Ok(Err(err)) => {
                        // In theory we can also detect a connection error here and exist the loop. Not sure if it is better or worse?!
                        let counter = &metrics.request_handle_errors_total;
                        observe_transport_error(&err, counter);
                        if let TransportError::Internal(internal_err) = &err {
                            warn!(log, "{:?}", internal_err);
                        }
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
}

/// Note: The method is cancel-safe.
async fn handle_bi_stream(
    peer_id: NodeId,
    conn_id: ConnId,
    router: Router,
    mut send_stream_guard: ResetStreamOnDrop,
    mut recv_stream: RecvStream,
) -> Result<(), TransportError> {
    // Note that the 'recv_stream' is dropped before we call any method on the 'send_stream'
    let request_bytes = recv_stream.read_to_end(MAX_MESSAGE_SIZE_BYTES).await?;
    // The destructor stops the stream.
    std::mem::drop(recv_stream);
    let mut request = read_request(request_bytes).map_err(TransportError::Internal)?;
    request.extensions_mut().insert::<NodeId>(peer_id);
    request.extensions_mut().insert::<ConnId>(conn_id);

    let send_stream = &mut send_stream_guard.send_stream;
    let svc = router.oneshot(request);
    let stopped_fut = send_stream.stopped();
    let response = tokio::select! {
        response = svc => response.expect("Infallible"),
        stopped = stopped_fut => {
            return stopped.map(|_| ()).map_err(|_| TransportError::StreamCancelled);
        }
    };

    // We can ignore the errors because if both peers follow the protocol an errors will only occur
    // if the other peer has closed the connection. In this case `accept_bi` in the peer event
    // loop will close this connection.
    let response_bytes = to_response_bytes(response)
        .await
        .map_err(TransportError::Internal)?;
    send_stream.write_all(&response_bytes).await?;
    send_stream
        .finish()
        .map_err(|err| TransportError::Internal(Box::new(err)))?;
    send_stream.stopped().await?;
    Ok(())
}

// The function returns infallible error.
fn read_request(
    request_bytes: Vec<u8>,
) -> Result<Request<Body>, Box<dyn std::error::Error + Send + 'static>> {
    let request_proto =
        pb::HttpRequest::decode(request_bytes.as_slice()).map_err(|err| Box::new(err) as Box<_>)?;
    let pb_http_method =
        pb::HttpMethod::try_from(request_proto.method).map_err(|err| Box::new(err) as Box<_>)?;
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
        .map_err(|err| Box::new(err) as Box<_>)
}

async fn to_response_bytes(
    response: Response<Body>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send>> {
    let (parts, body) = response.into_parts();
    // Check for axum error in body
    // TODO: Think about this. What is the error that can happen here?
    let body = axum::body::to_bytes(body, MAX_MESSAGE_SIZE_BYTES)
        .await
        .map_err(|err| Box::new(err) as Box<_>)?;
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
