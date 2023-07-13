//! Quic Transport request handler.
//!
//! The actual handler for incoming request.
//! We spawn a new tokio task for each request that does the following steps:
//!     - Reads the request from the substream
//!     - Adds metadata to the request based on the underlying connection.
//!       I.e add the NodeId of the peer as an extension.
//!     - Calls the router
//!     - Writes response to wire.
//!
use axum::Router;
use ic_logger::{info, ReplicaLogger};
use ic_types::NodeId;
use quinn::{RecvStream, SendStream};
use tokio_util::codec::length_delimited;
use tower::ServiceExt;

use crate::{
    connection_handle::ConnectionHandle,
    metrics::{
        QuicTransportMetrics, REQUEST_HANDLER_ERROR_TYPE_ACCEPT, REQUEST_HANDLER_ERROR_TYPE_APP,
        REQUEST_HANDLER_ERROR_TYPE_FINISH, REQUEST_HANDLER_ERROR_TYPE_READ,
        REQUEST_HANDLER_ERROR_TYPE_WRITE, REQUEST_HANDLER_STREAM_TYPE_BIDI,
        REQUEST_HANDLER_STREAM_TYPE_UNI,
    },
    utils::{read_request, write_response},
};

pub async fn start_request_handler(
    ConnectionHandle {
        peer_id,
        connection,
    }: ConnectionHandle,
    log: ReplicaLogger,
    metrics: QuicTransportMetrics,
    router: Router,
) {
    let mut inflight_requests = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            uni = connection.accept_uni() => {
                match uni {
                    Ok(uni_rx) => {
                        inflight_requests.spawn(
                            metrics.request_task_monitor.instrument(
                                handle_uni_stream(
                                    peer_id,
                                    log.clone(),
                                    metrics.clone(),
                                    router.clone(),
                                    uni_rx,
                                )
                            )
                        );
                    }
                    Err(e) => {
                        info!(log, "Error accepting uni dir stream {}", e.to_string());
                        metrics
                            .request_handle_errors_total
                            .with_label_values(&[
                                REQUEST_HANDLER_STREAM_TYPE_UNI,
                                REQUEST_HANDLER_ERROR_TYPE_ACCEPT,
                            ])
                            .inc();
                        break;
                    }
                }
            },
            bi = connection.accept_bi() => {
                match bi {
                    Ok((bi_tx, bi_rx)) => {
                        inflight_requests.spawn(
                            metrics.request_task_monitor.instrument(
                                handle_bi_stream(
                                    peer_id,
                                    log.clone(),
                                    metrics.clone(),
                                    router.clone(),
                                    bi_tx,
                                    bi_rx
                                )
                            )
                        );
                    }
                    Err(e) => {
                        info!(log, "Error accepting bi stream {}", e.to_string());
                        metrics
                            .request_handle_errors_total
                            .with_label_values(&[
                                REQUEST_HANDLER_STREAM_TYPE_BIDI,
                                REQUEST_HANDLER_ERROR_TYPE_ACCEPT,
                            ])
                            .inc();
                        break;
                    }
                }
            },
            _ = connection.read_datagram() => {},
            Some(completed_request) = inflight_requests.join_next() => {
                if let Err(err) = completed_request {
                    // Cancelling tasks is ok. Panicing tasks are not.
                    if err.is_panic() {
                        std::panic::resume_unwind(err.into_panic());
                    }
                }
            },
        }
    }
    info!(log, "Shutting down request handler for peer {}", peer_id);

    inflight_requests.shutdown().await;
}

async fn handle_bi_stream(
    peer_id: NodeId,
    log: ReplicaLogger,
    metrics: QuicTransportMetrics,
    router: Router,
    bi_tx: SendStream,
    bi_rx: RecvStream,
) {
    let mut send_stream = length_delimited::Builder::new().new_write(bi_tx);
    let mut recv_stream = length_delimited::Builder::new().new_read(bi_rx);

    let mut request = match read_request(&mut recv_stream).await {
        Ok(request) => request,
        Err(e) => {
            info!(
                log,
                "Failed to read request from bidi stream: {}",
                e.to_string()
            );
            metrics
                .request_handle_errors_total
                .with_label_values(&[
                    REQUEST_HANDLER_STREAM_TYPE_BIDI,
                    REQUEST_HANDLER_ERROR_TYPE_READ,
                ])
                .inc();
            return;
        }
    };

    request.extensions_mut().insert::<NodeId>(peer_id);

    let svc = router.oneshot(request);
    let stopped = send_stream.get_mut().stopped();
    let response = tokio::select! {
        response = svc => response.expect("Infallible"),
        _ = stopped => {
            return;
        }
    };

    // Record application level errors.
    if !response.status().is_success() {
        metrics
            .request_handle_errors_total
            .with_label_values(&[
                REQUEST_HANDLER_STREAM_TYPE_BIDI,
                REQUEST_HANDLER_ERROR_TYPE_APP,
            ])
            .inc();
    }

    // We can ignore the errors because if both peers follow the protocol an errors will only occur
    // if the other peer has closed the connection. In this case `accept_bi` in the peer event
    // loop will close this connection.
    if let Err(e) = write_response(&mut send_stream, response).await {
        info!(log, "Failed to write response to stream: {}", e.to_string());
        metrics
            .request_handle_errors_total
            .with_label_values(&[
                REQUEST_HANDLER_STREAM_TYPE_BIDI,
                REQUEST_HANDLER_ERROR_TYPE_WRITE,
            ])
            .inc();
    }
    if let Err(e) = send_stream.get_mut().finish().await {
        info!(log, "Failed to finish stream: {}", e.to_string());
        metrics
            .request_handle_errors_total
            .with_label_values(&[
                REQUEST_HANDLER_STREAM_TYPE_BIDI,
                REQUEST_HANDLER_ERROR_TYPE_FINISH,
            ])
            .inc();
    }
}

async fn handle_uni_stream(
    peer_id: NodeId,
    log: ReplicaLogger,
    metrics: QuicTransportMetrics,
    router: Router,
    uni_rx: RecvStream,
) {
    let mut recv_stream = length_delimited::Builder::new().new_read(uni_rx);

    let mut request = match read_request(&mut recv_stream).await {
        Ok(request) => request,
        Err(e) => {
            info!(
                log,
                "Failed to read request from uni stream: {}",
                e.to_string()
            );
            metrics
                .request_handle_errors_total
                .with_label_values(&[
                    REQUEST_HANDLER_STREAM_TYPE_UNI,
                    REQUEST_HANDLER_ERROR_TYPE_READ,
                ])
                .inc();
            return;
        }
    };

    // Explicity reading to end to avoid an ungraceful shutdown of the stream.
    // Docs: https://docs.rs/quinn/0.10.1/quinn/struct.RecvStream.html#closing-a-stream
    if recv_stream.get_mut().read_to_end(0).await.is_err() {
        // Discard unexpected data and notify the peer to stop sending it
        let _ = recv_stream.get_mut().stop(0u8.into());
        metrics
            .request_handle_errors_total
            .with_label_values(&[
                REQUEST_HANDLER_STREAM_TYPE_UNI,
                REQUEST_HANDLER_ERROR_TYPE_READ,
            ])
            .inc();
        return;
    }

    request.extensions_mut().insert::<NodeId>(peer_id);

    // Record application level errors.
    if !router
        .oneshot(request)
        .await
        .expect("Infallible")
        .status()
        .is_success()
    {
        metrics
            .request_handle_errors_total
            .with_label_values(&[
                REQUEST_HANDLER_STREAM_TYPE_UNI,
                REQUEST_HANDLER_ERROR_TYPE_APP,
            ])
            .inc();
    }
}
