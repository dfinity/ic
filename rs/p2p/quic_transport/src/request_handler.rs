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
use quinn::{Connection, RecvStream, SendStream};
use tower::ServiceExt;

use crate::{
    metrics::{
        QuicTransportMetrics, ERROR_TYPE_ACCEPT, ERROR_TYPE_APP, ERROR_TYPE_FINISH,
        ERROR_TYPE_READ, ERROR_TYPE_WRITE, STREAM_TYPE_BIDI, STREAM_TYPE_UNI,
    },
    utils::{read_request, write_response},
};

pub(crate) async fn start_request_handler(
    peer_id: NodeId,
    connection: Connection,
    metrics: QuicTransportMetrics,
    log: ReplicaLogger,
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
                                STREAM_TYPE_UNI,
                                ERROR_TYPE_ACCEPT,
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
                                STREAM_TYPE_BIDI,
                                ERROR_TYPE_ACCEPT,
                            ])
                            .inc();
                        break;
                    }
                }
            },
            _ = connection.read_datagram() => {},
            Some(completed_request) = inflight_requests.join_next() => {
                metrics.collect_quic_connection_stats(&connection, &peer_id);
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
    mut bi_tx: SendStream,
    mut bi_rx: RecvStream,
) {
    let mut request = match read_request(&mut bi_rx).await {
        Ok(request) => request,
        Err(e) => {
            info!(
                log,
                "Failed to read request from bidi stream: {}",
                e.to_string()
            );
            metrics
                .request_handle_errors_total
                .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_READ])
                .inc();
            return;
        }
    };

    request.extensions_mut().insert::<NodeId>(peer_id);

    let svc = router.oneshot(request);
    let stopped = bi_tx.stopped();
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
            .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_APP])
            .inc();
    }

    // We can ignore the errors because if both peers follow the protocol an errors will only occur
    // if the other peer has closed the connection. In this case `accept_bi` in the peer event
    // loop will close this connection.
    if let Err(e) = write_response(&mut bi_tx, response).await {
        info!(log, "Failed to write response to stream: {}", e.to_string());
        metrics
            .request_handle_errors_total
            .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_WRITE])
            .inc();
    }
    if let Err(e) = bi_tx.finish().await {
        info!(log, "Failed to finish stream: {}", e.to_string());
        metrics
            .request_handle_errors_total
            .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_FINISH])
            .inc();
    }
}

async fn handle_uni_stream(
    peer_id: NodeId,
    log: ReplicaLogger,
    metrics: QuicTransportMetrics,
    router: Router,
    mut uni_rx: RecvStream,
) {
    let mut request = match read_request(&mut uni_rx).await {
        Ok(request) => request,
        Err(e) => {
            info!(
                log,
                "Failed to read request from uni stream: {}",
                e.to_string()
            );
            metrics
                .request_handle_errors_total
                .with_label_values(&[STREAM_TYPE_UNI, ERROR_TYPE_READ])
                .inc();
            return;
        }
    };

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
            .with_label_values(&[STREAM_TYPE_UNI, ERROR_TYPE_APP])
            .inc();
    }
}
