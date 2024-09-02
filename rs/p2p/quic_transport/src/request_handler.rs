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

use axum::Router;
use ic_base_types::NodeId;
use ic_logger::{info, ReplicaLogger};
use quinn::{Connection, RecvStream, SendStream};
use tower::ServiceExt;
use tracing::instrument;

use crate::{
    metrics::{
        QuicTransportMetrics, ERROR_TYPE_ACCEPT, ERROR_TYPE_APP, ERROR_TYPE_FINISH,
        ERROR_TYPE_READ, ERROR_TYPE_STOPPED, ERROR_TYPE_WRITE, STREAM_TYPE_BIDI,
    },
    utils::{read_request, write_response},
    ConnId,
};

const QUIC_METRIC_SCRAPE_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) async fn run_stream_acceptor(
    log: ReplicaLogger,
    peer_id: NodeId,
    conn_id: ConnId,
    connection: Connection,
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
                metrics.collect_quic_connection_stats(&connection, &peer_id);
            }
            bi = connection.accept_bi() => {
                match bi {
                    Ok((bi_tx, bi_rx)) => {
                        inflight_requests.spawn(
                            metrics.request_task_monitor.instrument(
                                handle_bi_stream(
                                    log.clone(),
                                    peer_id,
                                    conn_id,
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
            _ = connection.accept_uni() => {},
            _ = connection.read_datagram() => {},
            Some(completed_request) = inflight_requests.join_next() => {
                if let Err(err) = completed_request {
                    // Cancelling tasks is ok. Panicking tasks are not.
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

#[instrument(skip(log, metrics, router, bi_tx, bi_rx))]
async fn handle_bi_stream(
    log: ReplicaLogger,
    peer_id: NodeId,
    conn_id: ConnId,
    metrics: QuicTransportMetrics,
    router: Router,
    mut bi_tx: SendStream,
    bi_rx: RecvStream,
) {
    let mut request = match read_request(bi_rx).await {
        Ok(request) => request,
        Err(e) => {
            info!(every_n_seconds => 60, log, "Failed to read request from bidi stream: {}", e);
            metrics
                .request_handle_errors_total
                .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_READ])
                .inc();
            return;
        }
    };

    request.extensions_mut().insert::<NodeId>(peer_id);
    request.extensions_mut().insert::<ConnId>(conn_id);

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
        info!(every_n_seconds => 60, log, "Failed to write response to stream: {}", e);
        metrics
            .request_handle_errors_total
            .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_WRITE])
            .inc();
    }
    if let Err(e) = bi_tx.finish() {
        info!(every_n_seconds => 60, log, "Failed to finish stream: {}", e.to_string());
        metrics
            .request_handle_errors_total
            .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_FINISH])
            .inc();
    }
    if let Err(e) = bi_tx.stopped().await {
        info!(every_n_seconds => 60, log, "Failed to stop stream: {}", e.to_string());
        metrics
            .request_handle_errors_total
            .with_label_values(&[STREAM_TYPE_BIDI, ERROR_TYPE_STOPPED])
            .inc();
    }
}
