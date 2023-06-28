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
    metrics::QuicTransportMetrics,
    utils::{read_request, write_response},
};

pub async fn start_request_handler(
    ConnectionHandle {
        peer_id,
        connection,
    }: ConnectionHandle,
    log: ReplicaLogger,
    _metrics: QuicTransportMetrics,
    router: Router,
) {
    let mut inflight_requests = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            // TODO: (NET-1468) Support unidirectional streams for broadcast
            _ = connection.accept_uni() => {},
            bi = connection.accept_bi() => {
                match bi {
                    Ok((bi_tx, bi_rx)) => {
                        inflight_requests.spawn(handle_bi_stream(peer_id, router.clone(), bi_tx, bi_rx));
                    }
                    Err(e) => {
                        info!(log, "Error accepting bi dir stream {:?}", e.to_string());
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

async fn handle_bi_stream(peer_id: NodeId, router: Router, bi_tx: SendStream, bi_rx: RecvStream) {
    let mut send_stream = length_delimited::Builder::new().new_write(bi_tx);
    let mut recv_stream = length_delimited::Builder::new().new_read(bi_rx);

    let mut request = match read_request(&mut recv_stream).await {
        Ok(request) => request,
        Err(_) => {
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

    // We can ignore the errors because if both peers follow the protocol an errors will only occur
    // if the other peer has closed the connection. In this case `accept_bi` in the peer event
    // loop will close this connection.
    let _ = write_response(&mut send_stream, response).await;
    let _ = send_stream.get_mut().finish().await;
}
