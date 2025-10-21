//! The module implements the RPC abstraction over an established QUIC connection.
//!
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::{Method, Request, Response, Version};
use ic_protobuf::transport::v1 as pb;
use prost::Message;
use quinn::Connection;

use crate::{
    ConnId, MAX_MESSAGE_SIZE_BYTES, MessagePriority, P2PError, ResetStreamOnDrop,
    metrics::{
        INFALIBBLE, QuicTransportMetrics, observe_conn_error, observe_read_to_end_error,
        observe_stopped_error, observe_write_error,
    },
};

static CONN_ID_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct ConnectionHandle {
    conn: Connection,
    metrics: QuicTransportMetrics,
    conn_id: ConnId,
}

impl ConnectionHandle {
    pub fn new(conn: Connection, metrics: QuicTransportMetrics) -> Self {
        let conn_id = CONN_ID_SEQ.fetch_add(1, Ordering::SeqCst);
        Self {
            conn,
            conn_id: conn_id.into(),
            metrics,
        }
    }

    pub fn conn_id(&self) -> ConnId {
        self.conn_id
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
    /// Executes an RPC operation over an already-established connection.
    ///
    /// This method leverages the QUIC transport layer, which continuously monitors the connection’s health
    /// and automatically attempts reconnection as necessary. As a result, any errors returned by this method
    /// should be considered transient (retryable).
    ///
    /// In this P2P architecture, where there is a designated dialer and receiver, connection management
    /// is delegated solely to the transport layer. This differs from typical client-server architectures,
    /// where connections can be managed directly by the caller.
    ///
    /// Note: The method is cancel-safe.
    pub async fn rpc(&self, request: Request<Bytes>) -> Result<Response<Bytes>, P2PError> {
        let _timer = self
            .metrics
            .connection_handle_duration_seconds
            .with_label_values(&[request.uri().path()])
            .start_timer();

        let bytes_sent_counter = self
            .metrics
            .connection_handle_bytes_sent_total
            .with_label_values(&[request.uri().path()]);
        let bytes_received_counter = self
            .metrics
            .connection_handle_bytes_received_total
            .with_label_values(&[request.uri().path()]);

        let (send_stream, mut recv_stream) = self.conn.open_bi().await.inspect_err(|err| {
            observe_conn_error(err, "open_bi", &self.metrics.connection_handle_errors_total);
        })?;

        let mut send_stream_guard = ResetStreamOnDrop::new(
            send_stream,
            self.metrics
                .connection_handle_outgoing_streams_total
                .clone(),
        );
        let send_stream = &mut send_stream_guard.send_stream;

        let priority = request
            .extensions()
            .get::<MessagePriority>()
            .copied()
            .unwrap_or_default();
        let _ = send_stream.set_priority(priority.into());

        bytes_sent_counter.inc_by(request.body().len() as u64);
        let request_bytes = into_request_bytes(request);

        send_stream
            .write_all(&request_bytes)
            .await
            .inspect_err(|err| {
                observe_write_error(
                    err,
                    "write_all",
                    &self.metrics.connection_handle_errors_total,
                );
            })?;

        send_stream.finish().inspect_err(|_| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&["finish", INFALIBBLE])
                .inc();
        })?;

        send_stream.stopped().await.inspect_err(|err| {
            observe_stopped_error(err, "stopped", &self.metrics.connection_handle_errors_total)
        })?;
        let response_bytes = recv_stream
            .read_to_end(MAX_MESSAGE_SIZE_BYTES)
            .await
            .inspect_err(|err| {
                observe_read_to_end_error(
                    err,
                    "read_to_end",
                    &self.metrics.connection_handle_errors_total,
                )
            })?;

        let response = to_response(response_bytes).inspect_err(|_| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&["decode", INFALIBBLE])
                .inc();
        })?;

        bytes_received_counter.inc_by(response.body().len() as u64);
        Ok(response)
    }
}

// The function returns infallible error.
fn to_response(response_bytes: Vec<u8>) -> Result<Response<Bytes>, P2PError> {
    let response_proto = pb::HttpResponse::decode(response_bytes.as_slice())?;
    let status: u16 = response_proto.status_code.try_into()?;

    let mut response = Response::builder().status(status).version(Version::HTTP_3);
    for h in response_proto.headers {
        let pb::HttpHeader { key, value } = h;
        response = response.header(key, value);
    }
    // This consumes the body without requiring allocation or cloning the whole content.
    let body_bytes = Bytes::from(response_proto.body);
    Ok(response.body(body_bytes)?)
}

fn into_request_bytes(request: Request<Bytes>) -> Vec<u8> {
    let (parts, body) = request.into_parts();

    let request_proto = pb::HttpRequest {
        uri: String::from(parts.uri.path()),
        headers: parts
            .headers
            .into_iter()
            .filter_map(|(k, v)| {
                k.map(|k| pb::HttpHeader {
                    key: k.to_string(),
                    value: v.as_bytes().to_vec(),
                })
            })
            .collect(),
        method: match parts.method {
            Method::GET => pb::HttpMethod::Get.into(),
            Method::POST => pb::HttpMethod::Post.into(),
            Method::PUT => pb::HttpMethod::Put.into(),
            Method::DELETE => pb::HttpMethod::Delete.into(),
            Method::HEAD => pb::HttpMethod::Head.into(),
            Method::OPTIONS => pb::HttpMethod::Options.into(),
            Method::CONNECT => pb::HttpMethod::Connect.into(),
            Method::PATCH => pb::HttpMethod::Patch.into(),
            Method::TRACE => pb::HttpMethod::Trace.into(),
            _ => pb::HttpMethod::Unspecified.into(),
        },
        body: body.into(),
    };

    request_proto.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use bytes::Bytes;
    use ic_p2p_test_utils::{
        SkipServerVerification, generate_self_signed_cert, turmoil::CustomUdp,
    };
    use prometheus::IntGauge;
    use quinn::{
        ClientConfig, Endpoint, EndpointConfig, ReadError, ReadToEndError,
        crypto::rustls::QuicClientConfig,
    };
    use rstest::rstest;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };
    use tokio::sync::Barrier;
    use turmoil::Builder;

    use crate::ResetStreamOnDrop;

    const MAX_READ_SIZE: usize = 10_000;

    /// Test that [`ResetStreamOnDrop`] sends a reset frame on drop. Also tests that
    /// the receiver will receive the message if the stream is finished and stopped,
    /// before dropping the guard.
    #[rstest]
    fn test_dropped_connection_handle_resets_the_stream(
        #[values(false, true)] stream_is_finished_and_stopped: bool,
    ) {
        let mut sim = Builder::new().build();
        let node_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 8080).into();
        let receiver = "receiver";

        // If the sender closes the connection immediately after sending, then
        // quinn might abort transmitting the message for the sender.
        // Thus we wait with closing the endpoints until all client simulations
        // complete.
        let client_completed = Arc::new(Barrier::new(2));
        let client_completed_clone = client_completed.clone();

        sim.client(receiver, async move {
            let udp_listener = turmoil::net::UdpSocket::bind(node_addr).await.unwrap();
            let this_ip = turmoil::lookup(receiver);
            let custom_udp = CustomUdp::new(this_ip, udp_listener);
            let server_config = generate_self_signed_cert();

            let endpoint = Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                Some(server_config),
                Arc::new(custom_udp),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();

            let (_send_stream, mut recv_stream) = endpoint
                .accept()
                .await
                .unwrap()
                .await
                .unwrap()
                .accept_bi()
                .await
                .unwrap();

            let server_result = recv_stream.read_to_end(MAX_READ_SIZE).await;
            if stream_is_finished_and_stopped {
                assert_matches!(
                    server_result,
                    Ok(data) if String::from_utf8(data.clone()).unwrap().as_str() == "hello world");
            } else {
                assert_matches!(
                    server_result,
                    Err(ReadToEndError::Read(ReadError::Reset(reason))) if reason == quinn::VarInt::from_u32(0x80000006)
                );
            }
            client_completed_clone.wait().await;

            Ok(())
        });

        let node_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 8080).into();
        let sender = "sender";

        sim.client(sender, async move {
            let udp_listener = turmoil::net::UdpSocket::bind(node_addr).await.unwrap();
            let this_ip = turmoil::lookup(sender);
            let custom_udp = CustomUdp::new(this_ip, udp_listener);

            let mut endpoint = Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                Arc::new(custom_udp),
                Arc::new(quinn::TokioRuntime),
            )
            .unwrap();

            endpoint.set_default_client_config(ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(
                    rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(SkipServerVerification::new())
                        .with_no_client_auth(),
                )
                .unwrap(),
            )));

            let peer_ip = turmoil::lookup(receiver);
            let peer_socket_addr = (peer_ip, 8080).into();

            // connect to server
            let connection = endpoint
                .connect(peer_socket_addr, "peer1")
                .unwrap()
                .await
                .unwrap();

            let (send_stream, _recv_stream) = connection.open_bi().await.unwrap();
            let metric = IntGauge::new("test", "test").unwrap();
            let mut drop_guard = ResetStreamOnDrop::new(send_stream, metric.clone());
            assert_eq!(metric.get(), 1);
            let send_stream = &mut drop_guard.send_stream;
            send_stream
                .write_chunk(Bytes::from(&b"hello wo"[..]))
                .await
                .unwrap();

            if stream_is_finished_and_stopped {
                send_stream
                    .write_chunk(Bytes::from(&b"rld"[..]))
                    .await
                    .unwrap();

                send_stream.finish().unwrap();
                send_stream.stopped().await.unwrap();
            };

            drop(drop_guard);
            assert_eq!(metric.get(), 0);
            client_completed.wait().await;

            Ok(())
        });

        sim.run().unwrap();
    }
}
