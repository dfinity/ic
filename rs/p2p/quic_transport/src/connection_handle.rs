//! Quic Transport connection handle.
//!
//! Contains a wrapper, called `ConnectionHandle`, around quinn's Connection.
//! The `ConnectionHandle` implements `rpc` and `push` methods for the given
//! connection.
//!

use anyhow::anyhow;
use anyhow::Context;
use axum::http::{Method, Request, Response, Version};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_protobuf::transport::v1 as pb;
use prost::Message;
use quinn::{Connection, RecvStream, SendStream};

use crate::{
    metrics::{
        QuicTransportMetrics, ERROR_TYPE_FINISH, ERROR_TYPE_OPEN, ERROR_TYPE_READ,
        ERROR_TYPE_STOPPED, ERROR_TYPE_WRITE, REQUEST_TYPE_PUSH, REQUEST_TYPE_RPC,
    },
    ConnId, MessagePriority, MAX_MESSAGE_SIZE_BYTES,
};

#[derive(Clone, Debug)]
pub(crate) struct ConnectionHandle {
    pub peer_id: NodeId,
    pub connection: Connection,
    pub metrics: QuicTransportMetrics,
    conn_id: ConnId,
}

impl ConnectionHandle {
    pub(crate) fn new(
        peer_id: NodeId,
        connection: Connection,
        metrics: QuicTransportMetrics,
        conn_id: ConnId,
    ) -> Self {
        Self {
            peer_id,
            connection,
            metrics,
            conn_id,
        }
    }

    pub(crate) fn conn_id(&self) -> ConnId {
        self.conn_id
    }

    pub(crate) async fn rpc(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, anyhow::Error> {
        let _timer = self
            .metrics
            .connection_handle_duration_seconds
            .with_label_values(&[request.uri().path()])
            .start_timer();
        self.metrics
            .connection_handle_bytes_sent_total
            .with_label_values(&[request.uri().path()])
            .inc_by(request.body().len() as u64);
        let in_counter = self
            .metrics
            .connection_handle_bytes_received_total
            .with_label_values(&[request.uri().path()]);

        let (mut send_stream, recv_stream) = self.connection.open_bi().await.map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_OPEN]);
            err
        })?;

        let priority = request
            .extensions()
            .get::<MessagePriority>()
            .copied()
            .unwrap_or_default();
        let _ = send_stream.set_priority(priority.into());

        write_request(&mut send_stream, request)
            .await
            .map_err(|err| {
                self.metrics
                    .connection_handle_errors_total
                    .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_WRITE])
                    .inc();
                err
            })?;

        send_stream.finish().map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_FINISH])
                .inc();
            err
        })?;

        send_stream.stopped().await.map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_PUSH, ERROR_TYPE_STOPPED])
                .inc();
            err
        })?;

        let mut response = read_response(recv_stream).await.map_err(|err| {
            self.metrics
                .connection_handle_errors_total
                .with_label_values(&[REQUEST_TYPE_RPC, ERROR_TYPE_READ])
                .inc();
            err
        })?;

        // Propagate PeerId from this request to upper layers.
        response.extensions_mut().insert(self.peer_id);

        in_counter.inc_by(response.body().len() as u64);
        Ok(response)
    }
}

pub(crate) async fn read_response(
    mut recv_stream: RecvStream,
) -> Result<Response<Bytes>, anyhow::Error> {
    let raw_msg = recv_stream
        .read_to_end(MAX_MESSAGE_SIZE_BYTES)
        .await
        .with_context(|| "Failed to read response from the stream.")?;

    let response_proto = pb::HttpResponse::decode(raw_msg.as_slice())
        .with_context(|| "Failed to decode response header.")?;

    let status: u16 = match response_proto.status_code.try_into() {
        Ok(status) => status,
        Err(e) => {
            return Err(anyhow!(
                "Received invalid status code {} {}",
                response_proto.status_code,
                e
            ))
        }
    };

    let mut response = Response::builder().status(status).version(Version::HTTP_3);
    for h in response_proto.headers {
        let pb::HttpHeader { key, value } = h;
        response = response.header(key, value);
    }
    // This consumes the body without requiring allocation or cloning the whole content.
    let body_bytes = Bytes::from(response_proto.body);
    response
        .body(body_bytes)
        .with_context(|| "Failed to build response.")
}

pub(crate) async fn write_request(
    send_stream: &mut SendStream,
    request: Request<Bytes>,
) -> Result<(), anyhow::Error> {
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
            _ => return Err(anyhow!("invalid method")),
        },
        body: body.into(),
    };

    let request_bytes = request_proto.encode_to_vec();
    send_stream
        .write_all(&request_bytes)
        .await
        .with_context(|| "Failed to write request to stream.")?;
    Ok(())
}
