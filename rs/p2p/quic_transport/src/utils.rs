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
use axum::body::{Body, BoxBody, HttpBody};
use bytes::{Buf, BufMut, Bytes};
use futures::{SinkExt, StreamExt};
use http::{
    request::Parts as RequestParts, response::Parts as ResponseParts, HeaderMap, Request, Response,
    StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub(crate) async fn read_request<T: AsyncRead + Unpin>(
    recv_stream: &mut FramedRead<T, LengthDelimitedCodec>,
) -> Result<Request<Body>, std::io::Error> {
    let header = recv_stream
        .next()
        .await
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))??;
    let raw_header: WireRequestHeader = bincode::deserialize(&header).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Bincode request wire header deserialization failed: {}", e),
        )
    })?;
    let body = recv_stream
        .next()
        .await
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))??;

    // TODO: Double check if it can not fail.
    let request = Request::builder()
        .uri(raw_header.uri)
        .body(Body::from(body.freeze()))
        .expect("Building from typed values can not fail");
    Ok(request)
}

pub(crate) async fn read_response<T: AsyncRead + Unpin>(
    recv_stream: &mut FramedRead<T, LengthDelimitedCodec>,
) -> Result<Response<Bytes>, std::io::Error> {
    let header = recv_stream
        .next()
        .await
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))??;
    let raw_header: WireResponseHeader = bincode::deserialize(&header).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Bincode response wire header deserialization failed: {}", e),
        )
    })?;
    let body = recv_stream
        .next()
        .await
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))??;

    // TODO: Double check if it can not fail.
    let response = Response::builder()
        .status(raw_header.status)
        .body(body.freeze())
        .expect("Building from typed values can not fail.");
    Ok(response)
}

pub(crate) async fn write_request<T: AsyncWrite + Unpin>(
    send_stream: &mut FramedWrite<T, LengthDelimitedCodec>,
    request: Request<Bytes>,
) -> Result<(), std::io::Error> {
    let (parts, body) = request.into_parts();
    let parts = WireRequestHeader::from(parts);

    let res = bincode::serialize(&parts).expect("serialization should not fail");
    send_stream.send(Bytes::from(res)).await?;

    send_stream.send(body).await?;

    Ok(())
}

pub(crate) async fn write_response<T: AsyncWrite + Unpin>(
    send_stream: &mut FramedWrite<T, LengthDelimitedCodec>,
    response: Response<BoxBody>,
) -> Result<(), std::io::Error> {
    let (parts, body) = response.into_parts();
    // Check for axum error in body
    // TODO: Think about this. What is the error that can happen here?
    let (parts, body) = match to_bytes(body).await {
        Ok(b) => (WireResponseHeader::from(parts), b),
        Err(e) => (
            WireResponseHeader {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                headers: http::HeaderMap::new(),
            },
            Bytes::from(e.to_string().into_bytes()),
        ),
    };

    let res = bincode::serialize(&parts).expect("serialization should not fail");
    send_stream.send(Bytes::from(res)).await?;

    send_stream.send(body).await?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct WireResponseHeader {
    #[serde(with = "http_serde::status_code")]
    status: StatusCode,
    #[serde(with = "http_serde::header_map")]
    headers: HeaderMap,
}

impl From<ResponseParts> for WireResponseHeader {
    fn from(value: ResponseParts) -> Self {
        Self {
            status: value.status,
            headers: value.headers,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WireRequestHeader {
    #[serde(with = "http_serde::uri")]
    uri: Uri,
    #[serde(with = "http_serde::header_map")]
    headers: HeaderMap,
}

impl From<RequestParts> for WireRequestHeader {
    fn from(value: RequestParts) -> Self {
        Self {
            uri: value.uri,
            headers: value.headers,
        }
    }
}

// Copied from hyper. Used to transform `BoxBodyBytes` to `Bytes`.
// It might look slow but since in our case the data is fully available
// the first data() call will immediately return everything.
// With hyper 1.0 etc. this situation will improve.
pub(crate) async fn to_bytes<T>(body: T) -> Result<Bytes, T::Error>
where
    T: HttpBody + Unpin,
{
    futures::pin_mut!(body);

    // If there's only 1 chunk, we can just return Buf::to_bytes()
    let mut first = if let Some(buf) = body.data().await {
        buf?
    } else {
        return Ok(Bytes::new());
    };

    let second = if let Some(buf) = body.data().await {
        buf?
    } else {
        return Ok(first.copy_to_bytes(first.remaining()));
    };

    // Don't pre-emptively reserve *too* much.
    let rest = (body.size_hint().lower() as usize).min(1024 * 16);
    let cap = first
        .remaining()
        .saturating_add(second.remaining())
        .saturating_add(rest);
    // With more than 1 buf, we gotta flatten into a Vec first.
    let mut vec = Vec::with_capacity(cap);
    vec.put(first);
    vec.put(second);

    while let Some(buf) = body.data().await {
        vec.put(buf?);
    }

    Ok(vec.into())
}
