use crate::{
    convert::Convert,
    http::{
        json::{ConstantSizeId, Id, Version},
        HttpRequest,
    },
};
use http::{header::CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use thiserror::Error;

/// Convert requests of type [`http::Request<T>`], where `T` is `Serializable`,
/// into [`HttpRequest`] by serializing the request body as a JSON byte vector.
#[derive(Debug)]
pub struct JsonRequestConverter<T> {
    _marker: PhantomData<T>,
}

impl<T> JsonRequestConverter<T> {
    /// Create a new instance of [`JsonRequestConverter`].
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

// #[derive(Clone)] would otherwise introduce a bound T: Clone, which is not needed.
impl<T> Clone for JsonRequestConverter<T> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
        }
    }
}

impl<T> Default for JsonRequestConverter<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Error return when converting requests with [`JsonRequestConverter`].
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum JsonRequestConversionError {
    /// Request body failed to be serialized.
    #[error("Invalid JSON body: {0}")]
    InvalidJson(String),
}

impl<T> Convert<http::Request<T>> for JsonRequestConverter<T>
where
    T: Serialize,
{
    type Output = HttpRequest;
    type Error = JsonRequestConversionError;

    fn try_convert(&mut self, request: http::Request<T>) -> Result<Self::Output, Self::Error> {
        try_serialize_request(request).map(add_content_type_header_if_missing)
    }
}

fn try_serialize_request<T>(
    request: http::Request<T>,
) -> Result<HttpRequest, JsonRequestConversionError>
where
    T: Serialize,
{
    let (parts, body) = request.into_parts();
    let json_body = serde_json::to_vec(&body)
        .map_err(|e| JsonRequestConversionError::InvalidJson(e.to_string()))?;
    Ok(HttpRequest::from_parts(parts, json_body))
}

fn add_content_type_header_if_missing(mut request: HttpRequest) -> HttpRequest {
    if !request.headers().contains_key(CONTENT_TYPE) {
        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    request
}

/// Batch JSON-RPC request over HTTP.
pub type HttpBatchJsonRpcRequest<T> = http::Request<BatchJsonRpcRequest<T>>;

/// JSON-RPC request over HTTP.
pub type HttpJsonRpcRequest<T> = http::Request<JsonRpcRequest<T>>;

/// Batch JSON-RPC request body, see the [specification].
///
/// [specification]: https://www.jsonrpc.org/specification
pub type BatchJsonRpcRequest<T> = Vec<JsonRpcRequest<T>>;

/// JSON-RPC request body, see the [specification].
///
/// [specification]: https://www.jsonrpc.org/specification
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    jsonrpc: Version,
    method: String,
    id: Id,
    params: Option<T>,
}

impl<T> JsonRpcRequest<T> {
    /// Create a new body of a JSON-RPC request.
    ///
    /// By default, constant-size ID is used. See [`ConstantSizeId`].
    pub fn new(method: impl Into<String>, params: T) -> Self {
        Self {
            jsonrpc: Version::V2,
            method: method.into(),
            id: ConstantSizeId::ZERO.into(),
            params: Some(params),
        }
    }

    /// Change the request ID following the builder pattern.
    pub fn with_id<I: Into<Id>>(self, id: I) -> Self {
        Self {
            id: id.into(),
            ..self
        }
    }

    /// Change the request ID.
    pub fn set_id(&mut self, id: Id) {
        self.id = id;
    }

    /// Returns the request ID, if any.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Returns the JSON-RPC method.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Return the JSON-RPC params, if any.
    pub fn params(&self) -> Option<&T> {
        self.params.as_ref()
    }
}
