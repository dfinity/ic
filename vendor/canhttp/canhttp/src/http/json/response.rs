use crate::{
    convert::{Convert, CreateResponseFilter, Filter},
    http::{
        json::{
            BatchJsonRpcRequest, HttpBatchJsonRpcRequest, HttpJsonRpcRequest, Id, JsonRpcRequest,
            Version,
        },
        HttpResponse,
    },
};
use itertools::{Either, Itertools};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::{collections::BTreeMap, fmt::Debug, marker::PhantomData};
use thiserror::Error;

#[cfg(test)]
mod tests;

/// Convert responses of type [HttpResponse] into [`http::Response<T>`], where `T` is `Deserialize`
/// by parsing the response body as JSON text bytes.
#[derive(Debug)]
pub struct JsonResponseConverter<T> {
    _marker: PhantomData<T>,
}

impl<T> JsonResponseConverter<T> {
    /// Create a new instance of [`JsonResponseConverter`].
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

// #[derive(Clone)] would otherwise introduce a bound T: Clone, which is not needed.
impl<T> Clone for JsonResponseConverter<T> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
        }
    }
}

impl<T> Default for JsonResponseConverter<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when converting responses with [`JsonResponseConverter`].
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum JsonResponseConversionError {
    /// Response body could not be deserialized into a JSON-RPC response.
    #[error("Invalid HTTP JSON-RPC response: status {status}, body: {body}, parsing error: {parsing_error:?}"
    )]
    InvalidJsonResponse {
        /// Response status code
        status: u16,
        /// Response body
        body: String,
        /// Deserialization error
        parsing_error: String,
    },
}

impl<T> Convert<HttpResponse> for JsonResponseConverter<T>
where
    T: DeserializeOwned,
{
    type Output = http::Response<T>;
    type Error = JsonResponseConversionError;

    fn try_convert(&mut self, response: HttpResponse) -> Result<Self::Output, Self::Error> {
        let (parts, body) = response.into_parts();
        let json_body: T = serde_json::from_slice(&body).map_err(|e| {
            JsonResponseConversionError::InvalidJsonResponse {
                status: parts.status.as_u16(),
                body: String::from_utf8_lossy(&body).to_string(),
                parsing_error: e.to_string(),
            }
        })?;
        Ok(http::Response::from_parts(parts, json_body))
    }
}

/// JSON-RPC response over HTTP.
pub type HttpJsonRpcResponse<T> = http::Response<JsonRpcResponse<T>>;

/// Batch JSON-RPC response body, see the [specification].
///
/// [specification]: https://www.jsonrpc.org/specification
pub type BatchJsonRpcResponse<T> = Vec<JsonRpcResponse<T>>;

/// Batch JSON-RPC response over HTTP.
pub type HttpBatchJsonRpcResponse<T> = http::Response<Vec<JsonRpcResponse<T>>>;

/// A specialized [`Result`] error type for JSON-RPC responses.
///
/// [`Result`]: enum@std::result::Result
pub type JsonRpcResult<T> = Result<T, JsonRpcError>;

/// JSON-RPC response body, see the [specification].
///
/// [specification]: https://www.jsonrpc.org/specification
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    jsonrpc: Version,
    id: Id,
    #[serde(flatten)]
    result: JsonRpcResultEnvelope<T>,
}

impl<T> JsonRpcResponse<T> {
    /// Creates a new successful response from a request ID and `Error` object.
    pub const fn from_ok(id: Id, result: T) -> Self {
        Self {
            jsonrpc: Version::V2,
            result: JsonRpcResultEnvelope::Ok(result),
            id,
        }
    }

    /// Creates a new error response from a request ID and `Error` object.
    pub const fn from_error(id: Id, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: Version::V2,
            result: JsonRpcResultEnvelope::Err(error),
            id,
        }
    }

    /// Creates a new response from a request ID and either an `Ok(Value)` or `Err(Error)` body.
    pub fn from_parts(id: Id, result: JsonRpcResult<T>) -> Self {
        match result {
            Ok(r) => JsonRpcResponse::from_ok(id, r),
            Err(e) => JsonRpcResponse::from_error(id, e),
        }
    }

    /// Splits the response into a request ID paired with either an `Ok(Value)` or `Err(Error)` to
    /// signify whether the response is a success or failure.
    pub fn into_parts(self) -> (Id, JsonRpcResult<T>) {
        (self.id, self.result.into_result())
    }

    /// Similar to [`Self::into_parts`] but only takes a reference.
    pub fn as_parts(&self) -> (&Id, Result<&T, &JsonRpcError>) {
        (&self.id, self.as_result())
    }

    /// Convert this response into a result.
    ///
    /// A successful response will be converted to an `Ok` value,
    /// while a non-successful response will be converted into an `Err(JsonRpcError)`.
    pub fn into_result(self) -> JsonRpcResult<T> {
        self.result.into_result()
    }

    /// Similar to [`Self::into_result`] but only takes a reference.
    pub fn as_result(&self) -> Result<&T, &JsonRpcError> {
        self.result.as_result()
    }

    /// Mutate this response as a mutable result.
    pub fn as_result_mut(&mut self) -> Result<&mut T, &mut JsonRpcError> {
        self.result.as_result_mut()
    }

    /// Return the response ID.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Map this response's result by the given function.
    pub fn map<R>(self, f: impl FnOnce(T) -> R) -> JsonRpcResponse<R> {
        JsonRpcResponse {
            jsonrpc: self.jsonrpc,
            id: self.id,
            result: self.result.map(f),
        }
    }
}

/// An envelope for all JSON-RPC responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum JsonRpcResultEnvelope<T> {
    /// Successful JSON-RPC response
    #[serde(rename = "result")]
    Ok(T),
    /// Failed JSON-RPC response
    #[serde(rename = "error")]
    Err(JsonRpcError),
}

impl<T> JsonRpcResultEnvelope<T> {
    fn into_result(self) -> JsonRpcResult<T> {
        match self {
            JsonRpcResultEnvelope::Ok(result) => Ok(result),
            JsonRpcResultEnvelope::Err(error) => Err(error),
        }
    }

    fn as_result(&self) -> Result<&T, &JsonRpcError> {
        match self {
            JsonRpcResultEnvelope::Ok(result) => Ok(result),
            JsonRpcResultEnvelope::Err(error) => Err(error),
        }
    }

    fn as_result_mut(&mut self) -> Result<&mut T, &mut JsonRpcError> {
        match self {
            JsonRpcResultEnvelope::Ok(result) => Ok(result),
            JsonRpcResultEnvelope::Err(error) => Err(error),
        }
    }

    fn map<R>(self, f: impl FnOnce(T) -> R) -> JsonRpcResultEnvelope<R> {
        match self {
            JsonRpcResultEnvelope::Ok(result) => JsonRpcResultEnvelope::Ok(f(result)),
            JsonRpcResultEnvelope::Err(error) => JsonRpcResultEnvelope::Err(error),
        }
    }
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, Eq, PartialEq, Error, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[error("JSON-RPC error (code: {code}): {message}. Details: {data:?}")]
pub struct JsonRpcError {
    /// Indicate error type that occurred.
    pub code: i64,
    /// Short description of the error.
    pub message: String,
    /// Additional information about the error, if any.
    ///
    /// The value of this member is defined by the Server
    /// (e.g. detailed error information, nested errors etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new JSON-RPC error without `data`.
    pub fn new(code: impl Into<i64>, message: impl Into<String>) -> Self {
        let code = code.into();
        let message = message.into();
        Self {
            code,
            message,
            data: None,
        }
    }

    /// Return `true` if and only if the error code indicates a parsing error
    /// according to the [JSON-RPC specification](https://www.jsonrpc.org/specification).
    pub fn is_parse_error(&self) -> bool {
        self.code == -32700
    }

    /// Return `true` if and only if the error code indicates an invalid request
    /// according to the [JSON-RPC specification](https://www.jsonrpc.org/specification).
    pub fn is_invalid_request(&self) -> bool {
        self.code == -32600
    }

    /// An invalid request JSON-RPC error object,
    /// as defined in the [JSON-RPC specification](https://www.jsonrpc.org/specification).
    pub fn invalid_request() -> Self {
        Self::new(-32600, "Invalid Request")
    }

    /// A parse error JSON-RPC error object,
    /// as defined in the [JSON-RPC specification](https://www.jsonrpc.org/specification).
    pub fn parse_error() -> Self {
        Self::new(-32700, "Parse error")
    }
}

/// Error returned by the [`ConsistentJsonRpcIdFilter`].
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ConsistentResponseIdFilterError {
    /// ID of the response does not match that of the request.
    #[error(
        "Unexpected identifier: expected response ID to be {request_id}, but got {response_id}"
    )]
    InconsistentId {
        /// Response status code.
        status: u16,
        /// ID from the request.
        request_id: Id,
        /// ID from the response.
        response_id: Id,
    },
    /// IDs in the response either contain unexpected IDs or are missing some request IDs
    #[error(
        "Inconsistent identifiers: expected batch response IDs to be {request_ids:?}, but got {response_ids:?}"
    )]
    InconsistentBatchIds {
        /// Response status code.
        status: u16,
        /// IDs from the request.
        request_ids: Vec<Id>,
        /// IDs from the response.
        response_ids: Vec<Id>,
    },
}

/// Create [`ConsistentJsonRpcIdFilter`] for each request.
pub struct CreateJsonRpcIdFilter<Request, Response> {
    _marker: PhantomData<(Request, Response)>,
}

impl<Request, Response> CreateJsonRpcIdFilter<Request, Response> {
    /// Create a new instance of [`CreateJsonRpcIdFilter`]
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<Request, Response> Clone for CreateJsonRpcIdFilter<Request, Response> {
    fn clone(&self) -> Self {
        Self {
            _marker: self._marker,
        }
    }
}

impl<Request, Response> Default for CreateJsonRpcIdFilter<Request, Response> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, O> CreateResponseFilter<HttpJsonRpcRequest<I>, HttpJsonRpcResponse<O>>
    for CreateJsonRpcIdFilter<JsonRpcRequest<I>, JsonRpcResponse<O>>
where
    JsonRpcRequest<I>: Serialize,
    JsonRpcResponse<O>: DeserializeOwned,
{
    type Filter = ConsistentJsonRpcIdFilter<JsonRpcRequest<I>, JsonRpcResponse<O>>;
    type Error = ConsistentResponseIdFilterError;

    fn create_filter(&self, request: &HttpJsonRpcRequest<I>) -> Self::Filter {
        let request_id = expected_response_id(request.body());
        ConsistentJsonRpcIdFilter::new(vec![request_id])
    }
}

impl<I, O> CreateResponseFilter<HttpBatchJsonRpcRequest<I>, HttpBatchJsonRpcResponse<O>>
    for CreateJsonRpcIdFilter<BatchJsonRpcRequest<I>, BatchJsonRpcResponse<O>>
where
    BatchJsonRpcRequest<I>: Serialize,
    BatchJsonRpcResponse<O>: DeserializeOwned,
{
    type Filter = ConsistentJsonRpcIdFilter<BatchJsonRpcRequest<I>, BatchJsonRpcResponse<O>>;
    type Error = ConsistentResponseIdFilterError;

    /// # Panics
    ///
    /// This implementation panics in the following cases:
    /// * The JSON-RPC batch is empty.
    /// * The IDs of the requests in the JSON-RPC batch are not unique.
    fn create_filter(&self, request: &HttpBatchJsonRpcRequest<I>) -> Self::Filter {
        let requests = request.body();

        assert!(!requests.is_empty(), "Expected batch to not be empty");

        let request_ids = requests
            .iter()
            .map(expected_response_id)
            .collect::<Vec<_>>();
        assert_eq!(
            BTreeSet::from_iter(request_ids.iter()).len(),
            requests.len(),
            "Expected request IDs to be unique, but got: {request_ids:?}"
        );

        ConsistentJsonRpcIdFilter::new(request_ids)
    }
}

/// Ensure that the ID of the response is consistent with the one from the request
/// that is stored internally.
pub struct ConsistentJsonRpcIdFilter<Request, Response> {
    request_ids: Vec<Id>,
    _marker: PhantomData<(Request, Response)>,
}

impl<Request, Response> ConsistentJsonRpcIdFilter<Request, Response> {
    /// Creates a new JSON-RPC filter to ensure that the response IDs match the given request
    /// IDs.
    ///
    /// # Panics
    ///
    /// The method panics if any of the given IDs is [`Id::Null`].
    /// This is because a request ID with value [`Id::Null`] indicates a Notification,
    /// which indicates that the client does not care about the response (see the
    /// JSON-RPC [specification](https://www.jsonrpc.org/specification)).
    fn new(request_ids: Vec<Id>) -> Self {
        Self {
            request_ids,
            _marker: PhantomData,
        }
    }
}

impl<I, O> Filter<HttpJsonRpcResponse<O>>
    for ConsistentJsonRpcIdFilter<JsonRpcRequest<I>, JsonRpcResponse<O>>
where
    JsonRpcRequest<I>: Serialize,
    JsonRpcResponse<O>: DeserializeOwned,
{
    type Error = ConsistentResponseIdFilterError;

    fn filter(
        &mut self,
        response: HttpJsonRpcResponse<O>,
    ) -> Result<HttpJsonRpcResponse<O>, Self::Error> {
        // From the [JSON-RPC specification](https://www.jsonrpc.org/specification):
        // > If there was an error in detecting the id in the Request object
        // > (e.g. Parse error/Invalid Request), it MUST be Null.
        fn should_have_null_id<T>(response: &JsonRpcResponse<T>) -> bool {
            let (response_id, result) = response.as_parts();
            response_id.is_null()
                && result.is_err_and(|e| e.is_parse_error() || e.is_invalid_request())
        }

        let request_id = self
            .request_ids
            .iter()
            .exactly_one()
            .expect("Expected request ID to contain only a single ID");
        let response_id = response.body().id();
        if request_id == response_id || should_have_null_id(response.body()) {
            Ok(response)
        } else {
            Err(ConsistentResponseIdFilterError::InconsistentId {
                status: response.status().into(),
                request_id: request_id.clone(),
                response_id: response_id.clone(),
            })
        }
    }
}

impl<I, O> Filter<HttpBatchJsonRpcResponse<O>>
    for ConsistentJsonRpcIdFilter<BatchJsonRpcRequest<I>, BatchJsonRpcResponse<O>>
where
    BatchJsonRpcRequest<I>: Serialize,
    BatchJsonRpcResponse<O>: DeserializeOwned,
{
    type Error = ConsistentResponseIdFilterError;

    fn filter(
        &mut self,
        response: HttpBatchJsonRpcResponse<O>,
    ) -> Result<HttpBatchJsonRpcResponse<O>, Self::Error> {
        let (head, responses) = response.into_parts();
        let response_ids: Vec<Id> = responses
            .iter()
            .map(|response| response.id())
            .cloned()
            .collect();
        let correlated_responses = try_order_responses_by_id(&self.request_ids, responses)
            .ok_or_else(|| ConsistentResponseIdFilterError::InconsistentBatchIds {
                status: head.status.into(),
                request_ids: self.request_ids.to_vec(),
                response_ids,
            })?;
        Ok(http::Response::from_parts(head, correlated_responses))
    }
}

fn expected_response_id<T>(request: &JsonRpcRequest<T>) -> Id {
    match request.id() {
        Id::Null => panic!("ERROR: a null request ID is a notification that indicates that the client is not interested in the response."),
        id @ (Id::Number(_) | Id::String(_)) => id.clone()
    }
}

fn try_order_responses_by_id<T>(
    request_ids: &[Id],
    responses: Vec<JsonRpcResponse<T>>,
) -> Option<Vec<JsonRpcResponse<T>>> {
    if request_ids.len() != responses.len() {
        return None;
    }

    let (responses_with_null_id, mut responses_with_non_null_id): (Vec<_>, BTreeMap<_, _>) =
        responses
            .into_iter()
            .partition_map(|response| match response.id() {
                Id::Null => Either::Left(response),
                _ => Either::Right((response.id().clone(), response)),
            });

    // From the [JSON-RPC specification](https://www.jsonrpc.org/specification):
    // > If there was an error in detecting the id in the Request object
    // > (e.g. Parse error/Invalid Request), it MUST be Null.
    // However, a parse error should result in a single error object for the response:
    // > If the batch rpc call itself fails to be recognized as an valid JSON or as an Array
    // > with at least one value, the response from the Server MUST be a single Response object.
    // Hence, a null ID must only occur in the event of an invalid request error.
    if !responses_with_null_id
        .iter()
        .all(|response| response.as_result().is_err_and(|e| e.is_invalid_request()))
    {
        return None;
    }
    let num_responses_with_null_id = responses_with_null_id.len();

    // Correlate responses to requests by ID
    let mut num_missing_request_ids = 0;
    let correlated_responses = request_ids
        .iter()
        .map(
            |request_id| match responses_with_non_null_id.remove(request_id) {
                Some(response) => response,
                None => {
                    num_missing_request_ids += 1;
                    JsonRpcResponse::from_parts(Id::Null, Err(JsonRpcError::invalid_request()))
                }
            },
        )
        .collect::<Vec<_>>();

    // Make sure there are no missing or unexpected request IDs, i.e., the only missing request IDs
    // are those for which the response is an invalid request error.
    if num_responses_with_null_id != num_missing_request_ids {
        return None;
    }

    Some(correlated_responses)
}
