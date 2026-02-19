#[cfg(test)]
mod tests;

use crate::mock::CanisterHttpRequestMatcher;
use canhttp::http::json::{ConstantSizeId, Id, JsonRpcRequest};
use pocket_ic::common::rest::{
    CanisterHttpHeader, CanisterHttpMethod, CanisterHttpReply, CanisterHttpRequest,
    CanisterHttpResponse,
};
use serde_json::Value;
use std::{collections::BTreeSet, str::FromStr};
use url::{Host, Url};

/// Matches [`CanisterHttpRequest`]s whose body is a JSON-RPC request.
#[derive(Clone, Debug)]
pub struct JsonRpcRequestMatcher {
    method: String,
    id: Option<Id>,
    params: Option<Value>,
    url: Option<Url>,
    host: Option<Host>,
    request_headers: Option<Vec<CanisterHttpHeader>>,
    max_response_bytes: Option<u64>,
}

impl JsonRpcRequestMatcher {
    /// Create a [`JsonRpcRequestMatcher`] that matches only JSON-RPC requests with the given method.
    pub fn with_method(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            id: None,
            params: None,
            url: None,
            host: None,
            request_headers: None,
            max_response_bytes: None,
        }
    }

    /// Mutates the [`JsonRpcRequestMatcher`] to match only requests whose JSON-RPC request ID is a
    /// [`ConstantSizeId`] with the given value.
    pub fn with_id(self, id: u64) -> Self {
        self.with_raw_id(Id::from(ConstantSizeId::from(id)))
    }

    /// Mutates the [`JsonRpcRequestMatcher`] to match only requests whose JSON-RPC request ID is an
    /// [`Id`] with the given value.
    pub fn with_raw_id(self, id: Id) -> Self {
        Self {
            id: Some(id),
            ..self
        }
    }

    /// Mutates the [`JsonRpcRequestMatcher`] to match only requests with the given JSON-RPC request
    /// parameters.
    pub fn with_params(self, params: impl Into<Value>) -> Self {
        Self {
            params: Some(params.into()),
            ..self
        }
    }

    /// Mutates the [`JsonRpcRequestMatcher`] to match only requests with the given [URL].
    ///
    /// [URL]: https://internetcomputer.org/docs/references/ic-interface-spec#ic-http_request
    pub fn with_url(self, url: &str) -> Self {
        Self {
            url: Some(Url::parse(url).expect("BUG: invalid URL")),
            ..self
        }
    }

    /// Mutates the [`JsonRpcRequestMatcher`] to match only requests whose [URL] has the given host.
    ///
    /// [URL]: https://internetcomputer.org/docs/references/ic-interface-spec#ic-http_request
    pub fn with_host(self, host: &str) -> Self {
        Self {
            host: Some(Host::parse(host).expect("BUG: invalid host for a URL")),
            ..self
        }
    }

    /// Mutates the [`JsonRpcRequestMatcher`] to match requests with the given HTTP headers.
    pub fn with_request_headers(self, headers: Vec<(impl ToString, impl ToString)>) -> Self {
        Self {
            request_headers: Some(
                headers
                    .into_iter()
                    .map(|(name, value)| CanisterHttpHeader {
                        name: name.to_string(),
                        value: value.to_string(),
                    })
                    .collect(),
            ),
            ..self
        }
    }

    /// Mutates the [`JsonRpcRequestMatcher`] to match requests with the given
    /// [`max_response_bytes`].
    ///
    /// [`max_response_bytes`]: https://internetcomputer.org/docs/references/ic-interface-spec#ic-http_request
    pub fn with_max_response_bytes(self, max_response_bytes: impl Into<u64>) -> Self {
        Self {
            max_response_bytes: Some(max_response_bytes.into()),
            ..self
        }
    }
}

impl CanisterHttpRequestMatcher for JsonRpcRequestMatcher {
    fn matches(&self, request: &CanisterHttpRequest) -> bool {
        let req_url = Url::from_str(&request.url).expect("BUG: invalid URL");
        if let Some(ref mock_url) = self.url {
            if mock_url != &req_url {
                return false;
            }
        }
        if let Some(ref host) = self.host {
            match req_url.host() {
                Some(ref req_host) if req_host == host => {}
                _ => return false,
            }
        }
        if CanisterHttpMethod::POST != request.http_method {
            return false;
        }
        if let Some(ref headers) = self.request_headers {
            fn lower_case_header_name(
                CanisterHttpHeader { name, value }: &CanisterHttpHeader,
            ) -> CanisterHttpHeader {
                CanisterHttpHeader {
                    name: name.to_lowercase(),
                    value: value.clone(),
                }
            }
            let expected: BTreeSet<_> = headers.iter().map(lower_case_header_name).collect();
            let actual: BTreeSet<_> = request.headers.iter().map(lower_case_header_name).collect();
            if expected != actual {
                return false;
            }
        }
        match serde_json::from_slice::<JsonRpcRequest<Value>>(&request.body) {
            Ok(actual_body) => {
                if self.method != actual_body.method() {
                    return false;
                }
                if let Some(ref id) = self.id {
                    if id != actual_body.id() {
                        return false;
                    }
                }
                if let Some(ref params) = self.params {
                    if Some(params) != actual_body.params() {
                        return false;
                    }
                }
            }
            // Not a JSON-RPC request
            Err(_) => return false,
        }
        if let Some(max_response_bytes) = self.max_response_bytes {
            if Some(max_response_bytes) != request.max_response_bytes {
                return false;
            }
        }
        true
    }
}

/// A mocked JSON-RPC HTTP outcall response.
#[derive(Clone)]
pub struct JsonRpcResponse {
    status: u16,
    headers: Vec<CanisterHttpHeader>,
    body: Value,
}

impl From<Value> for JsonRpcResponse {
    fn from(body: Value) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body,
        }
    }
}

impl JsonRpcResponse {
    /// Mutates the response to set the given JSON-RPC response ID to a [`ConstantSizeId`] with the
    /// given value.
    pub fn with_id(self, id: u64) -> JsonRpcResponse {
        self.with_raw_id(Id::from(ConstantSizeId::from(id)))
    }

    /// Mutates the response to set the given JSON-RPC response ID to the given [`Id`].
    pub fn with_raw_id(mut self, id: Id) -> JsonRpcResponse {
        self.body["id"] = serde_json::to_value(id).expect("BUG: cannot serialize ID");
        self
    }
}

impl From<&Value> for JsonRpcResponse {
    fn from(body: &Value) -> Self {
        Self::from(body.clone())
    }
}

impl From<String> for JsonRpcResponse {
    fn from(body: String) -> Self {
        Self::from(Value::from_str(&body).expect("BUG: invalid JSON-RPC response"))
    }
}

impl From<&str> for JsonRpcResponse {
    fn from(body: &str) -> Self {
        Self::from(body.to_string())
    }
}

impl From<JsonRpcResponse> for CanisterHttpResponse {
    fn from(response: JsonRpcResponse) -> Self {
        CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: response.status,
            headers: response.headers,
            body: serde_json::to_vec(&response.body).unwrap(),
        })
    }
}
