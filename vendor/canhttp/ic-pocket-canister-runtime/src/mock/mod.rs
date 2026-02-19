use pocket_ic::common::rest::{CanisterHttpHeader, CanisterHttpRequest, CanisterHttpResponse};
use serde_json::Value;
use std::fmt::Debug;

pub mod json;

/// A collection of HTTP outcall mocks.
///
/// When an instance of [`MockHttpOutcalls`] is dropped, it panics if not all mocks were
/// consumed (i.e., if it is not empty).
#[derive(Debug, Default)]
pub struct MockHttpOutcalls(Vec<MockHttpOutcall>);

impl MockHttpOutcalls {
    /// Asserts that no HTTP outcalls are performed.
    pub fn never() -> MockHttpOutcalls {
        MockHttpOutcalls(Vec::new())
    }

    /// Add a new mocked HTTP outcall.
    pub fn push(&mut self, mock: MockHttpOutcall) {
        self.0.push(mock);
    }

    /// Returns a matching [`MockHttpOutcall`] for the given request if there is one, otherwise
    /// [`None`].
    /// Panics if there are more than one matching [`MockHttpOutcall`]s for the given request.
    pub fn pop_matching(&mut self, request: &CanisterHttpRequest) -> Option<MockHttpOutcall> {
        let matching_positions = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(i, mock)| {
                if mock.request.matches(request) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        match matching_positions.len() {
            0 => None,
            1 => Some(self.0.swap_remove(matching_positions[0])),
            _ => panic!("Multiple mocks match the request: {:?}", request),
        }
    }
}

impl Drop for MockHttpOutcalls {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            panic!(
                "MockHttpOutcalls dropped but {} mocks were not consumed: {:?}",
                self.0.len(),
                self.0
            );
        }
    }
}

#[derive(Debug)]
#[must_use]
/// A mocked HTTP outcall with a mocked canister response and a [`CanisterHttpRequestMatcher`] to
/// find matching requests.
pub struct MockHttpOutcall {
    /// The matcher to find matching requests.
    pub request: Box<dyn CanisterHttpRequestMatcher>,
    /// The mocked canister response.
    pub response: CanisterHttpResponse,
}

/// A [`MockHttpOutcallsBuilder`] to create a [`MockHttpOutcalls`] with a fluent API.
#[derive(Debug, Default)]
pub struct MockHttpOutcallsBuilder(MockHttpOutcalls);

impl MockHttpOutcallsBuilder {
    /// Create a new empty [`MockHttpOutcallsBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Used with [`respond_with`] to add a new mock.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ic_pocket_canister_runtime::{
    ///     CanisterHttpReply, JsonRpcRequestMatcher, MockHttpOutcallsBuilder
    /// };
    ///
    /// # let builder =
    /// MockHttpOutcallsBuilder::new()
    ///     .given(JsonRpcRequestMatcher::with_method("eth_getLogs"))
    ///     .respond_with(CanisterHttpReply::with_status(403));
    /// # use candid::Principal;
    /// # use pocket_ic::common::rest::{CanisterHttpMethod, CanisterHttpRequest};
    /// # use serde_json::json;
    /// # let request = CanisterHttpRequest {
    /// #     subnet_id: Principal::anonymous(),
    /// #     request_id: 0,
    /// #     http_method: CanisterHttpMethod::POST,
    /// #     url: "https://ethereum.publicnode.com/".to_string(),
    /// #     headers: vec![],
    /// #     body: serde_json::to_vec(&json!({"jsonrpc": "2.0", "method": "eth_getLogs", "id": 1})).unwrap(),
    /// #     max_response_bytes: None,
    /// # };
    /// # builder.build().pop_matching(&request);
    /// ```
    ///
    /// [`respond_with`]: MockHttpOutcallBuilder::respond_with
    pub fn given(
        self,
        request: impl CanisterHttpRequestMatcher + 'static,
    ) -> MockHttpOutcallBuilder {
        MockHttpOutcallBuilder {
            parent: self,
            request: Box::new(request),
        }
    }

    /// Creates a [`MockHttpOutcalls`] from [`MockHttpOutcallBuilder`].
    pub fn build(self) -> MockHttpOutcalls {
        self.0
    }
}

impl From<MockHttpOutcallsBuilder> for MockHttpOutcalls {
    fn from(builder: MockHttpOutcallsBuilder) -> Self {
        builder.build()
    }
}

/// The result of calling [`MockHttpOutcallsBuilder::given`], used to add a new mock to a
/// [`MockHttpOutcallsBuilder`].
/// See the [`respond_with`] method.
///
/// [`respond_with`]: MockHttpOutcallBuilder::respond_with
#[must_use]
pub struct MockHttpOutcallBuilder {
    parent: MockHttpOutcallsBuilder,
    request: Box<dyn CanisterHttpRequestMatcher>,
}

impl MockHttpOutcallBuilder {
    /// Used with [`given`] to add a new mock.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ic_pocket_canister_runtime::{
    ///     CanisterHttpReply, JsonRpcRequestMatcher, MockHttpOutcallsBuilder
    /// };
    ///
    /// # let builder =
    /// MockHttpOutcallsBuilder::new()
    ///     .given(JsonRpcRequestMatcher::with_method("eth_getLogs"))
    ///     .respond_with(CanisterHttpReply::with_status(403));
    /// # use candid::Principal;
    /// # use pocket_ic::common::rest::{CanisterHttpMethod, CanisterHttpRequest};
    /// # use serde_json::json;
    /// # let request = CanisterHttpRequest {
    /// #     subnet_id: Principal::anonymous(),
    /// #     request_id: 0,
    /// #     http_method: CanisterHttpMethod::POST,
    /// #     url: "https://ethereum.publicnode.com/".to_string(),
    /// #     headers: vec![],
    /// #     body: serde_json::to_vec(&json!({"jsonrpc": "2.0", "method": "eth_getLogs", "id": 1})).unwrap(),
    /// #     max_response_bytes: None,
    /// # };
    /// # builder.build().pop_matching(&request);
    /// ```
    ///
    /// [`given`]: MockHttpOutcallsBuilder::given
    pub fn respond_with(
        mut self,
        response: impl Into<CanisterHttpResponse>,
    ) -> MockHttpOutcallsBuilder {
        self.parent.0.push(MockHttpOutcall {
            request: self.request,
            response: response.into(),
        });
        self.parent
    }
}

/// A trait that allows checking if a given [`CanisterHttpRequest`] matches an HTTP outcall mock.
pub trait CanisterHttpRequestMatcher: Send + Sync + Debug {
    /// Returns whether the given [`CanisterHttpRequest`] matches.
    fn matches(&self, request: &CanisterHttpRequest) -> bool;
}

/// Implementation of [`CanisterHttpRequestMatcher`] that matches all requests.
#[derive(Debug)]
pub struct AnyCanisterHttpRequestMatcher;

impl CanisterHttpRequestMatcher for AnyCanisterHttpRequestMatcher {
    fn matches(&self, _request: &CanisterHttpRequest) -> bool {
        true
    }
}

/// A wrapper over [`CanisterHttpReply`] that offers a fluent API to create instances.
///
/// # Examples
///
/// ```rust
/// use ic_pocket_canister_runtime::CanisterHttpReply;
/// use pocket_ic::common::rest::{CanisterHttpHeader, CanisterHttpResponse};
/// use serde_json::json;
///
/// let response: CanisterHttpResponse = CanisterHttpReply::with_status(200)
///     .with_body(json!({
///         "jsonrpc": "2.0",
///         "result": 19,
///         "id": 1
///     }))
///     .with_headers(vec![("Content-Type", "application/json")])
///     .into();
///
/// assert_eq!(response, CanisterHttpResponse::CanisterHttpReply(
///     pocket_ic::common::rest::CanisterHttpReply {
///         status: 200,
///         headers: vec![
///             CanisterHttpHeader {
///                 name: "Content-Type".to_string(),
///                 value: "application/json".to_string()
///             }
///         ],
///         body: serde_json::to_vec(&json!({
///             "jsonrpc": "2.0",
///             "result": 19,
///             "id": 1
///         })).unwrap(),
///     }
/// ))
/// ```
///
/// [`CanisterHttpReply`]: pocket_ic::common::rest::CanisterHttpReply
pub struct CanisterHttpReply(pocket_ic::common::rest::CanisterHttpReply);

impl CanisterHttpReply {
    /// Create a [`CanisterHttpReply`] with the given status.
    pub fn with_status(status: u16) -> Self {
        Self(pocket_ic::common::rest::CanisterHttpReply {
            status,
            headers: vec![],
            body: vec![],
        })
    }

    /// Mutates the [`CanisterHttpReply`] to set the body.
    pub fn with_body(mut self, body: impl Into<Value>) -> Self {
        self.0.body = serde_json::to_vec(&body.into()).unwrap();
        self
    }

    /// Mutates the [`CanisterHttpReply`] to set the headers.
    pub fn with_headers(
        mut self,
        headers: impl IntoIterator<Item = (impl ToString, impl ToString)>,
    ) -> Self {
        self.0.headers = headers
            .into_iter()
            .map(|(name, value)| CanisterHttpHeader {
                name: name.to_string(),
                value: value.to_string(),
            })
            .collect();
        self
    }
}

impl From<CanisterHttpReply> for CanisterHttpResponse {
    fn from(value: CanisterHttpReply) -> Self {
        CanisterHttpResponse::CanisterHttpReply(value.0)
    }
}

/// A wrapper over [`CanisterHttpReject`] that offers a fluent API to create instances.
///
/// # Examples
///
/// ```rust
/// use ic_error_types::RejectCode;
/// use ic_pocket_canister_runtime::CanisterHttpReject;
/// use pocket_ic::common::rest::CanisterHttpResponse;
///
/// let response: CanisterHttpResponse = CanisterHttpReject::with_reject_code(RejectCode::SysTransient)
///     .with_message("No consensus could be reached. Replicas had different responses.")
///     .into();
///
/// assert_eq!(response, CanisterHttpResponse::CanisterHttpReject(
///     pocket_ic::common::rest::CanisterHttpReject {
///         reject_code: RejectCode::SysTransient as u64,
///         message: "No consensus could be reached. Replicas had different responses.".to_string(),
///     }
/// ))
/// ```
///
/// [`CanisterHttpReject`]: pocket_ic::common::rest::CanisterHttpReject
pub struct CanisterHttpReject(pocket_ic::common::rest::CanisterHttpReject);

impl CanisterHttpReject {
    /// Create a [`CanisterHttpReject`] with the given reject code.
    pub fn with_reject_code(reject_code: ic_error_types::RejectCode) -> Self {
        Self(pocket_ic::common::rest::CanisterHttpReject {
            reject_code: reject_code as u64,
            message: String::new(),
        })
    }

    /// Mutates the [`CanisterHttpReject`] to set the message.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.0.message = message.into();
        self
    }
}

impl From<CanisterHttpReject> for CanisterHttpResponse {
    fn from(value: CanisterHttpReject) -> Self {
        CanisterHttpResponse::CanisterHttpReject(value.0)
    }
}
