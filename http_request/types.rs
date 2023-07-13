use crate::id;
use candid::CandidType;
use serde::{Deserialize, Serialize};

mod transform {
    #![allow(missing_docs)]

    // The struct `TransformFunc` is defined by a macro.
    // Adding doc comment directly above the macro doesn't work.
    // The workaround is to re-export it and document there.
    // TODO: upgrade Rust toolchain (https://dfinity.atlassian.net/browse/SDK-1183)
    use super::*;

    candid::define_function!(pub TransformFunc : (TransformArgs) -> (HttpResponse) query);
}

/// "transform" function of type: `func (http_response) -> (http_response) query`
pub use transform::TransformFunc;

/// Type used for encoding/decoding:
/// `record {
///     response : http_response;
///     context : blob;
/// }`
#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransformArgs {
    /// Raw response from remote service, to be transformed
    pub response: HttpResponse,

    /// Context for response transformation
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

/// Type used for encoding/decoding:
/// `record {
///     function : func (record {response : http_response; context : blob}) -> (http_response) query;
///     context : blob;
/// }`
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TransformContext {
    /// Reference function with signature: `func (record {response : http_response; context : blob}) -> (http_response) query;`.
    pub function: TransformFunc,

    /// Context to be passed to `transform` function to transform HTTP response for consensus
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

impl TransformContext {
    /// Constructs a TransformContext from a name and context. The principal is assumed to be the [current canister's](id).
    pub fn from_name(candid_function_name: String, context: Vec<u8>) -> Self {
        Self {
            context,
            function: TransformFunc(candid::Func {
                method: candid_function_name,
                principal: id(),
            }),
        }
    }
}

/// HTTP header.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct HttpHeader {
    /// Name
    pub name: String,
    /// Value
    pub value: String,
}

/// HTTP method.
///
/// Currently support following methods.
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    Copy,
    Default,
)]
pub enum HttpMethod {
    /// GET
    #[serde(rename = "get")]
    #[default]
    GET,
    /// POST
    #[serde(rename = "post")]
    POST,
    /// HEAD
    #[serde(rename = "head")]
    HEAD,
}

/// Argument type of [super::http_request].
#[derive(CandidType, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct CanisterHttpRequestArgument {
    /// The requested URL.
    pub url: String,
    /// The maximal size of the response in bytes. If None, 2MiB will be the limit.
    /// This value affects the cost of the http request and it is highly recommended
    /// to set it as low as possible to avoid unnecessary extra costs.
    /// See also the [pricing section of HTTP outcalls documentation](https://internetcomputer.org/docs/current/developer-docs/integrations/http_requests/http_requests-how-it-works#pricing).
    pub max_response_bytes: Option<u64>,
    /// The method of HTTP request.
    pub method: HttpMethod,
    /// List of HTTP request headers and their corresponding values.
    pub headers: Vec<HttpHeader>,
    /// Optionally provide request body.
    pub body: Option<Vec<u8>>,
    /// Name of the transform function which is `func (transform_args) -> (http_response) query`.
    /// Set to `None` if you are using `http_request_with` or `http_request_with_cycles_with`.
    pub transform: Option<TransformContext>,
}

/// The returned HTTP response.
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct HttpResponse {
    /// The response status (e.g., 200, 404).
    pub status: candid::Nat,
    /// List of HTTP response headers and their corresponding values.
    pub headers: Vec<HttpHeader>,
    /// The response’s body.
    pub body: Vec<u8>,
}
