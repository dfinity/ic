//! Types necessary for consensus to perform http requests.
//!
//! The lifecycle of a request looks as follows:
//!
//! 1a. When a canister makes a http request, the [`CanisterHttpRequestContext`] is stored in the state.
//!     The canister http pool manager (which is a thread that continuously checks for requests)
//!     will take the request and pass it to the network layer to make the actual request.
//!
//! 1b. The response may be passed to a transform function, which can make arbitrary changes to the response.
//!     The purpose of the transform function is to give the canister developer the ability to shrink the response to
//!     only contain the data that they are interested in. Furthermore, it allows the canister developer to remove
//!     non-determistic parts of the response (such as timestamps) from the response, to help reaching consensus on
//!     the response.
//!     Afterwards it is returned to the consensus layer as a [`CanisterHttpResponseContent`].
//!
//! 2. Now we need to get consensus of the content. Since the actual [`CanisterHttpResponseContent`] could be large and we
//!    require n-to-n communication, we will turn the content into a much smaller [`CanisterHttpResponseMetadata`] object,
//!    that contains all the the important information (such as the response hash) required to achieve consensus.
//!
//! 3a. We sign the metadata to get the [`CanisterHttpResponseShare`] and store it in the pool.
//!
//! 3b. We gossip [`CanisterHttpResponseShare`]s, until we have enough shares to aggregate them into a
//!     [`CanisterHttpResponseProof`]. Together with the content, this artifact forms the [`CanisterHttpResponseWithConsensus`],
//!     which is the artifact we can include into the block to prove consensus on the response.
//!
//! 4a. Once the [`CanisterHttpResponseWithConsensus`] has made it into a finalized block, the response is delivered
//!     to execution to resume the initial call.
//!
//! 4b. Since there is no guarantee that all nodes will get the same [`CanisterHttpResponseContent`] back from the server,
//!     there is no guarantee to reach consensus on a single [`CanisterHttpResponseMetadata`] either.
//!     This can often be detected by the block maker, allowing to return an error as soon as possible
//!     to the canister, such that execution to resume faster.
//!     The blockmaker compiles a [`CanisterHttpResponseDivergence`] proof and includes it in it's payload.
//!     Once the proof has made it into a finalized block, the request is answered with an error message.
//!
//! Early detection of non-deterministic server responses is not guaranteed to work if malicious nodes are present,
//! which sign multiple different responses for the same request.
//! In that case, the non-determisitic server responses will time out using the timeout mechanism (see 4c).
//!
//! 4c. If neither 4a nor 4b yield a result after a certrain amount of time, the timeout mechanism ends the request.
//! The blockmaker indicates, which requests have timed out, i.e. the blocktime of the latest finalized block is higher than
//! the timestamp of a request plus the timeout interval. This condition is verifiable by the other nodes in the network.
//! Once a timeout has made it into a finalized block, the request is answered with an error message.
use crate::{
    CanisterId, CountBytes, RegistryVersion, ReplicaVersion, Time,
    artifact::{CanisterHttpResponseId, IdentifiableArtifact, PbArtifact},
    crypto::{CryptoHashOf, Signed},
    messages::{CallbackId, RejectContext, Request},
    node_id_into_protobuf, node_id_try_from_protobuf,
    signature::*,
};
use ic_base_types::{NodeId, NumBytes, PrincipalId};
use ic_error_types::{ErrorCode, RejectCode, UserError};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_management_canister_types_private::{
    ALLOWED_HTTP_OUTCALLS_PRICING_VERSIONS, CanisterHttpRequestArgs,
    DEFAULT_HTTP_OUTCALLS_PRICING_VERSION, DataSize, HttpHeader, HttpMethod,
    PRICING_VERSION_LEGACY, PRICING_VERSION_PAY_AS_YOU_GO, TransformContext,
};
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    state::system_metadata::v1 as pb_metadata,
};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    convert::{TryFrom, TryInto},
    mem::size_of,
    time::Duration,
};
use strum::FromRepr;
use strum_macros::EnumIter;

/// Time after which a response is considered timed out and a timeout error will be returned to execution
pub const CANISTER_HTTP_TIMEOUT_INTERVAL: Duration = Duration::from_secs(60);

/// Number of CanisterHttpResponses to be included in a block.
///
/// Limiting the number of responses can improve performance, as otherwise validation times
/// could become too large.
pub const CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK: usize = 500;

/// Maximum number of request bytes for a canister http request.
pub const MAX_CANISTER_HTTP_REQUEST_BYTES: u64 = 2_000_000;

/// Maximum number of response bytes for a canister http request.
pub const MAX_CANISTER_HTTP_RESPONSE_BYTES: u64 = 2_000_000;

/// Maximum number of bytes to represent URL for a canister http request.
pub const MAX_CANISTER_HTTP_URL_SIZE: usize = 8192;

/// Maximum number of all HTTP headers.
pub const MAX_CANISTER_HTTP_HEADER_NUM: usize = 64;

/// Maximum number of bytes to represent one HTTP header name.
pub const MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH: usize = 8 * 1024;

/// Maximum total number of bytes to represent all HTTP header names and values.
pub const MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE: usize = 48 * 1024;

/// In the context of canister http, the [`CallbackId`] of the request
/// is used to uniquely identify the request and it's associated artifacts.
pub type CanisterHttpRequestId = CallbackId;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct Transform {
    pub method_name: String,
    #[serde(with = "serde_bytes")]
    pub context: Vec<u8>,
}

impl From<TransformContext> for Transform {
    fn from(item: TransformContext) -> Self {
        Transform {
            method_name: item.function.0.method,
            context: item.context,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct CanisterHttpRequestContext {
    pub request: Request,
    pub url: String,
    pub max_response_bytes: Option<NumBytes>,
    pub headers: Vec<CanisterHttpHeader>,
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none", default)]
    pub body: Option<Vec<u8>>,
    pub http_method: CanisterHttpMethod,
    pub transform: Option<Transform>,
    pub time: Time,
    /// The replication strategy for this request.
    pub replication: Replication,
    pub pricing_version: PricingVersion,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum Replication {
    /// The request is fully replicated, i.e. all nodes will attempt the http request.
    FullyReplicated,
    /// The request is not replicated, i.e. only the node with the given `NodeId` will attempt the http request.
    NonReplicated(NodeId),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, FromRepr)]
#[repr(u32)]
pub enum PricingVersion {
    Legacy = PRICING_VERSION_LEGACY,
    PayAsYouGo = PRICING_VERSION_PAY_AS_YOU_GO,
}

impl From<&CanisterHttpRequestContext> for pb_metadata::CanisterHttpRequestContext {
    fn from(context: &CanisterHttpRequestContext) -> Self {
        let replication_type = match context.replication {
            Replication::FullyReplicated => {
                pb_metadata::replication::ReplicationType::FullyReplicated(())
            }
            Replication::NonReplicated(node_id) => {
                pb_metadata::replication::ReplicationType::NonReplicated(node_id_into_protobuf(
                    node_id,
                ))
            }
        };

        let replication_message = pb_metadata::Replication {
            replication_type: Some(replication_type),
        };

        let pricing_version = match context.pricing_version {
            PricingVersion::Legacy => pb_metadata::pricing_version::Version::Legacy(()),
            PricingVersion::PayAsYouGo => pb_metadata::pricing_version::Version::PayAsYouGo(()),
        };

        let pricing_message = pb_metadata::PricingVersion {
            version: Some(pricing_version),
        };

        pb_metadata::CanisterHttpRequestContext {
            request: Some((&context.request).into()),
            url: context.url.clone(),
            max_response_bytes: context
                .max_response_bytes
                .map(|max_response_bytes| max_response_bytes.get()),
            headers: context
                .headers
                .clone()
                .into_iter()
                .map(|h| pb_metadata::HttpHeader {
                    name: h.name,
                    value: h.value,
                })
                .collect(),
            body: context.body.clone(),
            transform_method_name: context
                .transform
                .as_ref()
                .map(|transform| transform.method_name.clone()),
            transform_context: context
                .transform
                .as_ref()
                .map(|transform| transform.context.clone()),
            http_method: pb_metadata::HttpMethod::from(&context.http_method).into(),
            time: context.time.as_nanos_since_unix_epoch(),
            replication: Some(replication_message),
            pricing_version: Some(pricing_message),
        }
    }
}

pub fn default_pricing_version() -> PricingVersion {
    PricingVersion::from_repr(DEFAULT_HTTP_OUTCALLS_PRICING_VERSION)
        .unwrap_or(PricingVersion::Legacy)
}

impl TryFrom<pb_metadata::CanisterHttpRequestContext> for CanisterHttpRequestContext {
    type Error = ProxyDecodeError;

    fn try_from(context: pb_metadata::CanisterHttpRequestContext) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(context.request, "CanisterHttpRequestContext::request")?;

        let replication = match context.replication {
            Some(replication) => match replication.replication_type {
                Some(pb_metadata::replication::ReplicationType::FullyReplicated(_)) => {
                    Replication::FullyReplicated
                }
                Some(pb_metadata::replication::ReplicationType::NonReplicated(node_id)) => {
                    Replication::NonReplicated(node_id_try_from_protobuf(node_id)?)
                }
                None => Replication::FullyReplicated,
            },
            None => Replication::FullyReplicated,
        };

        let pricing_version = match context.pricing_version {
            Some(pricing_version) => match pricing_version.version {
                Some(pb_metadata::pricing_version::Version::Legacy(_)) => PricingVersion::Legacy,
                Some(pb_metadata::pricing_version::Version::PayAsYouGo(_)) => {
                    PricingVersion::PayAsYouGo
                }
                None => default_pricing_version(),
            },
            None => default_pricing_version(),
        };

        let transform_method_name = context.transform_method_name;
        let transform_context = context.transform_context;
        let transform = match (transform_method_name, transform_context) {
            (Some(method_name), Some(context)) => Some(Transform {
                method_name,
                context,
            }),
            // Might happen for an already serialized transform context that
            // contained only the method name, i.e. before the context field
            // was added. Can be squashed to the case below after the change
            // has been fully rolled out.
            (Some(method_name), None) => Some(Transform {
                method_name,
                context: vec![],
            }),
            (None, Some(_)) => {
                return Err(ProxyDecodeError::MissingField(
                    "CanisterHttpRequestContext is missing the transform method.",
                ));
            }
            (None, None) => None,
        };

        Ok(CanisterHttpRequestContext {
            request,
            url: context.url,
            max_response_bytes: context.max_response_bytes.map(NumBytes::from),
            headers: context
                .headers
                .into_iter()
                .map(|h| CanisterHttpHeader {
                    name: h.name,
                    value: h.value,
                })
                .collect(),
            body: context.body,
            http_method: pb_metadata::HttpMethod::try_from(context.http_method)
                .map_err(|_| ProxyDecodeError::ValueOutOfRange {
                    typ: "ic_protobuf::state::system_metadata::v1::HttpMethod",
                    err: format!(
                        "{} is not one of the expected variants of HttpMethod",
                        context.http_method
                    ),
                })?
                .try_into()?,
            transform,
            time: Time::from_nanos_since_unix_epoch(context.time),
            replication,
            pricing_version,
        })
    }
}

/// Check that the header and body of the request conform to the
/// [Interface Spec](https://ic-interface-spec.netlify.app/#ic-http_request).
pub fn validate_http_headers_and_body(
    headers: &[HttpHeader],
    body: &[u8],
) -> Result<(), CanisterHttpRequestContextError> {
    let mut headers_num = 0;
    let mut headers_max_name_len = 0;
    let mut headers_max_value_len = 0;
    let mut headers_size_bytes = 0;
    for h in headers.iter() {
        headers_num += 1;
        let name_len = h.name.len();
        let value_len = h.value.len();
        headers_max_name_len = name_len.max(headers_max_name_len);
        headers_max_value_len = value_len.max(headers_max_value_len);
        headers_size_bytes += name_len + value_len;
    }

    if headers_num > MAX_CANISTER_HTTP_HEADER_NUM {
        return Err(CanisterHttpRequestContextError::TooManyHeaders(headers_num));
    }

    if headers_max_name_len > MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH {
        return Err(CanisterHttpRequestContextError::TooLongHeaderName(
            headers_max_name_len,
        ));
    }

    if headers_max_value_len > MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH {
        return Err(CanisterHttpRequestContextError::TooLongHeaderValue(
            headers_max_value_len,
        ));
    }

    if headers_size_bytes > MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE {
        return Err(CanisterHttpRequestContextError::TooLargeHeaders(
            headers_size_bytes,
        ));
    }

    let body_size_bytes = body.len();
    let request_total_bytes = headers_size_bytes + body_size_bytes;
    if request_total_bytes > (MAX_CANISTER_HTTP_REQUEST_BYTES as usize) {
        return Err(CanisterHttpRequestContextError::TooLargeRequest(
            request_total_bytes,
        ));
    }

    Ok(())
}

impl CanisterHttpRequestContext {
    /// Calculate the size of all unbounded struct elements.
    pub fn variable_parts_size(&self) -> NumBytes {
        let request_size = self.url.len()
            + self
                .headers
                .iter()
                .map(|header| header.name.len() + header.value.len())
                .sum::<usize>()
            + self.body.as_ref().map_or(0, |body| body.len())
            + self.transform.as_ref().map_or(0, |transform| {
                transform.method_name.len() + transform.context.len()
            });
        NumBytes::from(request_size as u64)
    }

    pub fn generate_from_args(
        time: Time,
        request: &Request,
        args: CanisterHttpRequestArgs,
        node_ids: &BTreeSet<NodeId>,
        rng: &mut dyn RngCore,
    ) -> Result<Self, CanisterHttpRequestContextError> {
        if let Some(transform_principal_id) = args.transform_principal()
            && request.sender.get() != transform_principal_id
        {
            return Err(CanisterHttpRequestContextError::TransformPrincipalId(
                InvalidTransformPrincipalId {
                    expected_principal_id: request.sender.get(),
                    actual_principal_id: transform_principal_id,
                },
            ));
        };

        let max_response_bytes = match args.max_response_bytes {
            Some(max_response_bytes) => {
                if max_response_bytes > MAX_CANISTER_HTTP_RESPONSE_BYTES {
                    Err(CanisterHttpRequestContextError::MaxResponseBytes(
                        InvalidMaxResponseBytes {
                            min: 0,
                            max: MAX_CANISTER_HTTP_RESPONSE_BYTES,
                            given: max_response_bytes,
                        },
                    ))
                } else {
                    Ok(Some(NumBytes::from(max_response_bytes)))
                }
            }
            None => Ok(None),
        }?;

        let url_len = args.url.len();
        if url_len > MAX_CANISTER_HTTP_URL_SIZE {
            return Err(CanisterHttpRequestContextError::UrlTooLong(url_len));
        }

        let request_body = args.body;
        validate_http_headers_and_body(
            args.headers.get(),
            request_body.as_ref().unwrap_or(&vec![]),
        )?;

        let replication = match args.is_replicated {
            Some(false) => {
                if node_ids.is_empty() {
                    return Err(CanisterHttpRequestContextError::NoNodesAvailableForDelegation);
                }

                let random_index = rng.random_range(0..node_ids.len());

                let delegated_node_id = node_ids
                    .iter()
                    .nth(random_index)
                    .ok_or(CanisterHttpRequestContextError::NoNodesAvailableForDelegation)?; // never panic.

                Replication::NonReplicated(*delegated_node_id)
            }
            _ => Replication::FullyReplicated,
        };

        Ok(CanisterHttpRequestContext {
            request: request.clone(),
            url: args.url,
            max_response_bytes,
            headers: args
                .headers
                .get()
                .clone()
                .into_iter()
                .map(|h| CanisterHttpHeader {
                    name: h.name,
                    value: h.value,
                })
                .collect(),
            body: request_body,
            http_method: match args.method {
                HttpMethod::GET => CanisterHttpMethod::GET,
                HttpMethod::POST => CanisterHttpMethod::POST,
                HttpMethod::HEAD => CanisterHttpMethod::HEAD,
            },
            transform: args.transform.map(From::from),
            time,
            replication,
            pricing_version: {
                let final_version_u32 = args
                    .pricing_version
                    .filter(|v| ALLOWED_HTTP_OUTCALLS_PRICING_VERSIONS.contains(v))
                    .unwrap_or(DEFAULT_HTTP_OUTCALLS_PRICING_VERSION);
                PricingVersion::from_repr(final_version_u32).unwrap_or(PricingVersion::Legacy)
            },
        })
    }
}

/// The error that occurs when an end-user specifies an invalid
/// `max_response_bytes`
#[derive(Debug)]
pub struct InvalidMaxResponseBytes {
    min: u64,
    max: u64,
    given: u64,
}

/// The error occurs when the [`PrincipalId`] of the transform
/// function is invalid
#[derive(Debug)]
pub struct InvalidTransformPrincipalId {
    expected_principal_id: PrincipalId,
    actual_principal_id: PrincipalId,
}

/// Errors that can occur when converting from (time, request, [`CanisterHttpRequestArgs`]) to
/// an [`CanisterHttpRequestContext`].
#[derive(Debug)]
pub enum CanisterHttpRequestContextError {
    MaxResponseBytes(InvalidMaxResponseBytes),
    TransformPrincipalId(InvalidTransformPrincipalId),
    UrlTooLong(usize),
    TooManyHeaders(usize),
    TooLongHeaderName(usize),
    TooLongHeaderValue(usize),
    TooLargeHeaders(usize),
    TooLargeRequest(usize),
    NoNodesAvailableForDelegation,
}

impl From<CanisterHttpRequestContextError> for UserError {
    fn from(err: CanisterHttpRequestContextError) -> Self {
        match err {
            CanisterHttpRequestContextError::MaxResponseBytes(err) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "max_response_bytes expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            CanisterHttpRequestContextError::TransformPrincipalId(err) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "transform principal id expected to be {}, got {}",
                    err.expected_principal_id, err.actual_principal_id,
                ),
            ),
            CanisterHttpRequestContextError::UrlTooLong(url_size) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!("url size {url_size} exceeds {MAX_CANISTER_HTTP_URL_SIZE}"),
            ),
            CanisterHttpRequestContextError::TooManyHeaders(num_headers) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "number of all http headers {num_headers} exceeds {MAX_CANISTER_HTTP_HEADER_NUM}"
                ),
            ),
            CanisterHttpRequestContextError::TooLongHeaderName(name_size) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "number of bytes to represent some http header name {name_size} exceeds {MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH}"
                ),
            ),
            CanisterHttpRequestContextError::TooLongHeaderValue(value_size) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "number of bytes to represent some http header value {value_size} exceeds {MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH}"
                ),
            ),
            CanisterHttpRequestContextError::TooLargeHeaders(total_header_size) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "total number of bytes to represent all http header names and values {total_header_size} exceeds {MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE}"
                ),
            ),
            CanisterHttpRequestContextError::TooLargeRequest(total_request_size) => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "total number of bytes to represent all http header names and values and http body {total_request_size} exceeds {MAX_CANISTER_HTTP_REQUEST_BYTES}"
                ),
            ),
            CanisterHttpRequestContextError::NoNodesAvailableForDelegation => UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "No nodes available for delegation for non-replicated canister HTTP request."
                    .to_string(),
            ),
        }
    }
}

/// Contains the information that the pool manager hands to the canister http
/// client to make a request
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CanisterHttpRequest {
    /// Timestamp indicating when this request will be considered timed out.
    pub timeout: Time,
    /// This requests unique identifier
    pub id: CanisterHttpRequestId,
    /// The context of the request which captures all the metadata about this request
    pub context: CanisterHttpRequestContext,
    /// The most up to date api boundary nodes address that should be used as a socks proxy in the case of a request to an IPv4 address.
    /// The addresses should be sent in the following format: `socks5://[<ip>]:<port>`, for example:
    /// `socks5://[2602:fb2b:110:10:506f:cff:feff:fe69]:1080`
    pub socks_proxy_addrs: Vec<String>,
}

/// The content of a response after the transformation
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CanisterHttpResponse {
    pub id: CanisterHttpRequestId,
    pub timeout: Time,
    pub canister_id: CanisterId,
    pub content: CanisterHttpResponseContent,
}

impl CountBytes for CanisterHttpResponse {
    fn count_bytes(&self) -> usize {
        let CanisterHttpResponse {
            id,
            timeout,
            canister_id,
            content,
        } = &self;
        size_of_val(id)
            + size_of_val(timeout)
            + canister_id.get_ref().data_size()
            + content.count_bytes()
    }
}

/// Content of a [`CanisterHttpResponse`]
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum CanisterHttpResponseContent {
    /// In the case of a success, this will be the data returned by the server.
    Success(Vec<u8>),
    /// In case of a reject, this will be a [`CanisterHttpReject`], indicating why the
    /// request was rejected.
    Reject(CanisterHttpReject),
}

impl CountBytes for CanisterHttpResponseContent {
    fn count_bytes(&self) -> usize {
        match self {
            CanisterHttpResponseContent::Success(payload) => payload.len(),
            CanisterHttpResponseContent::Reject(err) => err.count_bytes(),
        }
    }
}

/// If a [`CanisterHttpRequest`] is rejected, the [`CanisterHttpReject`] provides additional
/// information about the rejection.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CanisterHttpReject {
    /// The [`RejectCode`] of the request
    pub reject_code: RejectCode,
    /// Error message to provide additional information
    pub message: String,
}

impl From<&CanisterHttpReject> for RejectContext {
    fn from(value: &CanisterHttpReject) -> RejectContext {
        RejectContext::new(value.reject_code, &value.message)
    }
}

impl CountBytes for CanisterHttpReject {
    fn count_bytes(&self) -> usize {
        let CanisterHttpReject {
            reject_code,
            message,
        } = &self;
        size_of_val(reject_code) + message.len()
    }
}

/// A header to be included in a [`CanisterHttpRequest`].
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct CanisterHttpHeader {
    pub name: String,
    pub value: String,
}

/// Specifies the HTTP method that is used in the [`CanisterHttpRequest`].
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Deserialize, EnumIter, Serialize)]
pub enum CanisterHttpMethod {
    GET = 1,
    POST = 2,
    HEAD = 3,
}

impl CanisterHttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            CanisterHttpMethod::GET => "GET",
            CanisterHttpMethod::POST => "POST",
            CanisterHttpMethod::HEAD => "HEAD",
        }
    }
}

impl From<&CanisterHttpMethod> for pb_metadata::HttpMethod {
    fn from(http_method: &CanisterHttpMethod) -> Self {
        match http_method {
            CanisterHttpMethod::GET => pb_metadata::HttpMethod::Get,
            CanisterHttpMethod::POST => pb_metadata::HttpMethod::Post,
            CanisterHttpMethod::HEAD => pb_metadata::HttpMethod::Head,
        }
    }
}

impl TryFrom<pb_metadata::HttpMethod> for CanisterHttpMethod {
    type Error = ProxyDecodeError;

    fn try_from(http_method: pb_metadata::HttpMethod) -> Result<Self, Self::Error> {
        match http_method {
            pb_metadata::HttpMethod::Get => Ok(CanisterHttpMethod::GET),
            pb_metadata::HttpMethod::Post => Ok(CanisterHttpMethod::POST),
            pb_metadata::HttpMethod::Head => Ok(CanisterHttpMethod::HEAD),
            pb_metadata::HttpMethod::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                typ: "ic_protobuf::state::system_metadata::v1::HttpMethod",
                err: "Unspecified HttpMethod".to_string(),
            }),
        }
    }
}

/// A proof that the replicas have reached consensus on some [`CanisterHttpResponseContent`].
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CanisterHttpResponseWithConsensus {
    pub content: CanisterHttpResponse,
    pub proof: CanisterHttpResponseProof,
}

impl CountBytes for CanisterHttpResponseWithConsensus {
    fn count_bytes(&self) -> usize {
        let CanisterHttpResponseWithConsensus { content, proof } = &self;
        proof.count_bytes() + content.count_bytes()
    }
}

/// A collection of signature shares supporting the same [`CallbackId`] with different hashes.
///
/// This can be used as a proof that consensus can not be reached for this call
/// as sufficiently many nodes have seen divergent content.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CanisterHttpResponseDivergence {
    pub shares: Vec<CanisterHttpResponseShare>,
}

impl CountBytes for CanisterHttpResponseDivergence {
    fn count_bytes(&self) -> usize {
        let CanisterHttpResponseDivergence { shares } = &self;
        shares.iter().map(|share| share.count_bytes()).sum()
    }
}

/// Metadata about some [`CanisterHttpResponseContent`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CanisterHttpResponseMetadata {
    pub id: CallbackId,
    pub timeout: Time,
    pub content_hash: CryptoHashOf<CanisterHttpResponse>,
    pub registry_version: RegistryVersion,
    pub replica_version: ReplicaVersion,
}

impl CountBytes for CanisterHttpResponseMetadata {
    fn count_bytes(&self) -> usize {
        size_of::<CanisterHttpResponseMetadata>()
    }
}

impl crate::crypto::SignedBytesWithoutDomainSeparator for CanisterHttpResponseMetadata {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// A signature share of of [`CanisterHttpResponseMetadata`].
pub type CanisterHttpResponseShare =
    Signed<CanisterHttpResponseMetadata, BasicSignature<CanisterHttpResponseMetadata>>;

/// Contains a share and optionally the full response.
///
/// This is the artifact that will actually be gossiped.
#[derive(Clone, Debug, PartialEq)]
pub struct CanisterHttpResponseArtifact {
    pub share: CanisterHttpResponseShare,
    // The response should not be included in the case of fully replicated outcalls.
    pub response: Option<CanisterHttpResponse>,
}

impl IdentifiableArtifact for CanisterHttpResponseArtifact {
    const NAME: &'static str = "canisterhttp";
    type Id = CanisterHttpResponseId;
    fn id(&self) -> Self::Id {
        self.share.clone()
    }
}

impl PbArtifact for CanisterHttpResponseArtifact {
    type PbId = ic_protobuf::types::v1::CanisterHttpShare;
    type PbIdError = ProxyDecodeError;
    type PbMessage = ic_protobuf::types::v1::CanisterHttpArtifact;
    type PbMessageError = ProxyDecodeError;
}

/// A signature of of [`CanisterHttpResponseMetadata`].
pub type CanisterHttpResponseProof =
    Signed<CanisterHttpResponseMetadata, BasicSignatureBatch<CanisterHttpResponseMetadata>>;

impl CountBytes for CanisterHttpResponseProof {
    fn count_bytes(&self) -> usize {
        size_of::<CanisterHttpResponseProof>()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Cycles, messages::NO_DEADLINE, time::UNIX_EPOCH};

    use super::*;

    use strum::IntoEnumIterator;

    #[test]
    fn test_request_arg_variable_size() {
        let context = CanisterHttpRequestContext {
            url: "https://example.com".to_string(),
            headers: vec![CanisterHttpHeader {
                name: "hi".to_string(),
                value: "bye".to_string(),
            }],
            body: Some(vec![0; 1024]),
            max_response_bytes: None,
            http_method: CanisterHttpMethod::GET,
            transform: Some(Transform {
                method_name: "willchange".to_string(),
                context: vec![],
            }),
            request: Request {
                receiver: CanisterId::ic_00(),
                sender: CanisterId::ic_00(),
                sender_reply_callback: CallbackId::from(3),
                payment: Cycles::new(10),
                method_name: "tansform".to_string(),
                method_payload: Vec::new(),
                metadata: Default::default(),
                deadline: NO_DEADLINE,
            },
            time: UNIX_EPOCH,
            replication: Replication::FullyReplicated,
            pricing_version: PricingVersion::Legacy,
        };

        let expected_size = context.url.len()
            + context
                .headers
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum::<usize>()
            + context.body.as_ref().map_or(0, |b| b.len())
            + context.transform.as_ref().map_or(0, |transform| {
                transform.method_name.len() + transform.context.len()
            });

        assert_eq!(
            context.variable_parts_size(),
            NumBytes::from(expected_size as u64)
        );
    }

    #[test]
    fn test_request_arg_variable_size_some_empty() {
        let context = CanisterHttpRequestContext {
            url: "https://example.com".to_string(),
            headers: vec![],
            body: None,
            max_response_bytes: None,
            http_method: CanisterHttpMethod::GET,
            transform: Some(Transform {
                method_name: "willchange".to_string(),
                context: vec![],
            }),
            request: Request {
                receiver: CanisterId::ic_00(),
                sender: CanisterId::ic_00(),
                sender_reply_callback: CallbackId::from(3),
                payment: Cycles::new(10),
                method_name: "tansform".to_string(),
                method_payload: Vec::new(),
                metadata: Default::default(),
                deadline: NO_DEADLINE,
            },
            time: UNIX_EPOCH,
            replication: Replication::FullyReplicated,
            pricing_version: PricingVersion::Legacy,
        };

        let expected_size = context.url.len()
            + context.transform.as_ref().map_or(0, |transform| {
                transform.method_name.len() + transform.context.len()
            });
        assert_eq!(
            context.variable_parts_size(),
            NumBytes::from(expected_size as u64)
        );
    }

    #[test]
    fn canister_http_method_proto_round_trip() {
        for initial in CanisterHttpMethod::iter() {
            let encoded = pb_metadata::HttpMethod::from(&initial);
            let round_trip = CanisterHttpMethod::try_from(encoded).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn compatibility_for_canister_http_method() {
        // If this fails, you are making a potentially incompatible change to `CanisterHttpMethod`.
        // See note [Handling changes to Enums in Replicated State] for how to proceed.
        assert_eq!(
            CanisterHttpMethod::iter()
                .map(|x| x as i32)
                .collect::<Vec<i32>>(),
            [1, 2, 3]
        );
    }
}

#[cfg(test)]
mod validate_http_headers_and_body_tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_management_canister_types_private::HttpHeader;

    #[test]
    fn test_empty_request() {
        let empty_headers: Vec<HttpHeader> = vec![];
        let empty_body = b"";
        assert!(validate_http_headers_and_body(&empty_headers, empty_body).is_ok());
    }

    #[test]
    fn test_valid_request() {
        let headers = vec![HttpHeader {
            name: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }];
        let body = b"Hello";
        assert!(validate_http_headers_and_body(&headers, body).is_ok());
    }

    #[test]
    fn test_headers_at_max_count() {
        // Create exactly the maximum allowed number of headers
        let headers = (0..MAX_CANISTER_HTTP_HEADER_NUM)
            .map(|i| HttpHeader {
                name: format!("Header-{i}"),
                value: "value".to_string(),
            })
            .collect::<Vec<_>>();
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_header_name_at_max_length() {
        // Create a header with name exactly at the limit
        let headers = vec![HttpHeader {
            name: "a".repeat(MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH),
            value: "value".to_string(),
        }];
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_header_value_at_max_length() {
        // Create a header with value exactly at the limit
        let headers = vec![HttpHeader {
            name: "Header".to_string(),
            value: "b".repeat(MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH),
        }];
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_headers_at_max_total_size() {
        // We'll keep the size of the header name and value to sum up to MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH.
        let headers_needed =
            MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE / MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH;

        let headers = (0..headers_needed)
            .map(|i| {
                let header_name = format!("Header-{i}");
                HttpHeader {
                    name: header_name.clone(),
                    // Going over a single byte for each header value should do it.
                    value: "a"
                        .repeat(MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH - header_name.len()),
                }
            })
            .collect::<Vec<_>>();
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_too_many_headers() {
        // Create more headers than allowed
        let headers = (0..=MAX_CANISTER_HTTP_HEADER_NUM)
            .map(|i| HttpHeader {
                name: format!("Header-{i}"),
                value: "value".to_string(),
            })
            .collect::<Vec<_>>();
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);
        assert_matches!(
            result,
            Err(CanisterHttpRequestContextError::TooManyHeaders(count))
            if count == MAX_CANISTER_HTTP_HEADER_NUM + 1
        );
    }

    #[test]
    fn test_header_name_too_long() {
        // Create a header with name exceeding the limit
        let headers = vec![HttpHeader {
            name: "a".repeat(MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH + 1),
            value: "value".to_string(),
        }];
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);
        assert_matches!(
            result,
            Err(CanisterHttpRequestContextError::TooLongHeaderName(size))
            if size == MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH + 1
        );
    }

    #[test]
    fn test_header_value_too_long() {
        // Create a header with value exceeding the limit
        let headers = vec![HttpHeader {
            name: "Header".to_string(),
            value: "b".repeat(MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH + 1),
        }];
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);
        assert_matches!(
            result,
            Err(CanisterHttpRequestContextError::TooLongHeaderValue(size))
            if size == MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH + 1
        );
    }

    #[test]
    fn test_headers_total_size_too_large() {
        let headers_needed =
            MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE / MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH;

        let headers = (0..headers_needed)
            .map(|i| {
                let header_name = format!("Header-{i}");
                HttpHeader {
                    name: header_name.clone(),
                    // Going over a single byte for each header value should do it.
                    value: "a"
                        .repeat(MAX_CANISTER_HTTP_HEADER_NAME_VALUE_LENGTH - header_name.len() + 1),
                }
            })
            .collect::<Vec<_>>();
        let body = b"";

        let result = validate_http_headers_and_body(&headers, body);

        assert_matches!(
            result,
            Err(CanisterHttpRequestContextError::TooLargeHeaders(size))
            if size > MAX_CANISTER_HTTP_HEADER_TOTAL_SIZE
        );
    }
}
