//! This module implements the types necessary for consensus to perform http requests.
//!
//! The life of a request looks as follows (from consensus perspective):
//!
//! 1. A [`CanisterHttpRequestContext`] is stored in the state.
//! The canister http pool manager will take the request pass it to the network layer to make the actual request.
//! The response may be passed to a filter and then is returned to the consensus layer as a [`CanisterHttpResponseContent`].
//!
//! 2. Now we need to get consensus of the content. Since the actual [`CanisterHttpResponseContent`] could be large and we
//! require n-to-n communication, we will turn the content into a much smaller [`CanisterHttpResponseMetadata`] object,
//! that contains all the the important information required to archieve consensus.
//!
//! 3. We sign the metdata to get the [`CanisterHttpResponseShare`] and store it together with the content as
//! a [`CanisterHttpResponseShare`] in the pool.
//!
//! 4a. We gossip [`CanisterHttpResponseShare`]s, until we have enough of those to aggregate them into a
//! [`CanisterHttpResponseProof`]. Together with the content, this artifact forms the [`CanisterHttpResponseWithConsensus`],
//! which is the artifact we can include into the block to prove consensus on the response.

use crate::messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64;
use crate::{
    crypto::{CryptoHashOf, Signed},
    messages::{CallbackId, RejectContext, Request},
    signature::*,
    CanisterId, CountBytes, RegistryVersion, Time,
};
use ic_base_types::NumBytes;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_ic00_types::{CanisterHttpRequestArgs, HttpMethod};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::system_metadata::v1 as pb_metadata,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
};

// TODO: Make this amount configurable
pub const CANISTER_HTTP_TIMEOUT_INTERVAL: Duration = Duration::from_secs(60);

pub type CanisterHttpRequestId = CallbackId;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpRequestContext {
    pub request: Request,
    pub url: String,
    pub max_response_bytes: Option<NumBytes>,
    pub headers: Vec<CanisterHttpHeader>,
    pub body: Option<Vec<u8>>,
    pub http_method: CanisterHttpMethod,
    pub transform_method_name: Option<String>,
    pub time: Time,
}

impl From<&CanisterHttpRequestContext> for pb_metadata::CanisterHttpRequestContext {
    fn from(context: &CanisterHttpRequestContext) -> Self {
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
                .transform_method_name
                .as_ref()
                .map(|method_name| method_name.into()),
            http_method: pb_metadata::HttpMethod::from(&context.http_method).into(),
            time: context.time.as_nanos_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb_metadata::CanisterHttpRequestContext> for CanisterHttpRequestContext {
    type Error = ProxyDecodeError;
    fn try_from(context: pb_metadata::CanisterHttpRequestContext) -> Result<Self, Self::Error> {
        let request: Request =
            try_from_option_field(context.request, "CanisterHttpRequestContext::request")?;
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
            http_method: pb_metadata::HttpMethod::from_i32(context.http_method)
                .ok_or(ProxyDecodeError::ValueOutOfRange {
                    typ: "ic_protobuf::state::system_metadata::v1::HttpMethod",
                    err: format!(
                        "{} is not one of the expected variants of HttpMethod",
                        context.http_method
                    ),
                })?
                .try_into()?,
            transform_method_name: context.transform_method_name.map(From::from),
            time: Time::from_nanos_since_unix_epoch(context.time),
        })
    }
}

impl TryFrom<(Time, &Request, CanisterHttpRequestArgs)> for CanisterHttpRequestContext {
    type Error = CanisterHttpRequestContextError;

    fn try_from(input: (Time, &Request, CanisterHttpRequestArgs)) -> Result<Self, Self::Error> {
        let (time, request, args) = input;

        let max_response_bytes = match args.max_response_bytes {
            Some(max_response_bytes) => {
                if max_response_bytes > MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 {
                    Err(CanisterHttpRequestContextError::MaxResponseBytes(
                        InvalidMaxResponseBytes {
                            min: 0,
                            max: MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64,
                            given: max_response_bytes,
                        },
                    ))
                } else {
                    Ok(Some(NumBytes::from(max_response_bytes)))
                }
            }
            None => Ok(None),
        }?;

        Ok(CanisterHttpRequestContext {
            request: request.clone(),
            url: args.url,
            max_response_bytes,
            headers: args
                .headers
                .clone()
                .into_iter()
                .map(|h| CanisterHttpHeader {
                    name: h.name,
                    value: h.value,
                })
                .collect(),
            body: args.body,
            http_method: match args.http_method {
                HttpMethod::GET => CanisterHttpMethod::GET,
                HttpMethod::POST => CanisterHttpMethod::POST,
                HttpMethod::HEAD => CanisterHttpMethod::HEAD,
            },
            transform_method_name: args.transform_method_name,
            time,
        })
    }
}

/// The error that occurs when an end-user specifies an invalid
/// [`max_response_bytes`].
pub struct InvalidMaxResponseBytes {
    min: u64,
    max: u64,
    given: u64,
}

/// Errors that can occur when converting from (time, request, [`CanisterHttpRequestArgs`]) to
/// an [`CanisterHttpRequestContext`].
pub enum CanisterHttpRequestContextError {
    MaxResponseBytes(InvalidMaxResponseBytes),
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
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpRequest {
    pub timeout: Time,
    pub id: CallbackId,
    pub content: CanisterHttpRequestContext,
}

/// The content of a response of a after the filtering step.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponse {
    pub id: CallbackId,
    pub timeout: Time,
    pub canister_id: CanisterId,
    pub content: CanisterHttpResponseContent,
}

impl CountBytes for CanisterHttpResponse {
    fn count_bytes(&self) -> usize {
        size_of::<CallbackId>() + size_of::<Time>() + self.content.count_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanisterHttpResponseContent {
    Success(Vec<u8>),
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct CanisterHttpReject {
    pub reject_code: RejectCode,
    pub message: String,
}

impl From<&CanisterHttpReject> for RejectContext {
    fn from(value: &CanisterHttpReject) -> RejectContext {
        RejectContext::new(value.reject_code, value.message.clone())
    }
}

impl CountBytes for CanisterHttpReject {
    fn count_bytes(&self) -> usize {
        size_of::<RejectCode>() + self.message.len()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct CanisterHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum CanisterHttpMethod {
    GET,
    POST,
    HEAD,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseWithConsensus {
    pub content: CanisterHttpResponse,
    pub proof: CanisterHttpResponseProof,
}

impl CountBytes for CanisterHttpResponseWithConsensus {
    fn count_bytes(&self) -> usize {
        self.proof.count_bytes() + self.content.count_bytes()
    }
}

/// A collection of signature shares supporting the same [`CallbackId`] with different hashes.
///
/// This can be used as a proof, that consensus can not be reached for this call, as sufficiently many nodes
/// have seen divergent content.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseDivergence {
    pub response_shares: Vec<CanisterHttpResponseShare>,
}

/// Metadata about some [`CanisterHttpResponseContent`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanisterHttpResponseMetadata {
    pub id: CallbackId,
    pub timeout: Time,
    pub content_hash: CryptoHashOf<CanisterHttpResponse>,
    pub registry_version: RegistryVersion,
}

impl crate::crypto::SignedBytesWithoutDomainSeparator for CanisterHttpResponseMetadata {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        serde_cbor::to_vec(&self).unwrap()
    }
}

/// A signature share of of [`CanisterHttpResponseMetadata`].
///
/// This is the artifact that will actually be gossiped.
pub type CanisterHttpResponseShare =
    Signed<CanisterHttpResponseMetadata, MultiSignatureShare<CanisterHttpResponseMetadata>>;

/// A signature of of [`CanisterHttpResponseMetadata`].
pub type CanisterHttpResponseProof =
    Signed<CanisterHttpResponseMetadata, MultiSignature<CanisterHttpResponseMetadata>>;

impl CountBytes for CanisterHttpResponseProof {
    fn count_bytes(&self) -> usize {
        size_of::<CanisterHttpResponseProof>()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanisterHttpResponseAttribute {
    Share(
        RegistryVersion,
        CallbackId,
        CryptoHashOf<CanisterHttpResponse>,
    ),
}
