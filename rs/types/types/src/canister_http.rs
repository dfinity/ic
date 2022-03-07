//! This module implements the types necessary for consensus to perform http requests.
//!
//! The life of a request looks as follows (from consensus perspective):
//!
//! 1. A [`CanisterHttpRequest`] will be generated from the metadata stored in the state manager.
//! The artifact pool manager will take the request pass it to the network layer to make the actual request.
//! The resonse will may be passed to a filter and then is returned to the consensus layer as a [`CanisterHttpResponseContent`].
//!
//! 2. Now we need to get consensus of the content. Since the actual [`CanisterHttpResponseContent`] could be large and we
//! require n-to-n communication, we will turn the content into a much smaller [`CanisterHttpResponseMetadata`] object,
//! that contains all the the important information required to archieve consensus.
//!
//! 3. We sign the metdata to get the [`CanisterHttpResponseShareSignature`] and store it together with the content as
//! a [`CanisterHttpResponseShare`] in the pool.
//!
//! 4a. We gossip [`CanisterHttpResponseShareSignature`]s, until we have enough of those to aggregate them into a
//! [`CanisterHttpResponseProof`]. Together with the content, this artifact forms the [`CanisterHttpResponseWithConsensus`],
//! which is the artifact we can include into the block to prove consensus on the response.
//!
//! 4b. (Not implemented) If we see a lot of [`CanisterHttpResponseShareSignature`]s with the same [`CanisterHttpRequestId`] but
//! different content hashes, we can include them into a [`CanisterHttpResponseDivergence`]. This artifact prooves, that consensus
//! on the request is not possible.
//!
//! 4c. If we can neither produce a [`CanisterHttpResponseWithConsensus`] nor a [`CanisterHttpResponseDivergence`], we have to return
//! a timeout to the upper layers, as soon as we have a finalized block with a block time higher than the timeout field in the shares.
//! Any artifacts that have timed out are discarded, as they are no longer valid and can no longer be included into a new block.

use crate::{
    crypto::{CryptoHashOf, Signed},
    messages::{CallbackId, Request},
    signature::*,
    Time,
};
use ic_base_types::HttpMethodType;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::system_metadata::v1 as pb_metadata,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub type CanisterHttpRequestId = CallbackId;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpRequestContext {
    pub request: Request,
    pub url: String,
    pub body: Option<Vec<u8>>,
    pub http_method: HttpMethodType,
    pub transform_method_name: Option<String>,
    pub time: Time,
}

impl From<&CanisterHttpRequestContext> for pb_metadata::CanisterHttpRequestContext {
    fn from(context: &CanisterHttpRequestContext) -> Self {
        pb_metadata::CanisterHttpRequestContext {
            request: Some((&context.request).into()),
            url: context.url.clone(),
            body: context.body.clone(),
            transform_method_name: context
                .transform_method_name
                .as_ref()
                .map(|method_name| method_name.into()),
            http_method: pb_metadata::HttpMethodType::from(&context.http_method) as i32,
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
            body: context.body,
            http_method: HttpMethodType::from(
                pb_metadata::HttpMethodType::from_i32(context.http_method).unwrap_or_default(),
            ),
            transform_method_name: context.transform_method_name.map(From::from),
            time: Time::from_nanos_since_unix_epoch(context.time),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpRequest {
    id: CanisterHttpRequestId,
    timeout: Time,
    content: CanisterHttpRequestContext,
}

/// The content of a response of a after the filtering step.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseContent {
    id: CanisterHttpRequestId,
    timeout: Time,
    // TODO: Content goes here
}

/// A proof that the replicas have reached consensus on some [`CanisterHttpResponseContent`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseWithConsensus {
    signature: CanisterHttpResponseProof,
    content: CanisterHttpResponseContent,
}

/// A collection of signature shares supporting the same [`CanisterHttpRequestId`] with different hashes.
///
/// This can be used as a proof, that consensus can not be reached for this call, as sufficiently many nodes
/// have seen divergent content.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseDivergence {
    response_shares: Vec<CanisterHttpResponseShareSignature>,
}

/// A signature indicating supporting of a specific [`CanisterHttpResponseContent`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseShare {
    signature: CanisterHttpResponseShareSignature,
    content: Option<Box<CanisterHttpResponseContent>>,
}

impl CanisterHttpResponseShare {
    /// Creates a [`CanisterHttpResponseShare`] from a [`CanisterHttpResponseShareSignature`]
    /// and a [`CanisterHttpResponseContent`].
    pub fn from_signature_and_content(
        signature: CanisterHttpResponseShareSignature,
        content: CanisterHttpResponseContent,
    ) -> Self {
        Self {
            signature,
            content: Some(Box::new(content)),
        }
    }

    /// Returns `true`, if this [`CanisterHttpResponseShare`] has it's content attached.
    pub fn has_content(&self) -> bool {
        self.content.is_some()
    }
}

impl From<&CanisterHttpResponseShare> for CanisterHttpResponseShareSignature {
    fn from(share: &CanisterHttpResponseShare) -> Self {
        share.signature.clone()
    }
}

impl From<CanisterHttpResponseShareSignature> for CanisterHttpResponseShare {
    fn from(signature: CanisterHttpResponseShareSignature) -> Self {
        Self {
            signature,
            content: None,
        }
    }
}

impl CanisterHttpResponseMetadata {
    pub fn from_content<F>(content: &CanisterHttpResponseContent, hash_fn: F) -> Self
    where
        F: Fn(&CanisterHttpResponseContent) -> CryptoHashOf<CanisterHttpResponseContent>,
    {
        Self {
            id: content.id,
            timeout: content.timeout,
            content_hash: hash_fn(content),
        }
    }
}

/// Metadata about some [`CanisterHttpResponseContent`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseMetadata {
    id: CanisterHttpRequestId,
    timeout: Time,
    content_hash: CryptoHashOf<CanisterHttpResponseContent>,
}

impl crate::crypto::SignedBytesWithoutDomainSeparator for CanisterHttpResponseMetadata {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        todo!()
    }
}

/// A signature share of of [`CanisterHttpResponseMetadata`].
///
/// This is the artifact that will actually be gossiped.
pub type CanisterHttpResponseShareSignature =
    Signed<CanisterHttpResponseMetadata, MultiSignatureShare<CanisterHttpResponseMetadata>>;

/// A signature of of [`CanisterHttpResponseMetadata`].
pub type CanisterHttpResponseProof =
    Signed<CanisterHttpResponseMetadata, MultiSignature<CanisterHttpResponseMetadata>>;
