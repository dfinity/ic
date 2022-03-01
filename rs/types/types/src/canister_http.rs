use crate::crypto::CryptoHashOf;
use crate::{
    crypto::Signed,
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
    content: CanisterHttpRequestContext,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpResponseContent {
    id: CanisterHttpRequestId,
}

pub type CanisterHttpResponseWithConsensus =
    Signed<CanisterHttpResponseContent, MultiSignature<CryptoHashOf<CanisterHttpResponseContent>>>;

pub type CanisterHttpResponseSignatureProof = Signed<
    CryptoHashOf<CanisterHttpResponseContent>,
    MultiSignatureShare<CryptoHashOf<CanisterHttpResponseContent>>,
>;

impl crate::crypto::SignedBytesWithoutDomainSeparator
    for CryptoHashOf<CanisterHttpResponseContent>
{
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        self.clone().get().0
    }
}

pub type CanisterHttpResponseShare = Signed<
    CanisterHttpResponseContent,
    MultiSignatureShare<CryptoHashOf<CanisterHttpResponseContent>>,
>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpRequestDivergence {
    response_shares: Vec<CanisterHttpResponseShare>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanisterHttpResponse {
    WithConsensus(CanisterHttpResponseWithConsensus),
    Divergence(CanisterHttpRequestDivergence),
    Timeout(CanisterHttpRequestId),
}
