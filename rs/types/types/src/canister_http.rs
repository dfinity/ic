use crate::crypto::CryptoHashOf;
use crate::{crypto::Signed, messages::CallbackId, signature::*};
use serde::{Deserialize, Serialize};

pub type CanisterHttpRequestId = CallbackId;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpRequest {
    id: CanisterHttpRequestId,
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
