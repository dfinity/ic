use crate::{
    CanisterId, CountBytes, ReplicaVersion,
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpReject, CanisterHttpRequestId,
        CanisterHttpResponse, CanisterHttpResponseArtifact, CanisterHttpResponseContent,
        CanisterHttpResponseDivergence, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
        CanisterHttpResponseReceipt, CanisterHttpResponseShare, CanisterHttpResponseSignature,
        CanisterHttpResponseWithConsensus,
    },
    crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed},
    messages::CallbackId,
    signature::BasicSignature,
};
use ic_base_types::{NodeId, PrincipalId};
use ic_error_types::RejectCode;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1 as pb,
};
use ic_types_cycles::Cycles;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom};

pub const MAX_CANISTER_HTTP_PAYLOAD_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

/// Payload that contains CanisterHttpPayload messages.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct CanisterHttpPayload {
    pub responses: Vec<CanisterHttpResponseWithConsensus>,
    pub timeouts: Vec<CallbackId>,
    pub divergence_responses: Vec<CanisterHttpResponseDivergence>,
    pub flexible_responses: Vec<FlexibleCanisterHttpResponses>,
    pub flexible_errors: Vec<FlexibleCanisterHttpError>,
}

/// An error detected during flexible HTTP outcall processing.
///
/// Each variant carries only the data needed for consensus validation
/// and later Candid encoding into `FlexibleHttpRequestResult::Err`.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum FlexibleCanisterHttpError {
    Timeout {
        callback_id: CallbackId,
    },
    ResponsesTooLarge {
        callback_id: CallbackId,
        all_seen_shares: Vec<CanisterHttpResponseShare>,
        total_requests: u32,
        min_responses: u32,
    },
    TooManyRejects {
        callback_id: CallbackId,
        reject_responses: Vec<FlexibleCanisterHttpResponseWithProof>,
        /// The total amount of cycles spent by the subnet to produce this response.
        initial_spent: Cycles,
    },
}

impl FlexibleCanisterHttpError {
    pub fn callback_id(&self) -> CallbackId {
        match self {
            Self::Timeout { callback_id }
            | Self::ResponsesTooLarge { callback_id, .. }
            | Self::TooManyRejects { callback_id, .. } => *callback_id,
        }
    }
}

/// A group of flexible HTTP outcall responses for a single callback.
///
/// Unlike regular outcalls, each response carries a single-signer share
/// rather than an aggregated threshold proof, because flexible responses
/// from individual committee members don't need to agree.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct FlexibleCanisterHttpResponses {
    pub callback_id: CallbackId,
    pub responses: Vec<FlexibleCanisterHttpResponseWithProof>,
    /// The total amount of cycles spent by the subnet to produce this response.
    pub initial_spent: Cycles,
}

/// A single flexible HTTP outcall response paired with its single-signer proof.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct FlexibleCanisterHttpResponseWithProof {
    pub response: CanisterHttpResponse,
    pub proof: CanisterHttpResponseShare,
}

impl FlexibleCanisterHttpResponseWithProof {
    pub fn count_bytes(
        response: &CanisterHttpResponse,
        proof: &CanisterHttpResponseShare,
    ) -> usize {
        Self::count_bytes_from_parts(&response.canister_id, response.content.count_bytes(), proof)
    }

    /// Same calculation as [`Self::count_bytes`] but from decomposed parts.
    pub fn count_bytes_from_parts(
        canister_id: &CanisterId,
        content_size: usize,
        proof: &CanisterHttpResponseShare,
    ) -> usize {
        let response_size = CanisterHttpResponse::count_bytes_from_parts(canister_id, content_size);
        response_size + proof.count_bytes()
    }
}

impl CountBytes for FlexibleCanisterHttpResponseWithProof {
    fn count_bytes(&self) -> usize {
        let Self { response, proof } = self;
        Self::count_bytes(response, proof)
    }
}

impl CountBytes for FlexibleCanisterHttpError {
    fn count_bytes(&self) -> usize {
        match self {
            Self::Timeout { callback_id } => callback_id.count_bytes(),
            Self::ResponsesTooLarge {
                callback_id,
                all_seen_shares,
                total_requests,
                min_responses,
            } => {
                callback_id.count_bytes()
                    + all_seen_shares
                        .iter()
                        .map(|s| s.count_bytes())
                        .sum::<usize>()
                    + std::mem::size_of_val(total_requests)
                    + std::mem::size_of_val(min_responses)
            }
            Self::TooManyRejects {
                callback_id,
                reject_responses,
                initial_spent,
            } => {
                callback_id.count_bytes()
                    + reject_responses
                        .iter()
                        .map(|r| r.count_bytes())
                        .sum::<usize>()
                    + std::mem::size_of_val(initial_spent)
            }
        }
    }
}

impl CanisterHttpPayload {
    /// Returns the number of responses that this payload contains
    pub fn num_responses(&self) -> usize {
        let CanisterHttpPayload {
            responses,
            timeouts,
            divergence_responses,
            flexible_responses,
            flexible_errors,
        } = self;
        responses.len()
            + timeouts.len()
            + divergence_responses.len()
            + flexible_responses.len()
            + flexible_errors.len()
    }

    /// Returns the number of non_timeout responses
    pub fn num_non_timeout_responses(&self) -> usize {
        let CanisterHttpPayload {
            responses,
            timeouts: _,
            divergence_responses,
            flexible_responses,
            flexible_errors,
        } = self;
        responses.len()
            + divergence_responses.len()
            + flexible_responses.len()
            + flexible_errors
                .iter()
                .filter(|error| !matches!(error, FlexibleCanisterHttpError::Timeout { .. }))
                .count()
    }

    /// Returns true, if this is an empty payload
    pub fn is_empty(&self) -> bool {
        self.num_responses() == 0
    }
}

impl From<CanisterHttpPaymentReceipt> for pb::CanisterHttpPaymentReceipt {
    fn from(receipt: CanisterHttpPaymentReceipt) -> Self {
        pb::CanisterHttpPaymentReceipt {
            spent: Some(receipt.spent.into()),
        }
    }
}

impl TryFrom<pb::CanisterHttpPaymentReceipt> for CanisterHttpPaymentReceipt {
    type Error = ProxyDecodeError;
    fn try_from(receipt: pb::CanisterHttpPaymentReceipt) -> Result<Self, Self::Error> {
        Ok(CanisterHttpPaymentReceipt {
            spent: try_from_option_field(receipt.spent, "CanisterHttpPaymentReceipt::spent")?,
        })
    }
}

impl From<CanisterHttpResponseWithConsensus> for pb::CanisterHttpResponseWithConsensus {
    fn from(payload: CanisterHttpResponseWithConsensus) -> Self {
        let CanisterHttpResponseProof {
            metadata,
            signatures,
        } = payload.proof;
        pb::CanisterHttpResponseWithConsensus {
            response: Some(pb::CanisterHttpResponse {
                id: payload.content.id.get(),
                content: Some(pb::CanisterHttpResponseContent::from(
                    payload.content.content,
                )),
                canister_id: Some(pb::CanisterId::from(payload.content.canister_id)),
            }),
            hash: metadata.content_hash.get().0,
            replica_version: metadata.replica_version.into(),
            signatures: signatures
                .into_iter()
                .map(|(signer, sig)| pb::CanisterHttpResponseSignature {
                    signer: signer.get().into_vec(),
                    signature: sig.signature.get().0,
                    payment_receipt: Some(sig.payment_receipt.into()),
                })
                .collect(),
            content_size: metadata.content_size,
            is_reject: metadata.is_reject,
            initial_spent: Some(payload.initial_spent.into()),
        }
    }
}

impl From<CanisterHttpResponseDivergence> for pb::CanisterHttpResponseDivergence {
    fn from(payload: CanisterHttpResponseDivergence) -> Self {
        pb::CanisterHttpResponseDivergence {
            shares: payload.shares.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<pb::CanisterHttpResponseWithConsensus> for CanisterHttpResponseWithConsensus {
    type Error = ProxyDecodeError;

    fn try_from(payload: pb::CanisterHttpResponseWithConsensus) -> Result<Self, Self::Error> {
        let response = payload
            .response
            .ok_or(ProxyDecodeError::MissingField("response"))?;
        let id = CanisterHttpRequestId::new(response.id);
        let canister_id = try_from_option_field(
            response.canister_id,
            "CanisterHttpResponseWithConsensus::canister_id",
        )?;

        let mut signatures = BTreeMap::new();
        for signature in payload.signatures {
            let signer = NodeId::from(PrincipalId::try_from(signature.signer)?);
            let payment_receipt = try_from_option_field(
                signature.payment_receipt,
                "CanisterHttpResponseSignature::payment_receipt",
            )?;
            signatures.insert(
                signer,
                CanisterHttpResponseSignature {
                    payment_receipt,
                    signature: BasicSigOf::new(BasicSig(signature.signature)),
                },
            );
        }

        Ok(CanisterHttpResponseWithConsensus {
            content: CanisterHttpResponse {
                id,
                canister_id,
                content: try_from_option_field(
                    response.content,
                    "CanisterHttpResponseWithConsensus::content",
                )?,
            },
            proof: CanisterHttpResponseProof {
                metadata: CanisterHttpResponseMetadata {
                    id,
                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(
                        payload.hash,
                    )),
                    content_size: payload.content_size,
                    is_reject: payload.is_reject,
                    replica_version: ReplicaVersion::try_from(payload.replica_version)
                        .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?,
                },
                signatures,
            },
            initial_spent: try_from_option_field(
                payload.initial_spent,
                "CanisterHttpResponseWithConsensus::initial_spent",
            )?,
        })
    }
}

impl TryFrom<pb::CanisterHttpResponseDivergence> for CanisterHttpResponseDivergence {
    type Error = ProxyDecodeError;

    fn try_from(
        divergence_response: pb::CanisterHttpResponseDivergence,
    ) -> Result<Self, Self::Error> {
        let shares = divergence_response
            .shares
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<CanisterHttpResponseShare>, ProxyDecodeError>>()?;
        Ok(CanisterHttpResponseDivergence { shares })
    }
}

impl From<CanisterHttpResponseContent> for pb::CanisterHttpResponseContent {
    fn from(content: CanisterHttpResponseContent) -> Self {
        let inner = match content {
            CanisterHttpResponseContent::Success(payload) => {
                pb::canister_http_response_content::Status::Success(payload)
            }
            CanisterHttpResponseContent::Reject(error) => {
                pb::canister_http_response_content::Status::Reject(pb::CanisterHttpReject {
                    message: error.message,
                    reject_code: pb::RejectCode::from(error.reject_code).into(),
                })
            }
        };

        pb::CanisterHttpResponseContent {
            status: Some(inner),
        }
    }
}

impl TryFrom<pb::CanisterHttpResponseContent> for CanisterHttpResponseContent {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::CanisterHttpResponseContent) -> Result<Self, Self::Error> {
        Ok(
            match value
                .status
                .ok_or(ProxyDecodeError::MissingField("status"))?
            {
                pb::canister_http_response_content::Status::Success(payload) => {
                    CanisterHttpResponseContent::Success(payload)
                }
                pb::canister_http_response_content::Status::Reject(error) => {
                    CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::try_from(
                            pb::RejectCode::try_from(error.reject_code).map_err(|_| {
                                ProxyDecodeError::ValueOutOfRange {
                                    typ: "reject_code",
                                    err: format!("value out of range: {}", error.reject_code),
                                }
                            })?,
                        )?,
                        message: error.message,
                    })
                }
            },
        )
    }
}

impl From<CanisterHttpResponseShare> for pb::CanisterHttpShare {
    fn from(share: CanisterHttpResponseShare) -> Self {
        let CanisterHttpResponseReceipt {
            metadata,
            payment_receipt,
        } = share.content;
        pb::CanisterHttpShare {
            metadata: Some(pb::CanisterHttpResponseMetadata {
                id: metadata.id.get(),
                content_hash: metadata.content_hash.get().0,
                replica_version: metadata.replica_version.into(),
                content_size: metadata.content_size,
                is_reject: metadata.is_reject,
            }),
            signature: Some(pb::CanisterHttpResponseSignature {
                signer: share.signature.signer.get().into_vec(),
                signature: share.signature.signature.get().0,
                payment_receipt: Some(payment_receipt.into()),
            }),
        }
    }
}

impl TryFrom<pb::CanisterHttpShare> for CanisterHttpResponseShare {
    type Error = ProxyDecodeError;
    fn try_from(share: pb::CanisterHttpShare) -> Result<Self, Self::Error> {
        let metadata = share
            .metadata
            .ok_or(ProxyDecodeError::MissingField("share.metadata"))?;
        let id = CanisterHttpRequestId::new(metadata.id);
        let content_hash = CryptoHashOf::new(CryptoHash(metadata.content_hash));
        let replica_version = ReplicaVersion::try_from(metadata.replica_version)
            .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?;
        let signature = share
            .signature
            .ok_or(ProxyDecodeError::MissingField("share.signature"))?;
        let payment_receipt = try_from_option_field(
            signature.payment_receipt,
            "CanisterHttpResponseSignature::payment_receipt",
        )?;
        Ok(Signed {
            content: CanisterHttpResponseReceipt {
                metadata: CanisterHttpResponseMetadata {
                    id,
                    content_hash,
                    content_size: metadata.content_size,
                    is_reject: metadata.is_reject,
                    replica_version,
                },
                payment_receipt,
            },
            signature: BasicSignature {
                signer: NodeId::from(PrincipalId::try_from(signature.signer)?),
                signature: BasicSigOf::new(BasicSig(signature.signature)),
            },
        })
    }
}

impl From<FlexibleCanisterHttpResponseWithProof> for pb::FlexibleCanisterHttpResponseWithProof {
    fn from(entry: FlexibleCanisterHttpResponseWithProof) -> Self {
        pb::FlexibleCanisterHttpResponseWithProof {
            response: Some(pb::CanisterHttpResponse::from(entry.response)),
            proof: Some(pb::CanisterHttpShare::from(entry.proof)),
        }
    }
}

impl TryFrom<pb::FlexibleCanisterHttpResponseWithProof> for FlexibleCanisterHttpResponseWithProof {
    type Error = ProxyDecodeError;

    fn try_from(entry: pb::FlexibleCanisterHttpResponseWithProof) -> Result<Self, Self::Error> {
        Ok(FlexibleCanisterHttpResponseWithProof {
            response: try_from_option_field(
                entry.response,
                "FlexibleCanisterHttpResponseWithProof::response",
            )?,
            proof: try_from_option_field(
                entry.proof,
                "FlexibleCanisterHttpResponseWithProof::proof",
            )?,
        })
    }
}

impl From<FlexibleCanisterHttpResponses> for pb::FlexibleCanisterHttpResponses {
    fn from(responses: FlexibleCanisterHttpResponses) -> Self {
        pb::FlexibleCanisterHttpResponses {
            callback_id: responses.callback_id.get(),
            responses: responses.responses.into_iter().map(Into::into).collect(),
            initial_spent: Some(responses.initial_spent.into()),
        }
    }
}

impl TryFrom<pb::FlexibleCanisterHttpResponses> for FlexibleCanisterHttpResponses {
    type Error = ProxyDecodeError;

    fn try_from(responses: pb::FlexibleCanisterHttpResponses) -> Result<Self, Self::Error> {
        Ok(FlexibleCanisterHttpResponses {
            callback_id: CallbackId::new(responses.callback_id),
            responses: responses
                .responses
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            initial_spent: try_from_option_field(
                responses.initial_spent,
                "FlexibleCanisterHttpResponses::initial_spent",
            )?,
        })
    }
}

impl From<FlexibleCanisterHttpError> for pb::FlexibleCanisterHttpError {
    fn from(error: FlexibleCanisterHttpError) -> Self {
        use pb::flexible_canister_http_error::ErrorDetails;
        let callback_id = error.callback_id().get();
        let error_details = match error {
            FlexibleCanisterHttpError::Timeout { .. } => {
                ErrorDetails::Timeout(pb::FlexibleCanisterHttpTimeout {})
            }
            FlexibleCanisterHttpError::ResponsesTooLarge {
                all_seen_shares,
                total_requests,
                min_responses,
                ..
            } => ErrorDetails::ResponsesTooLarge(pb::FlexibleCanisterHttpResponsesTooLarge {
                all_seen_shares: all_seen_shares
                    .into_iter()
                    .map(pb::CanisterHttpShare::from)
                    .collect(),
                total_requests,
                min_responses,
            }),
            FlexibleCanisterHttpError::TooManyRejects {
                reject_responses,
                initial_spent,
                ..
            } => ErrorDetails::TooManyRejects(pb::FlexibleCanisterHttpTooManyRejects {
                reject_responses: reject_responses
                    .into_iter()
                    .map(pb::FlexibleCanisterHttpResponseWithProof::from)
                    .collect(),
                initial_spent: Some(initial_spent.into()),
            }),
        };
        pb::FlexibleCanisterHttpError {
            callback_id,
            error_details: Some(error_details),
        }
    }
}

impl TryFrom<pb::FlexibleCanisterHttpError> for FlexibleCanisterHttpError {
    type Error = ProxyDecodeError;

    fn try_from(error: pb::FlexibleCanisterHttpError) -> Result<Self, Self::Error> {
        use pb::flexible_canister_http_error::ErrorDetails;
        let callback_id = CallbackId::new(error.callback_id);
        match error.error_details {
            Some(ErrorDetails::Timeout(_)) => {
                Ok(FlexibleCanisterHttpError::Timeout { callback_id })
            }
            Some(ErrorDetails::ResponsesTooLarge(details)) => {
                let all_seen_shares = details
                    .all_seen_shares
                    .into_iter()
                    .map(CanisterHttpResponseShare::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(FlexibleCanisterHttpError::ResponsesTooLarge {
                    callback_id,
                    all_seen_shares,
                    total_requests: details.total_requests,
                    min_responses: details.min_responses,
                })
            }
            Some(ErrorDetails::TooManyRejects(details)) => {
                let reject_responses = details
                    .reject_responses
                    .into_iter()
                    .map(FlexibleCanisterHttpResponseWithProof::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(FlexibleCanisterHttpError::TooManyRejects {
                    callback_id,
                    reject_responses,
                    initial_spent: try_from_option_field(
                        details.initial_spent,
                        "FlexibleCanisterHttpTooManyRejects::initial_spent",
                    )?,
                })
            }
            None => Err(ProxyDecodeError::MissingField(
                "FlexibleCanisterHttpError::error_details",
            )),
        }
    }
}

impl TryFrom<pb::CanisterHttpResponse> for CanisterHttpResponse {
    type Error = ProxyDecodeError;

    fn try_from(response: pb::CanisterHttpResponse) -> Result<Self, Self::Error> {
        let id = CanisterHttpRequestId::new(response.id);
        let canister_id =
            try_from_option_field(response.canister_id, "CanisterHttpResponse::canister_id")?;
        let content = try_from_option_field(response.content, "CanisterHttpResponse::content")?;
        Ok(CanisterHttpResponse {
            id,
            canister_id,
            content,
        })
    }
}

impl From<CanisterHttpResponse> for pb::CanisterHttpResponse {
    fn from(response: CanisterHttpResponse) -> Self {
        pb::CanisterHttpResponse {
            id: response.id.get(),
            content: Some(pb::CanisterHttpResponseContent::from(response.content)),
            canister_id: Some(pb::CanisterId::from(response.canister_id)),
        }
    }
}

impl TryFrom<pb::CanisterHttpArtifact> for CanisterHttpResponseArtifact {
    type Error = ProxyDecodeError;

    fn try_from(artifact: pb::CanisterHttpArtifact) -> Result<Self, Self::Error> {
        let share = artifact.share.ok_or(ProxyDecodeError::MissingField(
            "CanisterHttpArtifact::share",
        ))?;

        Ok(CanisterHttpResponseArtifact {
            share: share.try_into()?,
            response: artifact
                .response
                .map(|response| response.try_into())
                .transpose()?,
        })
    }
}

impl From<CanisterHttpResponseArtifact> for pb::CanisterHttpArtifact {
    fn from(artifact: CanisterHttpResponseArtifact) -> Self {
        pb::CanisterHttpArtifact {
            share: Some(artifact.share.into()),
            response: artifact.response.map(|response| response.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exhaustive::ExhaustiveSet;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
    use ic_types_cycles::Cycles;

    /// Tests that a roundtrip of protobuf conversions for `CanisterHttpResponse`
    /// works correctly.
    #[test]
    fn canister_http_response_conversion() {
        let response = CanisterHttpResponse {
            id: CanisterHttpRequestId::new(1),
            canister_id: crate::CanisterId::from(42),
            content: CanisterHttpResponseContent::Reject(CanisterHttpReject {
                reject_code: RejectCode::SysTransient,
                message: "test reject".to_string(),
            }),
        };

        let pb_response = pb::CanisterHttpResponse::from(response.clone());
        let new_response = CanisterHttpResponse::try_from(pb_response).unwrap();
        assert_eq!(response, new_response);
    }

    /// Tests that a roundtrip of protobuf conversions for `CanisterHttpResponseArtifact`
    /// works correctly, both with and without a full response.
    #[test]
    fn canister_http_response_artifact_conversion() {
        let signer = NodeId::from(PrincipalId::new_node_test_id(2));
        let share = Signed {
            content: CanisterHttpResponseReceipt {
                metadata: CanisterHttpResponseMetadata {
                    id: CanisterHttpRequestId::new(2),
                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(vec![
                        4, 5, 6, 7,
                    ])),
                    content_size: 42,
                    is_reject: false,
                    replica_version: ReplicaVersion::default(),
                },
                payment_receipt: CanisterHttpPaymentReceipt {
                    spent: Cycles::new(42),
                },
            },
            signature: BasicSignature {
                signer,
                signature: BasicSigOf::new(BasicSig(vec![4, 5, 6, 7])),
            },
        };

        let response = CanisterHttpResponse {
            id: CanisterHttpRequestId::new(2),
            canister_id: crate::CanisterId::from(100),
            content: CanisterHttpResponseContent::Success(vec![1, 2, 3]),
        };

        // Case 1: Artifact with both share and response
        let artifact_with_response = CanisterHttpResponseArtifact {
            share: share.clone(),
            response: Some(response.clone()),
        };

        let pb_artifact_with_response =
            pb::CanisterHttpArtifact::from(artifact_with_response.clone());
        let new_artifact_with_response =
            CanisterHttpResponseArtifact::try_from(pb_artifact_with_response).unwrap();
        assert_eq!(artifact_with_response, new_artifact_with_response);

        // Case 2: Artifact with only a share
        let artifact_without_response = CanisterHttpResponseArtifact {
            share,
            response: None,
        };

        let pb_artifact_without_response =
            pb::CanisterHttpArtifact::from(artifact_without_response.clone());
        let new_artifact_without_response =
            CanisterHttpResponseArtifact::try_from(pb_artifact_without_response).unwrap();
        assert_eq!(artifact_without_response, new_artifact_without_response);
    }

    #[test]
    fn canister_http_payload_exhaustive_conversion() {
        let rng = &mut ReproducibleRng::new();

        for payload in CanisterHttpPayload::exhaustive_set(rng) {
            let CanisterHttpPayload {
                responses,
                divergence_responses,
                flexible_responses,
                flexible_errors,
                timeouts: _, // skipped because there is no dedicated protobuf conversion for this
            } = payload;

            for mut response in responses {
                // The protobuf format for CanisterHttpResponseWithConsensus doesn't
                // store the id separately in the metadata — it reuses the response's
                // value on deserialization. Normalize here so the roundtrip
                // comparison holds.
                response.proof.metadata.id = response.content.id;

                let pb = pb::CanisterHttpResponseWithConsensus::from(response.clone());
                let roundtripped = CanisterHttpResponseWithConsensus::try_from(pb).unwrap();
                assert_eq!(response, roundtripped);
            }
            for divergence in divergence_responses {
                let pb = pb::CanisterHttpResponseDivergence::from(divergence.clone());
                let roundtripped = CanisterHttpResponseDivergence::try_from(pb).unwrap();
                assert_eq!(divergence, roundtripped);
            }
            for flexible in flexible_responses {
                let pb = pb::FlexibleCanisterHttpResponses::from(flexible.clone());
                let roundtripped = FlexibleCanisterHttpResponses::try_from(pb).unwrap();
                assert_eq!(flexible, roundtripped);
            }
            for error in flexible_errors {
                let pb = pb::FlexibleCanisterHttpError::from(error.clone());
                let roundtripped = FlexibleCanisterHttpError::try_from(pb).unwrap();
                assert_eq!(error, roundtripped);
            }
        }
    }
}
