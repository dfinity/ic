use crate::{
    ReplicaVersion, Time,
    canister_http::{
        CanisterHttpReject, CanisterHttpRequestId, CanisterHttpResponse,
        CanisterHttpResponseArtifact, CanisterHttpResponseContent, CanisterHttpResponseDivergence,
        CanisterHttpResponseMetadata, CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
    },
    crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed},
    messages::CallbackId,
    signature::{BasicSignature, BasicSignatureBatch},
};
use ic_base_types::{NodeId, PrincipalId, RegistryVersion};
use ic_error_types::RejectCode;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1 as pb,
};
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
}

impl CanisterHttpPayload {
    /// Returns the number of responses that this payload contains
    pub fn num_responses(&self) -> usize {
        self.responses.len() + self.timeouts.len() + self.divergence_responses.len()
    }

    /// Returns the number of non_timeout responses
    pub fn num_non_timeout_responses(&self) -> usize {
        self.responses.len()
    }

    /// Returns true, if this is an empty payload
    pub fn is_empty(&self) -> bool {
        self.num_responses() == 0
    }
}

impl From<&CanisterHttpResponseWithConsensus> for pb::CanisterHttpResponseWithConsensus {
    fn from(payload: &CanisterHttpResponseWithConsensus) -> Self {
        pb::CanisterHttpResponseWithConsensus {
            response: Some(pb::CanisterHttpResponse {
                id: payload.content.id.get(),
                timeout: payload.content.timeout.as_nanos_since_unix_epoch(),
                content: Some(pb::CanisterHttpResponseContent::from(
                    &payload.content.content,
                )),
                canister_id: Some(pb::CanisterId::from(payload.content.canister_id)),
            }),
            hash: payload.proof.content.content_hash.clone().get().0,
            registry_version: payload.proof.content.registry_version.get(),
            replica_version: payload.proof.content.replica_version.clone().into(),
            signatures: payload
                .proof
                .signature
                .signatures_map
                .iter()
                .map(|(signer, signature)| pb::CanisterHttpResponseSignature {
                    signer: (*signer).get().into_vec(),
                    signature: signature.clone().get().0,
                })
                .collect(),
        }
    }
}

impl From<&CanisterHttpResponseDivergence> for pb::CanisterHttpResponseDivergence {
    fn from(payload: &CanisterHttpResponseDivergence) -> Self {
        pb::CanisterHttpResponseDivergence {
            shares: payload.shares.iter().cloned().map(Into::into).collect(),
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
        let timeout = Time::from_nanos_since_unix_epoch(response.timeout);
        let canister_id = try_from_option_field(
            response.canister_id,
            "CanisterHttpResponseWithConsensus::canister_id",
        )?;

        Ok(CanisterHttpResponseWithConsensus {
            content: CanisterHttpResponse {
                id,
                timeout,
                canister_id,
                content: try_from_option_field(
                    response.content,
                    "CanisterHttpResponseWithConsensus::content",
                )?,
            },
            proof: Signed {
                content: CanisterHttpResponseMetadata {
                    id,
                    timeout,
                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(
                        payload.hash,
                    )),
                    registry_version: RegistryVersion::new(payload.registry_version),
                    replica_version: ReplicaVersion::try_from(payload.replica_version)
                        .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?,
                },
                signature: BasicSignatureBatch {
                    signatures_map: payload
                        .signatures
                        .into_iter()
                        .map(|signature| {
                            Ok((
                                NodeId::from(PrincipalId::try_from(signature.signer)?),
                                BasicSigOf::new(BasicSig(signature.signature)),
                            ))
                        })
                        .collect::<Result<BTreeMap<NodeId, BasicSigOf<_>>, ProxyDecodeError>>()?,
                },
            },
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

impl From<&CanisterHttpResponseContent> for pb::CanisterHttpResponseContent {
    fn from(content: &CanisterHttpResponseContent) -> Self {
        let inner = match content {
            CanisterHttpResponseContent::Success(payload) => {
                pb::canister_http_response_content::Status::Success(payload.clone())
            }
            CanisterHttpResponseContent::Reject(error) => {
                pb::canister_http_response_content::Status::Reject(pb::CanisterHttpReject {
                    message: error.message.clone(),
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
        pb::CanisterHttpShare {
            metadata: Some(pb::CanisterHttpResponseMetadata {
                id: share.content.id.get(),
                timeout: share.content.timeout.as_nanos_since_unix_epoch(),
                content_hash: share.content.content_hash.clone().get().0,
                registry_version: share.content.registry_version.get(),
                replica_version: share.content.replica_version.into(),
            }),
            signature: Some(pb::CanisterHttpResponseSignature {
                signer: share.signature.signer.get().into_vec(),
                signature: share.signature.signature.clone().get().0,
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
        let timeout = Time::from_nanos_since_unix_epoch(metadata.timeout);
        let content_hash = CryptoHashOf::new(CryptoHash(metadata.content_hash.clone()));
        let registry_version = RegistryVersion::new(metadata.registry_version);
        let replica_version = ReplicaVersion::try_from(metadata.replica_version)
            .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?;
        let signature = share
            .signature
            .ok_or(ProxyDecodeError::MissingField("share.signature"))?;
        Ok(Signed {
            content: CanisterHttpResponseMetadata {
                id,
                timeout,
                content_hash,
                registry_version,
                replica_version,
            },
            signature: BasicSignature {
                signer: NodeId::from(PrincipalId::try_from(signature.signer)?),
                signature: BasicSigOf::new(BasicSig(signature.signature)),
            },
        })
    }
}

impl TryFrom<pb::CanisterHttpResponse> for CanisterHttpResponse {
    type Error = ProxyDecodeError;

    fn try_from(response: pb::CanisterHttpResponse) -> Result<Self, Self::Error> {
        let id = CanisterHttpRequestId::new(response.id);
        let timeout = Time::from_nanos_since_unix_epoch(response.timeout);
        let canister_id =
            try_from_option_field(response.canister_id, "CanisterHttpResponse::canister_id")?;
        let content = try_from_option_field(response.content, "CanisterHttpResponse::content")?;
        Ok(CanisterHttpResponse {
            id,
            timeout,
            canister_id,
            content,
        })
    }
}

impl From<CanisterHttpResponse> for pb::CanisterHttpResponse {
    fn from(response: CanisterHttpResponse) -> Self {
        pb::CanisterHttpResponse {
            id: response.id.get(),
            timeout: response.timeout.as_nanos_since_unix_epoch(),
            content: Some(pb::CanisterHttpResponseContent::from(&response.content)),
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
    use candid::Encode;

    /// Tests, whether a roundtrip of protobuf conversions generates the same
    /// `CanisterHttpResponseWithConsensus`
    #[test]
    fn canister_http_response_with_consensus_conversion() {
        let payload = CanisterHttpResponseWithConsensus {
            content: CanisterHttpResponse {
                id: CanisterHttpRequestId::new(1),
                timeout: Time::from_nanos_since_unix_epoch(1234),
                canister_id: crate::CanisterId::from(1),
                content: CanisterHttpResponseContent::Success(
                    Encode!(
                        &ic_management_canister_types_private::CanisterHttpResponsePayload {
                            status: 200,
                            headers: vec![ic_management_canister_types_private::HttpHeader {
                                name: "test_header1".to_string(),
                                value: "value1".to_string()
                            }],
                            body: b"Test data in body".to_vec(),
                        }
                    )
                    .unwrap(),
                ),
            },
            proof: Signed {
                content: CanisterHttpResponseMetadata {
                    id: CanisterHttpRequestId::new(1),
                    timeout: Time::from_nanos_since_unix_epoch(1234),
                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(vec![
                        0, 1, 2, 3,
                    ])),
                    registry_version: RegistryVersion::new(1),
                    replica_version: ReplicaVersion::default(),
                },
                signature: BasicSignatureBatch {
                    signatures_map: vec![(
                        NodeId::from(PrincipalId::new_node_test_id(1)),
                        BasicSigOf::new(BasicSig(vec![0, 1, 2, 3])),
                    )]
                    .into_iter()
                    .collect(),
                },
            },
        };
        let pb_payload = pb::CanisterHttpResponseWithConsensus::from(&payload);
        let new_payload = CanisterHttpResponseWithConsensus::try_from(pb_payload).unwrap();
        assert_eq!(payload, new_payload);
    }

    /// Tests, whether a roundtrip of protobuf conversions generates the same
    /// `CanisterHttpResponseDivergence`
    #[test]
    fn canister_http_diverge_response_conversion() {
        let payload = CanisterHttpResponseDivergence {
            shares: vec![Signed {
                content: CanisterHttpResponseMetadata {
                    id: CanisterHttpRequestId::new(1),
                    timeout: Time::from_nanos_since_unix_epoch(1234),
                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(vec![
                        0, 1, 2, 3,
                    ])),
                    registry_version: RegistryVersion::new(1),
                    replica_version: ReplicaVersion::default(),
                },
                signature: BasicSignature {
                    signer: NodeId::from(PrincipalId::new_node_test_id(1)),
                    signature: BasicSigOf::new(BasicSig(vec![0, 1, 2, 3])),
                },
            }],
        };
        let pb_payload = pb::CanisterHttpResponseDivergence::from(&payload);
        let new_payload = CanisterHttpResponseDivergence::try_from(pb_payload).unwrap();
        assert_eq!(payload, new_payload);
    }

    /// Tests that a roundtrip of protobuf conversions for `CanisterHttpResponse`
    /// works correctly.
    #[test]
    fn canister_http_response_conversion() {
        let response = CanisterHttpResponse {
            id: CanisterHttpRequestId::new(1),
            timeout: Time::from_nanos_since_unix_epoch(5678),
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
        let share = Signed {
            content: CanisterHttpResponseMetadata {
                id: CanisterHttpRequestId::new(2),
                timeout: Time::from_nanos_since_unix_epoch(91011),
                content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(vec![
                    4, 5, 6, 7,
                ])),
                registry_version: RegistryVersion::new(2),
                replica_version: ReplicaVersion::default(),
            },
            signature: BasicSignature {
                signer: NodeId::from(PrincipalId::new_node_test_id(2)),
                signature: BasicSigOf::new(BasicSig(vec![4, 5, 6, 7])),
            },
        };

        let response = CanisterHttpResponse {
            id: CanisterHttpRequestId::new(2),
            timeout: Time::from_nanos_since_unix_epoch(91011),
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
}
