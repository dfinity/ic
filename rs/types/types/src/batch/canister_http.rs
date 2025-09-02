use crate::{
    artifact::CanisterHttpResponseId, canister_http::{
        CanisterHttpReject, CanisterHttpRequestId, CanisterHttpResponse, CanisterHttpResponseContent, CanisterHttpResponseDivergence, CanisterHttpResponseMetadata, CanisterHttpResponseProof, CanisterHttpResponseShare, CanisterHttpResponseWithConsensus, HttpOutcallShare, NonReplicatedHttpShare, ReplicatedHttpShare
    }, crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed, crypto_hash}, messages::CallbackId, signature::{BasicSignature, BasicSignatureBatch}, ReplicaVersion, Time
};
use ic_base_types::{NodeId, PrincipalId, RegistryVersion};
use ic_error_types::RejectCode;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
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
        let is_replicated = payload.proof.is_replicated();
        pb::CanisterHttpResponseWithConsensus {
            response: Some(pb::CanisterHttpResponse {
                id: payload.content.id.get(),
                timeout: payload.content.timeout.as_nanos_since_unix_epoch(),
                content: Some(pb::CanisterHttpResponseContent::from(
                    &payload.content.content,
                )),
                canister_id: Some(pb::CanisterId::from(payload.content.canister_id)),
            }),
            //TODO(urgent): hash not needed
            hash: payload.proof.get_hash(),
            registry_version: payload.proof.get_metadata().registry_version.get(),
            replica_version: payload.proof.get_metadata().replica_version.clone().into(),
            signatures: payload
                .proof
                .get_signatures()
                .into_iter()
                .map(|(node_id, sig)| pb::CanisterHttpResponseSignature {
                    signer: node_id,
                    signature: sig,
                })
                .collect(),
            is_replicated: Some(is_replicated)
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
        let is_replicated = payload.is_replicated.unwrap_or(true);
        let response = payload
            .response
            .ok_or(ProxyDecodeError::MissingField("response"))?;
        let id = CanisterHttpRequestId::new(response.id);
        let timeout = Time::from_nanos_since_unix_epoch(response.timeout);
        let canister_id = try_from_option_field(
            response.canister_id,
            "CanisterHttpResponseWithConsensus::canister_id",
        )?;

        let proof = if is_replicated {
            CanisterHttpResponseProof::Replicated {
                signatures: Signed {
                    content: ReplicatedHttpShare {
                        metadata: CanisterHttpResponseMetadata {
                            id,
                            timeout,
                            registry_version: RegistryVersion::new(payload.registry_version),
                            replica_version: ReplicaVersion::try_from(payload.replica_version)
                                .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?,
                        },
                        content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(
                            payload.hash,
                        )),
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
                }
            }
        } else {
            let siganture = payload.signatures.get(0).ok_or(
                ProxyDecodeError::MissingField("CanisterHttpResponseWithConsensus::signature"),
            )?;
            if payload.signatures.len() > 0 {
                return Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "signatures",
                    err: format!(
                        "expected exactly one signature for non-replicated proof, got {}",
                        payload.signatures.len()
                    ),
                });
            }
            CanisterHttpResponseProof::NonReplicated { 
                metadata: CanisterHttpResponseMetadata {
                    id,
                    timeout,
                    registry_version: RegistryVersion::new(payload.registry_version),
                    replica_version: ReplicaVersion::try_from(payload.replica_version)
                        .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?,
                },
                signature: BasicSignature {
                    //TODO(urgent): take ownership of the vec
                    signer: NodeId::from(PrincipalId::try_from(siganture.signer.clone())?),
                    signature: BasicSigOf::new(BasicSig(siganture.signature.clone()))
                }
            }
        };

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
            proof

            // proof: Signed {
            //     content: CanisterHttpResponseMetadata {
            //         id,
            //         timeout,
            //         content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(
            //             payload.hash,
            //         )),
            //         registry_version: RegistryVersion::new(payload.registry_version),
            //         replica_version: ReplicaVersion::try_from(payload.replica_version)
            //             .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?,
            //     },
            //     signature: BasicSignatureBatch {
            //         signatures_map: payload
            //             .signatures
            //             .into_iter()
            //             .map(|signature| {
            //                 Ok((
            //                     NodeId::from(PrincipalId::try_from(signature.signer)?),
            //                     BasicSigOf::new(BasicSig(signature.signature)),
            //                 ))
            //             })
            //             .collect::<Result<BTreeMap<NodeId, BasicSigOf<_>>, ProxyDecodeError>>()?,
            //     },
            // },
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
        let metadata = share.content.get_metadata().clone();
        let (content_hash, full_response) = match share.content {
            HttpOutcallShare::Replicated ( ReplicatedHttpShare { content_hash, .. }) => (content_hash.clone().get().0, None),
            //TODO(urgent): this is not right. 
            HttpOutcallShare::NonReplicated (NonReplicatedHttpShare {response, ..}) => (vec![], Some(response.clone())),
        };
        let full_response = full_response.map(|full_response| {
            pb::CanisterHttpResponse {
                id: full_response.id.get(),
                timeout: full_response.timeout.as_nanos_since_unix_epoch(),
                content: Some(pb::CanisterHttpResponseContent::from(
                    &full_response.content,
                )),
                canister_id: Some(pb::CanisterId::from(full_response.canister_id)),
            }
        });
        pb::CanisterHttpShare {
            metadata: Some(pb::CanisterHttpResponseMetadata {
                id: metadata.id.get(),
                timeout: metadata.timeout.as_nanos_since_unix_epoch(),
                content_hash,
                registry_version: metadata.registry_version.get(),
                replica_version: metadata.replica_version.clone().into(),
                full_response
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

        let is_replicated = !metadata.full_response.is_none();
        let full_response = metadata.full_response.clone();
        let id = CanisterHttpRequestId::new(metadata.id);
        let timeout = Time::from_nanos_since_unix_epoch(metadata.timeout);
        let content_hash = CryptoHashOf::new(CryptoHash(metadata.content_hash.clone()));
        let registry_version = RegistryVersion::new(metadata.registry_version);
        let replica_version = ReplicaVersion::try_from(metadata.replica_version)
            .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?;
        let signature = share
            .signature
            .ok_or(ProxyDecodeError::MissingField("share.signature"))?;
        let metadata = CanisterHttpResponseMetadata {
            id,
            timeout,
            registry_version,
            replica_version,
        };

        let content = if is_replicated {
            HttpOutcallShare::Replicated(ReplicatedHttpShare {
                metadata,
                content_hash,
            })
        } else {
            let full_response = full_response
                .ok_or(ProxyDecodeError::MissingField(
                    "share.metadata.full_response",
                ))?;
            let canister_id = try_from_option_field(
                full_response.canister_id,
                "CanisterHttpResponseShare::canister_id",
            )?;
            HttpOutcallShare::NonReplicated(NonReplicatedHttpShare {
                metadata,
                response: CanisterHttpResponse {
                    id: CanisterHttpRequestId::new(full_response.id),
                    timeout: Time::from_nanos_since_unix_epoch(full_response.timeout),
                    canister_id,
                    content: try_from_option_field(
                        full_response.content,
                        "CanisterHttpResponseShare::content",
                    )?,
                },
            })
        };

        Ok(Signed {
            content,
            signature: BasicSignature {
                signer: NodeId::from(PrincipalId::try_from(signature.signer)?),
                signature: BasicSigOf::new(BasicSig(signature.signature)),
            },
        })
    }
}

impl From<CanisterHttpResponseId> for pb::CanisterHttpResponseId {
    fn from(id: CanisterHttpResponseId) -> Self {
        Self {
            metadata: Some(pb::CanisterHttpResponseMetadata {
                id: id.metadata.id.get(),
                timeout: id.metadata.timeout.as_nanos_since_unix_epoch(),
                registry_version: id.metadata.registry_version.get(),
                replica_version: id.metadata.replica_version.to_string(),
                content_hash: vec![],
                full_response: None,
            }),
            hash: id.hash.get().0,
        }
    }
}

impl TryFrom<pb::CanisterHttpResponseId> for CanisterHttpResponseId {
    type Error = ProxyDecodeError;

    fn try_from(id_pb: pb::CanisterHttpResponseId) -> Result<Self, Self::Error> {
        let metadata_pb =
            id_pb.metadata.ok_or(ProxyDecodeError::MissingField("CanisterHttpResponseId::metadata"))?;

        let metadata = CanisterHttpResponseMetadata {
            id: CallbackId::from(metadata_pb.id),
            timeout: Time::from_nanos_since_unix_epoch(metadata_pb.timeout),
            registry_version: RegistryVersion::from(metadata_pb.registry_version),
            replica_version: ReplicaVersion::try_from(metadata_pb.replica_version)
                .map_err(|err| ProxyDecodeError::ReplicaVersionParseError(Box::new(err)))?,
        };

        Ok(Self {
            metadata,
            hash: CryptoHashOf::new(CryptoHash(id_pb.hash)),
        })
    }
}
