use crate::{
    canister_http::{
        CanisterHttpReject, CanisterHttpRequestId, CanisterHttpResponse,
        CanisterHttpResponseContent, CanisterHttpResponseDivergence, CanisterHttpResponseMetadata,
        CanisterHttpResponseShare, CanisterHttpResponseWithConsensus,
    },
    crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed},
    messages::CallbackId,
    signature::{BasicSignature, BasicSignatureBatch},
    CountBytes, Time,
};
use ic_base_types::{NodeId, PrincipalId, RegistryVersion};
use ic_error_types::RejectCode;
use ic_protobuf::{canister_http::v1 as canister_http_pb, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom};

pub const MAX_CANISTER_HTTP_PAYLOAD_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

/// Payload that contains CanisterHttpPayload messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl From<&CanisterHttpPayload> for pb::CanisterHttpPayload {
    fn from(payload: &CanisterHttpPayload) -> Self {
        Self {
            responses: payload
                .responses
                .iter()
                .map(
                    |payload| canister_http_pb::CanisterHttpResponseWithConsensus {
                        response: Some(canister_http_pb::CanisterHttpResponse {
                            id: payload.content.id.get(),
                            timeout: payload.content.timeout.as_nanos_since_unix_epoch(),
                            content: Some(canister_http_pb::CanisterHttpResponseContent::from(
                                &payload.content.content,
                            )),
                            canister_id: Some(pb::CanisterId::from(payload.content.canister_id)),
                        }),
                        hash: payload.proof.content.content_hash.clone().get().0,
                        registry_version: payload.proof.content.registry_version.get(),
                        signatures: payload
                            .proof
                            .signature
                            .signatures_map
                            .iter()
                            .map(|(signer, signature)| {
                                canister_http_pb::CanisterHttpResponseSignature {
                                    signer: (*signer).get().into_vec(),
                                    signature: signature.clone().get().0,
                                }
                            })
                            .collect(),
                    },
                )
                .collect(),
            timeouts: payload
                .timeouts
                .iter()
                .map(|timeout| timeout.get())
                .collect(),
            divergence_responses: payload
                .divergence_responses
                .iter()
                .map(
                    |response| canister_http_pb::CanisterHttpResponseDivergence {
                        shares: response
                            .shares
                            .iter()
                            .map(|share| canister_http_pb::CanisterHttpShare {
                                metadata: Some(canister_http_pb::CanisterHttpResponseMetadata {
                                    id: share.content.id.get(),
                                    timeout: share.content.timeout.as_nanos_since_unix_epoch(),
                                    content_hash: share.content.content_hash.clone().get().0,
                                    registry_version: share.content.registry_version.get(),
                                }),
                                signature: Some(canister_http_pb::CanisterHttpResponseSignature {
                                    signer: share.signature.signer.get().into_vec(),
                                    signature: share.signature.signature.clone().get().0,
                                }),
                            })
                            .collect(),
                    },
                )
                .collect(),
        }
    }
}

impl TryFrom<pb::CanisterHttpPayload> for CanisterHttpPayload {
    type Error = String;

    fn try_from(mut payload: pb::CanisterHttpPayload) -> Result<Self, Self::Error> {
        Ok(CanisterHttpPayload {
            divergence_responses: payload
                .divergence_responses
                .drain(..)
                .map(
                    |divergence_response| -> Result<CanisterHttpResponseDivergence, String> {
                        let shares = divergence_response
                            .shares
                            .iter()
                            .map(|share| -> Result<CanisterHttpResponseShare, String> {
                                let metadata = share.metadata.as_ref().ok_or_else(|| "No metadata on share in canister http response divergence".to_string())?;
                                let id = CanisterHttpRequestId::new(metadata.id);
                                let timeout =
                                    Time::from_nanos_since_unix_epoch(metadata.timeout);
                                let content_hash =
                                    CryptoHashOf::new(CryptoHash(metadata.content_hash.clone()));
                                let registry_version =
                                    RegistryVersion::new(metadata.registry_version);
                                let signature = share.signature.as_ref().ok_or_else(|| "No signature present on share in canister http response divergence".to_string())?;
                                Ok(Signed {
                                    content: CanisterHttpResponseMetadata {
                                        id,
                                        timeout,
                                        content_hash,
                                        registry_version,
                                    },
                                    signature: BasicSignature {
                                        signer: NodeId::from(
                                            PrincipalId::try_from(&signature.signer[..])
                                                .map_err(|err| format!("{:?}", err))?,
                                        ),
                                        signature: BasicSigOf::new(BasicSig(
                                            signature.signature.clone(),
                                        )),
                                    },
                                })
                            })
                            .collect::<Result<Vec<CanisterHttpResponseShare>, String>>()?;
                        Ok(CanisterHttpResponseDivergence { shares })
                    },
                )
                .collect::<Result<Vec<CanisterHttpResponseDivergence>, String>>()?,
            responses: payload
                .responses
                .drain(..)
                .map(
                    |payload| -> Result<CanisterHttpResponseWithConsensus, String> {
                        let response = payload
                            .response
                            .ok_or("Error: canister_http_payload does not contain a response")?;
                        let id = CanisterHttpRequestId::new(response.id);
                        let timeout = Time::from_nanos_since_unix_epoch(response.timeout);
                        let canister_id = response
                            .canister_id
                            .ok_or_else(|| "No canister id on canister http response".to_string())
                            .and_then(|canister_id| {
                                crate::CanisterId::try_from(canister_id)
                                    .map_err(|e| format!("Proxy decode error {:?}", e))
                            })?;

                        Ok(CanisterHttpResponseWithConsensus {
                            content: CanisterHttpResponse {
                                id,
                                timeout,
                                canister_id,
                                content: CanisterHttpResponseContent::try_from(
                                    response.content.ok_or(
                                        "Error: canistrer_http_response does not contain content",
                                    )?,
                                )?,
                            },
                            proof: Signed {
                                content: CanisterHttpResponseMetadata {
                                    id,
                                    timeout,
                                    content_hash: CryptoHashOf::<CanisterHttpResponse>::new(
                                        CryptoHash(payload.hash),
                                    ),
                                    registry_version: RegistryVersion::new(
                                        payload.registry_version,
                                    ),
                                },
                                signature: BasicSignatureBatch {
                                    signatures_map: payload
                                        .signatures
                                        .iter()
                                        .map(|signature| {
                                            Ok((
                                                NodeId::from(
                                                    PrincipalId::try_from(&signature.signer[..])
                                                        .map_err(|err| format!("{:?}", err))?,
                                                ),
                                                BasicSigOf::new(BasicSig(
                                                    signature.signature.clone(),
                                                )),
                                            ))
                                        })
                                        .collect::<Result<BTreeMap<NodeId, BasicSigOf<_>>, String>>(
                                        )?,
                                },
                            },
                        })
                    },
                )
                .collect::<Result<Vec<CanisterHttpResponseWithConsensus>, String>>()?,
            timeouts: payload
                .timeouts
                .iter()
                .map(|timeout| CallbackId::new(*timeout))
                .collect(),
        })
    }
}

impl CountBytes for CanisterHttpPayload {
    fn count_bytes(&self) -> usize {
        let timeouts_size: usize = self.timeouts.iter().map(CountBytes::count_bytes).sum();
        let response_size: usize = self.responses.iter().map(CountBytes::count_bytes).sum();
        timeouts_size + response_size
    }
}

impl From<&CanisterHttpResponseContent> for canister_http_pb::CanisterHttpResponseContent {
    fn from(content: &CanisterHttpResponseContent) -> Self {
        let inner = match content {
            CanisterHttpResponseContent::Success(payload) => {
                canister_http_pb::canister_http_response_content::Status::Success(payload.clone())
            }
            CanisterHttpResponseContent::Reject(error) => {
                canister_http_pb::canister_http_response_content::Status::Reject(
                    canister_http_pb::CanisterHttpReject {
                        reject_code: error.reject_code as u32,
                        message: error.message.clone(),
                    },
                )
            }
        };

        canister_http_pb::CanisterHttpResponseContent {
            status: Some(inner),
        }
    }
}

impl TryFrom<canister_http_pb::CanisterHttpResponseContent> for CanisterHttpResponseContent {
    type Error = String;

    fn try_from(value: canister_http_pb::CanisterHttpResponseContent) -> Result<Self, Self::Error> {
        Ok(
            match value
                .status
                .ok_or("Error: canister_http_content does not contain any value ")?
            {
                canister_http_pb::canister_http_response_content::Status::Success(payload) => {
                    CanisterHttpResponseContent::Success(payload)
                }
                canister_http_pb::canister_http_response_content::Status::Reject(error) => {
                    CanisterHttpResponseContent::Reject(CanisterHttpReject {
                        reject_code: RejectCode::try_from(error.reject_code as u64)
                            .map_err(|err| format!("{:?}", err))?,
                        message: error.message,
                    })
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Encode;
    /// Tests, whether a roundtrip of protobuf conversions generates the same
    /// `CanisterHttpPayload`
    #[test]
    fn into_canister_http_payload_and_back() {
        let payload = CanisterHttpPayload {
            divergence_responses: vec![CanisterHttpResponseDivergence {
                shares: vec![Signed {
                    content: CanisterHttpResponseMetadata {
                        id: CanisterHttpRequestId::new(1),
                        timeout: Time::from_nanos_since_unix_epoch(1234),
                        content_hash: CryptoHashOf::<CanisterHttpResponse>::new(CryptoHash(vec![
                            0, 1, 2, 3,
                        ])),
                        registry_version: RegistryVersion::new(1),
                    },
                    signature: BasicSignature {
                        signer: NodeId::from(PrincipalId::new_node_test_id(1)),
                        signature: BasicSigOf::new(BasicSig(vec![0, 1, 2, 3])),
                    },
                }],
            }],
            responses: vec![CanisterHttpResponseWithConsensus {
                content: CanisterHttpResponse {
                    id: CanisterHttpRequestId::new(1),
                    timeout: Time::from_nanos_since_unix_epoch(1234),
                    canister_id: crate::CanisterId::from(1),
                    content: CanisterHttpResponseContent::Success(
                        Encode!(&ic_ic00_types::CanisterHttpResponsePayload {
                            status: 200,
                            headers: vec![ic_ic00_types::HttpHeader {
                                name: "test_header1".to_string(),
                                value: "value1".to_string()
                            }],
                            body: b"Test data in body".to_vec(),
                        })
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
                    },
                    signature: BasicSignatureBatch {
                        signatures_map: vec![(
                            NodeId::from(PrincipalId::new_node_test_id(1)),
                            BasicSigOf::new(BasicSig(vec![0, 1, 2, 3])),
                        )]
                        .drain(..)
                        .collect(),
                    },
                },
            }],
            timeouts: vec![CanisterHttpRequestId::new(2)],
        };

        let pb_payload = pb::CanisterHttpPayload::from(&payload);
        let new_payload = CanisterHttpPayload::try_from(pb_payload).unwrap();

        assert_eq!(payload, new_payload)
    }
}
