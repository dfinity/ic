use crate::{
    canister_http::{
        CanisterHttpReject, CanisterHttpRequestId, CanisterHttpResponse,
        CanisterHttpResponseContent, CanisterHttpResponseMetadata,
        CanisterHttpResponseWithConsensus,
    },
    crypto::{CombinedMultiSig, CombinedMultiSigOf, CryptoHash, CryptoHashOf, Signed},
    signature::MultiSignature,
    CountBytes, Time,
};
use ic_base_types::{NodeId, PrincipalId, RegistryVersion};
use ic_error_types::RejectCode;
use ic_protobuf::{canister_http::v1 as canister_http_pb, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub const MAX_CANISTER_HTTP_PAYLOAD_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

/// Payload that contains CanisterHttpPayload messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterHttpPayload(pub Vec<CanisterHttpResponseWithConsensus>);

impl CanisterHttpPayload {
    /// Returns the number of responses that this payload contains
    pub fn num_responses(&self) -> usize {
        self.0.len()
    }

    /// Returns true, if this is an empty payload
    pub fn is_empty(&self) -> bool {
        self.num_responses() == 0
    }
}

impl From<&CanisterHttpPayload> for pb::CanisterHttpPayload {
    fn from(payload: &CanisterHttpPayload) -> Self {
        Self {
            payload: payload
                .0
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
                        signature: payload.proof.signature.signature.clone().get().0,
                        signers: payload
                            .proof
                            .signature
                            .signers
                            .iter()
                            .map(|node_id| (*node_id).get().into_vec())
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
        Ok(CanisterHttpPayload(
            payload
                .payload
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
                                signature: MultiSignature {
                                    signature: CombinedMultiSigOf::from(CombinedMultiSig(
                                        payload.signature,
                                    )),
                                    signers: payload
                                        .signers
                                        .iter()
                                        .map(|n| {
                                            Ok(NodeId::from(
                                                PrincipalId::try_from(&n[..])
                                                    .map_err(|err| format!("{:?}", err))?,
                                            ))
                                        })
                                        .collect::<Result<Vec<NodeId>, String>>()?,
                                },
                            },
                        })
                    },
                )
                .collect::<Result<Vec<CanisterHttpResponseWithConsensus>, String>>()?,
        ))
    }
}

impl CountBytes for CanisterHttpPayload {
    fn count_bytes(&self) -> usize {
        self.0.iter().map(CountBytes::count_bytes).sum()
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
        let payload = CanisterHttpPayload(vec![CanisterHttpResponseWithConsensus {
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
                signature: MultiSignature {
                    signature: CombinedMultiSigOf::from(CombinedMultiSig(vec![0, 1, 2, 3])),
                    signers: vec![NodeId::from(PrincipalId::new_node_test_id(1))],
                },
            },
        }]);

        let pb_payload = pb::CanisterHttpPayload::from(&payload);
        let new_payload = CanisterHttpPayload::try_from(pb_payload).unwrap();

        assert_eq!(payload, new_payload)
    }
}
