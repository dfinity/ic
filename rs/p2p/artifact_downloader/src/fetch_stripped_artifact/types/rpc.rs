use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1 as pb,
};
use ic_types::{
    NodeIndex,
    artifact::ConsensusMessageId,
    consensus::{ConsensusMessageHash, idkg::IDkgArtifactId},
    crypto::{CryptoHash, CryptoHashOf, canister_threshold_sig::idkg::SignedIDkgDealing},
    messages::SignedRequestBytes,
};

use super::SignedIngressId;

/// Parameters for the `/block/ingress/rpc` requests.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetIngressMessageInBlockRequest {
    pub(crate) signed_ingress_id: SignedIngressId,
    pub(crate) block_proposal_id: ConsensusMessageId,
}

impl TryFrom<pb::GetIngressMessageInBlockRequest> for GetIngressMessageInBlockRequest {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::GetIngressMessageInBlockRequest) -> Result<Self, Self::Error> {
        let ingress_message_id = try_from_option_field(
            value.ingress_message_id,
            "GetIngressMessageInBlockRequest::ingress_message_id",
        )?;
        let consensus_message_id: ConsensusMessageId = try_from_option_field(
            value.block_proposal_id,
            "GetIngressMessageInBlockRequest::block_proposal_id",
        )?;
        let ingress_bytes_hash = CryptoHashOf::from(CryptoHash(value.ingress_bytes_hash));

        match &consensus_message_id.hash {
            ConsensusMessageHash::BlockProposal(_) => {}
            // if it's not block proposal => return an error;
            _ => {
                return Err(ProxyDecodeError::Other(String::from(
                    "Not a BlockProposal consensus message id",
                )));
            }
        };

        Ok(Self {
            block_proposal_id: consensus_message_id,
            signed_ingress_id: SignedIngressId {
                ingress_message_id,
                ingress_bytes_hash,
            },
        })
    }
}

impl From<GetIngressMessageInBlockRequest> for pb::GetIngressMessageInBlockRequest {
    fn from(value: GetIngressMessageInBlockRequest) -> Self {
        Self {
            ingress_message_id: Some(value.signed_ingress_id.ingress_message_id.into()),
            block_proposal_id: Some(value.block_proposal_id.into()),
            ingress_bytes_hash: value.signed_ingress_id.ingress_bytes_hash.get().0,
        }
    }
}

/// `/block/ingress/rpc` response.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetIngressMessageInBlockResponse {
    pub(crate) serialized_ingress_message: SignedRequestBytes,
}

impl TryFrom<pb::GetIngressMessageInBlockResponse> for GetIngressMessageInBlockResponse {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::GetIngressMessageInBlockResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            serialized_ingress_message: SignedRequestBytes::from(value.ingress_message),
        })
    }
}

impl From<GetIngressMessageInBlockResponse> for pb::GetIngressMessageInBlockResponse {
    fn from(value: GetIngressMessageInBlockResponse) -> Self {
        pb::GetIngressMessageInBlockResponse {
            ingress_message: value.serialized_ingress_message.into(),
        }
    }
}

/// Parameters for the `/block/idkg_dealing/rpc` requests.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetIDkgDealingInBlockRequest {
    pub(crate) node_index: NodeIndex,
    pub(crate) dealing_id: IDkgArtifactId,
    pub(crate) block_proposal_id: ConsensusMessageId,
}

impl TryFrom<pb::GetIDkgDealingInBlockRequest> for GetIDkgDealingInBlockRequest {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::GetIDkgDealingInBlockRequest) -> Result<Self, Self::Error> {
        let dealing_id =
            try_from_option_field(value.dealing_id, "GetIDkgDealingInBlockRequest::dealing_id")?;
        let consensus_message_id: ConsensusMessageId = try_from_option_field(
            value.block_proposal_id,
            "GetIDkgDealingInBlockRequest::block_proposal_id",
        )?;

        match &consensus_message_id.hash {
            ConsensusMessageHash::BlockProposal(_) => {}
            // if it's not block proposal => return an error;
            _ => {
                return Err(ProxyDecodeError::Other(String::from(
                    "Not a BlockProposal consensus message id",
                )));
            }
        };

        match &dealing_id {
            IDkgArtifactId::Dealing(_, _) => {}
            // if it's not a dealing => return an error;
            _ => {
                return Err(ProxyDecodeError::Other(String::from(
                    "Not a dealing artifact id",
                )));
            }
        };

        Ok(Self {
            node_index: value.node_index,
            block_proposal_id: consensus_message_id,
            dealing_id,
        })
    }
}

impl From<GetIDkgDealingInBlockRequest> for pb::GetIDkgDealingInBlockRequest {
    fn from(value: GetIDkgDealingInBlockRequest) -> Self {
        Self {
            node_index: value.node_index,
            dealing_id: Some(value.dealing_id.into()),
            block_proposal_id: Some(value.block_proposal_id.into()),
        }
    }
}

/// `/block/idkg_dealing/rpc` response.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetIDkgDealingInBlockResponse {
    pub(crate) signed_dealing: SignedIDkgDealing,
}

impl TryFrom<pb::GetIDkgDealingInBlockResponse> for GetIDkgDealingInBlockResponse {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::GetIDkgDealingInBlockResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            signed_dealing: try_from_option_field(value.signed_dealing.as_ref(), "signed_dealing")?,
        })
    }
}

impl From<GetIDkgDealingInBlockResponse> for pb::GetIDkgDealingInBlockResponse {
    fn from(value: GetIDkgDealingInBlockResponse) -> Self {
        pb::GetIDkgDealingInBlockResponse {
            signed_dealing: Some((&value.signed_dealing).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
    use ic_test_utilities_consensus::fake::FakeSigner;
    use ic_types::{
        Height,
        artifact::IngressMessageId,
        consensus::idkg::{IDkgArtifactIdData, IDkgArtifactIdDataOf, dealing_prefix},
        crypto::{CryptoHash, CryptoHashOf, canister_threshold_sig::idkg::IDkgTranscriptId},
        signature::BasicSignature,
        time::UNIX_EPOCH,
    };
    use ic_types_test_utils::ids::{NODE_1, SUBNET_0, message_test_id};

    use crate::fetch_stripped_artifact::test_utils::{
        fake_finalization_consensus_message_id, fake_idkg_dealing_support_artifact_id,
    };

    use super::*;

    fn make_proposal_id() -> ConsensusMessageId {
        ConsensusMessageId {
            hash: ConsensusMessageHash::BlockProposal(CryptoHashOf::from(CryptoHash(Vec::new()))),
            height: Height::new(101),
        }
    }

    #[test]
    fn get_ingress_message_in_block_request_serialization_test() {
        let request = GetIngressMessageInBlockRequest {
            signed_ingress_id: SignedIngressId {
                ingress_message_id: IngressMessageId::new(UNIX_EPOCH, message_test_id(42)),
                ingress_bytes_hash: CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
            },
            block_proposal_id: make_proposal_id(),
        };

        let proto = pb::GetIngressMessageInBlockRequest::from(request.clone());
        let deserialized = GetIngressMessageInBlockRequest::try_from(proto)
            .expect("Should successfully deserialize the proto");

        assert_eq!(request, deserialized);
    }

    #[test]
    fn get_ingress_message_in_block_request_serialization_fails_if_not_block_proposal_test() {
        let request = GetIngressMessageInBlockRequest {
            signed_ingress_id: SignedIngressId {
                ingress_message_id: IngressMessageId::new(UNIX_EPOCH, message_test_id(42)),
                ingress_bytes_hash: CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
            },
            block_proposal_id: fake_finalization_consensus_message_id(),
        };

        let proto = pb::GetIngressMessageInBlockRequest::from(request.clone());
        let err = GetIngressMessageInBlockRequest::try_from(proto)
            .expect_err("Should not successfully deserialize the proto");

        assert_matches!(
            err,
            ProxyDecodeError::Other(s) if s.contains("Not a BlockProposal consensus message id")
        );
    }

    #[test]
    fn get_ingress_message_in_block_response_serialization_test() {
        let response = GetIngressMessageInBlockResponse {
            serialized_ingress_message: SignedRequestBytes::from(vec![1, 2, 3]),
        };

        let proto = pb::GetIngressMessageInBlockResponse::from(response.clone());
        let deserialized = GetIngressMessageInBlockResponse::try_from(proto)
            .expect("Should successfully deserialize the proto");

        assert_eq!(response, deserialized);
    }

    #[test]
    fn get_idkg_dealing_in_block_request_serialization_test() {
        let transcript_id = IDkgTranscriptId::new(SUBNET_0, 1, Height::new(101));
        let request = GetIDkgDealingInBlockRequest {
            node_index: 1,
            dealing_id: IDkgArtifactId::Dealing(
                dealing_prefix(&transcript_id, &NODE_1),
                IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
                    height: Height::new(101),
                    hash: CryptoHash(Vec::new()),
                    subnet_id: SUBNET_0,
                }),
            ),
            block_proposal_id: make_proposal_id(),
        };

        let proto = pb::GetIDkgDealingInBlockRequest::from(request.clone());
        let deserialized = GetIDkgDealingInBlockRequest::try_from(proto)
            .expect("Should successfully deserialize the proto");

        assert_eq!(request, deserialized);
    }

    #[test]
    fn get_idkg_dealing_in_block_request_serialization_fails_if_not_proposal_test() {
        let transcript_id = IDkgTranscriptId::new(SUBNET_0, 1, Height::new(101));
        let request = GetIDkgDealingInBlockRequest {
            node_index: 1,
            dealing_id: IDkgArtifactId::Dealing(
                dealing_prefix(&transcript_id, &NODE_1),
                IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
                    height: Height::new(101),
                    hash: CryptoHash(Vec::new()),
                    subnet_id: SUBNET_0,
                }),
            ),
            block_proposal_id: fake_finalization_consensus_message_id(),
        };

        let proto = pb::GetIDkgDealingInBlockRequest::from(request.clone());
        let err = GetIDkgDealingInBlockRequest::try_from(proto)
            .expect_err("Should not successfully deserialize the proto");

        assert_matches!(
            err,
            ProxyDecodeError::Other(s) if s.contains("Not a BlockProposal consensus message id")
        );
    }

    #[test]
    fn get_idkg_dealing_in_block_request_serialization_fails_if_not_dealing_test() {
        let request = GetIDkgDealingInBlockRequest {
            node_index: 1,
            dealing_id: fake_idkg_dealing_support_artifact_id(),
            block_proposal_id: make_proposal_id(),
        };

        let proto = pb::GetIDkgDealingInBlockRequest::from(request.clone());
        let err = GetIDkgDealingInBlockRequest::try_from(proto)
            .expect_err("Should not successfully deserialize the proto");

        assert_matches!(
            err,
            ProxyDecodeError::Other(s) if s.contains("Not a dealing artifact id")
        );
    }

    #[test]
    fn get_idkg_dealing_in_block_response_serialization_test() {
        let response = GetIDkgDealingInBlockResponse {
            signed_dealing: SignedIDkgDealing {
                content: dummy_idkg_dealing_for_tests(),
                signature: BasicSignature::fake(NODE_1),
            },
        };

        let proto = pb::GetIDkgDealingInBlockResponse::from(response.clone());
        let deserialized = GetIDkgDealingInBlockResponse::try_from(proto)
            .expect("Should successfully deserialize the proto");

        assert_eq!(response, deserialized);
    }
}
