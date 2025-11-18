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
    use ic_types::{
        Height,
        artifact::IngressMessageId,
        crypto::{CryptoHash, CryptoHashOf},
        time::UNIX_EPOCH,
    };
    use ic_types_test_utils::ids::message_test_id;

    use super::*;

    #[test]
    fn get_ingress_message_in_block_request_serialization_test() {
        let request = GetIngressMessageInBlockRequest {
            signed_ingress_id: SignedIngressId {
                ingress_message_id: IngressMessageId::new(UNIX_EPOCH, message_test_id(42)),
                ingress_bytes_hash: CryptoHashOf::from(CryptoHash(vec![1, 2, 3])),
            },
            block_proposal_id: ConsensusMessageId {
                hash: ConsensusMessageHash::BlockProposal(CryptoHashOf::from(CryptoHash(
                    Vec::new(),
                ))),
                height: Height::new(101),
            },
        };

        let proto = pb::GetIngressMessageInBlockRequest::from(request.clone());
        let deserialized = GetIngressMessageInBlockRequest::try_from(proto)
            .expect("Should successfully deserialize the proto");

        assert_eq!(request, deserialized);
    }
}
