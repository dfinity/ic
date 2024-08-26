use ic_protobuf::{
    p2p::v1 as pb,
    proxy::{try_from_option_field, ProxyDecodeError},
};
use ic_types::{
    artifact::{ConsensusMessageId, IngressMessageId},
    consensus::ConsensusMessageHash,
    messages::{SignedIngress, SignedRequestBytes},
};

use bytes::Bytes;

/// Parameters for the `/block/ingress/` rpc requests.
#[derive(Clone, Debug, PartialEq)]
// FIXME(kpop): check that it's a block proposal indeed
pub(crate) struct GetIngressMessageInBlockRequest {
    pub(crate) ingress_message_id: IngressMessageId,
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
            ingress_message_id,
            block_proposal_id: consensus_message_id,
        })
    }
}

impl From<GetIngressMessageInBlockRequest> for pb::GetIngressMessageInBlockRequest {
    fn from(value: GetIngressMessageInBlockRequest) -> Self {
        Self {
            ingress_message_id: Some(value.ingress_message_id.into()),
            block_proposal_id: Some(value.block_proposal_id.into()),
        }
    }
}

/// `/block/ingress/` rpc response.
#[derive(Debug, PartialEq)]
pub(crate) struct GetIngressMessageInBlockResponse {
    pub(crate) ingress_message: SignedIngress,
}

impl TryFrom<pb::GetIngressMessageInBlockResponse> for GetIngressMessageInBlockResponse {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::GetIngressMessageInBlockResponse) -> Result<Self, Self::Error> {
        let ingress_message = SignedIngress::try_from(Bytes::from(value.ingress_message))?;

        Ok(Self { ingress_message })
    }
}

impl From<GetIngressMessageInBlockResponse> for pb::GetIngressMessageInBlockResponse {
    fn from(value: GetIngressMessageInBlockResponse) -> Self {
        pb::GetIngressMessageInBlockResponse {
            ingress_message: SignedRequestBytes::from(value.ingress_message).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ic_types::{
        crypto::{CryptoHash, CryptoHashOf},
        time::UNIX_EPOCH,
        Height,
    };
    use ic_types_test_utils::ids::message_test_id;

    use super::*;

    #[test]
    fn get_ingress_message_in_block_request_serialization_test() {
        let request = GetIngressMessageInBlockRequest {
            ingress_message_id: IngressMessageId::new(UNIX_EPOCH, message_test_id(42)),
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
