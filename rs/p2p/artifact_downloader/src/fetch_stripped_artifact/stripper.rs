use ic_protobuf::types::v1 as pb;
use ic_types::{
    artifact::{IdentifiableArtifact, IngressMessageId},
    batch::IngressPayload,
    consensus::ConsensusMessage,
};

use super::types::stripped::{
    MaybeStrippedConsensusMessage, MaybeStrippedIngress, StrippedBlockProposal,
    StrippedIngressPayload,
};

/// Provides functionality for stripping objects of given information.
///
/// For example, one might want to remove ingress messages from a block proposal.
pub(crate) trait Strippable {
    type Output;

    /// Strips ingress messages from the object.
    fn strip(self) -> Self::Output;
}

impl Strippable for ConsensusMessage {
    type Output = MaybeStrippedConsensusMessage;

    fn strip(self) -> Self::Output {
        let unstripped_consensus_message_id = self.id();

        match self {
            // We only strip data blocks.
            ConsensusMessage::BlockProposal(block_proposal)
                if block_proposal.as_ref().payload.payload_type()
                    == ic_types::consensus::PayloadType::Data =>
            {
                let mut proto = pb::BlockProposal::from(&block_proposal);

                // Remove the ingress payload from the proto.
                if let Some(block) = proto.value.as_mut() {
                    block.ingress_payload = None;
                }

                let data_payload = block_proposal.content.as_ref().payload.as_ref().as_data();
                // TODO(CON-1402): avoid the clone
                let stripped_ingress_payload = data_payload.batch.ingress.clone().strip();

                MaybeStrippedConsensusMessage::StrippedBlockProposal(StrippedBlockProposal {
                    block_proposal_without_ingresses_proto: proto,
                    stripped_ingress_payload,
                    unstripped_consensus_message_id,
                })
            }
            msg => MaybeStrippedConsensusMessage::Unstripped(msg),
        }
    }
}

impl Strippable for IngressPayload {
    type Output = StrippedIngressPayload;

    fn strip(self) -> Self::Output {
        let ingresses: Vec<_> = self.try_into().expect(
            "A valid ingress payload shouldn't fail when converting to a vector of ingresses",
        );

        let stripped_ingresses = ingresses
            .into_iter()
            .map(|ingress| {
                let ingress_message_id = IngressMessageId::from(&ingress);
                MaybeStrippedIngress::Stripped(ingress_message_id)
            })
            .collect();

        Self::Output {
            ingress_messages: stripped_ingresses,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::fake_summary_block_proposal;

    use super::*;

    #[test]
    fn summary_blocks_are_not_stripped_test() {
        let summary_block = fake_summary_block_proposal();

        let stripped = summary_block.clone().strip();

        assert_eq!(
            stripped,
            MaybeStrippedConsensusMessage::Unstripped(summary_block)
        );
    }
}
