use ic_protobuf::types::v1 as pb;
use ic_types::{
    artifact::{IdentifiableArtifact, IngressMessageId},
    batch::IngressPayload,
    consensus::ConsensusMessage,
    CountBytes,
};

use super::types::stripped::{
    MaybeStrippedConsensusMessage, MaybeStrippedIngress, StrippedBlockProposal,
    StrippedIngressPayload,
};

/// If an ingress message has size above this threshold, we will strip it from the block.
const INGRESS_MESSAGE_SIZE_STRIPPING_THRESHOLD_BYTES: usize = 1024;

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

                if ingress.count_bytes() > INGRESS_MESSAGE_SIZE_STRIPPING_THRESHOLD_BYTES {
                    MaybeStrippedIngress::Stripped(ingress_message_id)
                } else {
                    MaybeStrippedIngress::Full(ingress_message_id, ingress)
                }
            })
            .collect();

        Self::Output {
            ingress_messages: stripped_ingresses,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_ingress_message_with_arg_size, fake_summary_block_proposal,
    };

    use super::*;

    #[test]
    fn stripping_only_big_messages_test() {
        let (small_ingress, small_ingress_id) = fake_ingress_message_with_arg_size("small", 0);
        let (big_ingress, big_ingress_id) = fake_ingress_message_with_arg_size("big", 1024);
        let ingress_payload =
            IngressPayload::from(vec![small_ingress.clone(), big_ingress.clone()]);

        let stripped_ingress_payload = ingress_payload.strip();

        assert_eq!(
            stripped_ingress_payload,
            StrippedIngressPayload {
                ingress_messages: vec![
                    MaybeStrippedIngress::Full(small_ingress_id, small_ingress),
                    MaybeStrippedIngress::Stripped(big_ingress_id)
                ],
            }
        );
    }

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
