use ic_protobuf::types::v1 as pb;
use ic_types::{
    artifact::IdentifiableArtifact,
    batch::IngressPayload,
    consensus::{ConsensusMessage, idkg::IDkgObject},
};

use crate::fetch_stripped_artifact::types::stripped::StrippedIDkgDealings;

use super::types::{
    SignedIngressId,
    stripped::{MaybeStrippedConsensusMessage, StrippedBlockProposal, StrippedIngressPayload},
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
            ConsensusMessage::BlockProposal(ref block_proposal)
                if block_proposal.as_ref().payload.payload_type()
                    == ic_types::consensus::PayloadType::Data =>
            {
                let mut proto = pb::BlockProposal::from(block_proposal);

                // Remove the ingress payload from the proto.
                if let Some(block) = proto.value.as_mut() {
                    block.ingress_payload = None;
                    if let Some(idkg) = block.idkg_payload.as_mut() {
                        for t in &mut idkg.idkg_transcripts {
                            for d in &mut t.verified_dealings {
                                d.signed_dealing_tuple = None;
                            }
                        }
                    }
                }

                let data_payload = block_proposal.content.as_ref().payload.as_ref().as_data();

                let transcripts = data_payload
                    .idkg
                    .as_ref()
                    .map(|idkg| idkg.idkg_transcripts.clone())
                    .unwrap_or_default();
                let stripped_dealings = transcripts
                    .into_iter()
                    .flat_map(|(_id, transcript)| {
                        transcript
                            .verified_dealings
                            .iter()
                            .map(|(dealer_index, signed_dealing)| {
                                (dealer_index.clone(), signed_dealing.content.message_id())
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();

                let stripped_ingress_payload = data_payload.batch.ingress.strip();

                MaybeStrippedConsensusMessage::StrippedBlockProposal(StrippedBlockProposal {
                    block_proposal_without_ingresses_proto: proto,
                    stripped_ingress_payload,
                    unstripped_consensus_message_id,
                    stripped_dealings: StrippedIDkgDealings { stripped_dealings },
                })
            }
            msg => MaybeStrippedConsensusMessage::Unstripped(msg),
        }
    }
}

impl Strippable for &IngressPayload {
    type Output = StrippedIngressPayload;

    fn strip(self) -> Self::Output {
        let ingress_messages = self
            .iter_serialized()
            .map(|(id, bytes)| SignedIngressId::new(id.clone(), bytes))
            .collect();

        StrippedIngressPayload { ingress_messages }
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
