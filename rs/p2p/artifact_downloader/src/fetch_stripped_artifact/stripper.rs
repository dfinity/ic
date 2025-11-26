use ic_protobuf::types::v1 as pb;
use ic_types::{
    artifact::IdentifiableArtifact,
    batch::{BatchPayload, IngressPayload},
    consensus::{
        ConsensusMessage, DataPayload,
        idkg::{IDkgObject, IDkgPayload},
    },
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

                if let Some(block) = proto.value.as_mut() {
                    // Remove the ingress payload from the proto.
                    block.ingress_payload = None;
                    // Remove the IDKG dealings from the proto.
                    if let Some(idkg) = block.idkg_payload.as_mut() {
                        for transcript in &mut idkg.idkg_transcripts {
                            for dealing in &mut transcript.verified_dealings {
                                dealing.signed_dealing_tuple = None;
                            }
                        }
                    }
                }

                let DataPayload {
                    batch: BatchPayload { ingress, .. },
                    idkg,
                    ..
                } = block_proposal.content.as_ref().payload.as_ref().as_data();

                MaybeStrippedConsensusMessage::StrippedBlockProposal(StrippedBlockProposal {
                    block_proposal_without_ingresses_proto: proto,
                    unstripped_consensus_message_id,
                    stripped_ingress_payload: ingress.strip(),
                    stripped_idkg_dealings: idkg.strip(),
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

impl Strippable for &Option<IDkgPayload> {
    type Output = StrippedIDkgDealings;

    fn strip(self) -> Self::Output {
        let stripped_dealings = if let Some(idkg) = self {
            idkg.idkg_transcripts
                .iter()
                .flat_map(|(_id, transcript)| {
                    transcript
                        .verified_dealings
                        .iter()
                        .map(|(dealer_index, signed_dealing)| {
                            (*dealer_index, signed_dealing.content.message_id())
                        })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        StrippedIDkgDealings { stripped_dealings }
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
