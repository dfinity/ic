use std::collections::{BTreeMap, BTreeSet};

use ic_protobuf::types::v1 as pb;
use ic_types::{
    NodeIndex,
    artifact::{IdentifiableArtifact, IngressMessageId},
    batch::{BatchPayload, IngressPayload},
    consensus::{
        ConsensusMessage, DataPayload, StrippedMessageIds,
        idkg::{IDkgArtifactId, IDkgObject, IDkgPayload},
    },
    crypto::{CryptoHashOf, crypto_hash},
    messages::SignedRequestBytes,
};

use crate::fetch_stripped_artifact::canister_http::strip_responses;

use super::types::stripped::{MaybeStrippedConsensusMessage, StrippedBlockProposal};

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
                let DataPayload {
                    batch: BatchPayload { ingress, .. },
                    idkg,
                    ..
                } = block_proposal.content.as_ref().payload.as_ref().as_data();

                let mut stripped_message_ids = StrippedMessageIds {
                    ingress_messages: ingress.strip(),
                    idkg_dealings: idkg.strip(),
                    canister_http_responses: BTreeSet::new(),
                };

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
                    // Remove the content of the canister HTTP responses, naming the ones
                    // that were removed so that the receiver does not have to scan the
                    // payload to find out. The payload is left untouched if there is
                    // nothing worth stripping, so that a block without a response never
                    // pays for re-encoding it.
                    if let Some((pruned, stripped)) =
                        strip_responses(&block.canister_http_payload_bytes)
                    {
                        block.canister_http_payload_bytes = pruned;
                        stripped_message_ids.canister_http_responses = stripped;
                    }
                }

                MaybeStrippedConsensusMessage::StrippedBlockProposal(StrippedBlockProposal {
                    pruned_block_proposal_proto: proto,
                    unstripped_consensus_message_id,
                    stripped_message_ids,
                })
            }
            msg => MaybeStrippedConsensusMessage::Unstripped(msg),
        }
    }
}

impl Strippable for &IngressPayload {
    type Output = BTreeMap<IngressMessageId, CryptoHashOf<SignedRequestBytes>>;

    fn strip(self) -> Self::Output {
        self.iter_serialized()
            .map(|(id, bytes)| (id.clone(), crypto_hash(bytes)))
            .collect()
    }
}

impl Strippable for &Option<IDkgPayload> {
    type Output = BTreeSet<(NodeIndex, IDkgArtifactId)>;

    fn strip(self) -> Self::Output {
        let Some(idkg) = self else {
            return BTreeSet::new();
        };
        idkg.idkg_transcripts
            .values()
            .flat_map(|transcript| {
                transcript
                    .verified_dealings
                    .iter()
                    .map(|(dealer_index, batch_signed_dealing)| {
                        (*dealer_index, batch_signed_dealing.content.message_id())
                    })
            })
            .collect()
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
