use ic_types::consensus::{BlockProposal, ConsensusMessage};

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
        match self {
            // We only strip data blocks.
            ConsensusMessage::BlockProposal(block_proposal)
                if block_proposal.as_ref().payload.payload_type()
                    == ic_types::consensus::PayloadType::Data =>
            {
                MaybeStrippedConsensusMessage::StrippedBlockProposal(block_proposal.strip())
            }
            msg => MaybeStrippedConsensusMessage::Unstripped(msg),
        }
    }
}

impl Strippable for BlockProposal {
    type Output = StrippedBlockProposal;

    // TODO(kpop): implement this
    fn strip(self) -> Self::Output {
        unimplemented!()
    }
}
