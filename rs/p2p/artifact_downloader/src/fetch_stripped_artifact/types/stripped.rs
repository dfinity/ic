use std::convert::Infallible;

use ic_protobuf::{
    p2p::v1 as p2p_pb,
    proxy::{try_from_option_field, ProxyDecodeError},
};
use ic_types::{
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId, PbArtifact},
    consensus::{BlockProposal, ConsensusMessage},
    messages::SignedIngress,
};

#[derive(Debug)]
// TODO(kpop): Add all fields necessary to reconstruct a block
pub struct StrippedBlockProposal {
    unstripped_consensus_message_id: ConsensusMessageId,
}

#[derive(Debug, PartialEq)]
pub(crate) enum InsertionError {}

#[derive(Debug, PartialEq)]
pub(crate) enum AssemblyError {}

impl StrippedBlockProposal {
    /// Returns the list of [`IngressMessageId`]s which have been stripped from the block.
    // TODO(kpop): Implement this
    pub(crate) fn missing_ingress_messages(&self) -> Vec<IngressMessageId> {
        unimplemented!()
    }

    /// Tries to insert a missing ingress message into the block.
    // TODO(kpop): Implement this
    pub(crate) fn try_insert_ingress_message(
        &mut self,
        _ingress_message: SignedIngress,
    ) -> Result<(), InsertionError> {
        unimplemented!()
    }

    /// Tries to reassemble a block.
    ///
    /// Fails if there are still some ingress messages missing.
    // TODO(kpop): Implement this
    pub(crate) fn try_assemble(self) -> Result<BlockProposal, AssemblyError> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum MaybeStrippedConsensusMessage {
    StrippedBlockProposal(StrippedBlockProposal),
    Unstripped(ConsensusMessage),
}

impl TryFrom<p2p_pb::StrippedConsensusMessage> for MaybeStrippedConsensusMessage {
    type Error = ProxyDecodeError;

    fn try_from(value: p2p_pb::StrippedConsensusMessage) -> Result<Self, Self::Error> {
        use p2p_pb::stripped_consensus_message::Msg;
        let Some(msg) = value.msg else {
            return Err(ProxyDecodeError::MissingField(
                "StrippedConsensusMessage::msg",
            ));
        };

        Ok(match msg {
            Msg::Unstripped(msg) => MaybeStrippedConsensusMessage::Unstripped(msg.try_into()?),
            // TODO(kpop): Implement this
            Msg::StrippedBlockProposal(_) => unimplemented!(),
        })
    }
}

impl From<MaybeStrippedConsensusMessage> for p2p_pb::StrippedConsensusMessage {
    fn from(value: MaybeStrippedConsensusMessage) -> Self {
        let msg = match value {
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => {
                p2p_pb::stripped_consensus_message::Msg::Unstripped(unstripped.into())
            }
            MaybeStrippedConsensusMessage::StrippedBlockProposal(_) => todo!(),
        };

        Self { msg: Some(msg) }
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct StrippedConsensusMessageId(ConsensusMessageId);

impl AsRef<ConsensusMessageId> for StrippedConsensusMessageId {
    fn as_ref(&self) -> &ConsensusMessageId {
        &self.0
    }
}

impl From<StrippedConsensusMessageId> for p2p_pb::StrippedConsensusMessageId {
    fn from(value: StrippedConsensusMessageId) -> Self {
        p2p_pb::StrippedConsensusMessageId {
            unstripped_id: Some(value.0.into()),
        }
    }
}

impl TryFrom<p2p_pb::StrippedConsensusMessageId> for StrippedConsensusMessageId {
    type Error = ProxyDecodeError;

    fn try_from(value: p2p_pb::StrippedConsensusMessageId) -> Result<Self, Self::Error> {
        let unstripped = try_from_option_field(
            value.unstripped_id,
            "StrippedConsensusMessageId::unstripped_id",
        )?;

        Ok(Self(unstripped))
    }
}

impl IdentifiableArtifact for MaybeStrippedConsensusMessage {
    const NAME: &'static str = "strippedconsensus";

    type Id = StrippedConsensusMessageId;

    type Attribute = ();

    fn id(&self) -> Self::Id {
        let unstripped_id = match self {
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => unstripped.id(),
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) => {
                stripped.unstripped_consensus_message_id.clone()
            }
        };

        StrippedConsensusMessageId(unstripped_id)
    }

    fn attribute(&self) -> Self::Attribute {}
}

impl PbArtifact for MaybeStrippedConsensusMessage {
    type PbId = p2p_pb::StrippedConsensusMessageId;

    type PbIdError = ProxyDecodeError;

    type PbMessage = p2p_pb::StrippedConsensusMessage;

    type PbMessageError = ProxyDecodeError;

    type PbAttribute = ();

    type PbAttributeError = Infallible;
}
