use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    types::v1 as pb,
};
use ic_types::{
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId, PbArtifact},
    consensus::ConsensusMessage,
    messages::{SignedIngress, SignedRequestBytes},
};

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum MaybeStrippedIngress {
    Full(IngressMessageId, SignedIngress),
    Stripped(IngressMessageId),
}

/// Stripped version of the [`IngressPayload`].
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct StrippedIngressPayload {
    pub(crate) ingress_messages: Vec<MaybeStrippedIngress>,
}

/// Stripped version of the [`BlockProposal`].
#[derive(Clone, Debug, PartialEq)]
pub struct StrippedBlockProposal {
    pub(crate) block_proposal_without_ingresses_proto: pb::BlockProposal,
    pub(crate) stripped_ingress_payload: StrippedIngressPayload,
    pub(crate) unstripped_consensus_message_id: ConsensusMessageId,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum MaybeStrippedConsensusMessage {
    StrippedBlockProposal(StrippedBlockProposal),
    Unstripped(ConsensusMessage),
}

impl TryFrom<pb::StrippedConsensusMessage> for MaybeStrippedConsensusMessage {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::StrippedConsensusMessage) -> Result<Self, Self::Error> {
        use pb::stripped_consensus_message::Msg;
        let Some(msg) = value.msg else {
            return Err(ProxyDecodeError::MissingField(
                "StrippedConsensusMessage::msg",
            ));
        };

        Ok(match msg {
            Msg::Unstripped(msg) => MaybeStrippedConsensusMessage::Unstripped(msg.try_into()?),
            Msg::StrippedBlockProposal(stripped_block_proposal_proto) => {
                MaybeStrippedConsensusMessage::StrippedBlockProposal(
                    stripped_block_proposal_proto.try_into()?,
                )
            }
        })
    }
}

impl TryFrom<pb::StrippedBlockProposal> for StrippedBlockProposal {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::StrippedBlockProposal) -> Result<Self, Self::Error> {
        Ok(Self {
            block_proposal_without_ingresses_proto: value
                .block_proposal_without_ingress_payload
                .ok_or_else(|| {
                    ProxyDecodeError::MissingField("block_proposal_without_ingress_payload")
                })?,
            stripped_ingress_payload: StrippedIngressPayload {
                ingress_messages: value
                    .ingress_messages
                    .into_iter()
                    .map(MaybeStrippedIngress::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            unstripped_consensus_message_id: try_from_option_field(
                value.unstripped_consensus_message_id,
                "unstripped_consensus_message_id",
            )?,
        })
    }
}

impl From<StrippedBlockProposal> for pb::StrippedBlockProposal {
    fn from(value: StrippedBlockProposal) -> Self {
        Self {
            block_proposal_without_ingress_payload: Some(
                value.block_proposal_without_ingresses_proto,
            ),
            ingress_messages: value
                .stripped_ingress_payload
                .ingress_messages
                .into_iter()
                .map(pb::StrippedIngressMessage::from)
                .collect(),
            unstripped_consensus_message_id: Some(value.unstripped_consensus_message_id.into()),
        }
    }
}

impl From<MaybeStrippedIngress> for pb::StrippedIngressMessage {
    fn from(value: MaybeStrippedIngress) -> Self {
        use pb::stripped_ingress_message::Msg as MaybeStrippedIngressProto;

        let msg = match value {
            MaybeStrippedIngress::Full(_ingress_id, ingress) => {
                MaybeStrippedIngressProto::Full(SignedRequestBytes::from(ingress).into())
            }
            MaybeStrippedIngress::Stripped(ingress_id) => {
                MaybeStrippedIngressProto::Stripped(ingress_id.into())
            }
        };

        pb::StrippedIngressMessage { msg: Some(msg) }
    }
}

impl TryFrom<pb::StrippedIngressMessage> for MaybeStrippedIngress {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::StrippedIngressMessage) -> Result<Self, Self::Error> {
        let Some(msg) = value.msg else {
            return Err(ProxyDecodeError::MissingField("msg"));
        };

        use pb::stripped_ingress_message::Msg as MaybeStrippedIngressProto;

        let ingress = match msg {
            MaybeStrippedIngressProto::Full(ingress) => {
                let ingress = SignedIngress::try_from(SignedRequestBytes::from(ingress))
                    .map_err(|err| ProxyDecodeError::Other(err.to_string()))?;
                MaybeStrippedIngress::Full(IngressMessageId::from(&ingress), ingress)
            }
            MaybeStrippedIngressProto::Stripped(ingress_id) => {
                MaybeStrippedIngress::Stripped(ingress_id.try_into()?)
            }
        };

        Ok(ingress)
    }
}

impl From<MaybeStrippedConsensusMessage> for pb::StrippedConsensusMessage {
    fn from(value: MaybeStrippedConsensusMessage) -> Self {
        let msg = match value {
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => {
                pb::stripped_consensus_message::Msg::Unstripped(unstripped.into())
            }
            MaybeStrippedConsensusMessage::StrippedBlockProposal(block_proposal) => {
                pb::stripped_consensus_message::Msg::StrippedBlockProposal(block_proposal.into())
            }
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

impl From<StrippedConsensusMessageId> for pb::StrippedConsensusMessageId {
    fn from(value: StrippedConsensusMessageId) -> Self {
        pb::StrippedConsensusMessageId {
            unstripped_id: Some(value.0.into()),
        }
    }
}

impl TryFrom<pb::StrippedConsensusMessageId> for StrippedConsensusMessageId {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::StrippedConsensusMessageId) -> Result<Self, Self::Error> {
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

    fn id(&self) -> Self::Id {
        let unstripped_id = match self {
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => unstripped.id(),
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) => {
                stripped.unstripped_consensus_message_id.clone()
            }
        };

        StrippedConsensusMessageId(unstripped_id)
    }
}

impl PbArtifact for MaybeStrippedConsensusMessage {
    type PbId = pb::StrippedConsensusMessageId;

    type PbIdError = ProxyDecodeError;

    type PbMessage = pb::StrippedConsensusMessage;

    type PbMessageError = ProxyDecodeError;
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_ingress_message, fake_stripped_block_proposal_with_ingresses,
    };

    use super::*;

    #[test]
    fn serialize_deserialize_stripped_block_proposal_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal = fake_stripped_block_proposal_with_ingresses(vec![
            MaybeStrippedIngress::Full(ingress_1_id, ingress_1),
            MaybeStrippedIngress::Stripped(ingress_2_id),
        ]);
        let original_consensus_message =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal);

        let proto = pb::StrippedConsensusMessage::from(original_consensus_message.clone());
        let consensus_message = MaybeStrippedConsensusMessage::try_from(proto)
            .expect("Should deserialize a valid proto");

        assert_eq!(consensus_message, original_consensus_message);
    }
}
