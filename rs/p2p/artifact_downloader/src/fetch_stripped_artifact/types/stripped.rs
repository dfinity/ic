use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1 as pb,
};
use ic_types::{
    NodeIndex,
    artifact::{ConsensusMessageId, IdentifiableArtifact, PbArtifact},
    consensus::{ConsensusMessage, ConsensusMessageHash, idkg::IDkgArtifactId},
};

use super::SignedIngressId;

/// Stripped version of the [`IngressPayload`].
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct StrippedIngressPayload {
    pub(crate) ingress_messages: Vec<SignedIngressId>,
}

/// Stripped version of the [`SignedIDkgDealing`]s.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct StrippedIDkgDealings {
    pub(crate) stripped_dealings: Vec<(NodeIndex, IDkgArtifactId)>,
}

/// Stripped version of the [`BlockProposal`].
#[derive(Clone, Debug, PartialEq)]
pub struct StrippedBlockProposal {
    pub(crate) block_proposal_without_ingresses_proto: pb::BlockProposal,
    pub(crate) stripped_ingress_payload: StrippedIngressPayload,
    pub(crate) unstripped_consensus_message_id: ConsensusMessageId,
    pub(crate) stripped_idkg_dealings: StrippedIDkgDealings,
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
        let block_proposal_without_ingresses_proto = value
            .block_proposal_without_ingress_payload
            .ok_or_else(|| {
            ProxyDecodeError::MissingField("block_proposal_without_ingress_payload")
        })?;

        if let Some(block) = block_proposal_without_ingresses_proto.value.as_ref() {
            if block.ingress_payload.is_some() {
                return Err(ProxyDecodeError::Other(String::from(
                    "The ingress payload is NOT empty",
                )));
            }

            if let Some(idkg) = block.idkg_payload.as_ref() {
                for transcript in &idkg.idkg_transcripts {
                    for dealing in &transcript.verified_dealings {
                        if dealing.signed_dealing_tuple.is_some() {
                            return Err(ProxyDecodeError::Other(String::from(
                                "The IDKG dealings are NOT stripped",
                            )));
                        }
                    }
                }
            }
        }

        let unstripped_consensus_message_id: ConsensusMessageId = try_from_option_field(
            value.unstripped_consensus_message_id,
            "unstripped_consensus_message_id",
        )?;

        if !matches!(
            unstripped_consensus_message_id.hash,
            ConsensusMessageHash::BlockProposal(_)
        ) {
            return Err(ProxyDecodeError::Other(format!(
                "The unstripped consensus message id {:?} is NOT for a block proposal",
                unstripped_consensus_message_id,
            )));
        }

        Ok(Self {
            block_proposal_without_ingresses_proto,
            stripped_ingress_payload: StrippedIngressPayload {
                ingress_messages: value
                    .ingress_messages
                    .into_iter()
                    .map(SignedIngressId::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            unstripped_consensus_message_id,
            stripped_idkg_dealings: StrippedIDkgDealings {
                stripped_dealings: value
                    .stripped_dealings
                    .into_iter()
                    .map(|dealing| {
                        let idkg_artifact_id: IDkgArtifactId = try_from_option_field(
                            dealing.dealing_id,
                            "StrippedIDkgDealings::dealing_id",
                        )?;
                        if !matches!(idkg_artifact_id, IDkgArtifactId::Dealing(_, _)) {
                            return Err(ProxyDecodeError::Other(format!(
                                "The stripped IDKG artifact id {:?} is NOT for a dealing",
                                idkg_artifact_id,
                            )));
                        }
                        Ok((dealing.dealer_index, idkg_artifact_id))
                    })
                    .collect::<Result<Vec<_>, ProxyDecodeError>>()?,
            },
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
                .map(|signed_ingress_id| pb::StrippedIngressMessage {
                    stripped: Some(signed_ingress_id.ingress_message_id.into()),
                    ingress_bytes_hash: signed_ingress_id.ingress_bytes_hash.get().0,
                })
                .collect(),
            unstripped_consensus_message_id: Some(value.unstripped_consensus_message_id.into()),
            stripped_dealings: value
                .stripped_idkg_dealings
                .stripped_dealings
                .into_iter()
                .map(|(dealer_index, dealing_id)| pb::StrippedDealing {
                    dealer_index,
                    dealing_id: Some(dealing_id.into()),
                })
                .collect(),
        }
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
    use assert_matches::assert_matches;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    use crate::fetch_stripped_artifact::{
        test_utils::{
            fake_finalization_consensus_message_id, fake_idkg_dealing,
            fake_idkg_dealing_support_artifact_id, fake_ingress_message,
            fake_stripped_block_proposal_with_messages,
        },
        types::StrippedMessageId,
    };

    use super::*;

    #[test]
    fn serialize_deserialize_stripped_block_proposal_test() {
        let ingress_1_id = fake_ingress_message("fake_1").id();
        let ingress_2_id = fake_ingress_message("fake_2").id();
        let idkg_dealing_1_id = fake_idkg_dealing(NODE_1, 1).id();
        let idkg_dealing_2_id = fake_idkg_dealing(NODE_2, 2).id();
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            ingress_1_id,
            ingress_2_id,
            idkg_dealing_1_id,
            idkg_dealing_2_id,
        ]);
        let original_consensus_message =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal);

        let proto = pb::StrippedConsensusMessage::from(original_consensus_message.clone());
        let consensus_message = MaybeStrippedConsensusMessage::try_from(proto)
            .expect("Should deserialize a valid proto");

        assert_eq!(consensus_message, original_consensus_message);
    }

    #[test]
    fn deserialize_non_proposal_message_id_should_fail() {
        let mut stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![]);
        stripped_block_proposal.unstripped_consensus_message_id =
            fake_finalization_consensus_message_id();

        let original_consensus_message =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal);
        let proto = pb::StrippedConsensusMessage::from(original_consensus_message.clone());
        let result = MaybeStrippedConsensusMessage::try_from(proto);
        assert_matches!(
            result,
            Err(ProxyDecodeError::Other(msg)) if msg.contains("is NOT for a block proposal")
        );
    }

    #[test]
    fn deserialize_non_dealing_artifact_id_should_fail() {
        let idkg_dealing_support_id = fake_idkg_dealing_support_artifact_id();
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_messages(vec![StrippedMessageId::IDkgDealing(
                idkg_dealing_support_id,
                1,
            )]);
        let original_consensus_message =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal);

        let proto = pb::StrippedConsensusMessage::from(original_consensus_message.clone());
        let result = MaybeStrippedConsensusMessage::try_from(proto);
        assert_matches!(
            result,
            Err(ProxyDecodeError::Other(msg)) if msg.contains("is NOT for a dealing")
        );
    }
}
