use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    types::v1 as pb,
};
use ic_types::{
    artifact::{ConsensusMessageId, IdentifiableArtifact, PbArtifact},
    consensus::{ConsensusMessage, ConsensusMessageHash, StrippedMessageIds, idkg::IDkgArtifactId},
    crypto::{CryptoHash, CryptoHashOf, crypto_hash},
};

use super::SignedIngressId;

/// Stripped version of the [`BlockProposal`].
#[derive(Clone, Debug, PartialEq)]
pub struct StrippedBlockProposal {
    /// The original block proposal proto but all [`Strippable`] data is removed.
    pub(crate) pruned_block_proposal_proto: pb::BlockProposal,
    /// The consensus message ID of the original (unstripped) block proposal, including the [`Strippable`] data.
    pub(crate) unstripped_consensus_message_id: ConsensusMessageId,
    /// The IDs of the messages that were pruned from the block proposal.
    pub(crate) stripped_message_ids: StrippedMessageIds,
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
        let pruned_block_proposal_proto = value
            .pruned_block_proposal
            .ok_or_else(|| ProxyDecodeError::MissingField("pruned_block_proposal"))?;

        if pruned_block_proposal_proto
            .value
            .as_ref()
            .is_some_and(|block| block.ingress_payload.is_some())
        {
            return Err(ProxyDecodeError::Other(String::from(
                "The ingress payload is NOT empty",
            )));
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

        // Every order and repetition of the same IDs decodes to the same IDs.
        let stripped_message_ids = StrippedMessageIds {
            ingress_messages: value
                .ingress_messages
                .into_iter()
                .map(|message| {
                    SignedIngressId::try_from(message)
                        .map(|id| (id.ingress_message_id, id.ingress_bytes_hash))
                })
                .collect::<Result<_, _>>()?,
            idkg_dealings: value
                .stripped_idkg_dealings
                .into_iter()
                .map(|dealing| {
                    let idkg_artifact_id: IDkgArtifactId = try_from_option_field(
                        dealing.dealing_id,
                        "StrippedIDkgDealing::dealing_id",
                    )?;
                    if !matches!(idkg_artifact_id, IDkgArtifactId::Dealing(_, _)) {
                        return Err(ProxyDecodeError::Other(format!(
                            "The stripped IDKG artifact id {:?} is NOT for a dealing",
                            idkg_artifact_id,
                        )));
                    }
                    Ok((dealing.dealer_index, idkg_artifact_id))
                })
                .collect::<Result<_, ProxyDecodeError>>()?,
            canister_http_responses: value
                .stripped_canister_http_responses
                .into_iter()
                .map(|response| CryptoHashOf::new(CryptoHash(response.content_hash)))
                .collect(),
        };

        Ok(Self {
            pruned_block_proposal_proto,
            unstripped_consensus_message_id,
            stripped_message_ids,
        })
    }
}

impl From<StrippedBlockProposal> for pb::StrippedBlockProposal {
    fn from(value: StrippedBlockProposal) -> Self {
        let StrippedMessageIds {
            ingress_messages,
            idkg_dealings,
            canister_http_responses,
        } = value.stripped_message_ids;
        Self {
            pruned_block_proposal: Some(value.pruned_block_proposal_proto),
            ingress_messages: ingress_messages
                .into_iter()
                .map(
                    |(ingress_message_id, ingress_bytes_hash)| pb::StrippedIngressMessage {
                        stripped: Some(ingress_message_id.into()),
                        ingress_bytes_hash: ingress_bytes_hash.get().0,
                    },
                )
                .collect(),
            unstripped_consensus_message_id: Some(value.unstripped_consensus_message_id.into()),
            stripped_idkg_dealings: idkg_dealings
                .into_iter()
                .map(|(dealer_index, dealing_id)| pb::StrippedIDkgDealing {
                    dealer_index,
                    dealing_id: Some(dealing_id.into()),
                })
                .collect(),
            stripped_canister_http_responses: canister_http_responses
                .into_iter()
                .map(|content_hash| pb::StrippedCanisterHttpResponse {
                    content_hash: content_hash.get().0,
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

/// The id of a [`MaybeStrippedConsensusMessage`], which also covers the IDs of the messages
/// stripped from a block proposal, so that a proposal listing other messages has another id.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct StrippedConsensusMessageId {
    unstripped_id: ConsensusMessageId,
    stripped_message_ids_hash: Option<CryptoHashOf<StrippedMessageIds>>,
}

impl AsRef<ConsensusMessageId> for StrippedConsensusMessageId {
    fn as_ref(&self) -> &ConsensusMessageId {
        &self.unstripped_id
    }
}

impl From<StrippedConsensusMessageId> for pb::StrippedConsensusMessageId {
    fn from(value: StrippedConsensusMessageId) -> Self {
        pb::StrippedConsensusMessageId {
            unstripped_id: Some(value.unstripped_id.into()),
            stripped_message_ids_hash: value
                .stripped_message_ids_hash
                .map(|hash| hash.get().0)
                .unwrap_or_default(),
        }
    }
}

impl TryFrom<pb::StrippedConsensusMessageId> for StrippedConsensusMessageId {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::StrippedConsensusMessageId) -> Result<Self, Self::Error> {
        let unstripped_id = try_from_option_field(
            value.unstripped_id,
            "StrippedConsensusMessageId::unstripped_id",
        )?;
        let hash = value.stripped_message_ids_hash;

        Ok(Self {
            unstripped_id,
            stripped_message_ids_hash: (!hash.is_empty())
                .then_some(CryptoHashOf::new(CryptoHash(hash))),
        })
    }
}

impl IdentifiableArtifact for MaybeStrippedConsensusMessage {
    const NAME: &'static str = "strippedconsensus";

    type Id = StrippedConsensusMessageId;

    fn id(&self) -> Self::Id {
        match self {
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => StrippedConsensusMessageId {
                unstripped_id: unstripped.id(),
                stripped_message_ids_hash: None,
            },
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) => {
                StrippedConsensusMessageId {
                    unstripped_id: stripped.unstripped_consensus_message_id.clone(),
                    stripped_message_ids_hash: Some(crypto_hash(&stripped.stripped_message_ids)),
                }
            }
        }
    }
}

impl PbArtifact for MaybeStrippedConsensusMessage {
    type PbId = pb::StrippedConsensusMessageId;

    type PbIdError = ProxyDecodeError;

    type PbMessage = pb::StrippedConsensusMessage;

    type PbMessageError = ProxyDecodeError;

    fn check_integrity(&self) -> bool {
        match self {
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => unstripped.check_integrity(),
            // A stripped proposal can only be checked once it is reassembled.
            MaybeStrippedConsensusMessage::StrippedBlockProposal(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};

    use crate::fetch_stripped_artifact::{
        stripper::Strippable,
        test_utils::{
            fake_block_proposal_with_ingresses, fake_canister_http_stripped_message,
            fake_finalization_consensus_message_id, fake_idkg_dealing,
            fake_idkg_dealing_support_artifact_id, fake_ingress_message,
            fake_ingress_message_with_arg_size, fake_ingress_message_with_sig,
            fake_stripped_block_proposal_with_messages, fake_summary_block_proposal,
        },
        types::StrippedMessageId,
    };

    use super::*;

    #[test]
    fn serialize_deserialize_stripped_block_proposal_ingress_test() {
        let ingress_1_id = fake_ingress_message("fake_1").id();
        let ingress_2_id = fake_ingress_message("fake_2").id();
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_messages(vec![ingress_1_id, ingress_2_id]);
        let original_consensus_message =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal);

        let proto = pb::StrippedConsensusMessage::from(original_consensus_message.clone());
        let consensus_message = MaybeStrippedConsensusMessage::try_from(proto)
            .expect("Should deserialize a valid proto");

        assert_eq!(consensus_message, original_consensus_message);
    }

    #[test]
    fn serialize_deserialize_stripped_block_proposal_test() {
        let ingress_1_id = fake_ingress_message("fake_1").id();
        let ingress_2_id = fake_ingress_message("fake_2").id();
        let idkg_dealing_1_id = fake_idkg_dealing(NODE_1, 1).id();
        let idkg_dealing_2_id = fake_idkg_dealing(NODE_2, 2).id();
        let canister_http_1_id = fake_canister_http_stripped_message(1).id();
        let canister_http_2_id = fake_canister_http_stripped_message(2).id();
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            ingress_1_id,
            ingress_2_id,
            idkg_dealing_1_id,
            idkg_dealing_2_id,
            canister_http_1_id,
            canister_http_2_id,
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

    #[test]
    fn stripped_consensus_message_id_roundtrip_test() {
        let stripped = ConsensusMessage::BlockProposal(fake_block_proposal_with_ingresses(vec![
            fake_ingress_message_with_arg_size("fake_1", 8).0,
        ]))
        .strip();
        let unstripped = fake_summary_block_proposal().strip();

        for message in [stripped, unstripped] {
            let id = message.id();
            let proto = pb::StrippedConsensusMessageId::from(id.clone());

            assert_eq!(StrippedConsensusMessageId::try_from(proto).unwrap(), id);
        }
    }

    /// The id covers which messages were stripped, but not the rest of the proposal, which is
    /// checked once it is reassembled.
    #[test]
    fn id_covers_the_stripped_message_ids_test() {
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) =
            ConsensusMessage::BlockProposal(fake_block_proposal_with_ingresses(vec![
                fake_ingress_message_with_arg_size("fake_1", 8).0,
            ]))
            .strip()
        else {
            panic!("Didn't strip the block proposal");
        };
        let mut modified_block = stripped.clone();
        modified_block
            .pruned_block_proposal_proto
            .value
            .as_mut()
            .unwrap()
            .time += 1;
        let mut other_messages = stripped.clone();
        let (_, other_ingress_id) = fake_ingress_message_with_arg_size("fake_2", 8);
        other_messages.stripped_message_ids.ingress_messages.insert(
            other_ingress_id.ingress_message_id,
            other_ingress_id.ingress_bytes_hash,
        );
        let id = MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped).id();

        let modified_block_id =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(modified_block).id();
        assert_eq!(modified_block_id, id);
        let other_messages_id =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(other_messages).id();
        assert_eq!(other_messages_id.as_ref(), id.as_ref());
        assert_ne!(other_messages_id, id);
    }

    /// However a peer orders or repeats the stripped message IDs on the wire, they decode to the
    /// same IDs.
    #[test]
    fn reordered_and_repeated_ids_decode_to_the_same_ids_test() {
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            fake_ingress_message("fake_1").id(),
            fake_ingress_message("fake_2").id(),
            fake_idkg_dealing(NODE_1, 1).id(),
            fake_idkg_dealing(NODE_2, 2).id(),
            fake_canister_http_stripped_message(1).id(),
            fake_canister_http_stripped_message(2).id(),
        ]);
        let mut proto = pb::StrippedBlockProposal::from(stripped_block_proposal.clone());
        proto.ingress_messages.reverse();
        proto
            .ingress_messages
            .push(proto.ingress_messages[0].clone());
        proto.stripped_idkg_dealings.reverse();
        proto
            .stripped_idkg_dealings
            .push(proto.stripped_idkg_dealings[0].clone());
        proto.stripped_canister_http_responses.reverse();
        proto
            .stripped_canister_http_responses
            .push(proto.stripped_canister_http_responses[0].clone());

        assert_eq!(
            StrippedBlockProposal::try_from(proto).unwrap(),
            stripped_block_proposal
        );
    }

    /// A block holds one signed version of each request, so the stripped IDs do as well.
    #[test]
    fn signed_versions_of_one_request_decode_to_one_id_test() {
        let (_, signed_ingress_id) = fake_ingress_message_with_sig("fake_1", vec![1, 2, 3]);
        let (_, other_signed_ingress_id) = fake_ingress_message_with_sig("fake_1", vec![2, 3, 4]);
        assert_eq!(
            signed_ingress_id.ingress_message_id,
            other_signed_ingress_id.ingress_message_id
        );
        let mut proto =
            pb::StrippedBlockProposal::from(fake_stripped_block_proposal_with_messages(vec![
                StrippedMessageId::Ingress(signed_ingress_id),
            ]));
        proto.ingress_messages.push(pb::StrippedIngressMessage {
            stripped: Some(other_signed_ingress_id.ingress_message_id.into()),
            ingress_bytes_hash: other_signed_ingress_id.ingress_bytes_hash.get().0,
        });
        assert_eq!(proto.ingress_messages.len(), 2);

        let stripped_block_proposal = StrippedBlockProposal::try_from(proto).unwrap();

        assert_eq!(
            stripped_block_proposal
                .stripped_message_ids
                .ingress_messages
                .len(),
            1
        );
    }
}
