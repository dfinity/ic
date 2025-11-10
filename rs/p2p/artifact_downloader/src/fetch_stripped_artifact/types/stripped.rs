use std::collections::BTreeMap;

use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    registry::subnet::v1::SignatureTuple,
    types::v1 as pb,
};
use ic_types::{
    NodeId,
    artifact::{ConsensusMessageId, IdentifiableArtifact, PbArtifact},
    consensus::{
        ConsensusMessage,
        idkg::{IDkgArtifactId, IDkgArtifactIdDataOf, IDkgPrefixOf},
    },
    crypto::{
        BasicSig, BasicSigOf, Signed,
        canister_threshold_sig::{
            error::InitialIDkgDealingsValidationError,
            idkg::{IDkgDealing, IDkgTranscriptId, SignedIDkgDealing},
        },
    },
    node_id_into_protobuf, node_id_try_from_option,
    signature::{BasicSignature, BasicSignatureBatch},
};

use super::SignedIngressId;

/// Stripped version of the [`IngressPayload`].
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct StrippedIngressPayload {
    pub(crate) ingress_messages: Vec<SignedIngressId>,
}

/// Stripped version of the [`Dealings`].
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct StrippedIDkgDealings {
    pub(crate) stripped_dealings: Vec<(
        IDkgTranscriptId,
        Vec<(
            u32,
            Signed<
                IDkgArtifactId,
                BasicSignatureBatch<Signed<IDkgDealing, BasicSignature<IDkgDealing>>>,
            >,
        )>,
    )>,
}

/// Stripped version of the [`BlockProposal`].
#[derive(Clone, Debug, PartialEq)]
pub struct StrippedBlockProposal {
    pub(crate) block_proposal_without_ingresses_proto: pb::BlockProposal,
    pub(crate) stripped_ingress_payload: StrippedIngressPayload,
    pub(crate) unstripped_consensus_message_id: ConsensusMessageId,
    pub(crate) stripped_dealings: StrippedIDkgDealings,
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

        if block_proposal_without_ingresses_proto
            .value
            .as_ref()
            .is_some_and(|block| block.ingress_payload.is_some())
        {
            return Err(ProxyDecodeError::Other(String::from(
                "The ingress payload is NOT empty",
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
            unstripped_consensus_message_id: try_from_option_field(
                value.unstripped_consensus_message_id,
                "unstripped_consensus_message_id",
            )?,
            stripped_dealings: StrippedIDkgDealings {
                stripped_dealings: value
                    .stripped_dealings
                    .into_iter()
                    .map(|ds| {
                        let transcript_id: IDkgTranscriptId =
                            try_from_option_field(ds.transcript_id.as_ref(), "transcript_id")?;
                        let dealings = ds
                            .dealing
                            .into_iter()
                            .map(|d| {
                                let did = d
                                    .dealing_id
                                    .ok_or(ProxyDecodeError::Other("missing".to_string()))?;
                                let dealing_id: IDkgArtifactId = IDkgArtifactId::Dealing(
                                    IDkgPrefixOf::new(try_from_option_field(
                                        did.prefix.as_ref(),
                                        "Dealing::prefix",
                                    )?),
                                    IDkgArtifactIdDataOf::new(try_from_option_field(
                                        did.id_data,
                                        "Dealing::id_data",
                                    )?),
                                );
                                Ok((
                                    d.dealer_index,
                                    Signed {
                                        content: dealing_id,
                                        signature: basic_signature_batch_struct(&d.support_tuples)?,
                                    },
                                ))
                            })
                            .collect::<Result<Vec<_>, ProxyDecodeError>>()?;
                        Ok((transcript_id, dealings))
                    })
                    .collect::<Result<Vec<_>, ProxyDecodeError>>()?,
            },
        })
    }
}

fn basic_signature_batch_struct(
    signature_batch: &[SignatureTuple],
) -> Result<BasicSignatureBatch<SignedIDkgDealing>, ProxyDecodeError> {
    let mut signatures_map = BTreeMap::new();
    for tuple in signature_batch {
        let signer = node_id_try_from_option(tuple.signer.clone())?;
        let signature = BasicSigOf::new(BasicSig(tuple.signature.clone()));
        if signatures_map.insert(signer, signature).is_some() {
            return Err(
                InitialIDkgDealingsValidationError::MultipleSupportSharesFromSameReceiver {
                    node_id: signer,
                }
                .into(),
            );
        };
    }
    Ok(BasicSignatureBatch { signatures_map })
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
                .stripped_dealings
                .stripped_dealings
                .into_iter()
                .map(|(transcript_id, dealings)| pb::StrippedDealings {
                    transcript_id: Some((&transcript_id).into()),
                    dealing: dealings
                        .into_iter()
                        .map(|(dealer_index, dealing)| {
                            let IDkgArtifactId::Dealing(id_prefix, id_data) = dealing.content
                            else {
                                panic!("done now");
                            };
                            pb::StrippedDealing {
                                dealer_index,
                                dealing_id: Some(pb::PrefixPairIDkg {
                                    prefix: Some((&id_prefix.get()).into()),
                                    id_data: Some(pb::IDkgArtifactIdData::from(id_data.get())),
                                }),
                                support_tuples: dealing
                                    .signature
                                    .signatures_map
                                    .iter()
                                    .map(|(signer, signature)| {
                                        signature_tuple_proto(*signer, signature.clone())
                                    })
                                    .collect(),
                            }
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

fn signature_tuple_proto(
    signer: NodeId,
    signature: BasicSigOf<SignedIDkgDealing>,
) -> SignatureTuple {
    SignatureTuple {
        signer: Some(node_id_into_protobuf(signer)),
        signature: signature.get().0,
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
        let (_ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_ingresses(vec![ingress_1_id, ingress_2_id]);
        let original_consensus_message =
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal);

        let proto = pb::StrippedConsensusMessage::from(original_consensus_message.clone());
        let consensus_message = MaybeStrippedConsensusMessage::try_from(proto)
            .expect("Should deserialize a valid proto");

        assert_eq!(consensus_message, original_consensus_message);
    }
}
