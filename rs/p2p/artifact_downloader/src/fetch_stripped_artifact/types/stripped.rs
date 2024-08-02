use std::convert::Infallible;

use ic_protobuf::{
    p2p::v1 as p2p_pb,
    proxy::{try_from_option_field, ProxyDecodeError},
    types::v1 as pb,
};
use ic_types::{
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId, PbArtifact},
    batch::{BatchPayload, IngressPayload, SelfValidatingPayload, ValidationContext, XNetPayload},
    consensus::{
        dkg, idkg, Block, BlockMetadata, BlockPayload, BlockProposal, ConsensusMessage,
        DataPayload, HashedBlock, Payload, Rank,
    },
    crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf},
    messages::{MessageId, SignedIngress},
    node_id_into_protobuf, node_id_try_from_option,
    signature::BasicSignature,
    Height, RegistryVersion, ReplicaVersion, Time,
};

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum MaybeStrippedIngress {
    Full(IngressMessageId, SignedIngress),
    Stripped(IngressMessageId),
}

/// Stripped version of the [`IngressPayload`].
#[derive(Debug, Default)]
pub(crate) struct StrippedIngressPayload {
    pub(crate) ingress_messages: Vec<MaybeStrippedIngress>,
}

/// Stripped version of the [`DataPayload`].
#[derive(Debug)]
pub(crate) struct StrippedDataPayload {
    pub(crate) ingress: StrippedIngressPayload,
    xnet: XNetPayload,
    self_validating: SelfValidatingPayload,
    canister_http: Vec<u8>,
    query_stats: Vec<u8>,
    dealings: dkg::Dealings,
    idkg: idkg::Payload,
}

/// Stripped version of the [`BlockProposal`].
#[derive(Debug)]
pub struct StrippedBlockProposal {
    pub(crate) version: ReplicaVersion,
    pub(crate) parent: CryptoHashOf<Block>,
    pub(crate) payload: StrippedDataPayload,
    pub(crate) height: Height,
    pub(crate) rank: Rank,
    pub(crate) context: ValidationContext,

    pub(crate) unstripped_id: ConsensusMessageId,
    pub(crate) block_hash: CryptoHashOf<Block>,
    pub(crate) signature: BasicSignature<BlockMetadata>,
}

#[derive(Debug)]
pub enum MaybeStrippedConsensusMessage {
    StrippedBlockProposal(StrippedBlockProposal),
    Unstripped(ConsensusMessage),
}

impl Strippable for IngressPayload {
    type Output = StrippedIngressPayload;

    fn strip_ingresses(self, predicate: impl Fn(&SignedIngress) -> bool) -> Self::Output {
        // TODO(kpop): don't use `get_by_id`...
        // TODO(kpop): remove `unwrap`
        let stripped_ingresses = self
            .id_and_pos
            .iter()
            .map(|(id, _)| {
                let ingress = self.get_by_id(id).unwrap();
                if predicate(&ingress) {
                    MaybeStrippedIngress::Stripped(id.clone())
                } else {
                    MaybeStrippedIngress::Full(id.clone(), ingress)
                }
            })
            .collect();

        Self::Output {
            ingress_messages: stripped_ingresses,
        }
    }
}

impl Strippable for BlockProposal {
    type Output = StrippedBlockProposal;

    fn strip_ingresses(self, predicate: impl Fn(&SignedIngress) -> bool) -> Self::Output {
        let cm = ConsensusMessage::BlockProposal(self.clone());
        let unstripped_id = cm.id();

        let BlockProposal {
            content: hashed_block,
            signature,
        } = self;

        let (hash, block) = hashed_block.decompose();

        let Block {
            version,
            parent,
            payload,
            height,
            rank,
            context,
        } = block;

        // TODO(kpop): remove the clone somehow?
        let stripped_payload = match payload.as_ref().clone() {
            // TODO(kpop): comment
            BlockPayload::Summary(_summary) => unimplemented!(),
            BlockPayload::Data(data) => {
                let DataPayload {
                    batch,
                    dealings,
                    idkg,
                } = data;

                let BatchPayload {
                    ingress,
                    xnet,
                    self_validating,
                    canister_http,
                    query_stats,
                } = batch;

                StrippedDataPayload {
                    ingress: ingress.strip_ingresses(predicate),
                    xnet,
                    self_validating,
                    canister_http,
                    query_stats,
                    dealings,
                    idkg,
                }
            }
        };

        Self::Output {
            version,
            parent,
            payload: stripped_payload,
            height,
            rank,
            context,
            block_hash: hash,
            signature,
            unstripped_id,
        }
    }
}

impl Strippable for ConsensusMessage {
    type Output = MaybeStrippedConsensusMessage;

    fn strip_ingresses(self, predicate: impl Fn(&SignedIngress) -> bool) -> Self::Output {
        match self {
            ConsensusMessage::BlockProposal(block_proposal) => {
                MaybeStrippedConsensusMessage::StrippedBlockProposal(
                    block_proposal.strip_ingresses(predicate),
                )
            }
            message => MaybeStrippedConsensusMessage::Unstripped(message),
        }
    }
}

impl StrippedIngressPayload {
    fn missing(&self) -> Vec<IngressMessageId> {
        self.ingress_messages
            .iter()
            .filter_map(|ingress| match ingress {
                MaybeStrippedIngress::Full(_, _) => None,
                MaybeStrippedIngress::Stripped(id) => Some(id.clone()),
            })
            .collect()
    }

    fn try_insert(&mut self, ingress_message: SignedIngress) -> Result<(), InsertionError> {
        let ingress_message_id = IngressMessageId::from(&ingress_message);
        let ingress = self
            .ingress_messages
            .iter_mut()
            .find(|ingress| match ingress {
                MaybeStrippedIngress::Full(id, _) => *id == ingress_message_id,
                MaybeStrippedIngress::Stripped(id) => *id == ingress_message_id,
            })
            .ok_or(InsertionError::NotNeeded)?;

        match &ingress {
            MaybeStrippedIngress::Full(_, _) => Err(InsertionError::AlreadyInserted),
            MaybeStrippedIngress::Stripped(_) => {
                *ingress = MaybeStrippedIngress::Full(ingress_message_id, ingress_message);
                Ok(())
            }
        }
    }

    fn try_assemble(self) -> Result<IngressPayload, AssemblyError> {
        let ingresses = self
            .ingress_messages
            .into_iter()
            .map(|msg| match msg {
                MaybeStrippedIngress::Full(_, message) => Ok(message),
                MaybeStrippedIngress::Stripped(id) => {
                    Err(AssemblyError::Missing(StrippableId::IngressMessage(id)))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ingresses.into())
    }
}

impl StrippedBlockProposal {
    pub(crate) fn missing(&self) -> Vec<StrippableId> {
        self.payload
            .ingress
            .missing()
            .into_iter()
            .map(StrippableId::IngressMessage)
            .collect()
    }

    pub(crate) fn try_insert(
        &mut self,
        stripped_data: StrippableData,
    ) -> Result<(), InsertionError> {
        match stripped_data {
            StrippableData::IngressMessage(ingress_message) => {
                self.payload.ingress.try_insert(ingress_message)
            }
        }
    }

    pub(crate) fn try_assemble(self) -> Result<BlockProposal, AssemblyError> {
        let reconstructed_block_payload = BlockPayload::Data(DataPayload {
            batch: BatchPayload {
                ingress: self.payload.ingress.try_assemble()?,
                xnet: self.payload.xnet,
                self_validating: self.payload.self_validating,
                canister_http: self.payload.canister_http,
                query_stats: self.payload.query_stats,
            },
            dealings: self.payload.dealings,
            idkg: self.payload.idkg,
        });

        let reconstructed_payload =
            Payload::new(ic_types::crypto::crypto_hash, reconstructed_block_payload);

        let reconstructed_block = Block {
            version: self.version,
            parent: self.parent,
            payload: reconstructed_payload,
            height: self.height,
            rank: self.rank,
            context: self.context,
        };

        // FIXME(kpop): check consistency
        Ok(BlockProposal {
            content: HashedBlock::recompose(self.block_hash, reconstructed_block),
            signature: self.signature,
        })
    }
}

impl TryFrom<pb::IngressPayload> for StrippedIngressPayload {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::IngressPayload) -> Result<Self, Self::Error> {
        let ingress_messages = value
            .id_and_pos
            .into_iter()
            .map(|ingress_offset| {
                Ok(MaybeStrippedIngress::Stripped(IngressMessageId::new(
                    Time::from_nanos_since_unix_epoch(ingress_offset.expiry),
                    MessageId::try_from(ingress_offset.message_id.as_slice())?,
                )))
            })
            .collect::<Result<_, Self::Error>>()?;

        Ok(Self { ingress_messages })
    }
}

impl From<StrippedIngressPayload> for pb::IngressPayload {
    fn from(value: StrippedIngressPayload) -> Self {
        Self {
            id_and_pos: value
                .ingress_messages
                .into_iter()
                .map(|ingress| {
                    let id = match ingress {
                        MaybeStrippedIngress::Full(id, _) => id,
                        MaybeStrippedIngress::Stripped(id) => id,
                    };

                    pb::IngressIdOffset {
                        expiry: id.expiry().as_nanos_since_unix_epoch(),
                        message_id: id.message_id.as_bytes().to_vec(),
                        offset: 0,
                    }
                })
                .collect(),
            buffer: vec![],
        }
    }
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
            Msg::StrippedBlockProposal(p2p_pb::StrippedBlockProposal {
                stripped_block,
                hash,
                signature,
                signer,
                unstripped_id,
            }) => {
                let Some(pb::Block {
                    version,
                    parent,
                    dkg_payload,
                    height,
                    rank,
                    time,
                    registry_version,
                    certified_height,
                    ingress_payload,
                    xnet_payload,
                    self_validating_payload,
                    idkg_payload,
                    canister_http_payload_bytes,
                    query_stats_payload_bytes,
                    payload_hash: _payload_hash,
                }) = stripped_block
                else {
                    return Err(ProxyDecodeError::MissingField(
                        "StrippedConsensusMessage::stripped_block_proposal::stripped_block",
                    ));
                };

                let dkg_payload = try_from_option_field(dkg_payload, "Block::dkg_payload")?;

                let payload = match dkg_payload {
                    dkg::Payload::Summary(_) => {
                        return Err(ProxyDecodeError::Other(String::from(
                            "Summary blocks cannot stripped",
                        )));
                    }
                    dkg::Payload::Dealings(dealings) => {
                        let ingress = ingress_payload
                            .map(StrippedIngressPayload::try_from)
                            .transpose()?
                            .unwrap_or_default();
                        let xnet = xnet_payload
                            .map(XNetPayload::try_from)
                            .transpose()?
                            .unwrap_or_default();
                        let self_validating = self_validating_payload
                            .map(SelfValidatingPayload::try_from)
                            .transpose()?
                            .unwrap_or_default();
                        let canister_http = canister_http_payload_bytes;
                        let query_stats = query_stats_payload_bytes;

                        let idkg = idkg_payload
                            .as_ref()
                            .map(|idkg| idkg.try_into())
                            .transpose()?;

                        StrippedDataPayload {
                            ingress,
                            xnet,
                            self_validating,
                            canister_http,
                            query_stats,
                            dealings,
                            idkg,
                        }
                    }
                };

                MaybeStrippedConsensusMessage::StrippedBlockProposal(StrippedBlockProposal {
                    version: ReplicaVersion::try_from(version)?,
                    parent: CryptoHashOf::from(CryptoHash(parent)),
                    payload,
                    height: Height::from(height),
                    rank: Rank(rank),
                    context: ValidationContext {
                        registry_version: RegistryVersion::from(registry_version),
                        certified_height: Height::from(certified_height),
                        time: Time::from_nanos_since_unix_epoch(time),
                    },

                    block_hash: CryptoHashOf::from(CryptoHash(hash)),
                    signature: BasicSignature {
                        signature: BasicSigOf::from(BasicSig(signature)),
                        signer: node_id_try_from_option(signer)?,
                    },
                    unstripped_id: try_from_option_field(unstripped_id, "unstripped_id")?,
                })
            }
            Msg::Unstripped(msg) => MaybeStrippedConsensusMessage::Unstripped(msg.try_into()?),
        })
    }
}

impl From<StrippedBlockProposal> for p2p_pb::StrippedBlockProposal {
    fn from(block_proposal: StrippedBlockProposal) -> Self {
        let stripped_block = pb::Block {
            version: block_proposal.version.to_string(),
            parent: block_proposal.parent.clone().get().0,
            dkg_payload: Some(pb::DkgPayload::from(&block_proposal.payload.dealings)),
            height: block_proposal.height.get(),
            rank: block_proposal.rank.0,
            registry_version: block_proposal.context.registry_version.get(),
            certified_height: block_proposal.context.certified_height.get(),
            time: block_proposal.context.time.as_nanos_since_unix_epoch(),
            ingress_payload: Some(block_proposal.payload.ingress.into()),
            xnet_payload: Some(pb::XNetPayload::from(&block_proposal.payload.xnet)),
            self_validating_payload: Some(pb::SelfValidatingPayload::from(
                &block_proposal.payload.self_validating,
            )),
            idkg_payload: block_proposal.payload.idkg.as_ref().map(|idkg| idkg.into()),
            canister_http_payload_bytes: block_proposal.payload.canister_http,
            query_stats_payload_bytes: block_proposal.payload.query_stats,
            // FIXME(kpop): fix this
            payload_hash: Default::default(),
        };
        Self {
            stripped_block: Some(stripped_block),
            hash: block_proposal.block_hash.get().0,
            signature: block_proposal.signature.signature.clone().get().0,
            signer: Some(node_id_into_protobuf(block_proposal.signature.signer)),
            unstripped_id: Some(block_proposal.unstripped_id.into()),
        }
    }
}

impl From<MaybeStrippedConsensusMessage> for p2p_pb::StrippedConsensusMessage {
    fn from(value: MaybeStrippedConsensusMessage) -> Self {
        let msg = match value {
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block) => {
                p2p_pb::stripped_consensus_message::Msg::StrippedBlockProposal(
                    stripped_block.into(),
                )
            }
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => {
                p2p_pb::stripped_consensus_message::Msg::Unstripped(unstripped.into())
            }
        };

        Self { msg: Some(msg) }
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct StrippedConsensusMessageId(pub(crate) ConsensusMessageId);

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
        let id = match self {
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) => {
                stripped.unstripped_id.clone()
            }
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => unstripped.id(),
        };

        StrippedConsensusMessageId(id)
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

/// Provides functionality for stripping objects of given information.
///
/// For example, one might want to remove ingress messages from a block proposal.
pub(crate) trait Strippable {
    type Output;

    /// Strips each ingress message from the object if `predicate` returns `true` for it.
    fn strip_ingresses(self, predicate: impl Fn(&SignedIngress) -> bool) -> Self::Output;
}

#[derive(Debug, PartialEq)]
pub(crate) enum StrippableId {
    IngressMessage(IngressMessageId),
}

pub(crate) enum StrippableData {
    IngressMessage(SignedIngress),
}

#[derive(Debug, PartialEq)]
pub(crate) enum InsertionError {
    AlreadyInserted,
    NotNeeded,
}

#[derive(Debug, PartialEq)]
pub(crate) enum AssemblyError {
    Missing(StrippableId),
}

#[cfg(test)]
mod tests {
    use ic_types::{
        messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope},
        time::expiry_time_from_now,
    };

    use super::*;

    #[test]
    fn ingress_payload_roundtrip_test() {
        let (ingress_1, _) = fake_ingress_message("fake_1");
        let (ingress_2, _) = fake_ingress_message("fake_2");
        let ingress_payload = IngressPayload::from(vec![ingress_1, ingress_2]);

        // don't strip anything
        let stripped_payload = ingress_payload.clone().strip_ingresses(|_| false);
        let reconstructed_payload = stripped_payload.try_assemble();

        assert_eq!(reconstructed_payload, Ok(ingress_payload));
    }

    #[test]
    fn ingress_payload_reconstruction_fails_when_ingresses_missing_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_payload = StrippedIngressPayload {
            ingress_messages: vec![
                MaybeStrippedIngress::Full(ingress_1_id, ingress_1),
                MaybeStrippedIngress::Stripped(ingress_2_id.clone()),
            ],
        };

        let reconstructed_payload = stripped_payload.try_assemble();

        assert_eq!(
            reconstructed_payload,
            Err(AssemblyError::Missing(StrippableId::IngressMessage(
                ingress_2_id
            )))
        );
    }

    #[test]
    fn ingress_payload_missing_returns_correct_ids_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_payload = StrippedIngressPayload {
            ingress_messages: vec![
                MaybeStrippedIngress::Full(ingress_1_id, ingress_1),
                MaybeStrippedIngress::Stripped(ingress_2_id.clone()),
            ],
        };

        assert_eq!(stripped_payload.missing(), vec![ingress_2_id],);
    }

    #[test]
    fn ingress_payload_insertion_works_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let mut stripped_payload = StrippedIngressPayload {
            ingress_messages: vec![
                MaybeStrippedIngress::Full(ingress_1_id, ingress_1),
                MaybeStrippedIngress::Stripped(ingress_2_id),
            ],
        };

        stripped_payload
            .try_insert(ingress_2)
            .expect("Should successfully insert the missing ingress");

        assert!(stripped_payload.missing().is_empty());
    }

    #[test]
    fn ingress_payload_insertion_existing_fails_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let mut stripped_payload = StrippedIngressPayload {
            ingress_messages: vec![
                MaybeStrippedIngress::Full(ingress_1_id, ingress_1.clone()),
                MaybeStrippedIngress::Stripped(ingress_2_id),
            ],
        };

        assert_eq!(
            stripped_payload.try_insert(ingress_1),
            Err(InsertionError::AlreadyInserted)
        );
    }

    #[test]
    fn ingress_payload_insertion_unknown_fails_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let mut stripped_payload = StrippedIngressPayload {
            ingress_messages: vec![MaybeStrippedIngress::Stripped(ingress_2_id)],
        };

        assert_eq!(
            stripped_payload.try_insert(ingress_1),
            Err(InsertionError::NotNeeded)
        );
    }

    fn fake_ingress_message(method_name: &str) -> (SignedIngress, IngressMessageId) {
        let ingress_expiry = expiry_time_from_now();
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: method_name.to_string(),
                arg: Blob(b"".to_vec()),
                sender: Blob(vec![0x05]),
                nonce: Some(Blob(vec![1, 2, 3, 4])),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            },
        };
        let ingress = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_pubkey: Some(Blob(vec![2; 32])),
            sender_sig: Some(Blob(vec![1; 32])),
            sender_delegation: None,
        }
        .try_into()
        .unwrap();
        let ingress_id = IngressMessageId::from(&ingress);

        (ingress, ingress_id)
    }
}
