use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
use ic_protobuf::types::v1 as pb;
use ic_test_utilities_consensus::{
    fake::{Fake, FakeContentSigner},
    make_genesis,
};
use ic_types::{
    Height, NodeId, NodeIndex, RegistryVersion,
    artifact::ConsensusMessageId,
    batch::{BatchPayload, IngressPayload},
    consensus::{
        Block, BlockPayload, BlockProposal, ConsensusMessage, ConsensusMessageHash, DataPayload,
        Payload, Rank, SummaryPayload,
        dkg::{DkgDataPayload, DkgSummary},
        idkg::{
            IDkgArtifactId, IDkgArtifactIdData, IDkgArtifactIdDataOf, IDkgObject, IDkgPayload,
            dealing_support_prefix,
        },
    },
    crypto::{
        AlgorithmId, CryptoHash, CryptoHashOf, Signed,
        canister_threshold_sig::idkg::{
            IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptType,
            IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
        },
    },
    messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope, SignedIngress},
    signature::BasicSignatureBatch,
    time::UNIX_EPOCH,
};
use ic_types_test_utils::ids::{NODE_1, NODE_2, SUBNET_0, node_test_id};

use crate::fetch_stripped_artifact::types::{
    StrippedMessage, StrippedMessageId, stripped::StrippedIDkgDealings,
};

use super::types::{
    SignedIngressId,
    stripped::{StrippedBlockProposal, StrippedIngressPayload},
};

impl StrippedMessage {
    pub(crate) fn id(&self) -> StrippedMessageId {
        match self {
            StrippedMessage::Ingress(id, _) => StrippedMessageId::Ingress(id.clone()),
            StrippedMessage::IDkgDealing(id, node_index, _) => {
                StrippedMessageId::IDkgDealing(id.clone(), *node_index)
            }
        }
    }
}

pub(crate) fn fake_ingress_message(method_name: &str) -> StrippedMessage {
    let (ingress, id) = fake_ingress_message_with_arg_size_and_sig(method_name, 0, vec![1; 32]);
    StrippedMessage::Ingress(id, ingress)
}

pub(crate) fn fake_ingress_message_with_sig(
    method_name: &str,
    sig: Vec<u8>,
) -> (SignedIngress, SignedIngressId) {
    fake_ingress_message_with_arg_size_and_sig(method_name, 0, sig)
}

pub(crate) fn fake_ingress_message_with_arg_size(
    method_name: &str,
    arg_size: usize,
) -> (SignedIngress, SignedIngressId) {
    fake_ingress_message_with_arg_size_and_sig(method_name, arg_size, vec![1; 32])
}

pub(crate) fn fake_ingress_message_with_arg_size_and_sig(
    method_name: &str,
    arg_size: usize,
    sig: Vec<u8>,
) -> (SignedIngress, SignedIngressId) {
    let ingress_expiry = UNIX_EPOCH;
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(vec![42; 8]),
            method_name: method_name.to_string(),
            arg: Blob(vec![0; arg_size]),
            sender: Blob(vec![0x05]),
            nonce: Some(Blob(vec![1, 2, 3, 4])),
            ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
        },
    };
    let ingress: SignedIngress = HttpRequestEnvelope::<HttpCallContent> {
        content,
        sender_pubkey: Some(Blob(vec![2; 32])),
        sender_sig: Some(Blob(sig)),
        sender_delegation: None,
    }
    .try_into()
    .unwrap();

    let signed_ingress_id = SignedIngressId::from(&ingress);

    (ingress, signed_ingress_id)
}

pub(crate) fn fake_block_proposal_with_ingresses(
    ingress_messages: Vec<SignedIngress>,
) -> BlockProposal {
    fake_block_proposal_with_ingresses_and_idkg(ingress_messages, None, false)
}

pub(crate) fn fake_idkg_dealing(dealer: NodeId, node_index: NodeIndex) -> StrippedMessage {
    let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), dealer);
    StrippedMessage::IDkgDealing(dealing.message_id(), node_index, dealing)
}

pub(crate) fn fake_block_proposal_with_ingresses_and_idkg(
    ingress_messages: Vec<SignedIngress>,
    idkg_payload: Option<IDkgPayload>,
    is_summary: bool,
) -> BlockProposal {
    let parent = make_genesis(DkgSummary::fake()).content.block;
    let payload = if is_summary {
        BlockPayload::Summary(SummaryPayload {
            dkg: DkgSummary::fake(),
            idkg: idkg_payload,
        })
    } else {
        BlockPayload::Data(DataPayload {
            batch: BatchPayload {
                ingress: IngressPayload::from(ingress_messages),
                ..BatchPayload::default()
            },
            dkg: DkgDataPayload::new_empty(Height::from(0)),
            idkg: idkg_payload,
        })
    };
    let block = Block::new(
        ic_types::crypto::crypto_hash(parent.as_ref()),
        Payload::new(ic_types::crypto::crypto_hash, payload),
        parent.as_ref().height.increment(),
        Rank(0),
        parent.as_ref().context.clone(),
    );
    BlockProposal::fake(block, node_test_id(0))
}

pub(crate) fn fake_stripped_block_proposal_with_messages(
    stripped_messages: Vec<StrippedMessageId>,
) -> StrippedBlockProposal {
    let ingress_messages = stripped_messages
        .iter()
        .filter_map(|msg_id| {
            if let StrippedMessageId::Ingress(ingress_id) = msg_id {
                Some(ingress_id.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let stripped_dealings = stripped_messages
        .iter()
        .filter_map(|msg_id| {
            if let StrippedMessageId::IDkgDealing(dealing_id, node_index) = msg_id {
                Some((*node_index, dealing_id.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    StrippedBlockProposal {
        block_proposal_without_ingresses_proto: pb::BlockProposal::default(),
        stripped_ingress_payload: StrippedIngressPayload { ingress_messages },
        unstripped_consensus_message_id: fake_consensus_message_id(),
        stripped_idkg_dealings: StrippedIDkgDealings { stripped_dealings },
    }
}

pub(crate) fn fake_summary_block_proposal() -> ConsensusMessage {
    let block = make_genesis(DkgSummary::fake()).content.block.into_inner();

    ConsensusMessage::BlockProposal(BlockProposal::fake(block, node_test_id(0)))
}

fn fake_consensus_message_id() -> ConsensusMessageId {
    ConsensusMessageId {
        hash: ConsensusMessageHash::BlockProposal(CryptoHashOf::new(CryptoHash(vec![]))),
        height: Height::new(42),
    }
}

pub(crate) fn fake_finalization_consensus_message_id() -> ConsensusMessageId {
    ConsensusMessageId {
        hash: ConsensusMessageHash::Finalization(CryptoHashOf::from(CryptoHash(Vec::new()))),
        height: Height::new(101),
    }
}

pub(crate) fn fake_idkg_dealing_support_artifact_id() -> IDkgArtifactId {
    let transcript_id = IDkgTranscriptId::new(SUBNET_0, 1, Height::new(101));
    IDkgArtifactId::DealingSupport(
        dealing_support_prefix(&transcript_id, &NODE_1, &NODE_2),
        IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
            height: Height::new(101),
            hash: CryptoHash(Vec::new()),
            subnet_id: SUBNET_0,
        }),
    )
}

pub(crate) fn fake_idkg_payload_with_dealings(
    dealings: Vec<(SignedIDkgDealing, NodeIndex)>,
) -> IDkgPayload {
    let mut idkg_transcripts = BTreeMap::new();
    for (dealing, node_index) in dealings {
        let transcript_id = dealing.idkg_dealing().transcript_id;
        let transcript = idkg_transcripts
            .entry(transcript_id)
            .or_insert_with(|| IDkgTranscript {
                transcript_id,
                receivers: IDkgReceivers::new(BTreeSet::from_iter([NODE_1])).unwrap(),
                registry_version: RegistryVersion::from(1),
                verified_dealings: Arc::new(BTreeMap::new()),
                transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random),
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                internal_transcript_raw: vec![],
            });

        let dealings = Arc::get_mut(&mut transcript.verified_dealings).unwrap();
        dealings.insert(
            node_index,
            Signed {
                content: dealing,
                signature: BasicSignatureBatch {
                    signatures_map: BTreeMap::new(),
                },
            },
        );
    }

    let mut idkg_payload = IDkgPayload::empty(Height::new(100), SUBNET_0, vec![]);
    idkg_payload.idkg_transcripts = idkg_transcripts;

    idkg_payload
}

pub(crate) fn fake_idkg_payload_with_dealing(
    dealing: SignedIDkgDealing,
    node_index: NodeIndex,
) -> IDkgPayload {
    fake_idkg_payload_with_dealings(vec![(dealing, node_index)])
}
