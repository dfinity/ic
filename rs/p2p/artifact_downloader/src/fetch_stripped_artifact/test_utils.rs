use ic_protobuf::types::v1 as pb;
use ic_test_utilities_consensus::{
    fake::{Fake, FakeContentSigner},
    make_genesis,
};
use ic_types::{
    artifact::{ConsensusMessageId, IngressMessageId},
    batch::{BatchPayload, IngressPayload},
    consensus::{
        dkg::{Dealings, Summary},
        Block, BlockPayload, BlockProposal, ConsensusMessage, ConsensusMessageHash, DataPayload,
        Payload, Rank,
    },
    crypto::{CryptoHash, CryptoHashOf},
    messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope, SignedIngress},
    time::expiry_time_from_now,
    Height,
};
use ic_types_test_utils::ids::node_test_id;

use super::types::stripped::{StrippedBlockProposal, StrippedIngressPayload};

pub(crate) fn fake_ingress_message(method_name: &str) -> (SignedIngress, IngressMessageId) {
    fake_ingress_message_with_arg_size(method_name, 0)
}

pub(crate) fn fake_ingress_message_with_arg_size(
    method_name: &str,
    arg_size: usize,
) -> (SignedIngress, IngressMessageId) {
    let ingress_expiry = expiry_time_from_now();
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

pub(crate) fn fake_block_proposal_with_ingresses(
    ingress_messages: Vec<SignedIngress>,
) -> BlockProposal {
    let parent = make_genesis(Summary::fake()).content.block;
    let block = Block::new(
        ic_types::crypto::crypto_hash(parent.as_ref()),
        Payload::new(
            ic_types::crypto::crypto_hash,
            BlockPayload::Data(DataPayload {
                batch: BatchPayload {
                    ingress: IngressPayload::from(ingress_messages),
                    ..BatchPayload::default()
                },
                dealings: Dealings::new_empty(Height::from(0)),
                idkg: None,
            }),
        ),
        parent.as_ref().height.increment(),
        Rank(0),
        parent.as_ref().context.clone(),
    );
    BlockProposal::fake(block, node_test_id(0))
}

pub(crate) fn fake_stripped_block_proposal_with_ingresses(
    ingress_messages: Vec<IngressMessageId>,
) -> StrippedBlockProposal {
    StrippedBlockProposal {
        block_proposal_without_ingresses_proto: pb::BlockProposal::default(),
        stripped_ingress_payload: StrippedIngressPayload { ingress_messages },
        unstripped_consensus_message_id: fake_consensus_message_id(),
    }
}

pub(crate) fn fake_summary_block_proposal() -> ConsensusMessage {
    let block = make_genesis(ic_types::consensus::dkg::Summary::fake())
        .content
        .block
        .into_inner();

    ConsensusMessage::BlockProposal(BlockProposal::fake(block, node_test_id(0)))
}

fn fake_consensus_message_id() -> ConsensusMessageId {
    ConsensusMessageId {
        hash: ConsensusMessageHash::BlockProposal(CryptoHashOf::new(CryptoHash(vec![]))),
        height: Height::new(42),
    }
}
