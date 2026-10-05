use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
use ic_error_types::RejectCode;
use ic_protobuf::types::v1 as pb;
use ic_test_utilities_consensus::{
    fake::{Fake, FakeContentSigner},
    make_genesis,
};
use ic_types::{
    CountBytes, Height, NodeId, NodeIndex, NumBytes, RegistryVersion,
    artifact::ConsensusMessageId,
    batch::{
        BatchPayload, FlexibleCanisterHttpError, FlexibleCanisterHttpResponseWithProof,
        FlexibleCanisterHttpResponses, IngressPayload, MAX_CANISTER_HTTP_PAYLOAD_SIZE,
        iterator_to_bytes, slice_to_messages,
    },
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpReject, CanisterHttpResponse,
        CanisterHttpResponseContent, CanisterHttpResponseMetadata, CanisterHttpResponseProof,
        CanisterHttpResponseReceipt, CanisterHttpResponseSignature,
        CanisterHttpResponseWithConsensus,
    },
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
        AlgorithmId, BasicSig, BasicSigOf, CryptoHash, CryptoHashOf, Signed,
        canister_threshold_sig::idkg::{
            IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptType,
            IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
        },
    },
    messages::{
        Blob, CallbackId, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope,
        RawSignedSenderInfo, SignedIngress,
    },
    signature::{BasicSignature, BasicSignatureBatch},
    time::UNIX_EPOCH,
};
use ic_types_cycles::Cycles;
use ic_types_test_utils::ids::{NODE_1, NODE_2, SUBNET_0, node_test_id, test_replica_version};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::fetch_stripped_artifact::types::{
    StrippedMessage, StrippedMessageId,
    stripped::{StrippedCanisterHttpResponses, StrippedIDkgDealings},
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
            StrippedMessage::CanisterHttpResponse(content_hash, _) => {
                StrippedMessageId::CanisterHttpResponse(content_hash.clone())
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
            sender_info: Some(RawSignedSenderInfo {
                info: Blob(vec![1; 32]),
                signer: Blob(vec![42; 8]),
                sig: Blob(vec![3; 32]),
            }),
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
    fake_block_proposal(ingress_messages, idkg_payload, Vec::new(), is_summary)
}

pub(crate) fn fake_block_proposal_with_canister_http(
    canister_http_payload: Vec<u8>,
) -> BlockProposal {
    fake_block_proposal(Vec::new(), None, canister_http_payload, false)
}

pub(crate) fn fake_block_proposal(
    ingress_messages: Vec<SignedIngress>,
    idkg_payload: Option<IDkgPayload>,
    canister_http_payload: Vec<u8>,
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
                canister_http: canister_http_payload,
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
        test_replica_version(),
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
    let stripped_responses = stripped_messages
        .iter()
        .filter_map(|msg_id| {
            if let StrippedMessageId::CanisterHttpResponse(content_hash) = msg_id {
                Some(content_hash.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    StrippedBlockProposal {
        pruned_block_proposal_proto: pb::BlockProposal::default(),
        stripped_ingress_payload: StrippedIngressPayload { ingress_messages },
        unstripped_consensus_message_id: fake_consensus_message_id(),
        stripped_idkg_dealings: StrippedIDkgDealings { stripped_dealings },
        stripped_canister_http_responses: StrippedCanisterHttpResponses { stripped_responses },
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

/// The id of a stripped canister http response, for the response to the given
/// callback id.
pub(crate) fn fake_canister_http_response_message_id(callback_id: u64) -> StrippedMessageId {
    StrippedMessageId::CanisterHttpResponse(ic_types::crypto::crypto_hash(
        &fake_canister_http_response(callback_id, 8),
    ))
}

/// A canister http response for the given callback id, with a body of the given size.
pub(crate) fn fake_canister_http_response(
    callback_id: u64,
    body_size: usize,
) -> CanisterHttpResponse {
    CanisterHttpResponse {
        id: CallbackId::new(callback_id),
        content: CanisterHttpResponseContent::Success(vec![42; body_size]),
    }
}

/// A canister http reject response for the given callback id.
pub(crate) fn fake_canister_http_reject(callback_id: u64) -> CanisterHttpResponse {
    CanisterHttpResponse {
        id: CallbackId::new(callback_id),
        content: CanisterHttpResponseContent::Reject(CanisterHttpReject {
            reject_code: RejectCode::SysTransient,
            message: String::from("rejected"),
        }),
    }
}

fn fake_canister_http_metadata(response: &CanisterHttpResponse) -> CanisterHttpResponseMetadata {
    CanisterHttpResponseMetadata {
        id: response.id,
        content_hash: ic_types::crypto::crypto_hash(response),
        content_size: response.content.count_bytes() as u32,
        is_reject: response.content.is_reject(),
        replica_version: test_replica_version(),
    }
}

fn fake_canister_http_signature() -> CanisterHttpResponseSignature {
    CanisterHttpResponseSignature {
        payment_receipt: CanisterHttpPaymentReceipt::default(),
        signature: BasicSigOf::new(BasicSig(vec![1; 32])),
    }
}

/// A `responses` entry of a canister http payload, signed by the given signers.
///
/// A single signer makes it the response of a non-replicated outcall, more than
/// one the response of a fully replicated one.
pub(crate) fn fake_canister_http_response_message(
    response: &CanisterHttpResponse,
    signers: &[NodeId],
) -> pb::CanisterHttpResponseMessage {
    let with_consensus = CanisterHttpResponseWithConsensus {
        content: response.clone(),
        proof: CanisterHttpResponseProof {
            metadata: fake_canister_http_metadata(response),
            signatures: signers
                .iter()
                .map(|signer| (*signer, fake_canister_http_signature()))
                .collect(),
        },
        initial_spent: Cycles::new(0),
    };

    pb::CanisterHttpResponseMessage {
        message_type: Some(pb::canister_http_response_message::MessageType::Response(
            pb::CanisterHttpResponseWithConsensus::from(with_consensus),
        )),
    }
}

fn fake_flexible_responses_with_proof(
    responses: &[(CanisterHttpResponse, NodeId)],
) -> Vec<FlexibleCanisterHttpResponseWithProof> {
    responses
        .iter()
        .map(|(response, signer)| FlexibleCanisterHttpResponseWithProof {
            response: response.clone(),
            proof: Signed {
                content: CanisterHttpResponseReceipt {
                    metadata: fake_canister_http_metadata(response),
                    payment_receipt: CanisterHttpPaymentReceipt::default(),
                },
                signature: BasicSignature {
                    signature: BasicSigOf::new(BasicSig(vec![1; 32])),
                    signer: *signer,
                },
            },
        })
        .collect()
}

/// A `flexible_responses` entry of a canister http payload: the responses a
/// flexible outcall delivers, each with the single-signer proof of the committee
/// member that produced it.
pub(crate) fn fake_flexible_canister_http_responses_message(
    callback_id: u64,
    responses: &[(CanisterHttpResponse, NodeId)],
) -> pb::CanisterHttpResponseMessage {
    let group = FlexibleCanisterHttpResponses {
        callback_id: CallbackId::new(callback_id),
        responses: fake_flexible_responses_with_proof(responses),
        extra_shares: vec![],
        initial_spent: Cycles::new(0),
    };

    pb::CanisterHttpResponseMessage {
        message_type: Some(
            pb::canister_http_response_message::MessageType::FlexibleResponses(
                pb::FlexibleCanisterHttpResponses::from(group),
            ),
        ),
    }
}

/// A `flexible_errors` entry of a canister http payload that delivers the
/// rejects which made a flexible outcall fail.
pub(crate) fn fake_flexible_canister_http_too_many_rejects_message(
    callback_id: u64,
    rejects: &[(CanisterHttpResponse, NodeId)],
) -> pb::CanisterHttpResponseMessage {
    let error = FlexibleCanisterHttpError::TooManyRejects {
        callback_id: CallbackId::new(callback_id),
        reject_responses: fake_flexible_responses_with_proof(rejects),
        extra_shares: vec![],
        initial_spent: Cycles::new(0),
    };

    pb::CanisterHttpResponseMessage {
        message_type: Some(
            pb::canister_http_response_message::MessageType::FlexibleError(
                pb::FlexibleCanisterHttpError::from(error),
            ),
        ),
    }
}

/// A `timeouts` entry of a canister http payload, which carries no response and
/// is thus never stripped.
pub(crate) fn fake_canister_http_timeout_message(
    callback_id: u64,
) -> pb::CanisterHttpResponseMessage {
    pb::CanisterHttpResponseMessage {
        message_type: Some(pb::canister_http_response_message::MessageType::Timeout(
            callback_id,
        )),
    }
}

/// Like [`fake_canister_http_response_message`], but without the response
/// content: what the payload of a block proposal that was stripped of it looks
/// like.
pub(crate) fn fake_stripped_canister_http_response_message(
    response: &CanisterHttpResponse,
    signers: &[NodeId],
) -> pb::CanisterHttpResponseMessage {
    let mut message = fake_canister_http_response_message(response, signers);
    if let Some(pb::canister_http_response_message::MessageType::Response(response)) =
        message.message_type.as_mut()
    {
        response.response = None;
    }
    message
}

/// Serializes the given messages the way the canister http payload builder does.
///
/// Panics if they do not all fit: `iterator_to_bytes` silently drops the messages
/// that exceed the limit, which would leave a test quietly working on fewer
/// messages than it asked for.
pub(crate) fn fake_canister_http_payload(
    messages: Vec<pb::CanisterHttpResponseMessage>,
) -> Vec<u8> {
    let expected = messages.len();
    let bytes = iterator_to_bytes(
        messages.into_iter(),
        NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
    );
    assert_no_messages_dropped(&bytes, expected);

    bytes
}

/// Fails unless `payload` carries all `expected` messages, i.e. unless every
/// message given to `iterator_to_bytes` fit into the payload limit.
fn assert_no_messages_dropped(payload: &[u8], expected: usize) {
    let encoded = slice_to_messages::<pb::CanisterHttpResponseMessage>(payload)
        .expect("Should encode a parseable payload")
        .len();

    assert_eq!(
        encoded, expected,
        "only {encoded} of {expected} messages fit into the \
         {MAX_CANISTER_HTTP_PAYLOAD_SIZE} byte payload limit; use smaller responses"
    );
}
