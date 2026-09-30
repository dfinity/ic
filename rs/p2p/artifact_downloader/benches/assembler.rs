use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::Duration,
    vec,
};

use criterion::{BatchSize, Bencher, Criterion, black_box, criterion_group, criterion_main};
use ic_artifact_downloader::FetchStrippedConsensusArtifact;
use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
use ic_interfaces::p2p::consensus::{ArtifactAssembler, BouncerValue, Peers, ValidatedPoolReader};
use ic_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::mocks::{
    FakeCanisterHttpPool, MockBouncerFactory, MockTransport, MockValidatedPoolReader,
};
use ic_protobuf::types::v1 as pb;
use ic_test_utilities_consensus::{
    fake::{Fake, FakeContentSigner},
    make_genesis,
};
use ic_types::{
    CountBytes, Height, NodeId, NumBytes, RegistryVersion,
    artifact::{IdentifiableArtifact, IngressMessageId},
    batch::{BatchPayload, IngressPayload, MAX_CANISTER_HTTP_PAYLOAD_SIZE, iterator_to_bytes},
    canister_http::{
        CanisterHttpPaymentReceipt, CanisterHttpResponse, CanisterHttpResponseContent,
        CanisterHttpResponseMetadata, CanisterHttpResponseProof, CanisterHttpResponseSignature,
        CanisterHttpResponseWithConsensus,
    },
    consensus::{
        Block, BlockPayload, BlockProposal, ConsensusMessage, DataPayload, Payload, Rank,
        dkg::{DkgDataPayload, DkgSummary},
        idkg::{IDkgArtifactId, IDkgMessage, IDkgObject, IDkgPayload},
    },
    crypto::{
        AlgorithmId, BasicSig, BasicSigOf, Signed,
        canister_threshold_sig::idkg::{
            IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptType,
            IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
        },
    },
    messages::{
        Blob, CallbackId, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope, SignedIngress,
    },
    signature::{BasicSignature, BasicSignatureBatch},
    time::UNIX_EPOCH,
};
use ic_types_cycles::Cycles;
use ic_types_test_utils::ids::{NODE_1, NODE_2, SUBNET_0, node_test_id, test_replica_version};
use tokio::runtime::{Handle, Runtime};

struct FakeIngressPool {
    ingresses: BTreeMap<IngressMessageId, SignedIngress>,
}

impl ValidatedPoolReader<SignedIngress> for FakeIngressPool {
    fn get(&self, id: &IngressMessageId) -> Option<SignedIngress> {
        self.ingresses.get(id).cloned()
    }

    fn get_all_for_initial_broadcast(&self) -> Box<dyn Iterator<Item = SignedIngress> + '_> {
        unimplemented!()
    }
}

struct FakeIDkgPool {
    dealings: BTreeMap<IDkgArtifactId, SignedIDkgDealing>,
}

impl ValidatedPoolReader<IDkgMessage> for FakeIDkgPool {
    fn get(&self, id: &IDkgArtifactId) -> Option<IDkgMessage> {
        self.dealings.get(id).cloned().map(IDkgMessage::Dealing)
    }

    fn get_all_for_initial_broadcast(&self) -> Box<dyn Iterator<Item = IDkgMessage> + '_> {
        unimplemented!()
    }
}

#[derive(Clone)]
struct MockPeers(NodeId);

impl Peers for MockPeers {
    fn peers(&self) -> Vec<NodeId> {
        vec![self.0]
    }
}

fn set_up_assembler(
    ingress_messages: Vec<SignedIngress>,
    idkg_dealings: Vec<SignedIDkgDealing>,
    canister_http_responses: Vec<CanisterHttpResponse>,
    handle: Handle,
) -> FetchStrippedConsensusArtifact {
    let mock_transport = MockTransport::new();
    let consensus_pool = MockValidatedPoolReader::<ConsensusMessage>::default();
    let idkg_pool = FakeIDkgPool {
        dealings: idkg_dealings
            .into_iter()
            .map(|dealing| (dealing.message_id(), dealing))
            .collect(),
    };
    let ingress_pool = FakeIngressPool {
        ingresses: ingress_messages
            .into_iter()
            .map(|ingress| (IngressMessageId::from(&ingress), ingress))
            .collect(),
    };
    let canister_http_pool = FakeCanisterHttpPool::new(canister_http_responses);
    let mut mock_bouncer_factory = MockBouncerFactory::default();
    mock_bouncer_factory
        .expect_new_bouncer()
        .returning(|_| Box::new(|_| BouncerValue::Wants));
    let handler = FetchStrippedConsensusArtifact::new(
        no_op_logger(),
        handle,
        Arc::new(RwLock::new(consensus_pool)),
        Arc::new(RwLock::new(ingress_pool)),
        Arc::new(RwLock::new(idkg_pool)),
        Arc::new(RwLock::new(canister_http_pool)),
        Arc::new(mock_bouncer_factory),
        MetricsRegistry::new(),
        NODE_1,
    )
    .0;

    handler(Arc::new(mock_transport))
}

fn fake_block_proposal(
    ingress_messages: Vec<SignedIngress>,
    idkg_dealings: Vec<SignedIDkgDealing>,
    canister_http_responses: Vec<CanisterHttpResponse>,
    canister_http_signers: usize,
) -> ConsensusMessage {
    let parent = make_genesis(DkgSummary::fake()).content.block;
    let block = Block::new(
        ic_types::crypto::crypto_hash(parent.as_ref()),
        Payload::new(
            ic_types::crypto::crypto_hash,
            BlockPayload::Data(DataPayload {
                batch: BatchPayload {
                    ingress: IngressPayload::from(ingress_messages),
                    canister_http: fake_canister_http_payload(
                        canister_http_responses,
                        canister_http_signers,
                    ),
                    ..BatchPayload::default()
                },
                dkg: DkgDataPayload::new_empty(Height::from(0)),
                idkg: (!idkg_dealings.is_empty()).then_some(fake_idkg_payload(idkg_dealings)),
            }),
        ),
        parent.as_ref().height.increment(),
        Rank(0),
        parent.as_ref().context.clone(),
        test_replica_version(),
    );

    ConsensusMessage::BlockProposal(BlockProposal::fake(block, NODE_1))
}

/// A canister http payload delivering the given responses, one outcall each,
/// each signed by `signers` replicas.
///
/// The signature count is the dimension that dominates the cost of stripping and
/// reassembling: a non-replicated or flexible response carries a single
/// signature, while a fully replicated one carries a quorum of `n - f`, all of
/// which stay behind in the stripped payload. (The flexible shape, which nests
/// its responses one level deeper, is covered by the unit tests.)
fn fake_canister_http_payload(responses: Vec<CanisterHttpResponse>, signers: usize) -> Vec<u8> {
    let messages = responses.into_iter().map(|response| {
        let with_consensus = CanisterHttpResponseWithConsensus {
            proof: CanisterHttpResponseProof {
                metadata: CanisterHttpResponseMetadata {
                    id: response.id,
                    content_hash: ic_types::crypto::crypto_hash(&response),
                    content_size: response.content.count_bytes() as u32,
                    is_reject: false,
                    replica_version: test_replica_version(),
                },
                signatures: (0..signers as u64)
                    .map(|signer| {
                        (
                            node_test_id(signer),
                            CanisterHttpResponseSignature {
                                payment_receipt: CanisterHttpPaymentReceipt::default(),
                                signature: BasicSigOf::new(BasicSig(vec![2; 64])),
                            },
                        )
                    })
                    .collect(),
            },
            content: response,
            initial_spent: Cycles::new(0),
        };

        pb::CanisterHttpResponseMessage {
            message_type: Some(pb::canister_http_response_message::MessageType::Response(
                pb::CanisterHttpResponseWithConsensus::from(with_consensus),
            )),
        }
    });

    iterator_to_bytes(
        messages,
        NumBytes::new(MAX_CANISTER_HTTP_PAYLOAD_SIZE as u64),
    )
}

fn fake_canister_http_responses(count: u64, body_size: usize) -> Vec<CanisterHttpResponse> {
    (0..count)
        .map(|i| CanisterHttpResponse {
            id: CallbackId::new(i),
            content: CanisterHttpResponseContent::Success(vec![42; body_size]),
        })
        .collect()
}

pub(crate) fn fake_idkg_payload(dealings: Vec<SignedIDkgDealing>) -> IDkgPayload {
    let mut idkg_transcripts = BTreeMap::new();
    for dealing in dealings {
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

        let verified_dealings = Arc::get_mut(&mut transcript.verified_dealings).unwrap();
        verified_dealings.insert(
            verified_dealings.len() as u32,
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

fn fake_idkg_dealings(
    transcript_count: u64,
    dealings_per_transcript: usize,
    dealing_size: usize,
) -> Vec<SignedIDkgDealing> {
    let mut dealings = vec![];
    for transcript_id in 0..transcript_count {
        for dealer_id in 0..dealings_per_transcript {
            let mut dealing = dummy_idkg_dealing_for_tests();
            dealing.transcript_id = IDkgTranscriptId::new(SUBNET_0, transcript_id, Height::from(5));
            dealing.internal_dealing_raw = vec![1; dealing_size];
            dealings.push(Signed {
                content: dealing,
                signature: BasicSignature {
                    signature: BasicSigOf::new(BasicSig(vec![2; 64])),
                    signer: node_test_id(dealer_id as u64),
                },
            });
        }
    }
    dealings
}

fn fake_ingress_message_with_arg_size(method_name: &str, arg_size: usize) -> SignedIngress {
    let ingress_expiry = UNIX_EPOCH;
    let content = HttpCallContent::Call {
        update: HttpCanisterUpdate {
            canister_id: Blob(vec![42; 8]),
            method_name: method_name.to_string(),
            arg: Blob(vec![0; arg_size]),
            sender: Blob(vec![0x05]),
            nonce: Some(Blob(vec![1, 2, 3, 4])),
            ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            sender_info: None,
        },
    };

    HttpRequestEnvelope::<HttpCallContent> {
        content,
        sender_pubkey: Some(Blob(vec![2; 32])),
        sender_sig: Some(Blob(vec![0; 64])),
        sender_delegation: None,
    }
    .try_into()
    .unwrap()
}

fn disassemble_ingress(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("disassemble_ingress");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for (ingresses_count, ingress_size) in [
        (1, 1),
        (1000, 1),
        (1000, 4 * 1024),
        (1000, 8 * 1024),
        (1000, 16 * 1024),
        (1000, 32 * 1024),
        (2, 2_000_000),
        (4, 2_000_000),
        (8, 2_000_000),
        (16, 2_000_000),
    ] {
        group.bench_function(
            format!("ingress_count:{ingresses_count}, ingress_size:{ingress_size}"),
            |b| {
                let ingress_messages: Vec<_> = (0..ingresses_count)
                    .map(|i| {
                        fake_ingress_message_with_arg_size(
                            &format!("method_name_{i}"),
                            ingress_size,
                        )
                    })
                    .collect();
                bench_disassemble(b, &rt, ingress_messages, vec![], vec![], 0);
            },
        );
    }
}

fn disassemble_idkg_dealings(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("disassemble_idkg_dealings");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let dealing_size = 4500;
    for (transcripts, dealings_per_transcript) in [
        (1, 1),
        (10, 12),
        (20, 12),
        (50, 12),
        (10, 23),
        (20, 23),
        (50, 23),
    ] {
        group.bench_function(
            format!("transcripts:{transcripts}, dealings_per_transcript:{dealings_per_transcript}, dealing_size:{dealing_size}"),
            |b| {
                let dealings = fake_idkg_dealings(transcripts, dealings_per_transcript, dealing_size);
                bench_disassemble(b, &rt, vec![], dealings, vec![], 0);
            },
        );
    }
}

fn disassemble_canister_http_responses(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("disassemble_canister_http_responses");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for (responses_count, response_size, signers) in CANISTER_HTTP_BENCH_CASES {
        group.bench_function(
            format!(
                "response_count:{responses_count}, response_size:{response_size}, \
                 signers:{signers}"
            ),
            |b| {
                let responses = fake_canister_http_responses(responses_count, response_size);
                bench_disassemble(b, &rt, vec![], vec![], responses, signers);
            },
        );
    }
}

fn assemble_canister_http_responses(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("assemble_canister_http_responses");
    group.measurement_time(Duration::from_secs(15));
    let rt = tokio::runtime::Runtime::new().unwrap();

    for (responses_count, response_size, signers) in CANISTER_HTTP_BENCH_CASES {
        group.bench_function(
            format!(
                "response_count:{responses_count}, response_size:{response_size}, \
                 signers:{signers}"
            ),
            |b| {
                let responses = fake_canister_http_responses(responses_count, response_size);
                bench_assemble(b, &rt, vec![], vec![], responses, signers);
            },
        );
    }
}

/// `(responses, response size, signatures per response)`. A single signature is a
/// non-replicated or flexible outcall; 27 is the quorum a fully replicated outcall
/// carries on a 40-node subnet.
///
/// Every case has to fit into `MAX_CANISTER_HTTP_PAYLOAD_SIZE` once the metadata
/// and the signatures are counted, which is why the larger response counts pair
/// with smaller bodies: 500 responses of 27 signatures each spend around 1.4 MB of
/// the 2 MiB limit on signatures alone. `fake_canister_http_payload` panics rather
/// than let a case silently measure fewer messages than it names.
const CANISTER_HTTP_BENCH_CASES: [(u64, usize, usize); 8] = [
    (1, 1, 1),
    (1, 2_000_000, 1),
    (1, 2_000_000, 27),
    (100, 16 * 1024, 1),
    (100, 16 * 1024, 27),
    (500, 1, 1),
    (500, 3 * 1024, 1),
    (500, 1024, 27),
];

fn bench_disassemble(
    bencher: &mut Bencher<'_>,
    rt: &Runtime,
    ingress_messages: Vec<SignedIngress>,
    idkg_dealings: Vec<SignedIDkgDealing>,
    canister_http_responses: Vec<CanisterHttpResponse>,
    canister_http_signers: usize,
) {
    let assembler = set_up_assembler(
        ingress_messages.clone(),
        idkg_dealings.clone(),
        canister_http_responses.clone(),
        rt.handle().clone(),
    );
    let block = fake_block_proposal(
        ingress_messages,
        idkg_dealings,
        canister_http_responses,
        canister_http_signers,
    );

    bencher.iter_batched(
        || (assembler.clone(), block.clone()),
        |(assembler, block)| {
            black_box(assembler.disassemble_message(block));
        },
        BatchSize::SmallInput,
    )
}

fn assemble_ingress(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("assemble_ingress");
    group.measurement_time(Duration::from_secs(15));
    let rt = tokio::runtime::Runtime::new().unwrap();

    for (ingresses_count, ingress_size) in [
        (1, 1),
        (1000, 1),
        (1000, 4 * 1024),
        (1000, 8 * 1024),
        (1000, 16 * 1024),
        (1000, 32 * 1024),
        (2, 2_000_000),
        (4, 2_000_000),
        (8, 2_000_000),
        (16, 2_000_000),
    ] {
        group.bench_function(
            format!("ingress_count:{ingresses_count}, ingress_size:{ingress_size}"),
            |b| {
                let ingress_messages: Vec<_> = (0..ingresses_count)
                    .map(|i| {
                        fake_ingress_message_with_arg_size(
                            &format!("method_name_{i}"),
                            ingress_size,
                        )
                    })
                    .collect();
                bench_assemble(b, &rt, ingress_messages, vec![], vec![], 0);
            },
        );
    }
}

fn assemble_idkg_dealings(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("assemble_idkg_dealings");
    group.measurement_time(Duration::from_secs(15));
    let rt = tokio::runtime::Runtime::new().unwrap();

    let dealing_size = 4500;
    for (transcripts, dealings_per_transcript) in [
        (1, 1),
        (10, 12),
        (20, 12),
        (50, 12),
        (10, 23),
        (20, 23),
        (50, 23),
    ] {
        group.bench_function(
            format!("transcripts:{transcripts}, dealings_per_transcript:{dealings_per_transcript}, dealing_size:{dealing_size}"),
            |b| {
                let dealings = fake_idkg_dealings(transcripts, dealings_per_transcript, dealing_size);
                bench_assemble(b, &rt, vec![], dealings, vec![], 0);
            },
        );
    }
}

fn bench_assemble(
    bencher: &mut Bencher<'_>,
    rt: &Runtime,
    ingress_messages: Vec<SignedIngress>,
    idkg_dealings: Vec<SignedIDkgDealing>,
    canister_http_responses: Vec<CanisterHttpResponse>,
    canister_http_signers: usize,
) {
    let assembler = set_up_assembler(
        ingress_messages.clone(),
        idkg_dealings.clone(),
        canister_http_responses.clone(),
        rt.handle().clone(),
    );
    let block = fake_block_proposal(
        ingress_messages,
        idkg_dealings,
        canister_http_responses,
        canister_http_signers,
    );

    let stripped_block = assembler.disassemble_message(block);
    let id = stripped_block.id();

    bencher.to_async(rt).iter_batched(
        || (assembler.clone(), stripped_block.clone(), id.clone()),
        |(assembler, stripped_block, id)| async move {
            assembler
                .assemble_message(id, Some((stripped_block, NODE_2)), MockPeers(NODE_2))
                .await;
        },
        BatchSize::SmallInput,
    )
}

criterion_group!(
    benches,
    assemble_ingress,
    disassemble_ingress,
    assemble_idkg_dealings,
    disassemble_idkg_dealings,
    assemble_canister_http_responses,
    disassemble_canister_http_responses
);

criterion_main!(benches);
