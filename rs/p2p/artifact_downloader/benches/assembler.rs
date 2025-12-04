use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
    vec,
};

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use ic_artifact_downloader::FetchStrippedConsensusArtifact;
use ic_interfaces::p2p::consensus::{ArtifactAssembler, BouncerValue, Peers, ValidatedPoolReader};
use ic_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_p2p_test_utils::mocks::{MockBouncerFactory, MockTransport, MockValidatedPoolReader};
use ic_test_utilities_consensus::{
    fake::{Fake, FakeContentSigner},
    make_genesis,
};
use ic_types::{
    Height, NodeId,
    artifact::{IdentifiableArtifact, IngressMessageId},
    batch::{BatchPayload, IngressPayload},
    consensus::{
        Block, BlockPayload, BlockProposal, ConsensusMessage, DataPayload, Payload, Rank,
        dkg::{DkgDataPayload, DkgSummary},
        idkg::IDkgMessage,
    },
    messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope, SignedIngress},
    time::UNIX_EPOCH,
};
use ic_types_test_utils::ids::{NODE_1, NODE_2};
use tokio::runtime::Handle;

struct FakeIngressPool {
    ingresses: BTreeMap<IngressMessageId, SignedIngress>,
}

impl ValidatedPoolReader<SignedIngress> for FakeIngressPool {
    fn get(&self, id: &IngressMessageId) -> Option<SignedIngress> {
        self.ingresses.get(id).cloned()
    }

    fn get_all_for_broadcast(&self) -> Box<dyn Iterator<Item = SignedIngress> + '_> {
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
    handle: Handle,
) -> FetchStrippedConsensusArtifact {
    let mock_transport = MockTransport::new();
    let consensus_pool = MockValidatedPoolReader::<ConsensusMessage>::default();
    let idkg_pool = MockValidatedPoolReader::<IDkgMessage>::default();
    let ingress_pool = FakeIngressPool {
        ingresses: ingress_messages
            .into_iter()
            .map(|ingress| (IngressMessageId::from(&ingress), ingress))
            .collect(),
    };
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
        Arc::new(mock_bouncer_factory),
        MetricsRegistry::new(),
        NODE_1,
    )
    .0;

    handler(Arc::new(mock_transport))
}

fn fake_block_proposal_with_ingresses(ingress_messages: Vec<SignedIngress>) -> ConsensusMessage {
    let parent = make_genesis(DkgSummary::fake()).content.block;
    let block = Block::new(
        ic_types::crypto::crypto_hash(parent.as_ref()),
        Payload::new(
            ic_types::crypto::crypto_hash,
            BlockPayload::Data(DataPayload {
                batch: BatchPayload {
                    ingress: IngressPayload::from(ingress_messages),
                    ..BatchPayload::default()
                },
                dkg: DkgDataPayload::new_empty(Height::from(0)),
                idkg: None,
            }),
        ),
        parent.as_ref().height.increment(),
        Rank(0),
        parent.as_ref().context.clone(),
    );

    ConsensusMessage::BlockProposal(BlockProposal::fake(block, NODE_1))
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

fn disassemble(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("disassemble");
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
                let assembler = set_up_assembler(ingress_messages.clone(), rt.handle().clone());
                let block = fake_block_proposal_with_ingresses(ingress_messages);

                b.iter_batched(
                    || (assembler.clone(), block.clone()),
                    |(assembler, block)| {
                        black_box(assembler.disassemble_message(block));
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

fn assemble(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("assemble");
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
                let assembler = set_up_assembler(ingress_messages.clone(), rt.handle().clone());
                let block = fake_block_proposal_with_ingresses(ingress_messages);

                let stripped_block = assembler.disassemble_message(block);
                let id = stripped_block.id();

                b.to_async(&rt).iter_batched(
                    || (assembler.clone(), stripped_block.clone(), id.clone()),
                    |(assembler, stripped_block, id)| async move {
                        assembler
                            .assemble_message(id, Some((stripped_block, NODE_2)), MockPeers(NODE_2))
                            .await;
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group!(benches, assemble, disassemble);

criterion_main!(benches);
