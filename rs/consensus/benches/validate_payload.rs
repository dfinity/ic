//! Benchmark for the payload builder payload validation
//!
//! Setting:
//! - Uses SignedIngress messages of size 1 KB
//! - Generates IngressPayload which contain 50..900 number of SignedIngress
//!   messages (in steps of 50)
//! - Sets up past payloads of depth 4
//! - The set up allows each of the contained SignedIngress message to be
//!   processed to completion (i.e) they pass all the validations, not present
//!   in the past payloads, and the user signature is checked eventually, and
//!   the message validates successfully

use criterion::{criterion_group, criterion_main, Criterion};
use ic_artifact_pool::{consensus_pool::ConsensusPoolImpl, ingress_pool::IngressPoolImpl};
use ic_config::state_manager::Config as StateManagerConfig;
use ic_consensus::consensus::{
    payload_builder::{PayloadBuilder, PayloadBuilderImpl},
    pool_reader::PoolReader,
};
use ic_consensus_message::ConsensusMessageHashable;
use ic_constants::MAX_INGRESS_TTL;
use ic_execution_environment::IngressHistoryReaderImpl;
use ic_ic00_types::IC_00;
use ic_ingress_manager::IngressManager;
use ic_interfaces::{
    consensus::PayloadValidationError,
    consensus_pool::{ChangeAction, ChangeSet, ConsensusPool, MutableConsensusPool},
    time_source::TimeSource,
    validation::ValidationResult,
};
use ic_interfaces_state_manager::{CertificationScope, StateManager};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::{
    consensus::{fake::*, make_genesis, MockConsensusCache},
    crypto::temp_crypto_component_with_fake_registry,
    cycles_account_manager::CyclesAccountManagerBuilder,
    self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    state::ReplicatedStateBuilder,
    state_manager::MockStateManager,
    types::ids::{canister_test_id, node_test_id, subnet_test_id},
    types::messages::SignedIngressBuilder,
    xnet_payload_builder::FakeXNetPayloadBuilder,
    FastForwardTimeSource,
};
use ic_test_utilities_registry::{setup_registry, SubnetRecordBuilder};
use ic_types::{
    batch::{BatchPayload, IngressPayload, ValidationContext},
    consensus::certification::*,
    consensus::*,
    crypto::Signed,
    ingress::{IngressState, IngressStatus},
    signature::*,
    Height, NumBytes, PrincipalId, RegistryVersion, Time, UserId,
};
use std::sync::{Arc, RwLock};
use std::time::Duration;

type SignedCertificationContent =
    Signed<CertificationContent, ThresholdSignature<CertificationContent>>;

/// Size of the signed ingress messages
const INGRESS_MESSAGE_SIZE: usize = 1024;

/// The validation context height
const CERTIFIED_HEIGHT: u64 = 1;

/// How far back the past payloads go to be checked for occurrence during
/// validation. These start from (CERTIFIED_HEIGHT + 1).
const PAST_PAYLOAD_HEIGHT: u64 = 4;

/// Ingress history size: 5 min worth of messages at 1000/sec = 300K.
const INGRESS_HISTORY_SIZE: usize = 300_000;

fn run_test<T>(_test_name: &str, test_fn: T)
where
    T: FnOnce(Time, &mut ConsensusPoolImpl, &dyn PayloadBuilder),
{
    ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
        let time_source = FastForwardTimeSource::new();
        let now = time_source.get_relative_time();
        let metrics_registry = MetricsRegistry::new();

        let tmpdir = tempfile::Builder::new()
            .prefix("validate_payload_benchmark")
            .tempdir()
            .unwrap();
        let mut state_manager = StateManagerImpl::new(
            Arc::new(FakeVerifier::new()),
            subnet_test_id(0),
            SubnetType::Application,
            no_op_logger(),
            &metrics_registry,
            &StateManagerConfig::new(tmpdir.path().to_path_buf()),
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        );
        setup_ingress_state(now, &mut state_manager);
        let state_manager = Arc::new(state_manager);
        let ingress_hist_reader =
            IngressHistoryReaderImpl::new(Arc::clone(&state_manager) as Arc<_>);

        let committee = vec![node_test_id(0)];
        let summary = dkg::Summary::fake();
        let mut consensus_pool = ConsensusPoolImpl::new_from_cup_without_bytes(
            subnet_test_id(0),
            make_genesis(summary),
            pool_config.clone(),
            ic_metrics::MetricsRegistry::new(),
            no_op_logger(),
        );

        let subnet_id = subnet_test_id(0);
        const VALIDATOR_NODE_ID: u64 = 42;
        let ingress_signature_crypto = Arc::new(temp_crypto_component_with_fake_registry(
            node_test_id(VALIDATOR_NODE_ID),
        ));
        let mut state_manager = MockStateManager::new();
        state_manager.expect_get_state_at().return_const(Ok(
            ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(ReplicatedStateBuilder::default().build()),
            ),
        ));

        let ingress_pool = Arc::new(RwLock::new(IngressPoolImpl::new(
            pool_config,
            metrics_registry.clone(),
            no_op_logger(),
        )));

        let registry_client = setup_registry(
            subnet_id,
            vec![(1, SubnetRecordBuilder::from(&committee).build())],
        );
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let ingress_manager = Arc::new(IngressManager::new(
            Arc::new(MockConsensusCache::new()),
            Box::new(ingress_hist_reader),
            ingress_pool,
            registry_client.clone(),
            ingress_signature_crypto,
            metrics_registry.clone(),
            subnet_id,
            no_op_logger(),
            Arc::new(state_manager),
            cycles_account_manager,
            ic_types::malicious_flags::MaliciousFlags::default(),
        ));

        let payload_builder = Arc::new(PayloadBuilderImpl::new(
            subnet_test_id(0),
            registry_client,
            ingress_manager,
            Arc::new(FakeXNetPayloadBuilder::new()),
            Arc::new(FakeSelfValidatingPayloadBuilder::new()),
            metrics_registry,
            no_op_logger(),
        ));

        test_fn(now, &mut consensus_pool, payload_builder.as_ref());
    })
}

/// Sets up the state manager ingress state with INGRESS_HISTORY_SIZE entries at
/// height CERTIFIED_HEIGHT. It makes sure that the messages in the history
/// don't match the payload being tested, so that the the paylod validation
/// succeeds.
fn setup_ingress_state(now: Time, state_manager: &mut StateManagerImpl) {
    let (_, mut state) = state_manager.take_tip();
    state.metadata.batch_time = now + Duration::from_secs(1);

    let seed: u8 = CERTIFIED_HEIGHT as u8;
    let expiry = std::time::Duration::from_secs(MAX_INGRESS_TTL.as_secs() - 1);
    for i in 0..INGRESS_HISTORY_SIZE {
        let ingress = SignedIngressBuilder::new()
            .method_name("provisional_create_canister_with_cycles")
            .method_payload(vec![seed; INGRESS_MESSAGE_SIZE])
            .nonce(i as u64)
            .expiry_time(now + expiry)
            // This needs to be a temporary measure. We can not simply
            // ignore the running time of validation in our benchmarks
            // and similarly we can not simply keep producing invalid
            // messages.
            .canister_id(IC_00)
            .sign_for_randomly_generated_sender()
            .build();
        state.metadata.ingress_history.insert(
            ingress.id(),
            IngressStatus::Known {
                receiver: canister_test_id(i as u64).get(),
                user_id: UserId::from(PrincipalId::new_user_test_id(i as u64)),
                time: now,
                state: IngressState::Received,
            },
            now,
            NumBytes::from(u64::MAX),
        );
    }

    state_manager.commit_and_certify(
        state,
        Height::new(CERTIFIED_HEIGHT),
        CertificationScope::Full,
    );

    let to_certify = state_manager.list_state_hashes_to_certify();
    assert_eq!(to_certify.len(), 1);
    let hash = &to_certify[0].1;
    state_manager.deliver_state_certification(Certification {
        height: Height::new(CERTIFIED_HEIGHT),
        signed: SignedCertificationContent::fake(CertificationContent::new(hash.clone())),
    });
}

/// Prepares the ingress payload which has 1K x specified number of
/// SignedIngress messages. The payload is filled with the specified 'seed'
/// bytes
fn prepare_ingress_payload(now: Time, message_count: usize, seed: u8) -> IngressPayload {
    let mut ingress_msgs = Vec::new();
    let expiry = std::time::Duration::from_secs(MAX_INGRESS_TTL.as_secs() - 1);
    for i in 0..message_count {
        let ingress = SignedIngressBuilder::new()
            .method_name("provisional_create_canister_with_cycles")
            .method_payload(vec![seed; INGRESS_MESSAGE_SIZE])
            .nonce(i as u64)
            .expiry_time(now + expiry)
            .canister_id(IC_00)
            .build();
        ingress_msgs.push(ingress);
    }
    IngressPayload::from(ingress_msgs)
}

/// Adds the past blocks to the pool, where the heights go from
/// 1 to [CERTIFIED_HEIGHT + PAST_PAYLOAD_HEIGHT + 1]. Returns a
/// copy of the last added block.
fn add_past_blocks(
    consensus_pool: &mut ConsensusPoolImpl,
    now: Time,
    message_count: usize,
) -> Block {
    let cup = consensus_pool
        .validated()
        .catch_up_package()
        .get_by_height(Height::from(0))
        .next()
        .unwrap();
    let mut parent = cup.content.block.into_inner();
    let mut changeset = ChangeSet::new();
    let to_add = CERTIFIED_HEIGHT + PAST_PAYLOAD_HEIGHT + 1;
    for i in 1..=to_add {
        let mut block = Block::from_parent(&parent);
        block.rank = Rank(i as u64);
        let ingress = prepare_ingress_payload(now, message_count, i as u8);
        block.payload = Payload::new(
            ic_crypto::crypto_hash,
            (
                BatchPayload {
                    ingress,
                    ..BatchPayload::default()
                },
                dkg::Dealings::new_empty(block.payload.as_ref().dkg_interval_start_height()),
                None,
            )
                .into(),
        );

        parent = block.clone();
        let proposal = BlockProposal::fake(block, node_test_id(i as u64));
        changeset.push(ChangeAction::AddToValidated(proposal.into_message()));
    }
    let time_source = FastForwardTimeSource::new();
    consensus_pool.apply_changes(time_source.as_ref(), changeset);

    parent
}

/// Reads the past payloads from the pool and invokes the payload builder
/// validate function
fn validate_payload(
    now: Time,
    payload: &Payload,
    pool_reader: &PoolReader<'_>,
    tip: &Block,
    payload_builder: &dyn PayloadBuilder,
) -> ValidationResult<PayloadValidationError> {
    let past_payloads =
        pool_reader.get_payloads_from_height(Height::from(CERTIFIED_HEIGHT + 1), tip.clone());
    assert!(past_payloads.len() == (PAST_PAYLOAD_HEIGHT + 1) as usize);
    assert!(
        past_payloads.first().unwrap().0
            == Height::from(CERTIFIED_HEIGHT + PAST_PAYLOAD_HEIGHT + 1)
    );
    assert!(past_payloads.last().unwrap().0 == Height::from(CERTIFIED_HEIGHT + 1));

    let validation_context = ValidationContext {
        time: now,
        registry_version: RegistryVersion::from(1),
        certified_height: Height::from(CERTIFIED_HEIGHT),
    };

    payload_builder.validate_payload(payload, &past_payloads, &validation_context)
}

fn validate_payload_benchmark(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("validate_payload");
    group.sample_size(30);
    group.measurement_time(std::time::Duration::from_secs(40));

    for message_count in (50..=850).step_by(50) {
        run_test(
            "validate_payload_benchmark",
            |now: Time,
             consensus_pool: &mut ConsensusPoolImpl,
             payload_builder: &dyn PayloadBuilder| {
                let tip = add_past_blocks(consensus_pool, now, message_count);
                let pool_reader = PoolReader::new(consensus_pool);

                let seed = CERTIFIED_HEIGHT + PAST_PAYLOAD_HEIGHT + 10;
                let ingress = prepare_ingress_payload(now, message_count, seed as u8);
                let payload = Payload::new(
                    ic_crypto::crypto_hash,
                    (
                        BatchPayload {
                            ingress,
                            ..BatchPayload::default()
                        },
                        dkg::Dealings::new_empty(tip.payload.as_ref().dkg_interval_start_height()),
                        None,
                    )
                        .into(),
                );

                let name = format!("validate_payload_{}", message_count);
                group.bench_function(&name, |bench| {
                    bench.iter(|| {
                        validate_payload(now, &payload, &pool_reader, &tip, payload_builder)
                            .expect("Invalid payload")
                    })
                });
            },
        )
    }
}

criterion_group!(benches, validate_payload_benchmark);

criterion_main!(benches);
