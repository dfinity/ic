use criterion::{criterion_group, criterion_main, Criterion};
use ic_config::{
    execution_environment::Config as ExecutionConfig, state_manager::Config as StateManagerConfig,
    subnet_config::SubnetConfigs,
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_execution_environment::ExecutionServices;
use ic_ic00_types::{self as ic00, CanisterInstallMode, Payload};
use ic_interfaces::{execution_environment::IngressHistoryReader, messaging::MessageRouting};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::{
    consensus::fake::FakeVerifier, mock_time, types::messages::SignedIngressBuilder,
};
use ic_test_utilities_registry::MockRegistryClient;
use ic_types::{
    batch::{Batch, BatchPayload, IngressPayload},
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::SignedIngress,
    Randomness, RegistryVersion,
};
use ic_types::{messages::MessageId, replica_config::ReplicaConfig, CanisterId};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HELLO_WORLD: &str = r#"
            (module
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "msg_reply" (func $msg_reply))

              (func $read
                (call $msg_reply_data_append (i32.const 0) (i32.const 0))
                (call $msg_reply)
              )

              (memory 0)
              (export "canister_query read" (func $read)))"#;

struct BenchReplica {
    metrics_registry: MetricsRegistry,
    log: ReplicaLogger,
    replica_config: ReplicaConfig,
    canister_id: CanisterId,
}

impl BenchReplica {
    fn new() -> BenchReplica {
        let log = no_op_logger();

        let replica_config = ReplicaConfig::default();
        let metrics_registry = MetricsRegistry::new();
        let canister_id = CanisterId::from(42);

        BenchReplica {
            metrics_registry,
            log,
            replica_config,
            canister_id,
        }
    }

    fn install(
        &self,
        message_routing: &dyn MessageRouting,
        ingress_hist_reader: &dyn IngressHistoryReader,
    ) {
        // Sign message
        let signed = SignedIngressBuilder::new()
            .canister_id(ic00::IC_00)
            .method_name(ic00::Method::InstallCode)
            .method_payload(
                ic00::InstallCodeArgs::new(
                    CanisterInstallMode::Install,
                    CanisterId::from(42),
                    wabt::wat2wasm(HELLO_WORLD).unwrap(),
                    vec![],
                    None,
                    None,
                    None,
                )
                .encode(),
            )
            .build();
        let message_id = signed.id();
        let _ = execute_ingress_message(message_routing, signed, &message_id, ingress_hist_reader);
    }

    fn ingress_directly(
        &self,
        ingress_hist_reader: &dyn IngressHistoryReader,
        message_routing: &MessageRoutingImpl,
        message_id: MessageId,
        signed_ingress: SignedIngress,
    ) {
        let _ = execute_ingress_message(
            message_routing,
            signed_ingress,
            &message_id,
            ingress_hist_reader,
        );
    }
}

fn build_batch(message_routing: &dyn MessageRouting, msgs: Vec<SignedIngress>) -> Batch {
    Batch {
        batch_number: message_routing.expected_batch_height(),
        requires_full_state_hash: !msgs.is_empty(),
        payload: BatchPayload {
            ingress: IngressPayload::from(msgs),
            ..BatchPayload::default()
        },
        randomness: Randomness::from([0; 32]),
        ecdsa_subnet_public_key: None,
        registry_version: RegistryVersion::from(1),
        time: mock_time(),
        consensus_responses: vec![],
    }
}

/// Block till the given ingress message has finished executing and
/// then return the result.  To ensure that this function does not
/// block forever (in case of bugs), this function will panic if the
/// process is not finished in some amount of time.
fn execute_ingress_message(
    message_routing: &dyn MessageRouting,
    msg: SignedIngress,
    msg_id: &MessageId,
    ingress_history: &dyn IngressHistoryReader,
) -> Result<WasmResult, UserError> {
    let mut batch = build_batch(message_routing, vec![msg]);

    let time_start = Instant::now();

    while Instant::now().duration_since(time_start) < Duration::from_secs(30) {
        // In the first batch we try to send the ingress message itself. If it fails, we
        // repeat with the same batch.
        //
        // After the batch with a message is delivered, we keep submitting work to
        // message routing in the form of empty batches till the ingress message has
        // finished executing. This is necessary to get message routing to process
        // potential inter-canister messages that the ingress message may have
        // triggered.
        if message_routing.deliver_batch(batch.clone()).is_ok() {
            batch = build_batch(message_routing, vec![])
        }

        let ingress_result = (ingress_history.get_latest_status())(msg_id);
        match ingress_result {
            IngressStatus::Known { state, .. } => match state {
                IngressState::Completed(result) => return Ok(result),
                IngressState::Failed(error) => return Err(error),
                IngressState::Done => {
                    return Err(UserError::new(
                        ErrorCode::SubnetOversubscribed,
                        "The call has completed but the reply/reject data has been pruned.",
                    ))
                }
                IngressState::Received | IngressState::Processing => (),
            },
            IngressStatus::Unknown => (),
        }
    }
    panic!("Ingress message did not finish executing within 30 seconds");
}

fn criterion_calls(criterion: &mut Criterion) {
    let bench_replica = BenchReplica::new();
    let mut id: u64 = 0;

    let registry = Arc::new(MockRegistryClient::new());

    let subnet_type = SubnetType::Application;
    let subnet_config = SubnetConfigs::default().own_subnet_config(subnet_type);
    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        subnet_config.scheduler_config.max_instructions_per_message,
        subnet_type,
        bench_replica.replica_config.subnet_id,
        SubnetConfigs::default()
            .own_subnet_config(subnet_type)
            .cycles_account_manager_config,
    ));
    let tmpdir = tempfile::Builder::new()
        .prefix("ic_config")
        .tempdir()
        .unwrap();
    let state_manager = Arc::new(StateManagerImpl::new(
        Arc::new(FakeVerifier::new()),
        bench_replica.replica_config.subnet_id,
        subnet_type,
        bench_replica.log.clone(),
        &bench_replica.metrics_registry,
        &StateManagerConfig::new(tmpdir.path().to_path_buf()),
        None,
        ic_types::malicious_flags::MaliciousFlags::default(),
    ));

    let (_, ingress_history_writer, ingress_history_reader, _, _, _, scheduler) =
        ExecutionServices::setup_execution(
            bench_replica.log.clone(),
            &bench_replica.metrics_registry,
            bench_replica.replica_config.subnet_id,
            subnet_type,
            subnet_config.scheduler_config,
            ExecutionConfig::default(),
            Arc::clone(&cycles_account_manager),
            Arc::clone(&state_manager) as Arc<_>,
        )
        .into_parts();

    let mut group = criterion.benchmark_group("user calls");

    let message_routing = MessageRoutingImpl::new(
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&state_manager) as Arc<_>,
        Arc::clone(&ingress_history_writer) as Arc<_>,
        scheduler,
        ExecutionConfig::default(),
        cycles_account_manager,
        bench_replica.replica_config.subnet_id,
        &bench_replica.metrics_registry,
        bench_replica.log.clone(),
        registry,
    );

    struct BenchData {
        message_id: MessageId,
        signed_ingress: SignedIngress,
    }

    bench_replica.install(&message_routing, ingress_history_reader.as_ref());

    group.bench_function("single-node update", |bench| {
        bench.iter_with_setup(
            // Setup messages to avoid counting the time for crypto etc
            || {
                let method_name = "read".to_string();
                let method_payload = b"Hello".to_vec();
                let nonce = id;

                let signed_ingress = SignedIngressBuilder::new()
                    .canister_id(bench_replica.canister_id)
                    .method_name(method_name)
                    .method_payload(method_payload)
                    .nonce(nonce)
                    .build();

                id += 1;

                BenchData {
                    message_id: signed_ingress.id(),
                    signed_ingress,
                }
            },
            |data| {
                bench_replica.ingress_directly(
                    ingress_history_reader.as_ref(),
                    &message_routing,
                    data.message_id,
                    data.signed_ingress,
                );
            },
        )
    });

    group.finish();
}

fn criterion_only_once() -> Criterion {
    Criterion::default().sample_size(40)
}

criterion_group! {
    name = benches;
    config = criterion_only_once();
    targets = criterion_calls
}

criterion_main!(benches);
