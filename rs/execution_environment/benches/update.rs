use criterion::Criterion;
use ic_config::{embedders::Config as EmbeddersConfig, execution_environment::Config};
use ic_embedders::WasmtimeEmbedder;
use ic_execution_environment::Hypervisor;
use ic_interfaces::{
    execution_environment::{ExecutionParameters, SubnetAvailableMemory},
    messages::RequestOrIngress,
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallContextAction, CanisterState};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder, mock_time,
    state::canister_from_exec_state, types::ids::subnet_test_id, types::messages::IngressBuilder,
    with_test_replica_logger,
};
use ic_types::{
    CanisterId, Cycles, MemoryAllocation, NumBytes, NumInstructions, PrincipalId, SubnetId, Time,
    UserId,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(10_000_000_000);

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(i64::MAX);
}

fn with_hypervisor<F>(f: F)
where
    F: FnOnce(Hypervisor, std::path::PathBuf),
{
    with_test_replica_logger(|log| {
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            subnet_test_id(1),
            SubnetType::Application,
            log,
            cycles_account_manager,
        );
        f(hypervisor, tmpdir.path().into());
    });
}

struct ExecuteUpdateArgs(
    CanisterState,
    RequestOrIngress,
    Time,
    Arc<RoutingTable>,
    Arc<BTreeMap<SubnetId, SubnetType>>,
    ExecutionParameters,
);

fn setup_update<W>(wat: W, canister_root: std::path::PathBuf) -> ExecuteUpdateArgs
where
    W: AsRef<str>,
{
    let mut features = wabt::Features::new();
    features.enable_multi_value();

    let wasm_embedder = WasmtimeEmbedder::new(EmbeddersConfig::new(), no_op_logger());
    let execution_state = wasm_embedder
        .create_execution_state(
            wabt::wat2wasm_with_features(wat.as_ref(), features).unwrap(),
            canister_root,
            &EmbeddersConfig::default(),
        )
        .expect("Failed to create execution state");
    let mut canister_state = canister_from_exec_state(execution_state);
    canister_state.system_state.memory_allocation =
        MemoryAllocation::try_from(NumBytes::from(0)).unwrap();
    let request = RequestOrIngress::Ingress(
        IngressBuilder::new()
            .method_name("test")
            .method_payload(vec![0; 8192])
            .source(UserId::from(
                PrincipalId::from_str(
                    "mvlzf-grr7q-nhzpd-geghp-zdgtp-ib3yt-hzgi6-texkf-kk6rz-p2ejr-iae",
                )
                .expect("we know this converts OK"),
            ))
            .build(),
    );
    let time = mock_time();
    let routing_table = Arc::new(RoutingTable::new(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_test_id(1),
    }));
    let subnet_records = Arc::new(btreemap! {
        subnet_test_id(1) => SubnetType::Application,
    });
    let execution_parameters = ExecutionParameters {
        instruction_limit: MAX_NUM_INSTRUCTIONS,
        canister_memory_limit: canister_state.memory_limit(NumBytes::new(std::u64::MAX)),
        subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        compute_allocation: canister_state.scheduler_state.compute_allocation,
    };
    ExecuteUpdateArgs(
        canister_state,
        request,
        time,
        routing_table,
        subnet_records,
        execution_parameters,
    )
}

/// Run execute_update() benchmark for a given WAT snippet.
pub fn run_benchmark<I, W>(c: Option<&mut Criterion>, id: I, wat: W, expected_instructions: u64)
where
    I: AsRef<str>,
    W: AsRef<str>,
{
    match c {
        // IAI benchmark
        None => {
            with_hypervisor(|hypervisor, tmp_path| {
                let ExecuteUpdateArgs(
                    canister_state,
                    request,
                    time,
                    routing_table,
                    subnet_records,
                    execution_parameters,
                ) = setup_update(wat.as_ref(), tmp_path);

                hypervisor.execute_update(
                    canister_state,
                    request,
                    time,
                    routing_table,
                    subnet_records,
                    execution_parameters,
                );
            });
        }
        // Criterion benchmark
        Some(c) => {
            let mut group = c.benchmark_group("update");
            with_hypervisor(|hypervisor, tmp_path| {
                let ExecuteUpdateArgs(
                    canister_state,
                    request,
                    time,
                    routing_table,
                    subnet_records,
                    execution_parameters,
                ) = setup_update(wat, tmp_path);
                group
                    .throughput(criterion::Throughput::Elements(expected_instructions))
                    .bench_function(id.as_ref(), |b| {
                        b.iter(|| {
                            let (_state, instructions, action, _bytes) = hypervisor.execute_update(
                                canister_state.clone(),
                                request.clone(),
                                time,
                                routing_table.clone(),
                                subnet_records.clone(),
                                execution_parameters.clone(),
                            );
                            match action {
                                CallContextAction::NoResponse { .. } => {}
                                CallContextAction::Reply { .. } => {}
                                CallContextAction::Reject { .. } => {}
                                _ => assert_eq!(
                                    action,
                                    CallContextAction::NoResponse {
                                        refund: Cycles::from(0),
                                    },
                                    "The system call should not fail"
                                ),
                            }
                            assert_eq!(
                                expected_instructions,
                                MAX_NUM_INSTRUCTIONS.get() - instructions.get(),
                                "Expected number of instructions is required for IPS metric"
                            );
                        });
                    });
            });
            group.finish();
        }
    }
}
