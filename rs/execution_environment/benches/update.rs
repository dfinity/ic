use criterion::{BatchSize, Criterion};
use ic_config::execution_environment::Config;
use ic_execution_environment::Hypervisor;
use ic_interfaces::{
    execution_environment::{ExecutionMode, ExecutionParameters, SubnetAvailableMemory},
    messages::RequestOrIngress,
};
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallContextAction, CanisterState, NetworkTopology, SubnetTopology};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    get_test_replica_logger, mock_time,
    state::canister_from_exec_state,
    types::ids::{canister_test_id, subnet_test_id},
    types::messages::IngressBuilder,
};
use ic_types::{
    CanisterId, Cycles, MemoryAllocation, NumBytes, NumInstructions, PrincipalId, Time, UserId,
};
use lazy_static::lazy_static;
use maplit::btreemap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(10_000_000_000);

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(i64::MAX);
}

#[derive(Clone)]
struct ExecuteUpdateArgs(
    CanisterState,
    RequestOrIngress,
    Time,
    Arc<NetworkTopology>,
    ExecutionParameters,
);

pub fn get_hypervisor() -> (Hypervisor, std::path::PathBuf) {
    let log = get_test_replica_logger();
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
    let metrics_registry = MetricsRegistry::new();
    let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
    let hypervisor = Hypervisor::new(
        Config::default(),
        &metrics_registry,
        subnet_test_id(1),
        SubnetType::Application,
        log,
        cycles_account_manager,
    );
    (hypervisor, tmpdir.path().into())
}

fn setup_update<W>(
    hypervisor: &Hypervisor,
    canister_root: &std::path::Path,
    wat: W,
) -> ExecuteUpdateArgs
where
    W: AsRef<str>,
{
    let mut features = wabt::Features::new();
    features.enable_multi_value();

    let canister_id = canister_test_id(0);
    let execution_state = hypervisor
        .create_execution_state(
            wabt::wat2wasm_with_features(wat.as_ref(), features).unwrap(),
            canister_root.into(),
            canister_id,
        )
        .expect("Failed to create execution state");
    let mut canister_state = canister_from_exec_state(execution_state, canister_id);
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
    let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_test_id(1),
    }).unwrap());
    let network_topology = Arc::new(NetworkTopology {
        routing_table,
        subnets: btreemap! {
            subnet_test_id(1) => SubnetTopology {
                subnet_type: SubnetType::Application,
                ..SubnetTopology::default()
            }
        },
        ..NetworkTopology::default()
    });
    let execution_parameters = ExecutionParameters {
        instruction_limit: MAX_NUM_INSTRUCTIONS,
        canister_memory_limit: canister_state.memory_limit(NumBytes::new(std::u64::MAX)),
        subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        compute_allocation: canister_state.scheduler_state.compute_allocation,
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    };
    ExecuteUpdateArgs(
        canister_state,
        request,
        time,
        network_topology,
        execution_parameters,
    )
}

/// Run execute_update() benchmark for a given WAT snippet.
pub fn run_benchmark<I, W>(
    c: &mut Criterion,
    id: I,
    wat: W,
    expected_instructions: u64,
    hypervisor: &Hypervisor,
    canister_root: &std::path::Path,
) where
    I: AsRef<str>,
    W: AsRef<str>,
{
    let mut group = c.benchmark_group("update");
    let mut bench_args = None;
    group
        .throughput(criterion::Throughput::Elements(expected_instructions))
        .bench_function(id.as_ref(), |b| {
            b.iter_batched(
                || {
                    // Lazily setup the benchmark arguments
                    if bench_args.is_none() {
                        println!(
                            "\n    Instructions per bench iteration: {} ({}M)",
                            expected_instructions,
                            expected_instructions / 1_000_000
                        );
                        println!("    WAT: {}", wat.as_ref());
                        bench_args = Some(setup_update(hypervisor, canister_root, wat.as_ref()));
                    }
                    // let (hypervisor, args) = bench_setup.take().unwrap();
                    bench_args.as_ref().unwrap().clone()
                },
                |ExecuteUpdateArgs(
                    cloned_canister_state,
                    cloned_request,
                    cloned_time,
                    cloned_network_topology,
                    cloned_execution_parameters,
                )| {
                    let (_state, instructions, action, _bytes) = hypervisor.execute_update(
                        cloned_canister_state,
                        cloned_request,
                        cloned_time,
                        cloned_network_topology,
                        cloned_execution_parameters,
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
                },
                BatchSize::SmallInput,
            );
        });
    group.finish();
}
