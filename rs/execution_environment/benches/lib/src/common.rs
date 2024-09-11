///
/// Common System API benchmark functions, types, constants.
///
use criterion::{BatchSize, Criterion};
use ic_config::embedders::{Config as EmbeddersConfig, MeteringType};
use ic_config::execution_environment::Config;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::{SchedulerConfig, SubnetConfig};
use ic_cycles_account_manager::{CyclesAccountManager, ResourceSaturation};
use ic_error_types::RejectCode;
use ic_execution_environment::{
    as_round_instructions, CompilationCostHandling, ExecutionEnvironment, Hypervisor,
    IngressHistoryWriterImpl, RoundLimits,
};
use ic_interfaces::execution_environment::{
    ExecutionMode, IngressHistoryWriter, SubnetAvailableMemory,
};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_nns_constants::CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::TestPageAllocatorFileDescriptorImpl;
use ic_replicated_state::{CallOrigin, CanisterState, NetworkTopology, ReplicatedState};
use ic_system_api::{ExecutionParameters, InstructionLimits};
use ic_test_utilities::state_manager::FakeStateManager;
use ic_test_utilities_execution_environment::generate_network_topology;
use ic_test_utilities_state::canister_from_exec_state;
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id};
use ic_test_utilities_types::messages::IngressBuilder;
use ic_types::{
    messages::{CallbackId, CanisterMessage, Payload, RejectContext, RequestMetadata, NO_DEADLINE},
    methods::{Callback, WasmClosure},
    time::UNIX_EPOCH,
    Cycles, MemoryAllocation, NumBytes, NumInstructions, Time,
};
use ic_wasm_types::CanisterModule;
use lazy_static::lazy_static;
use std::convert::TryFrom;
use std::sync::Arc;

pub const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(500_000_000_000);
// Note: this canister ID is required for the `ic0_mint_cycles()`
pub const LOCAL_CANISTER_ID: u64 = CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET;
pub const REMOTE_CANISTER_ID: u64 = 1;
pub const USER_ID: u64 = 0;

const SUBNET_MEMORY_CAPACITY: i64 = i64::MAX;

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory = SubnetAvailableMemory::new(
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY,
        SUBNET_MEMORY_CAPACITY
    );
}

/// Pieces needed to execute a benchmark.
#[derive(Clone)]
pub struct BenchmarkArgs {
    pub canister_state: CanisterState,
    pub ingress: CanisterMessage,
    pub reject: Payload,
    pub time: Time,
    pub network_topology: Arc<NetworkTopology>,
    pub execution_parameters: ExecutionParameters,
    pub subnet_available_memory: SubnetAvailableMemory,
    pub call_origin: CallOrigin,
    pub callback: Callback,
}

/// Benchmark to run: name (id), WAT, expected number of instructions.
pub struct Benchmark(pub String, pub String, pub u64);

pub fn get_execution_args<W>(exec_env: &ExecutionEnvironment, wat: W) -> BenchmarkArgs
where
    W: AsRef<str>,
{
    let own_subnet_id = subnet_test_id(1);
    let nns_subnet_id = subnet_test_id(2);
    let hypervisor = exec_env.hypervisor_for_testing();

    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
    let canister_root = tmpdir.path().to_path_buf();
    // Create Canister state
    let canister_id = canister_test_id(LOCAL_CANISTER_ID);
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions(MAX_NUM_INSTRUCTIONS),
        subnet_available_memory: *MAX_SUBNET_AVAILABLE_MEMORY,
        compute_allocation_used: 0,
    };
    let execution_state = hypervisor
        .create_execution_state(
            CanisterModule::new(wat::parse_str(wat.as_ref()).unwrap()),
            canister_root,
            canister_id,
            &mut round_limits,
            CompilationCostHandling::CountFullAmount,
        )
        .1
        .expect("Failed to create execution state");
    let mut canister_state = canister_from_exec_state(execution_state, canister_id);
    canister_state.system_state.memory_allocation =
        MemoryAllocation::try_from(NumBytes::from(0)).unwrap();
    canister_state.system_state.freeze_threshold = 0.into();

    // Create call context and callback
    let call_origin = CallOrigin::CanisterUpdate(
        canister_test_id(REMOTE_CANISTER_ID),
        CallbackId::new(0),
        NO_DEADLINE,
    );
    let call_context_id = canister_state
        .system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            call_origin.clone(),
            Cycles::new(10),
            UNIX_EPOCH,
            RequestMetadata::new(0, UNIX_EPOCH),
        );
    let callback = Callback::new(
        call_context_id,
        canister_test_id(LOCAL_CANISTER_ID),
        canister_test_id(REMOTE_CANISTER_ID),
        Cycles::new(0),
        Cycles::new(0),
        Cycles::new(0),
        WasmClosure::new(0, 1),
        WasmClosure::new(0, 1),
        None,
        NO_DEADLINE,
    );

    // Create an Ingress message
    let ingress = CanisterMessage::Ingress(
        IngressBuilder::new()
            .method_name("test")
            .method_payload(vec![0; 8192])
            .source(user_test_id(USER_ID))
            .build()
            .into(),
    );
    // Create a reject
    let reject = Payload::Reject(RejectContext::new(RejectCode::SysFatal, "reject message"));

    // Create execution parameters
    let execution_parameters = ExecutionParameters {
        instruction_limits: InstructionLimits::new(
            FlagStatus::Disabled,
            MAX_NUM_INSTRUCTIONS,
            MAX_NUM_INSTRUCTIONS,
        ),
        canister_memory_limit: canister_state.memory_limit(NumBytes::new(u64::MAX)),
        wasm_memory_limit: None,
        memory_allocation: canister_state.memory_allocation(),
        compute_allocation: canister_state.compute_allocation(),
        subnet_type: hypervisor.subnet_type(),
        execution_mode: ExecutionMode::Replicated,
        subnet_memory_saturation: ResourceSaturation::default(),
    };

    let subnets = vec![own_subnet_id, nns_subnet_id];
    let network_topology = Arc::new(generate_network_topology(
        SMALL_APP_SUBNET_MAX_SIZE,
        own_subnet_id,
        nns_subnet_id,
        hypervisor.subnet_type(),
        subnets,
        None,
    ));

    BenchmarkArgs {
        canister_state,
        ingress,
        reject,
        time: UNIX_EPOCH,
        network_topology,
        execution_parameters,
        subnet_available_memory: *MAX_SUBNET_AVAILABLE_MEMORY,
        call_origin,
        callback,
    }
}

/// Run benchmark for a given WAT snippet.
fn run_benchmark<G, I, W, R>(
    c: &mut Criterion,
    group: G,
    id: I,
    wat: W,
    expected_ops: u64,
    routine: R,
    exec_env: &ExecutionEnvironment,
) where
    G: AsRef<str>,
    I: AsRef<str>,
    W: AsRef<str>,
    R: Fn(&ExecutionEnvironment, u64, BenchmarkArgs),
{
    let mut group = c.benchmark_group(group.as_ref());
    let mut bench_args = None;
    group
        .throughput(criterion::Throughput::Elements(expected_ops))
        .bench_function(id.as_ref(), |b| {
            b.iter_batched(
                || {
                    // Lazily setup the benchmark arguments
                    if bench_args.is_none() {
                        println!(
                            "\n    Operations per benchmark iteration: {} ({}M)",
                            expected_ops,
                            expected_ops / 1_000_000
                        );
                        println!("    WAT: {}", wat.as_ref());
                        bench_args = Some(get_execution_args(exec_env, wat.as_ref()));
                    }
                    bench_args.as_ref().unwrap().clone()
                },
                |args| {
                    routine(exec_env, expected_ops, args);
                },
                BatchSize::SmallInput,
            );
        });
    group.finish();
}

fn check_sandbox_defined() -> bool {
    if std::env::var("SANDBOX_BINARY").is_err()
        || std::env::var("LAUNCHER_BINARY").is_err()
        || std::env::var("COMPILER_BINARY").is_err()
    {
        eprintln!("WARNING: The SANDBOX_BINARY or LAUNCHER_BINARY or COMPILER_BINARY env variables are not defined.");
        eprintln!("         Please use `bazel run ...` instead or define the variables manually.");
        eprintln!("         Skipping the benchmark...");
        return false;
    }
    true
}

/// Run all benchmark in the list.
/// List of benchmarks: benchmark id (name), WAT, expected number of instructions.
pub fn run_benchmarks<G, R>(c: &mut Criterion, group: G, benchmarks: &[Benchmark], routine: R)
where
    G: AsRef<str>,
    R: Fn(&ExecutionEnvironment, u64, BenchmarkArgs) + Copy,
{
    if !check_sandbox_defined() {
        return;
    }
    let log = no_op_logger();
    let own_subnet_id = subnet_test_id(1);
    let own_subnet_type = SubnetType::Application;
    let subnet_configs = SubnetConfig::new(own_subnet_type);
    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        subnet_configs.scheduler_config.max_instructions_per_message,
        own_subnet_type,
        own_subnet_id,
        subnet_configs.cycles_account_manager_config,
    ));
    let config = Config {
        embedders_config: EmbeddersConfig {
            metering_type: MeteringType::New,
            ..EmbeddersConfig::default()
        },
        ..Default::default()
    };

    let metrics_registry = MetricsRegistry::new();
    let hypervisor = Arc::new(Hypervisor::new(
        config.clone(),
        &metrics_registry,
        own_subnet_id,
        own_subnet_type,
        log.clone(),
        Arc::clone(&cycles_account_manager),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    ));

    let (completed_execution_messages_tx, _) = tokio::sync::mpsc::channel(1);
    let state_reader = Arc::new(FakeStateManager::new());
    let ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>> =
        Arc::new(IngressHistoryWriterImpl::new(
            config.clone(),
            log.clone(),
            &metrics_registry,
            completed_execution_messages_tx,
            state_reader,
        ));
    let exec_env = ExecutionEnvironment::new(
        log,
        hypervisor,
        Arc::clone(&ingress_history_writer),
        &metrics_registry,
        own_subnet_id,
        own_subnet_type,
        100,
        config,
        cycles_account_manager,
        SchedulerConfig::application_subnet().scheduler_cores,
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        subnet_configs.scheduler_config.heap_delta_rate_limit,
        subnet_configs
            .scheduler_config
            .upload_wasm_chunk_instructions,
        subnet_configs
            .scheduler_config
            .canister_snapshot_baseline_instructions,
    );
    for Benchmark(id, wat, expected_ops) in benchmarks {
        run_benchmark(
            c,
            group.as_ref(),
            id,
            wat,
            *expected_ops,
            routine,
            &exec_env,
        );
    }
}
