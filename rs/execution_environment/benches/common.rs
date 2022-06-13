///
/// Common System API benchmark functions, types, constants.
///
use criterion::{BatchSize, Criterion};
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::{
    AvailableMemory, ExecutionMode, ExecutionParameters, SubnetAvailableMemory,
};
use ic_interfaces::messages::CanisterInputMessage;
use ic_nns_constants::CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallOrigin, CanisterState, NetworkTopology};
use ic_test_utilities::execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_test_utilities::{
    mock_time,
    state::canister_from_exec_state,
    types::ids::{canister_test_id, user_test_id},
    types::messages::IngressBuilder,
};
use ic_types::{
    messages::{CallbackId, Payload, RejectContext},
    methods::{Callback, WasmClosure},
    Cycles, MemoryAllocation, NumBytes, NumInstructions, Time,
};
use lazy_static::lazy_static;
use std::convert::TryFrom;
use std::sync::Arc;

pub const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(10_000_000_000);
// Note: this canister ID is required for the `ic0_mint_cycles()`
pub const LOCAL_CANISTER_ID: u64 = CYCLES_MINTING_CANISTER_INDEX_IN_NNS_SUBNET;
pub const REMOTE_CANISTER_ID: u64 = 1;
pub const USER_ID: u64 = 0;

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        AvailableMemory::new(i64::MAX, i64::MAX).into();
}

/// Pieces needed to execute a benchmark.
#[derive(Clone)]
pub struct BenchmarkArgs {
    pub canister_state: CanisterState,
    pub ingress: CanisterInputMessage,
    pub reject: Payload,
    pub time: Time,
    pub network_topology: Arc<NetworkTopology>,
    pub execution_parameters: ExecutionParameters,
    pub call_origin: CallOrigin,
    pub callback: Callback,
}

/// Benchmark to run: name (id), WAT, expected number of instructions.
pub struct Benchmark(pub &'static str, pub String, pub u64);

pub fn get_execution_args<W>(ee_test: &ExecutionTest, wat: W) -> BenchmarkArgs
where
    W: AsRef<str>,
{
    let hypervisor = ee_test.hypervisor_deprecated();
    let canister_root = ee_test.state().root.clone();
    // Create Canister state
    let canister_id = canister_test_id(LOCAL_CANISTER_ID);
    let (_, execution_state) = hypervisor
        .create_execution_state(
            wabt::wat2wasm_with_features(wat.as_ref(), wabt::Features::new()).unwrap(),
            canister_root,
            canister_id,
        )
        .expect("Failed to create execution state");
    let mut canister_state = canister_from_exec_state(execution_state, canister_id);
    canister_state.system_state.memory_allocation =
        MemoryAllocation::try_from(NumBytes::from(0)).unwrap();

    // Create call context and callback
    let call_origin =
        CallOrigin::CanisterUpdate(canister_test_id(REMOTE_CANISTER_ID), CallbackId::new(0));
    let call_context_id = canister_state
        .system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(call_origin.clone(), Cycles::new(10), mock_time());
    let callback = Callback::new(
        call_context_id,
        Some(canister_test_id(LOCAL_CANISTER_ID)),
        Some(canister_test_id(REMOTE_CANISTER_ID)),
        Cycles::new(0),
        WasmClosure::new(0, 1),
        WasmClosure::new(0, 1),
        None,
    );

    // Create an Ingress message
    let ingress = CanisterInputMessage::Ingress(
        IngressBuilder::new()
            .method_name("test")
            .method_payload(vec![0; 8192])
            .source(user_test_id(USER_ID))
            .build()
            .into(),
    );
    // Create a reject
    let reject = Payload::Reject(RejectContext {
        code: RejectCode::SysFatal,
        message: "reject message".to_string(),
    });

    let network_topology = Arc::new(ee_test.state().metadata.network_topology.clone());

    // Create execution parameters
    let execution_parameters = ExecutionParameters {
        total_instruction_limit: MAX_NUM_INSTRUCTIONS,
        slice_instruction_limit: MAX_NUM_INSTRUCTIONS,
        canister_memory_limit: canister_state.memory_limit(NumBytes::new(std::u64::MAX)),
        subnet_available_memory: MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        compute_allocation: canister_state.scheduler_state.compute_allocation,
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    };

    BenchmarkArgs {
        canister_state,
        ingress,
        reject,
        time: mock_time(),
        network_topology,
        execution_parameters,
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
    expected_instructions: u64,
    routine: R,
    ee_test: &ExecutionTest,
) where
    G: AsRef<str>,
    I: AsRef<str>,
    W: AsRef<str>,
    R: Fn(&ExecutionTest, u64, BenchmarkArgs),
{
    let mut group = c.benchmark_group(group.as_ref());
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
                        bench_args = Some(get_execution_args(ee_test, wat.as_ref()));
                    }
                    bench_args.as_ref().unwrap().clone()
                },
                |args| {
                    routine(ee_test, expected_instructions, args);
                },
                BatchSize::SmallInput,
            );
        });
    group.finish();
}

/// Run all benchmark in the list.
/// List of benchmarks: benchmark id (name), WAT, expected number of instructions.
pub fn run_benchmarks<G, R>(c: &mut Criterion, group: G, benchmarks: &[Benchmark], routine: R)
where
    G: AsRef<str>,
    R: Fn(&ExecutionTest, u64, BenchmarkArgs) + Copy,
{
    let ee_test = ExecutionTestBuilder::new().build();
    for Benchmark(id, wat, expected_instructions) in benchmarks {
        run_benchmark(
            c,
            group.as_ref(),
            id,
            wat,
            *expected_instructions,
            routine,
            &ee_test,
        );
    }
}
