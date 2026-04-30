use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ic_config::execution_environment::{SUBNET_CALLBACK_SOFT_LIMIT, SUBNET_MEMORY_RESERVATION};
use ic_execution_environment::{CompilationCostHandling, RoundLimits, as_round_instructions};
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_test_utilities_execution_environment::ExecutionTestBuilder;
use ic_test_utilities_types::ids::canister_test_id;
use ic_types::NumInstructions;
use ic_wasm_types::CanisterModule;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(500_000_000_000);

fn run_benchmark(
    c: &mut Criterion,
    name: &str,
    wasm: Vec<u8>,
    compilation_cost_handling: CompilationCostHandling,
) {
    let canister_id = canister_test_id(1);
    c.bench_function(name, |b| {
        b.iter_batched(
            || {
                let exec_test = ExecutionTestBuilder::new().build();
                let tmpdir = tempfile::TempDir::new().unwrap();
                (exec_test, tmpdir)
            },
            |(exec_test, tmpdir)| {
                let exec_env = exec_test.execution_environment();
                let hypervisor = exec_env.hypervisor_for_testing();
                let mut round_limits = RoundLimits {
                    instructions: as_round_instructions(MAX_NUM_INSTRUCTIONS),
                    subnet_available_memory: SubnetAvailableMemory::new_for_testing(
                        i64::MAX,
                        i64::MAX,
                        i64::MAX,
                    ),
                    subnet_available_callbacks: SUBNET_CALLBACK_SOFT_LIMIT as i64,
                    compute_allocation_used: 0,
                    subnet_memory_reservation: SUBNET_MEMORY_RESERVATION,
                };
                let _ = hypervisor.create_execution_state(
                    CanisterModule::new(wasm.clone()),
                    tmpdir.path().to_path_buf(),
                    canister_id,
                    &mut round_limits,
                    compilation_cost_handling,
                );
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn benchmark(c: &mut Criterion) {
    let valid_wasm = wat::parse_str("(module)").unwrap();
    run_benchmark(
        c,
        "create_execution_state/wasm:empty/compilation_cost:full",
        valid_wasm.clone(),
        CompilationCostHandling::CountFullAmount,
    );
    run_benchmark(
        c,
        "create_execution_state/wasm:empty/compilation_cost:reduced",
        valid_wasm,
        CompilationCostHandling::CountReducedAmount,
    );
    run_benchmark(
        c,
        "create_execution_state/wasm:invalid/compilation_cost:full",
        vec![],
        CompilationCostHandling::CountFullAmount,
    );
}

criterion_group!(benchmarks, benchmark);
criterion_main!(benchmarks);
