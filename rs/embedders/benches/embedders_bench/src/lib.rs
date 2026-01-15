use candid::Encode;
use canister_test::{CanisterId, CanisterInstallMode, Cycles, InstallCodeArgs};
use criterion::{BatchSize, Criterion, Throughput};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::NumBytes;
use ic_types::ingress::WasmResult;
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};
use wirm::Module;

#[derive(Copy, Clone)]
pub enum SetupAction {
    PerformCheckpoint,
    PerformCheckpointCallSetup,
    None,
}

fn initialize_execution_test(
    wasm: &[u8],
    initialization_arg: &[u8],
    setup_action: SetupAction,
    cell: &RefCell<Option<(ExecutionTest, CanisterId)>>,
) {
    const LARGE_INSTRUCTION_LIMIT: u64 = 1_000_000_000_000;

    // Get the memory type of the wasm module using wirm.
    let is_wasm64 = {
        // 1f 8b is GZIP magic number, 08 is DEFLATE algorithm.
        if wasm.starts_with(b"\x1f\x8b\x08") {
            // Gzipped Wasm is wasm32.
            false
        } else {
            let module = Module::parse(wasm, true).unwrap();
            if let Some(mem) = module.memories.iter().next() {
                mem.ty.memory64
            } else {
                // Wasm with no memory is wasm32.
                false
            }
        }
    };

    let mut current = cell.borrow_mut();
    if current.is_some() {
        return;
    }

    let mut test = ExecutionTestBuilder::new()
        .with_query_caching_disabled()
        .with_install_code_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .with_install_code_slice_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .with_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .with_instruction_limit_per_query_message(LARGE_INSTRUCTION_LIMIT)
        .with_slice_instruction_limit(LARGE_INSTRUCTION_LIMIT);

    if is_wasm64 {
        // Set memory size to 8 GiB for Wasm64.
        test = test.with_max_wasm64_memory_size(NumBytes::from(8 * 1024 * 1024 * 1024));
    }
    let mut test = test.build();

    let canister_id = test.create_canister(Cycles::from(1_u128 << 64));
    let args = InstallCodeArgs::new(
        CanisterInstallMode::Install,
        canister_id,
        wasm.to_vec(),
        initialization_arg.to_vec(),
    );
    let result = test.install_code(args).unwrap();
    if let WasmResult::Reject(s) = result {
        panic!("Installation rejected: {s}")
    }
    match setup_action {
        SetupAction::PerformCheckpoint => {
            test.checkpoint_canister_memories();
        }
        SetupAction::PerformCheckpointCallSetup => {
            test.checkpoint_canister_memories();
            test.ingress(canister_id, "setup", Encode!(&()).unwrap())
                .unwrap();
        }
        SetupAction::None => {}
    }

    // Execute a message to sync the new memory so that time isn't included in
    // benchmarks.
    test.ingress(canister_id, "update_empty", Encode!(&()).unwrap())
        .unwrap();

    *current = Some((test, canister_id));
}

pub fn update_bench(
    c: &mut Criterion,
    group_name: &str,
    name: &str,
    wasm: &[u8],
    initialization_arg: &[u8],
    method: &str,
    payload: &[u8],
    throughput: Option<Throughput>,
    setup_action: SetupAction,
) {
    let cell = RefCell::new(None);

    let mut group = c.benchmark_group(group_name);
    if let Some(throughput) = throughput {
        group.throughput(throughput);
    }
    group.bench_function(name, |bench| {
        initialize_execution_test(wasm, initialization_arg, setup_action, &cell);
        bench.iter_custom(|iters| {
            let mut total_duration = Duration::ZERO;
            for _ in 0..iters {
                let mut setup = cell.borrow_mut();
                let (test, canister_id) = setup.as_mut().unwrap();
                let start = Instant::now();
                let result = test
                    .ingress(*canister_id, method, payload.to_vec())
                    .unwrap();
                total_duration += start.elapsed();
                assert!(matches!(result, WasmResult::Reply(_)));
                match setup_action {
                    SetupAction::PerformCheckpoint => {
                        test.checkpoint_canister_memories();
                    }
                    SetupAction::PerformCheckpointCallSetup => {
                        panic!(
                            "Error executing `update_bench()`, use `update_bench_once()` instead"
                        );
                    }
                    SetupAction::None => {}
                }
            }
            total_duration
        });
    });
    group.finish();
}

pub fn update_bench_once(
    c: &mut Criterion,
    group_name: &str,
    name: &str,
    wasm: &[u8],
    initialization_arg: &[u8],
    method: &str,
    payload: &[u8],
    throughput: Option<Throughput>,
    setup_action: SetupAction,
) {
    let mut group = c.benchmark_group(group_name);
    if let Some(throughput) = throughput {
        group.throughput(throughput);
    }
    group.bench_function(name, |bench| {
        bench.iter_batched(
            || {
                let cell = RefCell::new(None);
                initialize_execution_test(wasm, initialization_arg, setup_action, &cell);
                let mut setup = cell.borrow_mut();
                setup.take().unwrap()
            },
            |(mut test, canister_id)| {
                let result = test.ingress(canister_id, method, payload.to_vec()).unwrap();
                assert!(matches!(result, WasmResult::Reply(_)));
                (test, canister_id, result)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

pub fn query_bench(
    c: &mut Criterion,
    group_name: &str,
    name: &str,
    wasm: &[u8],
    initialization_arg: &[u8],
    method: &str,
    payload: &[u8],
    throughput: Option<Throughput>,
    setup_action: SetupAction,
) {
    let cell = RefCell::new(None);

    let mut group = c.benchmark_group(group_name);
    if let Some(throughput) = throughput {
        group.throughput(throughput);
    }
    group.bench_function(name, |bench| {
        initialize_execution_test(wasm, initialization_arg, setup_action, &cell);
        bench.iter(|| {
            let mut setup = cell.borrow_mut();
            let (test, canister_id) = setup.as_mut().unwrap();
            let result = test
                .non_replicated_query(*canister_id, method, payload.to_vec())
                .unwrap();
            assert!(matches!(result, WasmResult::Reply(_)));
        });
    });
    group.finish();
}
