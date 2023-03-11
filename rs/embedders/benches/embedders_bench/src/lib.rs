use candid::Encode;
use canister_test::{CanisterId, CanisterInstallMode, Cycles, InstallCodeArgs};
use criterion::{BatchSize, Criterion, Throughput};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::ingress::WasmResult;
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

fn initialize_execution_test(
    wasm: &[u8],
    initialization_arg: &[u8],
    cell: &RefCell<Option<(ExecutionTest, CanisterId)>>,
) {
    const LARGE_INSTRUCTION_LIMIT: u64 = 1_000_000_000_000;

    let mut current = cell.borrow_mut();
    if current.is_some() {
        return;
    }

    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .with_instruction_limit_without_dts(LARGE_INSTRUCTION_LIMIT)
        .with_slice_instruction_limit(LARGE_INSTRUCTION_LIMIT)
        .build();
    let canister_id = test.create_canister(Cycles::from(1_u128 << 64));
    let args = InstallCodeArgs::new(
        CanisterInstallMode::Install,
        canister_id,
        wasm.to_vec(),
        initialization_arg.to_vec(),
        None,
        None,
        None,
    );
    let result = test.install_code(args).unwrap();
    if let WasmResult::Reject(s) = result {
        panic!("Installation rejected: {}", s)
    }
    test.checkpoint_canister_memories();

    // Execute a message to synce the new memory so that time isn't included in
    // benchmarks.
    test.ingress(canister_id, "update_empty", Encode!(&()).unwrap())
        .unwrap();

    *current = Some((test, canister_id));
}

pub fn update_bench(
    c: &mut Criterion,
    name: &str,
    wasm: &[u8],
    initialization_arg: &[u8],
    method: &str,
    payload: &[u8],
    throughput: Option<Throughput>,
) {
    let cell = RefCell::new(None);

    let mut group = c.benchmark_group("update");
    if let Some(throughput) = throughput {
        group.throughput(throughput);
    }
    group.bench_function(name, |bench| {
        bench.iter_custom(|iters| {
            let mut total_duration = Duration::ZERO;
            for _ in 0..iters {
                initialize_execution_test(wasm, initialization_arg, &cell);
                let mut setup = cell.borrow_mut();
                let (test, canister_id) = setup.as_mut().unwrap();
                let start = Instant::now();
                let result = test
                    .ingress(*canister_id, method, payload.to_vec())
                    .unwrap();
                total_duration += start.elapsed();
                assert!(matches!(result, WasmResult::Reply(_)));
                test.checkpoint_canister_memories();
            }
            total_duration
        });
    });
    group.finish();
}

pub fn query_bench(
    c: &mut Criterion,
    name: &str,
    wasm: &[u8],
    initialization_arg: &[u8],
    method: &str,
    payload: &[u8],
    throughput: Option<Throughput>,
) {
    let cell = RefCell::new(None);

    let mut group = c.benchmark_group("query");
    if let Some(throughput) = throughput {
        group.throughput(throughput);
    }
    group.bench_function(name, |bench| {
        bench.iter_batched(
            || {
                initialize_execution_test(wasm, initialization_arg, &cell);
            },
            |()| {
                let mut setup = cell.borrow_mut();
                let (test, canister_id) = setup.as_mut().unwrap();
                let result = test
                    .non_replicated_query(*canister_id, method, payload.to_vec())
                    .unwrap();
                assert!(matches!(result, WasmResult::Reply(_)));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}
