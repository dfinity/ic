use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_config::flag_status::FlagStatus;
use ic_replicated_state::canister_state::system_state::log_memory_store::LogMemoryStore;
use ic_types::CanisterLog;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const MAX_LOG_MESSAGE_LEN: u64 = 32 * KIB;

const TEST_LOG_MEMORY_STORE_FEATURE: FlagStatus = FlagStatus::Enabled;
const TEST_DELTA_LOG_CAPACITY: usize = 2 * MIB as usize;

fn run_bench_resize<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    params: (u64, u64),
) {
    let (initial_log_memory_limit, new_log_memory_limit) = params;

    group.bench_function(bench_name, |b| {
        b.iter_batched(
            // Test setup.
            || {
                let mut store = LogMemoryStore::new(TEST_LOG_MEMORY_STORE_FEATURE);
                store.resize_for_testing(initial_log_memory_limit as usize);
                let log_message_size = initial_log_memory_limit.min(MAX_LOG_MESSAGE_LEN);
                let log_message = vec![b'a'; log_message_size as usize];

                let mut idx = 0;
                let mut logs_written = 0;
                while logs_written <= initial_log_memory_limit as usize {
                    let mut delta =
                        CanisterLog::new_delta_with_next_index(idx, TEST_DELTA_LOG_CAPACITY);
                    delta.add_record(idx, log_message.clone());
                    idx += 1;
                    logs_written += delta.bytes_used();
                    store.append_delta_log(&mut delta);
                }

                let approx_threshold = (90 * initial_log_memory_limit) / 100;
                assert!(
                    store.bytes_used() > approx_threshold as usize,
                    "Store is expected to be almost full (>90%)"
                );

                store
            },
            // Test measurement.
            |mut store| {
                store.resize_for_testing(new_log_memory_limit as usize);
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn log_memory_store_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_memory_store_resize");

    run_bench_resize(&mut group, "from:2MiB/to:-1", (2 * MIB, 2 * MIB - 1));
    run_bench_resize(&mut group, "from:-1/to:2MiB", (2 * MIB - 1, 2 * MIB));
}

criterion_group!(benchmarks, log_memory_store_benchmark);
criterion_main!(benchmarks);
