use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_config::flag_status::FlagStatus;
use ic_management_canister_types_private::{FetchCanisterLogsFilter, FetchCanisterLogsRange};
use ic_replicated_state::canister_state::system_state::log_memory_store::LogMemoryStore;
use ic_types::CanisterLog;
use more_asserts::assert_gt;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

const TEST_LOG_MEMORY_STORE_FEATURE: FlagStatus = FlagStatus::Enabled;
const TEST_DELTA_LOG_CAPACITY: usize = 2 * MIB as usize;
const MAX_LOG_MESSAGE_LEN: u64 = 32 * KIB;
const LOG_MESSAGE_LEN: u64 = 100;

/// Creates a `LogMemoryStore` resized to `capacity` and filled
/// with log records of `message_len` bytes each.
fn create_populated_store(capacity: u64, message_len: u64) -> LogMemoryStore {
    let mut store = LogMemoryStore::new(TEST_LOG_MEMORY_STORE_FEATURE);
    store.resize_for_testing(capacity as usize);
    let len = message_len.min(MAX_LOG_MESSAGE_LEN) as usize;
    let log_message = vec![b'a'; len];

    let mut idx = 0;
    let mut total_size = 0;
    while total_size < capacity as usize {
        let mut delta = CanisterLog::new_delta_with_next_index(idx, TEST_DELTA_LOG_CAPACITY);
        delta.add_record(idx, log_message.clone());
        let added_size = LogMemoryStore::estimate_storage_size(&delta);
        if added_size == 0 {
            break;
        }
        total_size += added_size;
        idx += 1;
        store.append_delta_log(&mut delta);
    }

    assert_eq!(store.byte_capacity(), capacity as usize);

    let expected_percentage = 90;
    let fill_percentage = 100 * store.bytes_used() / store.byte_capacity();
    assert_gt!(
        fill_percentage,
        expected_percentage,
        "Store is expected to be almost full (>{expected_percentage}%)"
    );

    store
}

// --- Resize benchmarks ---

fn run_bench_resize<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    params: (u64, u64, u64),
) {
    let (initial_log_memory_limit, new_log_memory_limit, message_len) = params;

    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || create_populated_store(initial_log_memory_limit, message_len),
            |mut store| {
                store.resize_for_testing(new_log_memory_limit as usize);
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn log_memory_store_resize_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_memory_store_resize");

    let message_len = 0;
    run_bench_resize(
        &mut group,
        &format!("from:2MiB/to:-1/msg:{message_len}"),
        (2 * MIB, 2 * MIB - 1, message_len),
    );
    run_bench_resize(
        &mut group,
        &format!("from:-1/to:2MiB/msg:{message_len}"),
        (2 * MIB - 1, 2 * MIB, message_len),
    );
}

// --- Records benchmarks ---

fn run_bench_records<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    filter: Option<FetchCanisterLogsFilter>,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || create_populated_store(2 * MIB, LOG_MESSAGE_LEN),
            |store| {
                let _records = store.records(filter);
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn log_memory_store_records_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_memory_store_records");

    run_bench_records(&mut group, "no_filter", None);

    for batch_size in [1, 10, 50, 100, 500, 1000] {
        let start = 7; // some random offset
        let end = start + batch_size;
        run_bench_records(
            &mut group,
            &format!("by_idx/{batch_size}"),
            Some(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange::new(
                start, end,
            ))),
        );
    }
}

criterion_group!(
    benchmarks,
    log_memory_store_resize_benchmark,
    //log_memory_store_records_benchmark
);
criterion_main!(benchmarks);
