use std::time::Duration;

use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::{CanisterId, PrincipalId};
use ic_config::execution_environment::{Config as ExecutionConfig, LOG_MEMORY_STORE_FEATURE};
use ic_config::flag_status::FlagStatus;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallMode, CanisterLogRecord, CanisterSettingsArgsBuilder,
    FetchCanisterLogsFilter, FetchCanisterLogsRange, FetchCanisterLogsRequest,
    FetchCanisterLogsResponse, LogVisibilityV2, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::log_memory_store::LogMemoryStore;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities_execution_environment::{
    ExecutionTest, ExecutionTestBuilder, wat_canister, wat_fn,
};
use ic_types_cycles::Cycles;
use ic_types_test_utils::ids::{canister_test_id, subnet_test_id};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// A by-index filter spanning the whole index space, so it matches every live
/// record. Used to exercise the filtered read path (index-table lookup + scan)
/// at the same data volume as the unfiltered cases.
const FETCH_FILTER_BY_IDX: Option<FetchCanisterLogsFilter> =
    Some(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
        start: 0,
        end: u64::MAX,
    }));

/// A by-index filter whose range is above every stored record index, so it
/// matches no records and yields an empty response even from a full buffer.
/// Used to measure the cost of a fetch that returns nothing.
const FETCH_FILTER_EMPTY: Option<FetchCanisterLogsFilter> =
    Some(FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
        start: u64::MAX - 1,
        end: u64::MAX,
    }));

/// Number of log records to write per `fill_logs` message: at most one
/// per-message delta's worth. The delta log holds records measured at
/// `size_of::<CanisterLogRecord>() + content` bytes and is capped at the
/// canister's log memory limit. Writing more than that per message makes the
/// delta evict its oldest records, which opens an index gap that clears the
/// store on append (so the buffer never grows past one delta). Staying at/below
/// the delta capacity keeps indices contiguous, so repeated fills accumulate in
/// the store's ring buffer until it reaches capacity.
fn records_per_fill(log_memory_limit: u64, log_message_size: usize) -> u32 {
    let delta_record_size =
        std::mem::size_of::<CanisterLogRecord>() as u64 + log_message_size as u64;
    (log_memory_limit / delta_record_size).max(1) as u32
}

/// Builds a WAT canister exporting a `fill_logs` update that writes
/// `records_to_fill` log records of the given content.
fn fill_logs_canister_wasm(records_to_fill: u32, log_message: &[u8]) -> Vec<u8> {
    wat_canister()
        .update(
            "fill_logs",
            wat_fn().repeat(records_to_fill, wat_fn().debug_print(log_message)),
        )
        .build_wasm()
}

/// A benchmark harness that can run a canister's `fill_logs` method and read its
/// log ring-buffer usage, letting `fill_log_buffer_to_capacity` be shared across
/// the `StateMachine` and `ExecutionTest` based setups.
trait LogFillHarness {
    fn run_fill_logs(&mut self, canister_id: CanisterId);
    fn log_bytes_used(&self, canister_id: CanisterId) -> usize;
    fn log_byte_capacity(&self, canister_id: CanisterId) -> usize;
}

impl LogFillHarness for StateMachine {
    fn run_fill_logs(&mut self, canister_id: CanisterId) {
        // `fill_logs` does not reply; ignore the resulting `CanisterDidNotReply`.
        let _ = self.execute_ingress(canister_id, "fill_logs", vec![]);
    }

    fn log_bytes_used(&self, canister_id: CanisterId) -> usize {
        self.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .log_memory_store
            .bytes_used()
    }

    fn log_byte_capacity(&self, canister_id: CanisterId) -> usize {
        self.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .log_memory_store
            .byte_capacity()
    }
}

impl LogFillHarness for ExecutionTest {
    fn run_fill_logs(&mut self, canister_id: CanisterId) {
        // `fill_logs` does not reply; ignore the resulting `CanisterDidNotReply`.
        let _ = self.ingress(canister_id, "fill_logs", vec![]);
    }

    fn log_bytes_used(&self, canister_id: CanisterId) -> usize {
        self.canister_state(canister_id)
            .system_state
            .log_memory_store
            .bytes_used()
    }

    fn log_byte_capacity(&self, canister_id: CanisterId) -> usize {
        self.canister_state(canister_id)
            .system_state
            .log_memory_store
            .byte_capacity()
    }
}

/// Repeatedly runs `fill_logs` until the log ring buffer is saturated. Each call
/// appends at most a delta's worth of records (see `records_per_fill`), so the
/// used bytes grow until the buffer is full, after which the ring buffer evicts
/// its oldest records and `bytes_used` plateaus at the buffer capacity.
///
/// `log_message_size` is the content size of each written record and must match
/// the size the canister actually logs. It is only used to size the
/// post-condition margin below.
fn fill_log_buffer_to_capacity(
    harness: &mut impl LogFillHarness,
    canister_id: CanisterId,
    log_message_size: usize,
) {
    let mut prev_used = 0;
    loop {
        harness.run_fill_logs(canister_id);
        let used = harness.log_bytes_used(canister_id);
        if used <= prev_used {
            break;
        }
        prev_used = used;
    }
    // Guard against terminating on an early plateau rather than a full buffer:
    // the loop stops as soon as `bytes_used` stops growing, which also happens if
    // each fill fails to accumulate (e.g. an index gap clears the store on
    // append, see `records_per_fill`), leaving `bytes_used` at ~one delta. A full
    // ring buffer instead sits within one stored record of its capacity, since
    // eviction is per-record and stops as soon as the next record fits.
    let capacity = harness.log_byte_capacity(canister_id);
    let record_size = LogMemoryStore::estimate_record_size(log_message_size);
    assert!(
        prev_used + record_size >= capacity,
        "log buffer plateaued at {prev_used} B, more than one record ({record_size} B) below \
         capacity {capacity} B — it was not filled to capacity",
    );
}

/// Creates a StateMachine with a canister whose log buffer is filled to capacity.
fn setup_canister_with_full_log(
    log_memory_limit: u64,
    log_message_size: usize,
) -> (StateMachine, CanisterId) {
    let log_message = vec![b'a'; log_message_size];
    let records_to_fill = records_per_fill(log_memory_limit, log_message_size);

    let mut env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_checkpoints_enabled(false)
        .build();
    let settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![PrincipalId::new_anonymous()])
        .with_log_memory_limit(log_memory_limit)
        .with_log_visibility(LogVisibilityV2::Public)
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::new(u128::MAX / 2), Some(settings));
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        fill_logs_canister_wasm(records_to_fill, &log_message),
        vec![],
    )
    .unwrap();
    fill_log_buffer_to_capacity(&mut env, canister_id, log_message_size);
    (env, canister_id)
}

/// Creates an `ExecutionTest` whose subnet input queue already holds a single
/// inter-canister call (from the caller canister to the management canister) so
/// that the next `execute_subnet_message` executes exactly that call.
///
/// The `target` canister has its log buffer filled to capacity and its logs
/// readable by the caller canister, so the fetch exercises the real read path.
/// `make_payload` builds the management-canister method payload from the target
/// canister id (e.g. `FetchCanisterLogsRequest` or `CanisterIdRecord`).
fn setup_fetch_bench<F: FnOnce(CanisterId) -> Vec<u8>>(
    method: &str,
    make_payload: F,
    log_memory_limit: u64,
    log_message_size: usize,
) -> ExecutionTest {
    let log_message = vec![b'a'; log_message_size];
    let records_to_fill = records_per_fill(log_memory_limit, log_message_size);

    // The caller lives on a remote subnet so that the injected call arrives via
    // the subnet input queue as an inter-canister request.
    let caller = canister_test_id(1);
    let config = ExecutionConfig {
        replicated_inter_canister_log_fetch: FlagStatus::Enabled,
        log_memory_store_feature: LOG_MEMORY_STORE_FEATURE,
        ..ExecutionConfig::default()
    };
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_execution_config(config)
        .with_caller(subnet_test_id(2), caller)
        .build();

    // Create the target canister, controlled by both the test user (so it can be
    // installed and configured) and the caller (so the caller may read its logs).
    let target = test
        .create_canister_with_settings(
            Cycles::new(u128::MAX / 2),
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![test.user_id().get(), caller.get()])
                .with_log_memory_limit(log_memory_limit)
                .with_log_visibility(LogVisibilityV2::Controllers)
                .build(),
        )
        .unwrap();
    test.install_canister(
        target,
        fill_logs_canister_wasm(records_to_fill, &log_message),
    )
    .unwrap();
    fill_log_buffer_to_capacity(&mut test, target, log_message_size);

    // Enqueue the inter-canister call. It is the only pending subnet message, so
    // the next `execute_subnet_message` executes exactly this call. No cycles are
    // attached: `fetch_canister_logs` deducts only round instructions, not cycles.
    test.inject_call_to_ic00(method, make_payload(target), Cycles::zero());
    test
}

fn run_bench_resize_canister_log<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    initial_log_memory_limit: u64,
    new_log_memory_limit: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || setup_canister_with_full_log(initial_log_memory_limit, 0),
            |(env, canister_id)| {
                let result = env.update_settings(
                    &canister_id,
                    CanisterSettingsArgsBuilder::new()
                        .with_log_memory_limit(new_log_memory_limit)
                        .build(),
                );
                assert!(result.is_ok());
            },
            BatchSize::LargeInput,
        );
    });
}

fn run_bench_fetch_canister_log<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    log_memory_limit: u64,
    log_message_size: usize,
    filter: Option<FetchCanisterLogsFilter>,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || {
                setup_fetch_bench(
                    "fetch_canister_logs",
                    |target| {
                        let mut request = FetchCanisterLogsRequest::new(target);
                        request.filter = filter;
                        request.encode()
                    },
                    log_memory_limit,
                    log_message_size,
                )
            },
            |mut test| {
                // Measure only the execution of the `fetch_canister_logs` subnet
                // message, not the surrounding inter-canister call machinery.
                assert!(test.execute_subnet_message());
            },
            BatchSize::LargeInput,
        );
    });
}

/// Executes a single `fetch_canister_logs` subnet message against a target whose
/// log buffer is filled to capacity and returns the Candid-encoded reply payload.
/// Panics if the call was rejected. Used for one-off sanity checks.
fn fetch_response(
    filter: Option<FetchCanisterLogsFilter>,
    log_memory_limit: u64,
    log_message_size: usize,
) -> Vec<u8> {
    let mut test = setup_fetch_bench(
        "fetch_canister_logs",
        |target| {
            let mut request = FetchCanisterLogsRequest::new(target);
            request.filter = filter;
            request.encode()
        },
        log_memory_limit,
        log_message_size,
    );
    assert!(test.execute_subnet_message());
    test.induct_messages();
    match &test.get_xnet_response(0).response_payload {
        ic_types::messages::Payload::Data(data) => data.clone(),
        other => panic!("fetch_canister_logs was rejected: {other:?}"),
    }
}

/// Size of the Candid-encoded `fetch_canister_logs` reply payload.
fn fetch_reply_len(
    filter: Option<FetchCanisterLogsFilter>,
    log_memory_limit: u64,
    log_message_size: usize,
) -> usize {
    fetch_response(filter, log_memory_limit, log_message_size).len()
}

/// The log records returned by a `fetch_canister_logs` call.
fn fetch_records(
    filter: Option<FetchCanisterLogsFilter>,
    log_memory_limit: u64,
    log_message_size: usize,
) -> Vec<CanisterLogRecord> {
    FetchCanisterLogsResponse::decode(&fetch_response(filter, log_memory_limit, log_message_size))
        .unwrap()
        .canister_log_records
}

pub fn canister_logging_benchmark(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("resize_canister_log");
        group.sample_size(60);
        group.warm_up_time(Duration::from_secs(1));

        // Baseline: update_settings with the same log_memory_limit (no-op resize).
        // Measures pure update_settings overhead without log migration work.
        group.bench_function("baseline:2MiB/same_limit", |b| {
            b.iter_batched(
                || setup_canister_with_full_log(2 * MIB, 0),
                |(env, canister_id)| {
                    let result = env.update_settings(
                        &canister_id,
                        CanisterSettingsArgsBuilder::new()
                            .with_log_memory_limit(2 * MIB)
                            .build(),
                    );
                    assert!(result.is_ok());
                },
                BatchSize::LargeInput,
            );
        });

        // Varying sizes to verify linear scaling of resize cost.
        run_bench_resize_canister_log(
            &mut group,
            "from:256KiB/to:-1/msg:0B",
            256 * KIB,
            256 * KIB - 1,
        );
        run_bench_resize_canister_log(&mut group, "from:1MiB/to:-1/msg:0B", MIB, MIB - 1);
        run_bench_resize_canister_log(&mut group, "from:2MiB/to:-1/msg:0B", 2 * MIB, 2 * MIB - 1);
        // Resize up to confirm symmetric cost.
        run_bench_resize_canister_log(
            &mut group,
            "from:2MiB-1/to:2MiB/msg:0B",
            2 * MIB - 1,
            2 * MIB,
        );
    }

    {
        // Sanity checks (run once, outside the timed loop) so the benchmarks
        // measure the real read/encode path rather than an error or empty result.
        // Unfiltered worst case must return a full ~2 MiB response of log data
        // (the response is trimmed to `RESULT_MAX_SIZE`, i.e. 2 MB).
        assert!(fetch_reply_len(None, 2 * MIB, (32 * KIB) as usize) > 1_800_000);
        // A match-all by-index filter returns the same records as no filter (the
        // 128 KiB buffer is small enough not to be trimmed to `RESULT_MAX_SIZE`).
        assert_eq!(
            fetch_records(FETCH_FILTER_BY_IDX, 128 * KIB, 0),
            fetch_records(None, 128 * KIB, 0),
        );
        // The empty filter must return no records even from a full buffer.
        assert!(fetch_records(FETCH_FILTER_EMPTY, 2 * MIB, 0).is_empty());
    }

    {
        let mut group = c.benchmark_group("fetch_canister_log");
        group.sample_size(60);
        group.warm_up_time(Duration::from_secs(1));

        // Baseline: canister_status subnet message (same subnet-message
        // machinery, no log reading). Subtract this from fetch results to
        // isolate the fetch cost.
        group.bench_function("baseline", |b| {
            b.iter_batched(
                || {
                    setup_fetch_bench(
                        "canister_status",
                        |target| CanisterIdRecord::from(target).encode(),
                        128 * KIB,
                        0,
                    )
                },
                |mut test| {
                    assert!(test.execute_subnet_message());
                },
                BatchSize::LargeInput,
            );
        });

        // Worst case: 0-byte messages maximize records per buffer.
        run_bench_fetch_canister_log(&mut group, "fetch:128KiB/msg:0B", 128 * KIB, 0, None);
        run_bench_fetch_canister_log(&mut group, "fetch:1MiB/msg:0B", MIB, 0, None);
        run_bench_fetch_canister_log(&mut group, "fetch:2MiB/msg:0B", 2 * MIB, 0, None);
        // Same 0-byte-message cases, but with a by-index filter, to measure the
        // extra cost of the filtered read path (index-table lookup + scan).
        run_bench_fetch_canister_log(
            &mut group,
            "fetch:128KiB/msg:0B/filter:by_idx",
            128 * KIB,
            0,
            FETCH_FILTER_BY_IDX,
        );
        run_bench_fetch_canister_log(
            &mut group,
            "fetch:1MiB/msg:0B/filter:by_idx",
            MIB,
            0,
            FETCH_FILTER_BY_IDX,
        );
        run_bench_fetch_canister_log(
            &mut group,
            "fetch:2MiB/msg:0B/filter:by_idx",
            2 * MIB,
            0,
            FETCH_FILTER_BY_IDX,
        );
        // Full buffer, but the filter matches no records so the response is
        // empty: measures the cost of a fetch that returns nothing.
        run_bench_fetch_canister_log(
            &mut group,
            "fetch:2MiB/msg:0B/filter:empty",
            2 * MIB,
            0,
            FETCH_FILTER_EMPTY,
        );
        // Realistic: 100-byte messages.
        run_bench_fetch_canister_log(&mut group, "fetch:128KiB/msg:100B", 128 * KIB, 100, None);
        run_bench_fetch_canister_log(&mut group, "fetch:1MiB/msg:100B", MIB, 100, None);
        run_bench_fetch_canister_log(&mut group, "fetch:2MiB/msg:100B", 2 * MIB, 100, None);
        // Worst case for the returned payload size: large (32 KiB, the maximum
        // `debug_print` size) messages so a single fetch returns a full ~2 MiB
        // response (`RESULT_MAX_SIZE`) of actual log data rather than mostly
        // per-record overhead.
        run_bench_fetch_canister_log(
            &mut group,
            "fetch:2MiB/msg:32KiB",
            2 * MIB,
            (32 * KIB) as usize,
            None,
        );
    }
}

criterion_group!(benchmarks, canister_logging_benchmark);
criterion_main!(benchmarks);
