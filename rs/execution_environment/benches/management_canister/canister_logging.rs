use std::time::Duration;

use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::{CanisterId, PrincipalId};
use ic_execution_environment::fetch_canister_logs_response_for_bench;
use ic_management_canister_types_private::{
    CanisterInstallMode, CanisterLogRecord, CanisterSettingsArgsBuilder, FetchCanisterLogsFilter,
    FetchCanisterLogsRange, FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2,
    Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::log_memory_store::LogMemoryStore;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities_execution_environment::{wat_canister, wat_fn};
use ic_types_cycles::Cycles;

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

/// Repeatedly runs `fill_logs` until the log ring buffer is saturated. Each call
/// appends at most a delta's worth of records (see `records_per_fill`), so the
/// used bytes grow until the buffer is full, after which the ring buffer evicts
/// its oldest records and `bytes_used` plateaus at the buffer capacity.
///
/// `log_message_size` is the content size of each written record and must match
/// the size the canister actually logs. It is only used to size the
/// post-condition margin below.
fn fill_log_buffer_to_capacity(
    env: &mut StateMachine,
    canister_id: CanisterId,
    log_message_size: usize,
) {
    let log_bytes_used = |env: &StateMachine| {
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .log_memory_store
            .bytes_used()
    };
    let mut prev_used = 0;
    loop {
        // `fill_logs` does not reply; ignore the resulting `CanisterDidNotReply`.
        let _ = env.execute_ingress(canister_id, "fill_logs", vec![]);
        let used = log_bytes_used(env);
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
    let capacity = env
        .get_latest_state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .log_memory_store
        .byte_capacity();
    let record_size = LogMemoryStore::estimate_record_size(log_message_size);
    assert!(
        prev_used + record_size >= capacity,
        "log buffer plateaued at {prev_used} B, more than one record ({record_size} B) below \
         capacity {capacity} B — it was not filled to capacity",
    );
}

/// Creates a `StateMachine` with a canister whose log buffer is filled to
/// capacity and whose logs are public (readable by any caller). Shared by the
/// resize benchmarks and the fetch benchmarks / `fetch_response` helper, so all
/// exercise an identically-filled buffer.
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
                // Return the harness so criterion drops it (an expensive teardown
                // that scales with the buffer) outside the timed region.
                (env, canister_id)
            },
            BatchSize::LargeInput,
        );
    });
}

/// Times `fetch_canister_logs_response` — the read/encode work that drives
/// `fetch_canister_logs_instructions` — directly on a `CanisterState` whose log
/// buffer is filled to capacity.
///
/// The filled state is built once and reused across all iterations: the read is
/// immutable, so there is no per-iteration setup or teardown to leak into the
/// timed region. This measures exactly the costed operation, excluding the
/// surrounding subnet-message and inter-canister-call machinery (which is not
/// charged to the call and, being ~1000x the sub-millisecond read on large
/// buffers, would otherwise swamp the measurement).
fn run_bench_fetch_canister_log<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    log_memory_limit: u64,
    log_message_size: usize,
    filter: Option<FetchCanisterLogsFilter>,
) {
    let (env, target) = setup_canister_with_full_log(log_memory_limit, log_message_size);
    // The target's logs are public, so any sender is allowed to read them.
    let sender = PrincipalId::new_anonymous();
    let state = env.get_latest_state();
    let canister = state.canister_state(&target).unwrap();
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || {
                let mut request = FetchCanisterLogsRequest::new(target);
                request.filter = filter;
                request
            },
            |request| fetch_canister_logs_response_for_bench(sender, canister, request),
            BatchSize::LargeInput,
        );
    });
}

/// Like `run_bench_fetch_canister_log`, but the fetch filters for a single record
/// whose index lies in the middle of the buffer's live idx range (derived from the
/// filled buffer). This isolates the index-guided seek plus single-record decode
/// from the full-buffer scan, showing whether a one-record lookup stays cheap as
/// the buffer (log memory limit) grows. `log_message_size` is the content size of
/// each record filling the buffer (0 bytes maximizes the record count per byte).
fn run_bench_fetch_single_log_in_middle<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    log_memory_limit: u64,
    log_message_size: usize,
) {
    let (env, target) = setup_canister_with_full_log(log_memory_limit, log_message_size);
    // The target's logs are public, so any sender is allowed to read them.
    let sender = PrincipalId::new_anonymous();
    let state = env.get_latest_state();
    let canister = state.canister_state(&target).unwrap();
    // Pick a record in the middle of the live idx range and filter for exactly
    // that one index (`[mid, mid + 1)`).
    let log_memory_store = &canister.system_state.log_memory_store;
    let records = log_memory_store.records(None);
    let mid_idx = records[records.len() / 2].idx;
    let filter = FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
        start: mid_idx,
        end: mid_idx + 1,
    });
    // Guard against the benchmark silently measuring an empty result: the filter
    // must match exactly the one record.
    assert_eq!(log_memory_store.records(Some(filter)).len(), 1);
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || {
                let mut request = FetchCanisterLogsRequest::new(target);
                request.filter = Some(filter);
                request
            },
            |request| fetch_canister_logs_response_for_bench(sender, canister, request),
            BatchSize::LargeInput,
        );
    });
}

/// Regression guard for the filtered read path against an adversarial filter whose
/// range sits entirely *below* the buffer's live index range. Its `start` makes the
/// index seek land at the head, so the very first scanned record is already past the
/// range's end.
///
/// `records()` scans in ascending key order and stops as soon as it reaches a record
/// past the range's end (`LogRecord::is_past_range_end`), so this returns nothing in
/// O(1) — it must NOT degrade into a full head-to-tail scan as the buffer (log memory
/// limit) grows. Before that early-exit was added, this case scanned the whole buffer
/// (e.g. ~15 ms on a full 2 MiB buffer) while returning zero records, which the
/// instruction deduction — derived from the returned record count and content size —
/// undercharged as an empty response. This differs from `FETCH_FILTER_EMPTY` (range
/// *above* the newest index), which the seek instead lands at the tail.
fn run_bench_fetch_no_match_scan<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    log_memory_limit: u64,
    log_message_size: usize,
) {
    let (env, target) = setup_canister_with_full_log(log_memory_limit, log_message_size);
    // The target's logs are public, so any sender is allowed to read them.
    let sender = PrincipalId::new_anonymous();
    let state = env.get_latest_state();
    let canister = state.canister_state(&target).unwrap();
    let log_memory_store = &canister.system_state.log_memory_store;
    // Oldest live index: after filling to capacity the buffer has evicted its
    // earliest records, so the oldest live index is > 0 and the range `[0, oldest)`
    // is non-empty (valid) yet matches no live record. A `ByIdx` filter spanning the
    // whole index space returns records oldest-first, trimming from the newest end,
    // so `.first()` is the true oldest live record even when the result is trimmed to
    // `RESULT_MAX_SIZE` (unlike an unfiltered read, which trims from the oldest end).
    let oldest_idx = log_memory_store
        .records(Some(FetchCanisterLogsFilter::ByIdx(
            FetchCanisterLogsRange {
                start: 0,
                end: u64::MAX,
            },
        )))
        .first()
        .expect("buffer is non-empty")
        .idx;
    assert!(
        oldest_idx > 0,
        "buffer did not evict any records — cannot build a head-positioned no-match filter",
    );
    let filter = FetchCanisterLogsFilter::ByIdx(FetchCanisterLogsRange {
        start: 0,
        end: oldest_idx,
    });
    // Guard against the benchmark silently measuring a normal read: the filter must
    // match nothing (while remaining head-positioned so it would force a full-buffer
    // scan absent the early-exit, see the doc comment).
    assert!(log_memory_store.records(Some(filter)).is_empty());
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || {
                let mut request = FetchCanisterLogsRequest::new(target);
                request.filter = Some(filter);
                request
            },
            |request| fetch_canister_logs_response_for_bench(sender, canister, request),
            BatchSize::LargeInput,
        );
    });
}

/// Runs the `fetch_canister_logs` read/encode path (the exact work the benchmarks
/// time) against a target whose log buffer is filled to capacity and returns the
/// Candid-encoded reply payload. Used for one-off sanity checks.
fn fetch_response(
    filter: Option<FetchCanisterLogsFilter>,
    log_memory_limit: u64,
    log_message_size: usize,
) -> Vec<u8> {
    let (env, target) = setup_canister_with_full_log(log_memory_limit, log_message_size);
    // The target's logs are public, so any sender is allowed to read them.
    let sender = PrincipalId::new_anonymous();
    let state = env.get_latest_state();
    let mut request = FetchCanisterLogsRequest::new(target);
    request.filter = filter;
    let (reply, _record_count, _content_size) = fetch_canister_logs_response_for_bench(
        sender,
        state.canister_state(&target).unwrap(),
        request,
    );
    reply
}

/// Size of the Candid-encoded `fetch_canister_logs` reply payload.
fn fetch_response_len(
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
                    // Drop the harness outside the timed region (see other routines).
                    (env, canister_id)
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
        // Unfiltered worst case must return a full ~2 MB response of log data
        // (the response is trimmed to `RESULT_MAX_SIZE`, i.e. 2 MB).
        assert!(fetch_response_len(None, 2 * MIB, (32 * KIB) as usize) > 1_800_000);
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
        // Empty-response cost across growing log memory limits (buffer sizes):
        // each buffer is filled to capacity, but the filter matches nothing, so
        // the fetch returns an empty response. This isolates the minimum work a
        // fetch on a full buffer does (no records returned) as a function of the
        // log memory limit. Both content sizes are swept: 0-byte messages maximize
        // the record count per byte, while 100-byte messages hold ~6× fewer
        // records in the same buffer.
        let log_memory_limits = [
            ("4KiB", 4 * KIB),
            ("16KiB", 16 * KIB),
            ("64KiB", 64 * KIB),
            ("256KiB", 256 * KIB),
            ("1MiB", MIB),
            ("2MiB", 2 * MIB),
        ];
        for (msg_name, msg_size) in [("0B", 0_usize), ("100B", 100_usize)] {
            for (name, limit) in log_memory_limits {
                run_bench_fetch_canister_log(
                    &mut group,
                    &format!("fetch:{name}/msg:{msg_name}/filter:empty"),
                    limit,
                    msg_size,
                    FETCH_FILTER_EMPTY,
                );
            }
        }
        // Single-record lookup in the middle of the idx range across the same
        // growing log memory limits and content sizes: the filter matches exactly
        // one record whose index is in the middle of the buffer's live idx range.
        // This shows whether an index-guided one-record lookup stays cheap as the
        // buffer grows (in contrast to the full-buffer empty scan above).
        for (msg_name, msg_size) in [("0B", 0_usize), ("100B", 100_usize)] {
            for (name, limit) in log_memory_limits {
                run_bench_fetch_single_log_in_middle(
                    &mut group,
                    &format!("fetch:{name}/msg:{msg_name}/filter:single_mid"),
                    limit,
                    msg_size,
                );
            }
        }
        // No-match scan across the same growing log memory limits and content sizes:
        // a valid filter positioned below the live idx range. Its seek lands at the head
        // (unlike `filter:empty`, positioned past the newest index, whose seek lands at
        // the tail), so the scan must early-exit on the first record — already past the
        // range end — to return nothing in O(1) rather than walk the whole buffer. These
        // times must therefore stay flat as the buffer grows: a regression would
        // reintroduce a full head-to-tail scan that returns zero records yet is charged
        // only the fixed base.
        for (msg_name, msg_size) in [("0B", 0_usize), ("100B", 100_usize)] {
            for (name, limit) in log_memory_limits {
                run_bench_fetch_no_match_scan(
                    &mut group,
                    &format!("fetch:{name}/msg:{msg_name}/filter:no_match_scan"),
                    limit,
                    msg_size,
                );
            }
        }
        // Realistic: 100-byte messages.
        run_bench_fetch_canister_log(&mut group, "fetch:128KiB/msg:100B", 128 * KIB, 100, None);
        run_bench_fetch_canister_log(&mut group, "fetch:1MiB/msg:100B", MIB, 100, None);
        run_bench_fetch_canister_log(&mut group, "fetch:2MiB/msg:100B", 2 * MIB, 100, None);
        // Worst case for the returned payload size: large (32 KiB, the maximum
        // `debug_print` size) messages so a single fetch returns a full ~2 MB
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
