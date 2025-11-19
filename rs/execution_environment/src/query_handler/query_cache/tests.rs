use super::{QueryCache, QueryCacheMetrics};
use crate::{
    InternalHttpQueryHandler, metrics,
    query_handler::query_cache::{EntryEnv, EntryKey, EntryValue},
};
use ic_base_types::CanisterId;
use ic_error_types::ErrorCode;
use ic_heap_bytes::{DeterministicHeapBytes, HeapBytes, total_bytes};
use ic_interfaces::execution_environment::{SystemApiCallCounters, SystemApiCallId};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_test_utilities::universal_canister::wasm;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{
    batch::QueryStats,
    ingress::WasmResult,
    messages::{
        CanisterTask, CertificateDelegationFormat, CertificateDelegationMetadata, Query,
        QuerySource,
    },
    time,
};
use ic_types_test_utils::ids::subnet_test_id;
use ic_universal_canister::call_args;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const MAX_EXPIRY_TIME: Duration = Duration::from_secs(10);
const MORE_THAN_MAX_EXPIRY_TIME: Duration = Duration::from_secs(11);
const DATA_CERTIFICATE_EXPIRY_TIME: Duration = Duration::from_secs(2);
const MORE_THAN_DATA_CERTIFICATE_EXPIRY_TIME: Duration = Duration::from_secs(3);
const ITERATIONS: usize = 5;
const REPLY_SIZE: usize = 10_000;
const BIG_REPLY_SIZE: usize = 1_000_000;

const QUERY_CACHE_WAT: &str = r#"
(module
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32 i32)))
    (import "ic0" "canister_cycle_balance" (func $canister_cycle_balance (result i64)))

    (memory 100)
    (data (i32.const 0) "42")

    (func $f
        (call $msg_reply_data_append (i32.const 0) (i32.const 2))
        (call $msg_reply)
    )

    (func (export "canister_query canister_balance_sized_reply")
        ;; Produce a `canister_cycle_balance` sized reply
        (call $msg_reply_data_append
            (i32.const 0)
            (i32.wrap_i64 (call $canister_cycle_balance))
        )
        (call $msg_reply)
    )

    (export "canister_query f1" (func $f))
    (export "canister_query f2" (func $f))
)"#;

fn downcast_query_handler(query_handler: &dyn std::any::Any) -> &InternalHttpQueryHandler {
    // SAFETY:
    //
    // The type `InternalHttpQueryHandler` is imported in
    // `ic_test_utilities_execution_environment` but because this dependency is
    // only added as a dev dependency it's considered different than the type
    // imported here which is used in non-dev dependencies. However, we know
    // that the two types are the same under the hood, so we can safely perform
    // a downcast.
    unsafe { &*(query_handler as *const dyn std::any::Any as *const InternalHttpQueryHandler) }
}

/// Return a reference to `InternalHttpQueryHandler`.
fn query_handler(test: &ExecutionTest) -> &InternalHttpQueryHandler {
    downcast_query_handler(test.query_handler())
}

/// Return a reference to query cache.
fn query_cache(test: &ExecutionTest) -> &QueryCache {
    &query_handler(test).query_cache
}

/// Return a reference to query cache metrics.
fn query_cache_metrics(test: &ExecutionTest) -> &QueryCacheMetrics {
    &query_cache(test).metrics
}

/// Return `ExecutionTestBuilder` with query caching, composite queries
/// and query stats enabled.
fn builder_with_query_caching() -> ExecutionTestBuilder {
    ExecutionTestBuilder::new().with_query_stats()
}

/// Return `ExecutionTestBuilder` with specified query cache `capacity`.
fn builder_with_query_cache_capacity(capacity: usize) -> ExecutionTestBuilder {
    builder_with_query_caching().with_query_cache_capacity(capacity as u64)
}

/// Return `ExecutionTestBuilder` with query cache expiry times.
fn builder_with_query_cache_expiry_times() -> ExecutionTestBuilder {
    builder_with_query_caching()
        .with_query_cache_max_expiry_time(MAX_EXPIRY_TIME)
        .with_query_cache_data_certificate_expiry_time(DATA_CERTIFICATE_EXPIRY_TIME)
}

/// Runs the specified Universal Canister payload for a query and then
/// for a composite query in a newly created execution test.
fn for_query_and_composite_query<F>(query: ic_universal_canister::PayloadBuilder, f: F)
where
    F: Fn(ExecutionTest, CanisterId, CanisterId, &str, Vec<u8>),
{
    let mut test = builder_with_query_cache_expiry_times().build();
    let q = query.build();
    let id = test.universal_canister().unwrap();
    f(test, id, id, "query", q.clone());

    let mut test = builder_with_query_cache_expiry_times().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let b = q;
    let a = wasm()
        // By default the on reply and on reject handlers propagate the other side response.
        .composite_query(b_id, call_args().other_side(b))
        .build();
    f(test, a_id, b_id, "composite_query", a);
}

#[test]
fn query_cache_entry_value_counts_elapsed_seconds() {
    let current_time = time::GENESIS;
    let entry_env = EntryEnv {
        batch_time: current_time,
        canisters_versions_balances_stats: vec![],
    };
    let entry_value = EntryValue::new(
        entry_env,
        Result::Ok(WasmResult::Reply(vec![])),
        &SystemApiCallCounters::default(),
    );
    let forward_time = current_time + Duration::from_secs(2);
    assert_eq!(2.0, entry_value.elapsed_seconds(forward_time));

    // Negative time differences should give just 0.
    let backward_time = current_time.saturating_sub(Duration::from_secs(2));
    assert_eq!(0.0, entry_value.elapsed_seconds(backward_time));
}

#[test]
fn query_cache_reports_hits_and_misses_metrics() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        assert_eq!(query_cache_metrics(&test).hits.get(), 0);
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Do not change balance or time.

        let res_2 = test.non_replicated_query(a_id, method, q);
        assert_eq!(query_cache_metrics(&test).hits.get(), 1);
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, res_2);
    });
}

#[test]
fn query_cache_reports_evicted_entries_and_memory_bytes_metrics() {
    const QUERY_CACHE_SIZE: usize = 2;
    /// Includes some room for the keys, headers etc.
    const QUERY_CACHE_CAPACITY: usize = REPLY_SIZE * (QUERY_CACHE_SIZE + 1);
    let mut test = builder_with_query_cache_capacity(QUERY_CACHE_CAPACITY).build();
    let id = test.universal_canister().unwrap();

    for i in 0..ITERATIONS {
        let res = test.non_replicated_query(
            id,
            "query",
            // Every query is unique and should produce a new cache entry.
            // The bytes are stored twice: as a payload in key and as a reply in value.
            wasm().reply_data(&[i as u8; REPLY_SIZE / 2]).build(),
        );
        assert_eq!(res, Ok(WasmResult::Reply(vec![i as u8; REPLY_SIZE / 2])));
        // One unique query per 2 seconds.
        test.state_mut().metadata.batch_time += Duration::from_secs(2);
    }

    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(ITERATIONS, m.misses.get() as usize);
    const EVICTED_ENTRIES: usize = ITERATIONS - QUERY_CACHE_SIZE;
    assert_eq!(EVICTED_ENTRIES, m.evicted_entries.get() as usize);
    // Times 2 seconds per each query.
    assert_eq!(
        EVICTED_ENTRIES * QUERY_CACHE_SIZE * 2,
        m.evicted_entries_duration.get_sample_sum() as usize
    );
    assert_eq!(
        EVICTED_ENTRIES,
        m.evicted_entries_duration.get_sample_count() as usize
    );
    assert_eq!(0, m.invalidated_entries.get());

    let memory_bytes = m.count_bytes.get() as usize;
    // We can't match the size exactly, as it includes the key and the captured environment.
    // But we can assert that the sum of the sizes should be:
    // REPLY_SIZE < memory_bytes < REPLY_SIZE * 2
    assert!(REPLY_SIZE < memory_bytes);
    assert!(REPLY_SIZE * 2 * QUERY_CACHE_SIZE > memory_bytes);
}

#[test]
fn query_cache_reports_memory_bytes_metric_on_invalidation() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let key = EntryKey {
        source: user_test_id(1),
        receiver: a_id,
        method_name: "method".into(),
        method_payload: vec![],
        certificate_delegation_format: None,
    };

    // Assert initial cache state.
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(0, m.misses.get());
    let initial_memory_bytes = m.count_bytes.get();
    assert!((initial_memory_bytes as usize) < BIG_REPLY_SIZE);

    // Push a big result into the cache.
    let big_result = Ok(WasmResult::Reply(vec![0; BIG_REPLY_SIZE]));
    let query_cache = &query_handler(&test).query_cache;
    let mut evaluated_stats = BTreeMap::new();
    evaluated_stats.insert(a_id, QueryStats::default());
    query_cache.push(
        key.clone(),
        &big_result,
        test.state(),
        &SystemApiCallCounters::default(),
        &evaluated_stats,
        0,
    );
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    let memory_bytes = m.count_bytes.get();
    assert!(((memory_bytes - initial_memory_bytes) as usize) > BIG_REPLY_SIZE);

    // Bump up the version
    test.canister_state_mut(a_id).system_state.canister_version += 1;

    // Invalidate and pop the result.
    let query_cache = &query_handler(&test).query_cache;
    query_cache.get_valid_result(&key, test.state(), None);
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    let final_memory_bytes = m.count_bytes.get();
    assert!((final_memory_bytes as usize) < BIG_REPLY_SIZE);
}

#[test]
fn query_cache_reports_evicted_entries_duration_metric_on_negative_durations() {
    /// Includes some room for the keys, headers etc.
    const QUERY_CACHE_CAPACITY: usize = REPLY_SIZE + REPLY_SIZE;
    let mut test = builder_with_query_cache_capacity(QUERY_CACHE_CAPACITY).build();
    let id = test.universal_canister().unwrap();

    // As there are no updates, the default system time is unix epoch, so we explicitly set it here.
    test.state_mut().metadata.batch_time = time::GENESIS;

    // Run the first query.
    let res = test.non_replicated_query(
        id,
        "query",
        // The bytes are stored twice: as a payload in key and as a reply in value.
        wasm().reply_data(&[1; REPLY_SIZE / 2]).build(),
    );
    assert_eq!(res, Ok(WasmResult::Reply(vec![1; REPLY_SIZE / 2])));

    // Move the time backward.
    test.state_mut().metadata.batch_time = time::UNIX_EPOCH;

    // The second query should evict the first one, as there is no room in the cache for two queries.
    let res = test.non_replicated_query(
        id,
        "query",
        // The bytes are stored twice: as a payload in key and as a reply in value.
        wasm().reply_data(&[2; REPLY_SIZE / 2]).build(),
    );
    assert_eq!(res, Ok(WasmResult::Reply(vec![2; REPLY_SIZE / 2])));

    let m = query_cache_metrics(&test);
    // Negative durations should give just 0.
    assert_eq!(0, m.evicted_entries_duration.get_sample_sum() as usize);
    // One entry should be evicted.
    assert_eq!(1, m.evicted_entries_duration.get_sample_count());
}

#[test]
fn query_cache_reports_invalidated_entries_metric() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();

    for _ in 0..ITERATIONS {
        // Every query is the same and should hit the same cache entry.
        let res = test.non_replicated_query(id, "query", wasm().reply_data(&[42]).build());
        assert_eq!(res, Ok(WasmResult::Reply(vec![42])));
        // Executing a default UC heartbeat should render the cache entry invalid.
        test.canister_task(id, CanisterTask::Heartbeat);
    }

    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(ITERATIONS, m.misses.get() as usize);
    assert_eq!(0, m.evicted_entries.get() as usize);
    // Minus one for the first iteration when the entry was just added into the cache.
    assert_eq!(ITERATIONS - 1, m.invalidated_entries.get() as usize,);
}

#[test]
fn query_cache_returns_different_results_for_different_sources() {
    let q = wasm().caller().append_and_reply();
    for_query_and_composite_query(q, |test, a_id, b_id, method, q| {
        let res_1 = test.query(
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(1),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: a_id,
                method_name: method.into(),
                method_payload: q.clone(),
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
        );
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        let caller = if a_id == b_id {
            // For normal query, caller is the user 1.
            user_test_id(1).get()
        } else {
            // For composite query canister B, caller is the canister A.
            a_id.get()
        };
        assert_eq!(Ok(WasmResult::Reply(caller.into())), res_1);

        let res_2 = test.query(
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(2),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: a_id,
                method_name: method.into(),
                method_payload: q,
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
        );
        assert_eq!(query_cache_metrics(&test).misses.get(), 2);
        let caller = if a_id == b_id {
            // For normal query, caller is the user 2.
            user_test_id(2).get()
        } else {
            // For composite query canister B, caller is the canister A.
            a_id.get()
        };
        assert_eq!(Ok(WasmResult::Reply(caller.into())), res_2);
    });
}

#[test]
fn query_cache_returns_different_results_for_different_receivers() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let q = wasm().reply_data(&[42]).build();

    let res_1 = test.non_replicated_query(a_id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    let res_2 = test.non_replicated_query(b_id, "query", q);
    assert_eq!(query_cache_metrics(&test).misses.get(), 2);
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_returns_different_results_for_different_method_names() {
    let mut test = builder_with_query_caching().build();
    let id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();

    let res_1 = test.non_replicated_query(id, "f1", vec![]);
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(b"42".to_vec())));

    let res_2 = test.non_replicated_query(id, "f2", vec![]);
    assert_eq!(query_cache_metrics(&test).misses.get(), 2);
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_returns_different_results_for_different_certificate_delegation_formats() {
    let mut test = builder_with_query_caching().build();
    let id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();
    let method_name = "f1";
    let method_payload = vec![];

    let res_1 = test.non_replicated_query_with_certificate_delegation_metadata(
        id,
        method_name,
        method_payload.clone(),
        None,
    );
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(b"42".to_vec())));

    let res_2 = test.non_replicated_query_with_certificate_delegation_metadata(
        id,
        method_name,
        method_payload.clone(),
        Some(CertificateDelegationMetadata {
            format: CertificateDelegationFormat::Flat,
        }),
    );
    assert_eq!(query_cache_metrics(&test).misses.get(), 2);

    let res_3 = test.non_replicated_query_with_certificate_delegation_metadata(
        id,
        method_name,
        method_payload.clone(),
        Some(CertificateDelegationMetadata {
            format: CertificateDelegationFormat::Tree,
        }),
    );
    assert_eq!(query_cache_metrics(&test).misses.get(), 3);

    assert_eq!(res_1, res_2);
    assert_eq!(res_2, res_3);
}

#[test]
fn query_cache_returns_different_results_for_different_method_payloads() {
    let mut test = builder_with_query_caching().build();
    let id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();

    let res_1 = test.non_replicated_query(id, "f1", vec![]);
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(b"42".to_vec())));

    let res_2 = test.non_replicated_query(id, "f1", vec![42]);
    assert_eq!(query_cache_metrics(&test).misses.get(), 2);
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_returns_different_results_for_different_batch_times() {
    // The query must get the time, otherwise the entry won't be invalidated.
    let q = wasm().time().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        test.state_mut().metadata.batch_time += Duration::from_secs(1);

        let res_2 = test.non_replicated_query(a_id, method, q);
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(res_1, res_2);
        assert_eq!(1, m.invalidated_entries.get());
        assert_eq!(1, m.invalidated_entries_by_time.get());
        assert_eq!(0, m.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(
            0,
            m.invalidated_entries_by_data_certificate_expiry_time.get()
        );
        assert_eq!(0, m.invalidated_entries_by_canister_version.get());
        assert_eq!(0, m.invalidated_entries_by_canister_balance.get());
        assert_eq!(1, m.invalidated_entries_duration.get_sample_sum() as u64);
        assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
    });
}

#[test]
fn query_cache_ignores_batch_time_changes_when_query_does_not_read_time() {
    // The query does not depend on time.
    let q = wasm().cycles_balance().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.hits.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Change the time.
        test.state_mut().metadata.batch_time += Duration::from_secs(1);

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's a hit despite the changed balance and time.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(1, m.hits.get());
        assert_eq!(1, m.hits_with_ignored_time.get());
        assert_eq!(0, m.hits_with_ignored_canister_balance.get());
        assert_eq!(res_1, res_2);
    });
}

#[test]
fn query_cache_ignores_balance_changes_when_query_does_not_read_balance() {
    // The query does not depend on time.
    let q = wasm().time().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.hits.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Change the canister balance.
        test.canister_state_mut(b_id)
            .system_state
            .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's a hit despite the changed balance and time.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(1, m.hits.get());
        assert_eq!(0, m.hits_with_ignored_time.get());
        assert_eq!(1, m.hits_with_ignored_canister_balance.get());
        assert_eq!(res_1, res_2);
    });
}

#[test]
fn query_cache_ignores_balance_and_time_changes_when_query_is_static() {
    // The query does not depend on time.
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.hits.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Change the canister balance.
        test.canister_state_mut(b_id)
            .system_state
            .remove_cycles(1_u64.into(), CyclesUseCase::Memory);
        // Change the time.
        test.state_mut().metadata.batch_time += Duration::from_secs(1);

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's a hit despite the changed balance and time.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(1, m.hits.get());
        assert_eq!(1, m.hits_with_ignored_time.get());
        assert_eq!(1, m.hits_with_ignored_canister_balance.get());
        assert_eq!(res_1, res_2);
    });
}

#[test]
fn query_cache_returns_different_results_after_max_expiry_time() {
    // The query does not depend on time.
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Change the batch time more than the max expiry time.
        test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(res_1, res_2);
        assert_eq!(1, m.invalidated_entries.get());
        assert_eq!(0, m.invalidated_entries_by_time.get());
        assert_eq!(1, m.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(
            MORE_THAN_MAX_EXPIRY_TIME.as_secs(),
            m.invalidated_entries_duration.get_sample_sum() as u64
        );
        assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
    });
}

#[test]
// The data certificate can be called only in the normal query.
fn query_cache_always_returns_different_results_after_data_certificate_expiry_time() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let id = test.universal_canister().unwrap();
    let q = wasm().data_certificate().reply().build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![])));

    // Change the batch time more than the data certificate expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_DATA_CERTIFICATE_EXPIRY_TIME;

    let res_2 = test.non_replicated_query(id, "query", q);
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(res_1, res_2);
    assert_eq!(1, m.invalidated_entries.get());
    assert_eq!(0, m.invalidated_entries_by_time.get());
    assert_eq!(0, m.invalidated_entries_by_max_expiry_time.get());
    assert_eq!(
        1,
        m.invalidated_entries_by_data_certificate_expiry_time.get()
    );
    assert_eq!(0, m.invalidated_entries_by_canister_version.get());
    assert_eq!(0, m.invalidated_entries_by_canister_balance.get());
    assert_eq!(
        MORE_THAN_DATA_CERTIFICATE_EXPIRY_TIME.as_secs(),
        m.invalidated_entries_duration.get_sample_sum() as u64
    );
    assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
}

#[test]
fn query_cache_reports_invalidated_entries_duration_metric_on_negative_durations() {
    // The query must get the time, otherwise the entry won't be invalidated.
    let q = wasm().time().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        // As there are no updates, the default system time is unix epoch, so we explicitly set it here.
        test.state_mut().metadata.batch_time = time::GENESIS;

        let res_1 = test.non_replicated_query(a_id, method, q.clone());

        // Move the time backward.
        test.state_mut().metadata.batch_time = time::UNIX_EPOCH;

        let res_2 = test.non_replicated_query(a_id, method, q);
        let m = query_cache_metrics(&test);
        assert_eq!(res_1, res_2);
        assert_eq!(1, m.invalidated_entries_by_time.get());
        assert_eq!(0, m.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(
            0,
            m.invalidated_entries_by_data_certificate_expiry_time.get()
        );
        // Negative durations should give just 0.
        assert_eq!(0, m.invalidated_entries_duration.get_sample_sum() as usize);
        assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
    });
}

#[test]
fn query_cache_returns_different_results_for_different_canister_versions() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Bump up the version
        test.canister_state_mut(b_id).system_state.canister_version += 1;

        let res_2 = test.non_replicated_query(a_id, method, q);
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(res_1, res_2);
        assert_eq!(1, m.invalidated_entries.get());
        assert_eq!(0, m.invalidated_entries_by_time.get());
        assert_eq!(0, m.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(
            0,
            m.invalidated_entries_by_data_certificate_expiry_time.get()
        );
        assert_eq!(1, m.invalidated_entries_by_canister_version.get());
        assert_eq!(0, m.invalidated_entries_by_canister_balance.get());
        assert_eq!(0, m.invalidated_entries_duration.get_sample_sum() as usize);
        assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
    });
}

#[test]
fn query_cache_returns_different_results_for_different_canister_balances() {
    // The query must get the balance, otherwise the entry won't be invalidated.
    let q = wasm().cycles_balance().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Change the canister balance.
        test.canister_state_mut(b_id)
            .system_state
            .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

        let res_2 = test.non_replicated_query(a_id, method, q);
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(res_1, res_2);
        assert_eq!(1, m.invalidated_entries.get());
        assert_eq!(0, m.invalidated_entries_by_time.get());
        assert_eq!(0, m.invalidated_entries_by_canister_version.get());
        assert_eq!(1, m.invalidated_entries_by_canister_balance.get());
        assert_eq!(0, m.invalidated_entries_duration.get_sample_sum() as usize);
        assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
    });
}

#[test]
fn query_cache_returns_different_results_for_different_canister_balance128s() {
    // The query must get the balance, otherwise the entry won't be invalidated.
    let q = wasm().cycles_balance128().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Change the canister balance.
        test.canister_state_mut(b_id)
            .system_state
            .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

        let res_2 = test.non_replicated_query(a_id, method, q);
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(res_1, res_2);
        assert_eq!(1, m.invalidated_entries.get());
        assert_eq!(0, m.invalidated_entries_by_time.get());
        assert_eq!(0, m.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(
            0,
            m.invalidated_entries_by_data_certificate_expiry_time.get()
        );
        assert_eq!(0, m.invalidated_entries_by_canister_version.get());
        assert_eq!(1, m.invalidated_entries_by_canister_balance.get());
        assert_eq!(0, m.invalidated_entries_duration.get_sample_sum() as usize);
        assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
    });
}

#[test]
fn query_cache_returns_different_results_on_combined_invalidation() {
    // The query must get the time and balance, otherwise the entry won't be invalidated.
    // The data certificate can be called only in the normal query.
    let q = wasm().time().cycles_balance().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());

        // Change the batch time more than the max expiry time.
        test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;
        test.canister_state_mut(b_id).system_state.canister_version += 1;
        test.canister_state_mut(b_id)
            .system_state
            .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

        let res_2 = test.non_replicated_query(a_id, method, q);
        assert_eq!(res_1, res_2);
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(1, m.invalidated_entries.get());
        assert_eq!(1, m.invalidated_entries_by_time.get());
        assert_eq!(1, m.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(1, m.invalidated_entries_by_canister_version.get());
        assert_eq!(1, m.invalidated_entries_by_canister_balance.get());
    });
}

#[test]
fn query_cache_frees_memory_after_invalidated_entries() {
    static BIG_RESPONSE_SIZE: usize = 1_000_000;
    static SMALL_RESPONSE_SIZE: usize = 42;

    let mut test = builder_with_query_caching()
        // Use system subnet so all the executions are free.
        .with_subnet_type(SubnetType::System)
        // To replace the cache entry in the cache, the query requests must be identical,
        // i.e. source, receiver, method name and payload must all be the same. Hence,
        // we can't use them to construct a different reply.
        // For the test purpose, the cycles balance is used to construct different replies,
        // keeping all other parameters the same.
        // The first reply will be 1MB.
        .with_initial_canister_cycles(BIG_RESPONSE_SIZE.try_into().unwrap())
        .build();
    let id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();

    let heap_bytes = query_cache(&test).heap_bytes();
    // Initially the cache should be empty, i.e. less than 1MB.
    assert!(heap_bytes < BIG_RESPONSE_SIZE);

    // The 1MB result will be cached internally.
    let res = test
        .non_replicated_query(id, "canister_balance_sized_reply", vec![])
        .unwrap();
    assert_eq!(BIG_RESPONSE_SIZE, res.deterministic_heap_bytes());
    let heap_bytes = query_cache(&test).heap_bytes();
    // After the first reply, the cache should have more than 1MB of data.
    assert!(heap_bytes > BIG_RESPONSE_SIZE);

    // Set the canister balance to 42, so the second reply will have just 42 bytes.
    test.canister_state_mut(id).system_state.remove_cycles(
        ((BIG_RESPONSE_SIZE - SMALL_RESPONSE_SIZE) as u64).into(),
        CyclesUseCase::Memory,
    );

    // The new 42 reply must invalidate and replace the previous 1MB reply in the cache.
    let res = test
        .non_replicated_query(id, "canister_balance_sized_reply", vec![])
        .unwrap();
    assert_eq!(SMALL_RESPONSE_SIZE, res.deterministic_heap_bytes());
    let heap_bytes = query_cache(&test).heap_bytes();
    // The second 42 reply should invalidate and replace the first 1MB reply in the cache.
    assert!(heap_bytes > SMALL_RESPONSE_SIZE);
    assert!(heap_bytes < BIG_RESPONSE_SIZE);
}

#[test]
fn query_cache_respects_cache_capacity() {
    /// Includes some room for the keys, headers etc.
    const QUERY_CACHE_CAPACITY: usize = REPLY_SIZE * 3;
    let mut test = builder_with_query_cache_capacity(QUERY_CACHE_CAPACITY).build();
    let id = test.universal_canister().unwrap();

    // Initially the cache should be empty, i.e. less than REPLY_SIZE.
    let heap_bytes = query_cache(&test).heap_bytes();
    assert!(heap_bytes < REPLY_SIZE);

    // All replies should hit the same cache entry.
    for _ in 0..ITERATIONS {
        // The bytes are stored twice: as payload and then as reply.
        let _res =
            test.non_replicated_query(id, "query", wasm().reply_data(&[1; REPLY_SIZE / 2]).build());
        // Now there should be only one reply in the cache.
        let heap_bytes = query_cache(&test).heap_bytes();
        assert!(heap_bytes > REPLY_SIZE);
        assert!(heap_bytes < QUERY_CACHE_CAPACITY);
    }

    // Now the replies should hit another entry.
    for _ in 0..ITERATIONS {
        let _res =
            test.non_replicated_query(id, "query", wasm().reply_data(&[2; REPLY_SIZE / 2]).build());
        // Now there should be two replies in the cache.
        let heap_bytes = query_cache(&test).heap_bytes();
        assert!(heap_bytes > REPLY_SIZE * 2);
        assert!(heap_bytes < QUERY_CACHE_CAPACITY);
    }

    // Now the replies should evict the first entry.
    for _ in 0..ITERATIONS {
        let _res =
            test.non_replicated_query(id, "query", wasm().reply_data(&[3; REPLY_SIZE / 2]).build());
        // There should be still just two replies in the cache.
        let heap_bytes = query_cache(&test).heap_bytes();
        assert!(heap_bytes > REPLY_SIZE * 2);
        assert!(heap_bytes < QUERY_CACHE_CAPACITY);
    }
}

#[test]
fn query_cache_works_with_zero_cache_capacity() {
    let mut test = builder_with_query_cache_capacity(0).build();
    let id = test.universal_canister().unwrap();

    // Even with zero capacity the cache data structure uses some bytes for the pointers etc.
    let initial_heap_bytes = query_cache(&test).heap_bytes();

    // Replies should not change the initial (zero) capacity.
    for _ in 0..ITERATIONS {
        let _res = test.non_replicated_query(id, "query", wasm().reply_data(&[1]).build());
        let heap_bytes = query_cache(&test).heap_bytes();
        assert_eq!(initial_heap_bytes, heap_bytes);
    }
}

#[test]
fn query_cache_reports_system_api_calls_metric() {
    let q = wasm().cycles_balance().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        test.non_replicated_query(a_id, method, q).unwrap();
        let m = &query_handler(&test).metrics.query_system_api_calls;
        assert_eq!(
            1,
            m.with_label_values(&[metrics::SYSTEM_API_CANISTER_CYCLE_BALANCE])
                .get()
        );
    });
    let q = wasm().cycles_balance128().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        test.non_replicated_query(a_id, method, q).unwrap();
        let m = &query_handler(&test).metrics.query_system_api_calls;
        assert_eq!(
            1,
            m.with_label_values(&[metrics::SYSTEM_API_CANISTER_CYCLE_BALANCE128])
                .get()
        );
    });
    let q = wasm().time().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        test.non_replicated_query(a_id, method, q).unwrap();
        let m = &query_handler(&test).metrics.query_system_api_calls;
        assert_eq!(1, m.with_label_values(&[metrics::SYSTEM_API_TIME]).get());
    });
}

#[test]
fn composite_query_cache_reports_system_api_calls_metric() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        // Fist group of System API calls.
        .data_certificate()
        .data_certificate()
        .data_certificate()
        .cycles_balance()
        .cycles_balance128()
        .time()
        // First nested call.
        .composite_query(
            b_id,
            call_args().on_reply(
                wasm()
                    // Third group of System API calls.
                    .cycles_balance()
                    .cycles_balance128()
                    .time()
                    .time()
                    // Second nested call.
                    .composite_query(
                        b_id,
                        call_args().on_reply(
                            wasm()
                                // Forth group of System API calls.
                                .cycles_balance()
                                .cycles_balance128()
                                .cycles_balance128()
                                .time()
                                .time()
                                .reply_int64(),
                        ),
                    ),
            ),
        )
        // Second group of System API calls.
        .data_certificate()
        .data_certificate()
        .data_certificate()
        .data_certificate()
        .cycles_balance()
        .cycles_balance128()
        .time()
        .build();
    test.non_replicated_query(a_id, "composite_query", a)
        .unwrap();

    let m = &query_handler(&test).metrics;
    // Four `ic0.canister_cycle_balance()` calls.
    assert_eq!(
        4,
        m.query_system_api_calls
            .with_label_values(&[metrics::SYSTEM_API_CANISTER_CYCLE_BALANCE])
            .get()
    );
    // Five `ic0.canister_cycle_balance128()` calls.
    assert_eq!(
        5,
        m.query_system_api_calls
            .with_label_values(&[metrics::SYSTEM_API_CANISTER_CYCLE_BALANCE128])
            .get()
    );
    // Six `ic0.time()` calls.
    assert_eq!(
        6,
        m.query_system_api_calls
            .with_label_values(&[metrics::SYSTEM_API_TIME])
            .get()
    );
    // Seven `ic0.data_certificate_copy()` calls.
    assert_eq!(
        7,
        m.query_system_api_calls
            .with_label_values(&[metrics::SYSTEM_API_DATA_CERTIFICATE_COPY])
            .get()
    );
}

#[test]
fn query_cache_reports_evaluated_canisters_metric() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        test.non_replicated_query(a_id, method, q).unwrap();
        let m = &query_handler(&test).metrics;
        // Reported once.
        assert_eq!(1, m.evaluated_canisters.get_sample_count());
        // One or two canisters.
        assert_eq!(
            if a_id == b_id { 1.0 } else { 2.0 },
            m.evaluated_canisters.get_sample_sum()
        );
    });
}

#[test]
fn composite_query_cache_reports_evaluated_canisters_metric() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        .composite_query(
            b_id,
            call_args().on_reply(
                wasm().composite_query(b_id, call_args().on_reply(wasm().reply_data(&[42]))),
            ),
        )
        .build();
    test.non_replicated_query(a_id, "composite_query", a)
        .unwrap();

    let m = &query_handler(&test).metrics;

    // Two canisters reported once.
    assert_eq!(1, m.evaluated_canisters.get_sample_count());
    assert_eq!(2.0, m.evaluated_canisters.get_sample_sum());
}

#[test]
fn query_cache_reports_transient_errors_metric() {
    let q = wasm();
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Increase the freezing threshold, so the call to canister B
        // should return transient error.
        test.update_freezing_threshold(b_id, u64::MAX.into())
            .expect("The settings update must succeed.");
        // The query returns a user error, while the composite query returns result with a reject.
        let _res_1 = test.non_replicated_query(a_id, method, q);
        let m = &query_handler(&test).metrics;
        assert_eq!(1, m.transient_errors.get());
    });
}

#[test]
fn composite_query_cache_reports_transient_errors_metric() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    let c_id = test.universal_canister().unwrap();

    // Increase the freezing threshold, so the call to canister C
    // should return transient error.
    test.update_freezing_threshold(c_id, u64::MAX.into())
        .expect("The settings update must succeed.");

    // Canister A calls canister B, which calls canister C three times.
    let a =
        wasm()
            .composite_query(
                b_id,
                call_args().other_side(wasm().composite_query(
                    c_id,
                    call_args().on_reject(wasm().composite_query(
                        c_id,
                        call_args().on_reject(wasm().composite_query(
                            c_id,
                            call_args().on_reject(wasm().reply_data(&[42])),
                        )),
                    )),
                )),
            )
            .build();
    test.non_replicated_query(a_id, "composite_query", a)
        .unwrap();

    let m = &query_handler(&test).metrics;

    // Three calls to a frozen canister.
    assert_eq!(3, m.transient_errors.get());
}

#[test]
fn query_cache_caches_errors() {
    // The query explicitly traps.
    let q = wasm().trap();
    for_query_and_composite_query(q, |mut test, a_id, _b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.hits.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());

        // Do not change balance or time.

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's a hit now.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(1, m.hits.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_1, res_2);
    });
}

#[test]
fn query_cache_never_caches_transient_errors() {
    let q = wasm();
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Increase the freezing threshold, so the call to canister B
        // should return transient error.
        test.update_freezing_threshold(b_id, u64::MAX.into())
            .expect("The settings update must succeed.");

        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.hits.get());
        assert_eq!(1, m.invalidated_entries_by_transient_error.get());

        // Do not change balance or time.

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's a miss again, despite there were no changes.
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(0, m.hits.get());
        assert_eq!(2, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_1, res_2);
    });
}

#[test]
fn query_cache_returns_different_results_on_canister_stop() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(0, m.hits.get());
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Stop the canister.
        test.stop_canister(b_id);
        test.process_stopping_canisters();

        // Run the same query for the second time.
        // The query returns a user error, while the composite query returns result with a reject.
        let _res_2 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(0, m.hits.get());
        assert_eq!(2, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
    });
}

#[test]
fn query_cache_returns_different_results_on_canister_start() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Stop the canister initially.
        test.stop_canister(b_id);
        test.process_stopping_canisters();

        // Run the query for the first time.
        // The query returns a user error, while the composite query returns result with a reject.
        let _res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(0, m.hits.get());
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());

        // Start the canister.
        test.start_canister(b_id)
            .expect("The canister should successfully start.");

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss again.
        let m = query_cache_metrics(&test);
        assert_eq!(0, m.hits.get());
        assert_eq!(2, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_2, Ok(WasmResult::Reply(vec![42])));
    });
}

#[test]
fn query_cache_returns_different_results_on_canister_stop_start() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Stop/start the canister.
        test.stop_canister(b_id);
        test.process_stopping_canisters();
        test.start_canister(b_id)
            .expect("The canister should successfully start.");

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss again.
        let m = query_cache_metrics(&test);
        assert_eq!(2, m.misses.get());
        assert_eq!(1, m.invalidated_entries_by_canister_version.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_1, res_2);
    });
}

#[test]
fn query_cache_returns_different_results_on_canister_create() {
    let mut test = builder_with_query_caching().build();
    let expected_id = CanisterId::from_u64(0);
    let q = wasm().reply_data(&[42]).build();

    // There is no canister initially.

    // Run the query for the first time.
    test.non_replicated_query(expected_id, "query", q.clone())
        .expect_err("The query should fail as the canister is not created yet.");
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_transient_error.get());

    // Create a canister with expected ID.
    let a_id = test.universal_canister().unwrap();
    assert_eq!(expected_id, a_id);

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss now.
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_transient_error.get());
    assert_eq!(res_2, Ok(WasmResult::Reply(vec![42])));
}

#[test]
fn composite_query_cache_returns_different_results_on_canister_create() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let expected_b_id = CanisterId::from_u64(1);
    let b = wasm().reply_data(&[42]).build();
    let a = wasm()
        // By default the on reply and on reject handlers propagate the other side response.
        .composite_query(expected_b_id, call_args().other_side(b))
        .build();

    // There is no canister B initially.

    // Run the query for the first time.
    // The query returns a user error, while the composite query returns result with a reject.
    let _res_1 = test.non_replicated_query(a_id, "composite_query", a.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_transient_error.get());

    // Create a canister with expected ID.
    let b_id = test.universal_canister().unwrap();
    assert_eq!(expected_b_id, b_id);

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "composite_query", a.clone());
    // Assert it's a miss now.
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_transient_error.get());
    assert_eq!(res_2, Ok(WasmResult::Reply(vec![42])));
}

#[test]
fn query_cache_returns_different_results_on_canister_delete() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Delete the canister.
        test.stop_canister(b_id);
        test.process_stopping_canisters();
        test.delete_canister(b_id)
            .expect("The deletion should succeed");

        // Run the same query for the second time.
        // The query returns a user error, while the composite query returns result with a reject.
        let _res_2 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(0, m.hits.get());
        assert_eq!(2, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
    });
}

#[test]
fn query_cache_returns_different_results_on_canister_going_below_freezing_threshold() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Run the query for the first time.
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(0, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        // Increase the freezing threshold.
        // The update setting message, so it invalidates the cache entry.
        test.update_freezing_threshold(b_id, u64::MAX.into())
            .expect("The settings update must succeed.");

        // Run the same query for the second time.
        // The query returns a user error, while the composite query returns result with a reject.
        let _res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's a miss with an error.
        let m = query_cache_metrics(&test);
        assert_eq!(0, m.hits.get());
        assert_eq!(2, m.misses.get());
        assert_eq!(1, m.invalidated_entries_by_transient_error.get());
    });
}

#[test]
fn query_cache_returns_different_results_on_canister_going_above_freezing_threshold() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        // Increase the freezing threshold initially.
        test.update_freezing_threshold(b_id, u64::MAX.into())
            .expect("The settings update must succeed.");

        // Run the query for the first time.
        // The query returns a user error, while the composite query returns result with a reject.
        let _res_1 = test.non_replicated_query(a_id, method, q.clone());
        // Assert it's a miss with an error.
        let m = query_cache_metrics(&test);
        assert_eq!(1, m.misses.get());
        assert_eq!(1, m.invalidated_entries_by_transient_error.get());

        // Remove the freezing threshold.
        // The update setting message, so it invalidates the cache entry.
        test.update_freezing_threshold(b_id, 0.into())
            .expect("The settings update must succeed.");

        // Run the same query for the second time.
        let res_2 = test.non_replicated_query(a_id, method, q);
        // Assert it's just a miss, no new errors.
        let m = query_cache_metrics(&test);
        assert_eq!(0, m.hits.get());
        assert_eq!(2, m.misses.get());
        assert_eq!(1, m.invalidated_entries_by_transient_error.get());
        assert_eq!(res_2, Ok(WasmResult::Reply(vec![42])));
    });
}

#[test]
fn query_cache_never_caches_calls_to_management_canister() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let a_id = test.universal_canister().unwrap();
    let q = wasm()
        .call_simple(CanisterId::ic_00(), "raw_rand", call_args())
        .build();

    let res_1 = test
        .non_replicated_query(a_id, "query", q.clone())
        .unwrap_err();
    assert_eq!(query_cache_metrics(&test).hits.get(), 0);
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    let description = format!(
        "Error from Canister {a_id}: Canister violated contract: \
        \"ic0_call_new\" cannot be executed in non replicated query mode"
    );
    res_1.assert_contains(ErrorCode::CanisterContractViolation, &description);

    let res_2 = test
        .non_replicated_query(a_id, "query", q.clone())
        .unwrap_err();
    assert_eq!(query_cache_metrics(&test).hits.get(), 1);
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, res_2);
}

#[test]
fn composite_query_cache_never_caches_calls_to_management_canister() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let a_id = test.universal_canister().unwrap();
    let q = wasm()
        .call_simple(
            CanisterId::ic_00(),
            "raw_rand",
            call_args().on_reject(wasm().reject_message().append_and_reply()),
        )
        .build();

    let res_1 = test.non_replicated_query(a_id, "composite_query", q.clone());
    assert_eq!(query_cache_metrics(&test).hits.get(), 0);
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    // There should be no route to the management canister.
    let message = format!("Canister {} not found", subnet_test_id(1));
    assert_eq!(Ok(WasmResult::Reply(message.as_bytes().to_owned())), res_1);

    let res_2 = test.non_replicated_query(a_id, "composite_query", q.clone());
    assert_eq!(query_cache_metrics(&test).hits.get(), 0);
    assert_eq!(query_cache_metrics(&test).misses.get(), 2);
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_supports_query_stats() {
    let q = wasm().reply_data(&[42]);
    for_query_and_composite_query(q, |mut test, a_id, b_id, method, q| {
        let res_1 = test.non_replicated_query(a_id, method, q.clone());
        assert_eq!(query_cache_metrics(&test).hits.get(), 0);
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

        let a_stats_1 = test.query_stats_for_testing(&a_id).unwrap();
        let b_stats_1 = test.query_stats_for_testing(&b_id).unwrap();
        assert_eq!(a_stats_1.num_calls, 1);
        assert_eq!(b_stats_1.num_calls, 1);
        assert!(a_stats_1.num_instructions > 0);
        assert!(b_stats_1.num_instructions > 0);
        assert!(a_stats_1.ingress_payload_size > 0);
        assert!(b_stats_1.ingress_payload_size > 0);

        // Do not change balance or time.

        let res_2 = test.non_replicated_query(a_id, method, q);
        assert_eq!(query_cache_metrics(&test).hits.get(), 1);
        assert_eq!(query_cache_metrics(&test).misses.get(), 1);
        assert_eq!(res_1, res_2);

        let a_stats_2 = test.query_stats_for_testing(&a_id).unwrap();
        let b_stats_2 = test.query_stats_for_testing(&b_id).unwrap();
        // As the second query is served form the cache, there should be
        // twice the amount of calls, instructions and payload now.
        assert_eq!(a_stats_2.num_calls, 2);
        assert_eq!(b_stats_2.num_calls, 2);
        assert_eq!(a_stats_1.num_instructions * 2, a_stats_2.num_instructions);
        assert_eq!(b_stats_1.num_instructions * 2, b_stats_2.num_instructions);
        assert_eq!(
            a_stats_1.ingress_payload_size * 2,
            a_stats_2.ingress_payload_size
        );
        assert_eq!(
            b_stats_1.ingress_payload_size * 2,
            b_stats_2.ingress_payload_size
        );
        assert_eq!(
            a_stats_1.egress_payload_size * 2,
            a_stats_2.egress_payload_size
        );
        assert_eq!(
            b_stats_1.egress_payload_size * 2,
            b_stats_2.egress_payload_size
        );
    });
}

#[test]
fn query_cache_future_proof_test() {
    match SystemApiCallId::AcceptMessage {
        SystemApiCallId::AcceptMessage
        | SystemApiCallId::CallCyclesAdd
        | SystemApiCallId::CallCyclesAdd128
        | SystemApiCallId::CallDataAppend
        | SystemApiCallId::CallNew
        | SystemApiCallId::CallOnCleanup
        | SystemApiCallId::CallPerform
        | SystemApiCallId::CallWithBestEffortResponse
        | SystemApiCallId::CanisterCycleBalance
        | SystemApiCallId::CanisterCycleBalance128
        | SystemApiCallId::CanisterLiquidCycleBalance128
        | SystemApiCallId::CanisterSelfCopy
        | SystemApiCallId::CanisterSelfSize
        | SystemApiCallId::CanisterStatus
        | SystemApiCallId::CanisterVersion
        | SystemApiCallId::RootKeySize
        | SystemApiCallId::RootKeyCopy
        | SystemApiCallId::CertifiedDataSet
        | SystemApiCallId::CostCall
        | SystemApiCallId::CostCreateCanister
        | SystemApiCallId::CostHttpRequest
        | SystemApiCallId::CostHttpRequestV2
        | SystemApiCallId::CostSignWithEcdsa
        | SystemApiCallId::CostSignWithSchnorr
        | SystemApiCallId::CostVetkdDeriveKey
        | SystemApiCallId::CyclesBurn128
        | SystemApiCallId::DataCertificateCopy
        | SystemApiCallId::DataCertificatePresent
        | SystemApiCallId::DataCertificateSize
        | SystemApiCallId::DebugPrint
        | SystemApiCallId::GlobalTimerSet
        | SystemApiCallId::InReplicatedExecution
        | SystemApiCallId::IsController
        | SystemApiCallId::MintCycles128
        | SystemApiCallId::MsgArgDataCopy
        | SystemApiCallId::MsgArgDataSize
        | SystemApiCallId::MsgCallerCopy
        | SystemApiCallId::MsgCallerSize
        | SystemApiCallId::MsgCyclesAccept
        | SystemApiCallId::MsgCyclesAccept128
        | SystemApiCallId::MsgCyclesAvailable
        | SystemApiCallId::MsgCyclesAvailable128
        | SystemApiCallId::MsgCyclesRefunded
        | SystemApiCallId::MsgCyclesRefunded128
        | SystemApiCallId::MsgDeadline
        | SystemApiCallId::MsgMethodNameCopy
        | SystemApiCallId::MsgMethodNameSize
        | SystemApiCallId::MsgReject
        | SystemApiCallId::MsgRejectCode
        | SystemApiCallId::MsgRejectMsgCopy
        | SystemApiCallId::MsgRejectMsgSize
        | SystemApiCallId::MsgReply
        | SystemApiCallId::MsgReplyDataAppend
        | SystemApiCallId::OutOfInstructions
        | SystemApiCallId::PerformanceCounter
        | SystemApiCallId::SubnetSelfSize
        | SystemApiCallId::SubnetSelfCopy
        | SystemApiCallId::Stable64Grow
        | SystemApiCallId::Stable64Read
        | SystemApiCallId::Stable64Size
        | SystemApiCallId::Stable64Write
        | SystemApiCallId::StableGrow
        | SystemApiCallId::StableRead
        | SystemApiCallId::StableSize
        | SystemApiCallId::StableWrite
        | SystemApiCallId::EnvVarCount
        | SystemApiCallId::EnvVarNameSize
        | SystemApiCallId::EnvVarNameCopy
        | SystemApiCallId::EnvVarNameExists
        | SystemApiCallId::EnvVarValueSize
        | SystemApiCallId::EnvVarValueCopy
        | SystemApiCallId::Time
        | SystemApiCallId::Trap
        | SystemApiCallId::TryGrowWasmMemory => {
            ////////////////////////////////////////////////////////////////////
            // ATTENTION!
            ////////////////////////////////////////////////////////////////////
            // By adding a new System API call here, please consider potential
            // direct or indirect effects on the Query Cache.
            //
            // Query Cache coherency relies on three assumptions:
            // * Changes in `batch_time` invalidate cache entries.
            //   `ic0.time()` is the only System API call providing
            //   different values for distinct `batch_time`s.
            // * Changes in `canister_balance` invalidate cache entries.
            //   `ic0.canister_cycle_balance[128]()` is the sole System API
            //   call dependent on canister balance.
            // * Changes in `canister_version` always invalidate cache entries.
            //   This includes update calls, configuration changes, upgrades...
            //
            // If you introduce a new System API call that depends on
            // time or balance or a new Canister property that should
            // invalidate cache entries, please check with the Runtime and/or
            // Execution teams.
            //
            // BREAKING QUERY CACHE COHERENCY CAN RESULT IN UNEXPECTED
            // OUTCOMES. PLEASE DOUBLE-CHECK YOUR DESIGN FOR POTENTIAL
            // QUERY CACHING SIDE EFFECTS.
            ////////////////////////////////////////////////////////////////////
        }
    }
}

#[test]
fn total_bytes_future_proof_guard() {
    const HEAP_BYTES: usize = 5;

    // Key with no heap data.
    let key = EntryKey {
        source: user_test_id(1),
        receiver: CanisterId::from_u64(1),
        method_name: String::new(),
        method_payload: vec![],
        certificate_delegation_format: None,
    };
    assert_eq!(size_of_val(&key), 112);
    assert_eq!(total_bytes(&key), size_of_val(&key));

    // Key with some heap data.
    let key = EntryKey {
        source: user_test_id(1),
        receiver: CanisterId::from_u64(1),
        method_name: " ".repeat(HEAP_BYTES),
        method_payload: vec![42; HEAP_BYTES],
        certificate_delegation_format: None,
    };
    assert_eq!(size_of_val(&key), 112);
    assert_eq!(total_bytes(&key), size_of_val(&key) + HEAP_BYTES * 2);

    // Value with no heap data.
    let env = EntryEnv {
        batch_time: time::GENESIS,
        canisters_versions_balances_stats: vec![],
    };
    let value = EntryValue::new(
        env,
        Result::Ok(WasmResult::Reply(vec![])),
        &SystemApiCallCounters::default(),
    );
    assert_eq!(size_of_val(&value), 80);
    assert_eq!(total_bytes(&value), size_of_val(&value));

    // Value with some heap data.
    let env = EntryEnv {
        batch_time: time::GENESIS,
        canisters_versions_balances_stats: vec![
            (
                CanisterId::from_u64(1),
                0,
                0_u64.into(),
                QueryStats::default(),
            );
            HEAP_BYTES
        ],
    };
    let env_vec_size = size_of_val(&*env.canisters_versions_balances_stats);
    let value = EntryValue::new(
        env,
        Result::Ok(WasmResult::Reply(vec![42; HEAP_BYTES])),
        &SystemApiCallCounters::default(),
    );
    assert_eq!(size_of_val(&value), 80);
    assert_eq!(
        total_bytes(&value),
        size_of_val(&value) + env_vec_size + HEAP_BYTES
    );
}
