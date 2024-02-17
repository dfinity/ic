use super::{EntryEnv, EntryValue, QueryCache, QueryCacheMetrics};
use crate::{metrics, query_handler::query_cache::EntryKey, InternalHttpQueryHandler};
use ic_base_types::CanisterId;
use ic_interfaces::execution_environment::{SystemApiCallCounters, SystemApiCallId};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_test_utilities::{types::ids::user_test_id, universal_canister::wasm};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::{
    ingress::WasmResult,
    messages::{CanisterTask, UserQuery},
    time, CountBytes, Cycles,
};
use ic_types_test_utils::ids::canister_test_id;
use ic_universal_canister::call_args;
use std::{sync::Arc, time::Duration};

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

/// Return `ExecutionTestBuilder` with query caching and composite queries enabled.
fn builder_with_query_caching() -> ExecutionTestBuilder {
    ExecutionTestBuilder::new()
        .with_query_caching()
        .with_composite_queries()
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

#[test]
fn query_cache_entry_value_elapsed_seconds_work() {
    let current_time = time::GENESIS;
    let entry_env = EntryEnv {
        batch_time: current_time,
        canister_version: 1,
        canister_balance: Cycles::new(0),
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
fn query_cache_metrics_hits_and_misses_work() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    let q = wasm().caller().append_and_reply().build();

    let res_1 = test.non_replicated_query(id, "query", q.clone()).unwrap();
    assert_eq!(query_cache_metrics(&test).hits.get(), 0);
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);

    let res_2 = test.non_replicated_query(id, "query", q).unwrap();
    assert_eq!(query_cache_metrics(&test).hits.get(), 1);
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_metrics_evicted_entries_and_count_bytes_work() {
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

    let count_bytes = m.count_bytes.get() as usize;
    // We can't match the size exactly, as it includes the key and the captured environment.
    // But we can assert that the sum of the sizes should be:
    // REPLY_SIZE < count_bytes < REPLY_SIZE * 2
    assert!(REPLY_SIZE < count_bytes);
    assert!(REPLY_SIZE * 2 * QUERY_CACHE_SIZE > count_bytes);
}

#[test]
fn query_cache_metrics_count_bytes_work_on_invalidation() {
    let mut test = builder_with_query_caching().build();
    let _id = test.universal_canister().unwrap();
    let query_cache = &query_handler(&test).query_cache;
    let m = query_cache_metrics(&test);
    let key = EntryKey {
        source: user_test_id(1),
        receiver: canister_test_id(1),
        method_name: "method".into(),
        method_payload: vec![],
    };

    // Assert initial cache state.
    assert_eq!(0, m.hits.get());
    assert_eq!(0, m.misses.get());
    let initial_count_bytes = m.count_bytes.get();
    assert!((initial_count_bytes as usize) < BIG_REPLY_SIZE);

    // Push a big result into the cache.
    let env = EntryEnv {
        batch_time: time::GENESIS,
        canister_version: 1,
        canister_balance: Cycles::from(1_u64),
    };
    let big_result = Ok(WasmResult::Reply(vec![0; BIG_REPLY_SIZE]));
    let system_api_call_counters = SystemApiCallCounters::default();
    query_cache.push(key.clone(), env, &big_result, &system_api_call_counters);
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    let count_bytes = m.count_bytes.get();
    assert!(((count_bytes - initial_count_bytes) as usize) > BIG_REPLY_SIZE);

    // Invalidate and pop the result.
    let new_env = EntryEnv {
        batch_time: time::GENESIS,
        canister_version: 2,
        canister_balance: Cycles::from(1_u64),
    };
    query_cache.get_valid_result(&key, &new_env);
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    let final_count_bytes = m.count_bytes.get();
    assert!((final_count_bytes as usize) < BIG_REPLY_SIZE);
}

#[test]
fn query_cache_metrics_evicted_entries_work_with_negative_durations() {
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
fn query_cache_metrics_invalidated_entries_work() {
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
fn query_cache_different_sources_return_different_results() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    let q = wasm().caller().append_and_reply().build();

    let res_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: id,
            method_name: "query".into(),
            method_payload: q.clone(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(user_test_id(1).get().into())));

    let res_2 = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: id,
            method_name: "query".into(),
            method_payload: q,
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_cache_metrics(&test).misses.get(), 2);
    assert_eq!(res_2, Ok(WasmResult::Reply(user_test_id(2).get().into())));
}

#[test]
fn query_cache_different_receivers_return_different_results() {
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
fn query_cache_different_method_names_return_different_results() {
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
fn query_cache_different_method_payloads_return_different_results() {
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
fn query_cache_different_batch_times_return_different_results() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    // The query must get the time, otherwise the entry won't be invalidated.
    let q = wasm().time().reply_data(&[42]).build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    test.state_mut().metadata.batch_time += Duration::from_secs(1);

    let res_2 = test.non_replicated_query(id, "query", q);
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
}

#[test]
fn query_cache_different_batch_times_return_the_same_idempotent_result() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    // The query does not depend on time.
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(id, "query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the time.
    test.state_mut().metadata.batch_time += Duration::from_secs(1);

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(id, "query", q);
    // Assert it's a hit despite the changed balance and time.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(1, m.hits.get());
    assert_eq!(1, m.hits_with_ignored_time.get());
    assert_eq!(0, m.hits_with_ignored_canister_balance.get());
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_different_batch_times_return_different_idempotent_results_after_expiry_time() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let id = test.universal_canister().unwrap();
    // The query does not depend on time.
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(id, "query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(id, "query", q);
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_always_returns_different_idempotent_results_after_expiry_time() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let id = test.universal_canister().unwrap();
    let q = wasm().reply_data(&[42]).build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;

    let res_2 = test.non_replicated_query(id, "query", q);
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(res_1, res_2);
    assert_eq!(1, m.invalidated_entries.get());
    assert_eq!(0, m.invalidated_entries_by_time.get());
    assert_eq!(1, m.invalidated_entries_by_max_expiry_time.get());
    assert_eq!(
        0,
        m.invalidated_entries_by_data_certificate_expiry_time.get()
    );
    assert_eq!(0, m.invalidated_entries_by_canister_version.get());
    assert_eq!(0, m.invalidated_entries_by_canister_balance.get());
    assert_eq!(
        MORE_THAN_MAX_EXPIRY_TIME.as_secs(),
        m.invalidated_entries_duration.get_sample_sum() as u64
    );
    assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
}

#[test]
fn query_cache_always_returns_different_results_after_data_certificate_expiry_time() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let id = test.universal_canister().unwrap();
    let q = wasm().data_certificate().reply().build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![])));

    // Change the batch time more than the max expiry time.
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
fn query_cache_invalidated_entries_work_with_negative_durations() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    // The query must get the time, otherwise the entry won't be invalidated.
    let q = wasm().time().reply_data(&[42]).build();

    // As there are no updates, the default system time is unix epoch, so we explicitly set it here.
    test.state_mut().metadata.batch_time = time::GENESIS;

    let res_1 = test.non_replicated_query(id, "query", q.clone());

    // Move the time backward.
    test.state_mut().metadata.batch_time = time::UNIX_EPOCH;

    let res_2 = test.non_replicated_query(id, "query", q);
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
}

#[test]
fn query_cache_different_canister_versions_return_different_results() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    let q = wasm().reply_data(&[42]).build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Bump up the version
    test.canister_state_mut(id).system_state.canister_version += 1;

    let res_2 = test.non_replicated_query(id, "query", q);
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
}

#[test]
fn query_cache_different_canister_balances_return_different_results() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    // The query must get the balance, otherwise the entry won't be invalidated.
    let q = wasm().cycles_balance().reply_data(&[42]).build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the canister balance.
    test.canister_state_mut(id)
        .system_state
        .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

    let res_2 = test.non_replicated_query(id, "query", q);
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(res_1, res_2);
    assert_eq!(1, m.invalidated_entries.get());
    assert_eq!(0, m.invalidated_entries_by_time.get());
    assert_eq!(0, m.invalidated_entries_by_canister_version.get());
    assert_eq!(1, m.invalidated_entries_by_canister_balance.get());
    assert_eq!(0, m.invalidated_entries_duration.get_sample_sum() as usize);
    assert_eq!(1, m.invalidated_entries_duration.get_sample_count());
}

#[test]
fn query_cache_different_canister_balances_return_the_same_idempotent_result() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    // The query does not depend on canister balance.
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(id, "query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the canister balance.
    test.canister_state_mut(id)
        .system_state
        .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(id, "query", q);
    // Assert it's a hit despite the changed balance and time.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(1, m.hits.get());
    assert_eq!(0, m.hits_with_ignored_time.get());
    assert_eq!(1, m.hits_with_ignored_canister_balance.get());
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_different_canister_balance128s_return_different_results() {
    let mut test = builder_with_query_caching().build();
    let id = test.universal_canister().unwrap();
    // The query must get the balance, otherwise the entry won't be invalidated.
    let q = wasm().cycles_balance128().reply_data(&[42]).build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());
    assert_eq!(query_cache_metrics(&test).misses.get(), 1);
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the canister balance.
    test.canister_state_mut(id)
        .system_state
        .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

    let res_2 = test.non_replicated_query(id, "query", q);
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
}

#[test]
fn query_cache_combined_invalidation_works() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let id = test.universal_canister().unwrap();
    // The query must get the time and balance, otherwise the entry won't be invalidated.
    let q = wasm()
        .time()
        .cycles_balance()
        .data_certificate()
        .reply()
        .build();

    let res_1 = test.non_replicated_query(id, "query", q.clone());

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;
    test.canister_state_mut(id).system_state.canister_version += 1;
    test.canister_state_mut(id)
        .system_state
        .remove_cycles(1_u64.into(), CyclesUseCase::Memory);

    let res_2 = test.non_replicated_query(id, "query", q);
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(res_1, res_2);
    assert_eq!(1, m.invalidated_entries.get());
    assert_eq!(1, m.invalidated_entries_by_time.get());
    assert_eq!(1, m.invalidated_entries_by_max_expiry_time.get());
    assert_eq!(
        1,
        m.invalidated_entries_by_data_certificate_expiry_time.get()
    );
    assert_eq!(1, m.invalidated_entries_by_canister_version.get());
    assert_eq!(1, m.invalidated_entries_by_canister_balance.get());
}

#[test]
fn query_cache_invalidated_entries_free_memory() {
    static BIG_RESPONSE_SIZE: usize = 1_000_000;
    static SMALL_RESPONSE_SIZE: usize = 42;

    let mut test = builder_with_query_caching()
        // Use system subnet so all the executions are free.
        .with_subnet_type(SubnetType::System)
        // To replace the cache entry in the cache, the query requests must be identical,
        // i.e. source, receiver, method name and payload must all be the same. Hence,
        // we cant use them to construct a different reply.
        // For the test purpose, the cycles balance is used to construct different replies,
        // keeping all other parameters the same.
        // The first reply will be 1MB.
        .with_initial_canister_cycles(BIG_RESPONSE_SIZE.try_into().unwrap())
        .build();
    let id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();

    let count_bytes = query_cache(&test).count_bytes();
    // Initially the cache should be empty, i.e. less than 1MB.
    assert!(count_bytes < BIG_RESPONSE_SIZE);

    // The 1MB result will be cached internally.
    let res = test
        .non_replicated_query(id, "canister_balance_sized_reply", vec![])
        .unwrap();
    assert_eq!(BIG_RESPONSE_SIZE, res.count_bytes());
    let count_bytes = query_cache(&test).count_bytes();
    // After the first reply, the cache should have more than 1MB of data.
    assert!(count_bytes > BIG_RESPONSE_SIZE);

    // Set the canister balance to 42B, so the second reply will have just 42 bytes.
    test.canister_state_mut(id).system_state.remove_cycles(
        ((BIG_RESPONSE_SIZE - SMALL_RESPONSE_SIZE) as u64).into(),
        CyclesUseCase::Memory,
    );

    // The new 42B reply must invalidate and replace the previous 1MB reply in the cache.
    let res = test
        .non_replicated_query(id, "canister_balance_sized_reply", vec![])
        .unwrap();
    assert_eq!(SMALL_RESPONSE_SIZE, res.count_bytes());
    let count_bytes = query_cache(&test).count_bytes();
    // The second 42B reply should invalidate and replace the first 1MB reply in the cache.
    assert!(count_bytes > SMALL_RESPONSE_SIZE);
    assert!(count_bytes < BIG_RESPONSE_SIZE);
}

#[test]
fn query_cache_capacity_is_respected() {
    /// Includes some room for the keys, headers etc.
    const QUERY_CACHE_CAPACITY: usize = REPLY_SIZE * 3;
    let mut test = builder_with_query_cache_capacity(QUERY_CACHE_CAPACITY).build();
    let id = test.universal_canister().unwrap();

    // Initially the cache should be empty, i.e. less than REPLY_SIZE.
    let count_bytes = query_cache(&test).count_bytes();
    assert!(count_bytes < REPLY_SIZE);

    // All replies should hit the same cache entry.
    for _ in 0..ITERATIONS {
        // The bytes are stored twice: as payload and then as reply.
        let _res =
            test.non_replicated_query(id, "query", wasm().reply_data(&[1; REPLY_SIZE / 2]).build());
        // Now there should be only one reply in the cache.
        let count_bytes = query_cache(&test).count_bytes();
        assert!(count_bytes > REPLY_SIZE);
        assert!(count_bytes < QUERY_CACHE_CAPACITY);
    }

    // Now the replies should hit another entry.
    for _ in 0..ITERATIONS {
        let _res =
            test.non_replicated_query(id, "query", wasm().reply_data(&[2; REPLY_SIZE / 2]).build());
        // Now there should be two replies in the cache.
        let count_bytes = query_cache(&test).count_bytes();
        assert!(count_bytes > REPLY_SIZE * 2);
        assert!(count_bytes < QUERY_CACHE_CAPACITY);
    }

    // Now the replies should evict the first entry.
    for _ in 0..ITERATIONS {
        let _res =
            test.non_replicated_query(id, "query", wasm().reply_data(&[3; REPLY_SIZE / 2]).build());
        // There should be still just two replies in the cache.
        let count_bytes = query_cache(&test).count_bytes();
        assert!(count_bytes > REPLY_SIZE * 2);
        assert!(count_bytes < QUERY_CACHE_CAPACITY);
    }
}

#[test]
fn query_cache_with_zero_capacity_works() {
    let mut test = builder_with_query_cache_capacity(0).build();
    let id = test.universal_canister().unwrap();

    // Even with zero capacity the cache data structure uses some bytes for the pointers etc.
    let initial_count_bytes = query_cache(&test).count_bytes();

    // Replies should not change the initial (zero) capacity.
    for _ in 0..ITERATIONS {
        let _res = test.non_replicated_query(id, "query", wasm().reply_data(&[1]).build());
        let count_bytes = query_cache(&test).count_bytes();
        assert_eq!(initial_count_bytes, count_bytes);
    }
}

#[test]
fn query_cache_metrics_system_api_calls_work_on_composite_query() {
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
    // Two nested calls.
    assert_eq!(
        2,
        m.query_system_api_calls
            .with_label_values(&[metrics::SYSTEM_API_CALL_PERFORM])
            .get()
    );
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
fn query_cache_metrics_evaluated_canisters_work() {
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
fn query_cache_metrics_nested_execution_errors_work() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        .composite_query(
            b_id,
            call_args().other_side(wasm().trap()).on_reject(
                wasm().composite_query(
                    b_id,
                    call_args()
                        .other_side(wasm().trap())
                        .on_reject(wasm().reply_data(&[42])),
                ),
            ),
        )
        .build();
    test.non_replicated_query(a_id, "composite_query", a)
        .unwrap();

    let m = &query_handler(&test).metrics;

    // Two traps in the nested queries.
    assert_eq!(2, m.nested_execution_errors.get());
}

#[test]
fn query_cache_composite_queries_return_the_same_result() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    // The query has no time or balance dependencies.
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(a_id, "composite_query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the canister balance and time.
    test.canister_state_mut(a_id)
        .system_state
        .remove_cycles(1_u64.into(), CyclesUseCase::Memory);
    test.state_mut().metadata.batch_time += Duration::from_secs(1);

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "composite_query", q);
    // Assert it's a hit despite the changed balance and time.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(1, m.hits.get());
    assert_eq!(1, m.hits_with_ignored_time.get());
    assert_eq!(1, m.hits_with_ignored_canister_balance.get());
    assert_eq!(0, m.invalidated_entries_by_nested_call.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_composite_queries_return_different_results_after_expiry_time() {
    let mut test = builder_with_query_cache_expiry_times().build();
    let id = test.universal_canister().unwrap();
    // The query has no time or balance dependencies.
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(id, "composite_query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(id, "composite_query", q);
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(0, m.invalidated_entries_by_nested_call.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_nested_queries_never_get_cached() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();
    // The query has no time or balance dependencies...
    let q = wasm()
        // ...but there is a nested query.
        .composite_query(b_id, call_args().on_reply(wasm().reply_data(&[42])))
        .build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(a_id, "composite_query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Do not change balance or time.

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "composite_query", q);
    // Assert it's a miss again, despite there were no changes.
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(2, m.invalidated_entries_by_nested_call.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_transient_errors_never_get_cached() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    // The query explicitly traps.
    let q = wasm().trap().build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert!(res_1.is_err());

    // Do not change balance or time.

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "query", q);
    // Assert it's a miss again, despite there were no changes.
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(0, m.invalidated_entries_by_nested_call.get());
    assert_eq!(2, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, res_2);
}

#[test]
fn query_cache_returns_different_results_on_canister_stop() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Stop the canister.
    test.stop_canister(a_id);
    test.process_stopping_canisters();

    // Run the same query for the second time.
    test.non_replicated_query(a_id, "query", q.clone())
        .expect_err("The query should fail as the canister is stopped.");
    // Assert it's a fail (the query didn't run).
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
}

#[test]
fn query_cache_returns_different_results_on_canister_start() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let q = wasm().reply_data(&[42]).build();

    // Stop the canister initially.
    test.stop_canister(a_id);
    test.process_stopping_canisters();

    // Run the query for the first time.
    test.non_replicated_query(a_id, "query", q.clone())
        .expect_err("The query should fail as the canister is stopped.");
    // Assert it's a fail (the query didn't run).
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(0, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());

    // Start the canister.
    test.start_canister(a_id)
        .expect("The canister should successfully start.");

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss now.
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_2, Ok(WasmResult::Reply(vec![42])));
}

#[test]
fn query_cache_returns_different_results_on_canister_stop_start() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Stop/start the canister.
    test.stop_canister(a_id);
    test.process_stopping_canisters();
    test.start_canister(a_id)
        .expect("The canister should successfully start.");

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss again.
    let m = query_cache_metrics(&test);
    assert_eq!(2, m.misses.get());
    assert_eq!(1, m.invalidated_entries_by_canister_version.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, res_2);
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
    // Assert it's a fail (the query didn't run).
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.misses.get());
    assert_eq!(0, m.hits.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());

    // Create a canister with expected ID.
    let a_id = test.universal_canister().unwrap();
    assert_eq!(expected_id, a_id);

    // Run the same query for the second time.
    let res_2 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss now.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_2, Ok(WasmResult::Reply(vec![42])));
}

#[test]
fn query_cache_returns_different_results_on_canister_delete() {
    let mut test = builder_with_query_caching().build();
    let a_id = test.universal_canister().unwrap();
    let q = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let res_1 = test.non_replicated_query(a_id, "query", q.clone());
    // Assert it's a miss.
    let m = query_cache_metrics(&test);
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
    assert_eq!(res_1, Ok(WasmResult::Reply(vec![42])));

    // Delete the canister.
    test.stop_canister(a_id);
    test.process_stopping_canisters();
    test.delete_canister(a_id)
        .expect("The deletion should succeed");

    // Run the same query for the second time.
    test.non_replicated_query(a_id, "query", q.clone())
        .expect_err("The query should fail as there is no more canister.");

    // Assert it's a fail (the query didn't run).
    let m = query_cache_metrics(&test);
    assert_eq!(0, m.hits.get());
    assert_eq!(1, m.misses.get());
    assert_eq!(0, m.invalidated_entries_by_error.get());
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
        | SystemApiCallId::CanisterCycleBalance
        | SystemApiCallId::CanisterCycleBalance128
        | SystemApiCallId::CanisterSelfCopy
        | SystemApiCallId::CanisterSelfSize
        | SystemApiCallId::CanisterStatus
        | SystemApiCallId::CanisterVersion
        | SystemApiCallId::CertifiedDataSet
        | SystemApiCallId::CyclesBurn128
        | SystemApiCallId::DataCertificateCopy
        | SystemApiCallId::DataCertificatePresent
        | SystemApiCallId::DataCertificateSize
        | SystemApiCallId::DebugPrint
        | SystemApiCallId::GlobalTimerSet
        | SystemApiCallId::IsController
        | SystemApiCallId::MintCycles
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
        | SystemApiCallId::Stable64Grow
        | SystemApiCallId::Stable64Read
        | SystemApiCallId::Stable64Size
        | SystemApiCallId::Stable64Write
        | SystemApiCallId::StableGrow
        | SystemApiCallId::StableRead
        | SystemApiCallId::StableSize
        | SystemApiCallId::StableWrite
        | SystemApiCallId::Time
        | SystemApiCallId::Trap
        | SystemApiCallId::UpdateAvailableMemory => {
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
