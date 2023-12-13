use super::{EntryEnv, EntryValue};
use crate::{
    metrics::{
        SYSTEM_API_CALL_PERFORM, SYSTEM_API_CANISTER_CYCLE_BALANCE,
        SYSTEM_API_CANISTER_CYCLE_BALANCE128, SYSTEM_API_TIME,
    },
    query_handler::query_cache::EntryKey,
    InternalHttpQueryHandler,
};
use ic_interfaces::execution_environment::SystemApiCallCounters;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_test_utilities::{types::ids::user_test_id, universal_canister::wasm};
use ic_test_utilities_execution_environment::ExecutionTestBuilder;
use ic_types::{
    ingress::WasmResult,
    messages::{CanisterTask, UserQuery},
    time, CountBytes, Cycles,
};
use ic_types_test_utils::ids::canister_test_id;
use ic_universal_canister::call_args;
use std::{sync::Arc, time::Duration};

const CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);
const MAX_EXPIRY_TIME: Duration = Duration::from_secs(10);
const MORE_THAN_MAX_EXPIRY_TIME: Duration = Duration::from_secs(11);

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

#[test]
fn query_cache_entry_value_elapsed_seconds() {
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
    let backward_time = current_time.saturating_sub_duration(Duration::from_secs(2));
    assert_eq!(0.0, entry_value.elapsed_seconds(backward_time));
}

#[test]
fn query_cache_metrics_work() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let query_handler = downcast_query_handler(test.query_handler());
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().caller().append_and_reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.hits.get(), 0);
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().caller().append_and_reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.hits.get(), 1);
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_metrics_evicted_entries_count_bytes_work() {
    const ITERATIONS: usize = 5;
    const REPLY_SIZE: usize = 10_000;
    const QUERY_CACHE_SIZE: usize = 1;
    // Plus some room for the keys, headers etc.
    const QUERY_CACHE_CAPACITY: usize = REPLY_SIZE * QUERY_CACHE_SIZE + REPLY_SIZE;

    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_query_cache_capacity(QUERY_CACHE_CAPACITY as u64)
        .build();

    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    for i in 0..ITERATIONS {
        let output = test.query(
            UserQuery {
                // Every query is unique and should produce a new cache entry.
                source: user_test_id(i as u64),
                receiver: canister_id,
                method_name: "query".into(),
                // The bytes are stored twice: as a payload in key and as a reply in value.
                method_payload: wasm().reply_data(&[1; REPLY_SIZE / 2]).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );
        assert_eq!(output, Ok(WasmResult::Reply([1; REPLY_SIZE / 2].into())));
        // One unique query per 2 seconds.
        test.state_mut().metadata.batch_time += Duration::from_secs(2);
    }

    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(0, metrics.hits.get());
    assert_eq!(ITERATIONS, metrics.misses.get() as usize);
    assert_eq!(
        ITERATIONS - QUERY_CACHE_SIZE,
        metrics.evicted_entries.get() as usize
    );
    // Times 2 seconds per each query.
    assert_eq!(
        (ITERATIONS - QUERY_CACHE_SIZE) * 2,
        metrics.evicted_entries_duration.get_sample_sum() as usize
    );
    assert_eq!(
        ITERATIONS - QUERY_CACHE_SIZE,
        metrics.evicted_entries_duration.get_sample_count() as usize
    );
    assert_eq!(0, metrics.invalidated_entries.get(),);

    let count_bytes = metrics.count_bytes.get() as usize;
    // We can't match the size exactly, as it includes the key and the captured environment.
    // But we can assert that the sum of the sizes should be:
    // REPLY_SIZE < count_bytes < REPLY_SIZE * 2
    assert!(REPLY_SIZE < count_bytes);
    assert!(REPLY_SIZE * 2 > count_bytes);
}

#[test]
fn query_cache_metrics_count_bytes_work() {
    const BIG_RESULT_SIZE: usize = 1_000_000;

    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let _canister_id = test.universal_canister().unwrap();

    let query_cache = &downcast_query_handler(test.query_handler()).query_cache;
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    let key = EntryKey {
        source: user_test_id(1),
        receiver: canister_test_id(1),
        method_name: "method".into(),
        method_payload: vec![],
    };

    // Assert initial cache state.
    assert_eq!(0, metrics.hits.get());
    assert_eq!(0, metrics.misses.get());
    let initial_count_bytes = metrics.count_bytes.get();
    assert!((initial_count_bytes as usize) < BIG_RESULT_SIZE);

    // Push a big result into the cache.
    let env = EntryEnv {
        batch_time: time::GENESIS,
        canister_version: 1,
        canister_balance: Cycles::from(1_u64),
    };
    let big_result = Ok(WasmResult::Reply(vec![0; BIG_RESULT_SIZE]));
    let system_api_call_counters = SystemApiCallCounters::default();
    query_cache.push(key.clone(), env, &big_result, &system_api_call_counters);
    assert_eq!(0, metrics.hits.get());
    assert_eq!(1, metrics.misses.get());
    let count_bytes = metrics.count_bytes.get();
    assert!((count_bytes as usize) > BIG_RESULT_SIZE);

    // Invalidate and pop the result.
    let new_env = EntryEnv {
        batch_time: time::GENESIS,
        canister_version: 2,
        canister_balance: Cycles::from(1_u64),
    };
    query_cache.get_valid_result(&key, &new_env);
    assert_eq!(0, metrics.hits.get());
    assert_eq!(1, metrics.misses.get());
    let final_count_bytes = metrics.count_bytes.get();
    assert!((final_count_bytes as usize) < BIG_RESULT_SIZE);
}

#[test]
fn query_cache_metrics_evicted_entries_negative_duration_works() {
    const REPLY_SIZE: usize = 10_000;
    const QUERY_CACHE_SIZE: usize = 1;
    // Plus some room for the keys, headers etc.
    const QUERY_CACHE_CAPACITY: usize = REPLY_SIZE * QUERY_CACHE_SIZE + REPLY_SIZE;

    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_query_cache_capacity(QUERY_CACHE_CAPACITY as u64)
        .build();

    // As there are no updates, the default system time is unix epoch, so we explicitly set it here.
    test.state_mut().metadata.batch_time = time::GENESIS;

    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    // Run the first query.
    let output = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            // The bytes are stored twice: as a payload in key and as a reply in value.
            method_payload: wasm().reply_data(&[1; REPLY_SIZE / 2]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(output, Ok(WasmResult::Reply([1; REPLY_SIZE / 2].into())));

    // Move the time backward.
    test.state_mut().metadata.batch_time = test
        .state_mut()
        .metadata
        .batch_time
        .saturating_sub_duration(Duration::from_secs(2));

    // The second query should evict the first one, as there is no room in the cache for two queries.
    let output = test.query(
        UserQuery {
            // The query should be different, so we evict, not invalidate.
            source: user_test_id(2),
            receiver: canister_id,
            method_name: "query".into(),
            // The bytes are stored twice: as a payload in key and as a reply in value.
            method_payload: wasm().reply_data(&[2; REPLY_SIZE / 2]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(output, Ok(WasmResult::Reply([2; REPLY_SIZE / 2].into())));

    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    // Negative durations should give just 0.
    assert_eq!(
        0,
        metrics.evicted_entries_duration.get_sample_sum() as usize
    );
    // One entry should be evicted.
    assert_eq!(
        1,
        metrics.evicted_entries_duration.get_sample_count() as usize
    );
}

#[test]
fn query_cache_metrics_invalidated_entries_work() {
    const ITERATIONS: usize = 5;

    let mut test = ExecutionTestBuilder::new().with_query_caching().build();

    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    for _ in 0..ITERATIONS {
        // Every query is the same and should hit the same cache entry.
        let output = test.query(
            UserQuery {
                source: user_test_id(1),
                receiver: canister_id,
                method_name: "query".into(),
                method_payload: wasm().reply_data(&[42]).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );
        assert_eq!(output, Ok(WasmResult::Reply([42].into())));
        // Executing a default UC heartbeat should render the cache entry invalid.
        test.canister_task(canister_id, CanisterTask::Heartbeat);
    }

    let query_handler = downcast_query_handler(test.query_handler());
    assert_eq!(0, query_handler.query_cache.metrics.hits.get());
    assert_eq!(
        ITERATIONS,
        query_handler.query_cache.metrics.misses.get() as usize
    );
    assert_eq!(
        0,
        query_handler.query_cache.metrics.evicted_entries.get() as usize
    );
    // Minus one for the first iteration when the entry was just added into the cache.
    assert_eq!(
        ITERATIONS - 1,
        query_handler.query_cache.metrics.invalidated_entries.get() as usize,
    );
}

#[test]
fn query_cache_key_different_source_returns_different_results() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let query_handler = downcast_query_handler(test.query_handler());
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().caller().append_and_reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
    assert_eq!(
        output_1,
        Ok(WasmResult::Reply(user_test_id(1).get().into()))
    );
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().caller().append_and_reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 2);
    assert_eq!(
        output_2,
        Ok(WasmResult::Reply(user_test_id(2).get().into()))
    );
}

#[test]
fn query_cache_key_different_receiver_returns_different_results() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id_1 = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_id_2 = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let query_handler = downcast_query_handler(test.query_handler());
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id_1,
            method_name: "query".into(),
            method_payload: wasm().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
    assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id_2,
            method_name: "query".into(),
            method_payload: wasm().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 2);
    assert_eq!(output_1, output_2);
}

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

#[test]
fn query_cache_key_different_method_name_returns_different_results() {
    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_initial_canister_cycles(CYCLES_BALANCE.get())
        .build();
    let canister_id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();
    let query_handler = downcast_query_handler(test.query_handler());
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "f1".into(),
            method_payload: vec![],
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
    assert_eq!(output_1, Ok(WasmResult::Reply(b"42".to_vec())));
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "f2".into(),
            method_payload: vec![],
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 2);
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_key_different_method_payload_returns_different_results() {
    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_initial_canister_cycles(CYCLES_BALANCE.get())
        .build();
    let canister_id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();
    let query_handler = downcast_query_handler(test.query_handler());
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "f1".into(),
            method_payload: vec![],
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
    assert_eq!(output_1, Ok(WasmResult::Reply(b"42".to_vec())));
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "f1".into(),
            method_payload: vec![42],
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(query_handler.query_cache.metrics.misses.get(), 2);
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_env_different_batch_time_returns_different_results() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            // The query must get the time, otherwise the entry won't be invalidated.
            method_payload: wasm().time().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let query_handler = downcast_query_handler(test.query_handler());
        assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
        assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));
    }
    test.state_mut().metadata.batch_time += Duration::from_secs(1);
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().time().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let metrics = &downcast_query_handler(test.query_handler())
            .query_cache
            .metrics;
        assert_eq!(2, metrics.misses.get());
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries.get());
        assert_eq!(1, metrics.invalidated_entries_by_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_canister_version.get());
        assert_eq!(0, metrics.invalidated_entries_by_canister_balance.get());
        assert_eq!(
            1,
            metrics.invalidated_entries_duration.get_sample_sum() as usize
        );
        assert_eq!(
            1,
            metrics.invalidated_entries_duration.get_sample_count() as usize
        );
    }
}

#[test]
fn query_cache_different_batch_times_return_the_same_result() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister().unwrap();

    // The query does not depend on time.
    let query = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let output_1 = test.non_replicated_query(canister_id, "query", query.clone());
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));

    // Change the canister balance and time.
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(1_u128.into(), CyclesUseCase::Memory);
    test.state_mut().metadata.batch_time += Duration::from_secs(1);

    // Run the same query for the second time.
    let output_2 = test.non_replicated_query(canister_id, "query", query);
    // Assert it's a hit despite the changed balance and time.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(1, metrics.hits.get());
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_different_batch_times_return_different_results_after_expiry_time() {
    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_query_cache_max_expiry_time(MAX_EXPIRY_TIME)
        .build();
    let canister_id = test.universal_canister().unwrap();

    // The query does not depend on time.
    let query = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let output_1 = test.non_replicated_query(canister_id, "query", query.clone());
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;

    // Run the same query for the second time.
    let output_2 = test.non_replicated_query(canister_id, "query", query);
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(2, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_env_expired_entries_returns_different_results() {
    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_query_cache_max_expiry_time(MAX_EXPIRY_TIME)
        .build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let query_handler = downcast_query_handler(test.query_handler());
        assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
        assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));
    }

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;

    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let metrics = &downcast_query_handler(test.query_handler())
            .query_cache
            .metrics;
        assert_eq!(2, metrics.misses.get());
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries.get());
        assert_eq!(0, metrics.invalidated_entries_by_time.get());
        assert_eq!(1, metrics.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_canister_version.get());
        assert_eq!(0, metrics.invalidated_entries_by_canister_balance.get());
        assert_eq!(
            MORE_THAN_MAX_EXPIRY_TIME.as_secs(),
            metrics.invalidated_entries_duration.get_sample_sum() as u64
        );
        assert_eq!(
            1,
            metrics.invalidated_entries_duration.get_sample_count() as usize
        );
    }
}

#[test]
fn query_cache_env_invalidated_entries_negative_duration_works() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();

    // As there are no updates, the default system time is unix epoch, so we explicitly set it here.
    test.state_mut().metadata.batch_time = time::GENESIS;

    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            // The query must get the time, otherwise the entry won't be invalidated.
            method_payload: wasm().time().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    // Move the time backward.
    test.state_mut().metadata.batch_time = test
        .state_mut()
        .metadata
        .batch_time
        .saturating_sub_duration(Duration::from_secs(1));
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().time().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let metrics = &downcast_query_handler(test.query_handler())
            .query_cache
            .metrics;
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries_by_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_max_expiry_time.get());
        // Negative durations should give just 0.
        assert_eq!(
            0,
            metrics.invalidated_entries_duration.get_sample_sum() as usize
        );
        assert_eq!(
            1,
            metrics.invalidated_entries_duration.get_sample_count() as usize
        );
    }
}

#[test]
fn query_cache_env_different_canister_version_returns_different_results() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let query_handler = downcast_query_handler(test.query_handler());
        assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
        assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));
    }
    test.canister_state_mut(canister_id)
        .system_state
        .canister_version += 1;
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let metrics = &downcast_query_handler(test.query_handler())
            .query_cache
            .metrics;
        assert_eq!(2, metrics.misses.get());
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries.get());
        assert_eq!(0, metrics.invalidated_entries_by_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(1, metrics.invalidated_entries_by_canister_version.get());
        assert_eq!(0, metrics.invalidated_entries_by_canister_balance.get());
        assert_eq!(
            0,
            metrics.invalidated_entries_duration.get_sample_sum() as usize
        );
        assert_eq!(
            1,
            metrics.invalidated_entries_duration.get_sample_count() as usize
        );
    }
}

#[test]
fn query_cache_env_different_canister_balance_returns_different_results() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            // The query must get the balance, otherwise the entry won't be invalidated.
            method_payload: wasm().cycles_balance().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let query_handler = downcast_query_handler(test.query_handler());
        assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
        assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));
    }
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(1_u128.into(), CyclesUseCase::Memory);
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().cycles_balance().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let metrics = &downcast_query_handler(test.query_handler())
            .query_cache
            .metrics;
        assert_eq!(2, metrics.misses.get());
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries.get());
        assert_eq!(0, metrics.invalidated_entries_by_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_canister_version.get());
        assert_eq!(1, metrics.invalidated_entries_by_canister_balance.get());
        assert_eq!(
            0,
            metrics.invalidated_entries_duration.get_sample_sum() as usize
        );
        assert_eq!(
            1,
            metrics.invalidated_entries_duration.get_sample_count() as usize
        );
    }
}

#[test]
fn query_cache_different_canister_balances_return_the_same_result() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister().unwrap();

    // The query does not depend on canister balance.
    let query = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let output_1 = test.non_replicated_query(canister_id, "query", query.clone());
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));

    // Change the canister balance and time.
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(1_u128.into(), CyclesUseCase::Memory);
    test.state_mut().metadata.batch_time += Duration::from_secs(1);

    // Run the same query for the second time.
    let output_2 = test.non_replicated_query(canister_id, "query", query.clone());
    // Assert it's a hit despite the changed balance and time.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(1, metrics.hits.get());
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_env_different_canister_balance128_returns_different_results() {
    let mut test = ExecutionTestBuilder::new().with_query_caching().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            // The query must get the balance, otherwise the entry won't be invalidated.
            method_payload: wasm().cycles_balance128().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let query_handler = downcast_query_handler(test.query_handler());
        assert_eq!(query_handler.query_cache.metrics.misses.get(), 1);
        assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));
    }
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(1_u128.into(), CyclesUseCase::Memory);
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().cycles_balance128().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let metrics = &downcast_query_handler(test.query_handler())
            .query_cache
            .metrics;
        assert_eq!(2, metrics.misses.get());
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries.get());
        assert_eq!(0, metrics.invalidated_entries_by_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(0, metrics.invalidated_entries_by_canister_version.get());
        assert_eq!(1, metrics.invalidated_entries_by_canister_balance.get());
        assert_eq!(
            0,
            metrics.invalidated_entries_duration.get_sample_sum() as usize
        );
        assert_eq!(
            1,
            metrics.invalidated_entries_duration.get_sample_count() as usize
        );
    }
}

#[test]
fn query_cache_env_combined_invalidation() {
    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_query_cache_max_expiry_time(MAX_EXPIRY_TIME)
        .build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let output_1 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            // The query must get the time and balance, otherwise the entry won't be invalidated.
            method_payload: wasm().time().cycles_balance().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;
    test.canister_state_mut(canister_id)
        .system_state
        .canister_version += 1;
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(1_u128.into(), CyclesUseCase::Memory);
    let output_2 = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_id,
            method_name: "query".into(),
            method_payload: wasm().time().cycles_balance().reply_data(&[42]).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    {
        let metrics = &downcast_query_handler(test.query_handler())
            .query_cache
            .metrics;
        assert_eq!(2, metrics.misses.get());
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries.get());
        assert_eq!(1, metrics.invalidated_entries_by_time.get());
        assert_eq!(1, metrics.invalidated_entries_by_max_expiry_time.get());
        assert_eq!(1, metrics.invalidated_entries_by_canister_version.get());
        assert_eq!(1, metrics.invalidated_entries_by_canister_balance.get());
    }
}

#[test]
fn query_cache_env_old_invalid_entry_frees_memory() {
    static BIG_RESPONSE_SIZE: usize = 1_000_000;
    static SMALL_RESPONSE_SIZE: usize = 42;

    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
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
    let canister_id = test.canister_from_wat(QUERY_CACHE_WAT).unwrap();

    let count_bytes = downcast_query_handler(test.query_handler())
        .query_cache
        .count_bytes();
    // Initially the cache should be empty, i.e. less than 1MB.
    assert!(count_bytes < BIG_RESPONSE_SIZE);

    // The 1MB result will be cached internally.
    let output = test
        .query(
            UserQuery {
                source: user_test_id(1),
                receiver: canister_id,
                method_name: "canister_balance_sized_reply".into(),
                method_payload: vec![],
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap();
    assert_eq!(BIG_RESPONSE_SIZE, output.count_bytes());
    let count_bytes = downcast_query_handler(test.query_handler())
        .query_cache
        .count_bytes();
    // After the first reply, the cache should have more than 1MB of data.
    assert!(count_bytes > BIG_RESPONSE_SIZE);

    // Set the canister balance to 42B, so the second reply will heave just 42 bytes.
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(
            ((BIG_RESPONSE_SIZE - SMALL_RESPONSE_SIZE) as u128).into(),
            CyclesUseCase::Memory,
        );

    // The new 42B reply must invalidate and replace the previous 1MB reply in the cache.
    let output = test
        .query(
            UserQuery {
                source: user_test_id(1),
                receiver: canister_id,
                method_name: "canister_balance_sized_reply".into(),
                method_payload: vec![],
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap();
    assert_eq!(SMALL_RESPONSE_SIZE, output.count_bytes());
    let count_bytes = downcast_query_handler(test.query_handler())
        .query_cache
        .count_bytes();
    // The second 42B reply should invalidate and replace the first 1MB reply in the cache.
    assert!(count_bytes > SMALL_RESPONSE_SIZE);
    assert!(count_bytes < BIG_RESPONSE_SIZE);
}

#[test]
fn query_cache_capacity_is_respected() {
    const REPLY_SIZE: usize = 10_000;
    const QUERY_CACHE_CAPACITY: usize = REPLY_SIZE * 3;

    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_query_cache_capacity(QUERY_CACHE_CAPACITY as u64)
        .build();

    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    // Initially the cache should be empty, i.e. less than REPLY_SIZE.
    let count_bytes = downcast_query_handler(test.query_handler())
        .query_cache
        .count_bytes();
    assert!(count_bytes < REPLY_SIZE);

    // All replies should hit the same cache entry.
    for _ in 0..5 {
        let _res = test.query(
            UserQuery {
                source: user_test_id(1),
                receiver: canister_id,
                method_name: "query".into(),
                // The bytes are stored twice: as payload and then as reply.
                method_payload: wasm().reply_data(&[1; REPLY_SIZE / 2]).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );

        // Now there should be only one reply in the cache.
        let count_bytes = downcast_query_handler(test.query_handler())
            .query_cache
            .count_bytes();
        assert!(count_bytes > REPLY_SIZE);
        assert!(count_bytes < QUERY_CACHE_CAPACITY);
    }

    // Now the replies should hit another entry.
    for _ in 0..5 {
        let _res = test.query(
            UserQuery {
                source: user_test_id(2),
                receiver: canister_id,
                method_name: "query".into(),
                method_payload: wasm().reply_data(&[2; REPLY_SIZE / 2]).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );

        // Now there should be two replies in the cache.
        let count_bytes = downcast_query_handler(test.query_handler())
            .query_cache
            .count_bytes();
        assert!(count_bytes > REPLY_SIZE * 2);
        assert!(count_bytes < QUERY_CACHE_CAPACITY);
    }

    // Now the replies should evict the first entry.
    for _ in 0..5 {
        let _res = test.query(
            UserQuery {
                source: user_test_id(3),
                receiver: canister_id,
                method_name: "query".into(),
                method_payload: wasm().reply_data(&[3; REPLY_SIZE / 2]).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );

        // There should be still just two replies in the cache.
        let count_bytes = downcast_query_handler(test.query_handler())
            .query_cache
            .count_bytes();
        assert!(count_bytes > REPLY_SIZE * 2);
        assert!(count_bytes < QUERY_CACHE_CAPACITY);
    }
}

#[test]
fn query_cache_capacity_zero() {
    let mut test = ExecutionTestBuilder::new()
        .with_query_caching()
        .with_query_cache_capacity(0)
        .build();

    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    // Even with zero capacity the cache data structure uses some bytes for the pointers etc.
    let initial_count_bytes = downcast_query_handler(test.query_handler())
        .query_cache
        .count_bytes();

    // Replies should not change the initial (zero) capacity.
    for _ in 0..5 {
        let _res = test.query(
            UserQuery {
                source: user_test_id(1),
                receiver: canister_id,
                method_name: "query".into(),
                method_payload: wasm().reply_data(&[1]).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );

        let count_bytes = downcast_query_handler(test.query_handler())
            .query_cache
            .count_bytes();
        assert_eq!(initial_count_bytes, count_bytes);
    }
}

#[test]
fn query_cache_system_api_calls_correctly_reported_on_composite_query() {
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        // Fist group of System API calls.
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
        .cycles_balance()
        .cycles_balance128()
        .time()
        .build();
    test.non_replicated_query(a_id, "composite_query", a)
        .unwrap();

    let metrics = &downcast_query_handler(test.query_handler()).metrics;

    // Two nested calls.
    assert_eq!(
        2,
        metrics
            .query_system_api_calls
            .with_label_values(&[SYSTEM_API_CALL_PERFORM])
            .get()
    );
    // Four `ic0.canister_cycle_balance()` calls.
    assert_eq!(
        4,
        metrics
            .query_system_api_calls
            .with_label_values(&[SYSTEM_API_CANISTER_CYCLE_BALANCE])
            .get()
    );
    // Five `ic0.canister_cycle_balance128()` calls.
    assert_eq!(
        5,
        metrics
            .query_system_api_calls
            .with_label_values(&[SYSTEM_API_CANISTER_CYCLE_BALANCE128])
            .get()
    );
    // Six `ic0.time()` calls.
    assert_eq!(
        6,
        metrics
            .query_system_api_calls
            .with_label_values(&[SYSTEM_API_TIME])
            .get()
    );
}

#[test]
fn query_cache_composite_queries_return_the_same_result() {
    let mut test = ExecutionTestBuilder::new()
        .with_composite_queries()
        .with_query_caching()
        .build();
    let a_id = test.universal_canister().unwrap();

    // The query has no time or balance dependencies.
    let query = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let output_1 = test.non_replicated_query(a_id, "composite_query", query.clone());
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));

    // Change the canister balance and time.
    test.canister_state_mut(a_id)
        .system_state
        .remove_cycles(1_u128.into(), CyclesUseCase::Memory);
    test.state_mut().metadata.batch_time += Duration::from_secs(1);

    // Run the same query for the second time.
    let output_2 = test.non_replicated_query(a_id, "composite_query", query);
    // Assert it's a hit despite the changed balance and time.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(1, metrics.hits.get());
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_composite_queries_return_different_results_after_expiry_time() {
    let mut test = ExecutionTestBuilder::new()
        .with_composite_queries()
        .with_query_caching()
        .with_query_cache_max_expiry_time(MAX_EXPIRY_TIME)
        .build();
    let a_id = test.universal_canister().unwrap();

    // The query has no time or balance dependencies.
    let query = wasm().reply_data(&[42]).build();

    // Run the query for the first time.
    let output_1 = test.non_replicated_query(a_id, "composite_query", query.clone());
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));

    // Change the batch time more than the max expiry time.
    test.state_mut().metadata.batch_time += MORE_THAN_MAX_EXPIRY_TIME;

    // Run the same query for the second time.
    let output_2 = test.non_replicated_query(a_id, "composite_query", query);
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(2, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, output_2);
}

#[test]
fn query_cache_nested_queries_never_get_cached() {
    let mut test = ExecutionTestBuilder::new()
        .with_composite_queries()
        .with_query_caching()
        .build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    // The query has no time or balance dependencies...
    let query = wasm()
        // ...but there is a nested query.
        .composite_query(b_id, call_args())
        .reply_data(&[42])
        .build();

    // Run the query for the first time.
    let output_1 = test.non_replicated_query(a_id, "composite_query", query.clone());
    // Assert it's a miss.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(1, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, Ok(WasmResult::Reply([42].into())));

    // Do not change balance or time.

    // Run the same query for the second time.
    let output_2 = test.non_replicated_query(a_id, "composite_query", query);
    // Assert it's a miss again, despite there were no changes.
    let metrics = &downcast_query_handler(test.query_handler())
        .query_cache
        .metrics;
    assert_eq!(2, metrics.misses.get());
    assert_eq!(0, metrics.hits.get());
    assert_eq!(output_1, output_2);
}
