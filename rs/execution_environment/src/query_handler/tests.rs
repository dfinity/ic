use crate::InternalHttpQueryHandler;
use ic_base_types::NumSeconds;
use ic_config::execution_environment::INSTRUCTION_OVERHEAD_PER_QUERY_CALL;
use ic_error_types::{ErrorCode, UserError};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_test_utilities::{
    types::ids::user_test_id,
    universal_canister::{call_args, wasm},
};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::{
    ingress::WasmResult,
    messages::{CanisterTask, UserQuery},
    time, CountBytes, Cycles, NumInstructions,
};
use std::{sync::Arc, time::Duration};

const CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

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

fn downcast_query_handler_mut(
    query_handler: &mut dyn std::any::Any,
) -> &mut InternalHttpQueryHandler {
    // SAFETY:
    //
    // Refer to the documentation in `downcast_query_handler`.
    unsafe { &mut *(query_handler as *mut dyn std::any::Any as *mut InternalHttpQueryHandler) }
}

#[test]
fn query_metrics_are_reported() {
    // In this test we have two canisters A and B.
    // Canister A handles the user query by calling canister B.

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::VerifiedApplication)
        .build();

    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canister_a,
            method_name: "query".to_string(),
            method_payload: wasm()
                .inter_query(
                    canister_b,
                    call_args().other_side(wasm().reply_data(b"pong".as_ref())),
                )
                .build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(output, Ok(WasmResult::Reply(b"pong".to_vec())));

    let query_handler = downcast_query_handler(test.query_handler());

    assert_eq!(
        1,
        query_handler.metrics.query.instructions.get_sample_count()
    );
    assert!(0 < query_handler.metrics.query.instructions.get_sample_sum() as u64);
    assert_eq!(1, query_handler.metrics.query.messages.get_sample_count());
    // We expect four messages:
    // - canister_a.query() as pure
    // - canister_a.query() as stateful
    // - canister_b.query() as stateful
    // - canister_a.on_reply()
    assert_eq!(
        4,
        query_handler.metrics.query.messages.get_sample_sum() as u64
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_initial_call
            .duration
            .get_sample_count()
    );
    assert!(
        0 < query_handler
            .metrics
            .query_initial_call
            .instructions
            .get_sample_sum() as u64
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_initial_call
            .instructions
            .get_sample_count()
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_initial_call
            .messages
            .get_sample_count()
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_initial_call
            .messages
            .get_sample_sum() as u64
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_retry_call
            .duration
            .get_sample_count()
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_spawned_calls
            .duration
            .get_sample_count()
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_spawned_calls
            .instructions
            .get_sample_count()
    );
    assert!(
        0 < query_handler
            .metrics
            .query_spawned_calls
            .instructions
            .get_sample_sum() as u64
    );
    assert_eq!(
        1,
        query_handler
            .metrics
            .query_spawned_calls
            .messages
            .get_sample_count()
    );
    assert_eq!(
        2,
        query_handler
            .metrics
            .query_spawned_calls
            .messages
            .get_sample_sum() as u64
    );
    assert_eq!(
        query_handler.metrics.query.instructions.get_sample_sum() as u64,
        query_handler
            .metrics
            .query_initial_call
            .instructions
            .get_sample_sum() as u64
            + query_handler
                .metrics
                .query_retry_call
                .instructions
                .get_sample_sum() as u64
            + query_handler
                .metrics
                .query_spawned_calls
                .instructions
                .get_sample_sum() as u64
    )
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
    test.state_mut().metadata.batch_time += Duration::from_secs(1);
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
        assert_eq!(1, metrics.invalidated_entries_by_time.get());
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
            method_payload: wasm().reply_data(&[42]).build(),
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
        assert_eq!(output_1, output_2);
        assert_eq!(1, metrics.invalidated_entries_by_time.get());
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
        .remove_cycles(1_u128.into(), CyclesUseCase::Memory);
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
    test.state_mut().metadata.batch_time += Duration::from_secs(1);
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
        assert_eq!(1, metrics.invalidated_entries_by_time.get());
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
fn query_call_with_side_effects() {
    // In this test we have two canisters A and B.
    // Canister A does a side-effectful operation (stable_grow) and then
    // calls canister B. The side effect must happen once and only once.

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canister_a,
            method_name: "query".to_string(),
            method_payload: wasm()
                .stable_grow(10)
                .inter_query(
                    canister_b,
                    call_args()
                        .other_side(wasm().reply_data(b"ignore".as_ref()))
                        .on_reply(wasm().stable_size().reply_int()),
                )
                .build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(output, Ok(WasmResult::Reply(10_i32.to_le_bytes().to_vec())));
}

#[test]
fn query_calls_disabled_for_application_subnet() {
    // In this test we have two canisters A and B.
    // Canister A attempts to call canister B but this should fail because
    // inter-canister query calls are disabled on application subnets.

    let mut test = ExecutionTestBuilder::new().build();

    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canister_a,
            method_name: "query".to_string(),
            method_payload: wasm()
                .stable_grow(10)
                .inter_query(
                    canister_b,
                    call_args()
                        .other_side(wasm().reply_data(b"ignore".as_ref()))
                        .on_reply(wasm().stable_size().reply_int()),
                )
                .build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    match output {
        Ok(_) => unreachable!("The query was expected to fail, but it succeeded."),
        Err(err) => assert_eq!(err.code(), ErrorCode::CanisterContractViolation),
    }
}

#[test]
fn query_callgraph_depth_is_enforced() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System) // For now, query calls are only allowed in system subnets
        .build();

    const NUM_CANISTERS: usize = 20;

    let mut canisters = vec![];
    for _ in 0..NUM_CANISTERS {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    fn generate_call_to(
        canisters: &[ic_types::CanisterId],
        canister_idx: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        assert!(canister_idx != 0 && canister_idx < canisters.len());
        wasm().stable_grow(10).inter_query(
            canisters[canister_idx],
            call_args()
                .other_side(generate_return(canisters, canister_idx - 1))
                .on_reply(wasm().stable_size().reply_int()),
        )
    }

    // Each canister should either just return or trigger another ICQC
    fn generate_return(
        canisters: &[ic_types::CanisterId],
        canister_idx: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        if canister_idx == 0 {
            wasm().reply_data(b"ignore".as_ref())
        } else {
            generate_call_to(canisters, canister_idx)
        }
    }

    fn test_query(
        test: &ExecutionTest,
        canisters: &[ic_types::CanisterId],
        num_calls: usize,
    ) -> Result<WasmResult, UserError> {
        test.query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "query".to_string(),
                method_payload: generate_call_to(canisters, num_calls).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
    }

    // Those should succeed
    for num_calls in 1..7 {
        match &test_query(&test, &canisters, num_calls) {
            Ok(_) => {}
            Err(err) => panic!(
                "Query with depth {} failed, when it should have succeeded: {:?}",
                num_calls, err
            ),
        }
    }

    // Those should fail
    for num_calls in 7..19 {
        match test_query(&test, &canisters, num_calls) {
            Ok(_) => panic!(
                "Call with depth {} should have failed with call graph being too large",
                num_calls
            ),
            Err(err) => {
                assert_eq!(err.code(), ErrorCode::QueryCallGraphTooDeep)
            }
        }
    }
}

#[test]
fn query_callgraph_max_instructions_is_enforced() {
    const NUM_CANISTERS: u64 = 20;
    const NUM_SUCCESSFUL_QUERIES: u64 = 5; // Number of calls expected to succeed

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System) // For now, query calls are only allowed in system subnets
        .with_max_query_call_graph_instructions(NumInstructions::from(
            NUM_SUCCESSFUL_QUERIES * INSTRUCTION_OVERHEAD_PER_QUERY_CALL,
        ))
        .build();

    let mut canisters = vec![];
    for _ in 0..NUM_CANISTERS {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    // Generate call tree of depth 1.
    // Canister 0 will call into each canister 1..num_canisters exactly once in a sequential manner.
    // This will therefore *not* hit the call graph depth limit, but should hit a limit
    // on the maximum number of instructions in a call graph.
    fn generate_call_to(
        canisters: &[ic_types::CanisterId],
        canister_idx: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        assert!(canister_idx < canisters.len());

        let reply = if canister_idx <= 1 {
            wasm().stable_size().reply_int()
        } else {
            generate_call_to(canisters, canister_idx - 1)
        };

        wasm().stable_grow(10).inter_query(
            canisters[canister_idx],
            call_args()
                .other_side(wasm().reply_data(b"ignore".as_ref()))
                .on_reply(reply),
        )
    }

    // Those should succeed
    for num_calls in 1..NUM_SUCCESSFUL_QUERIES {
        let test = test.query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "query".to_string(),
                method_payload: generate_call_to(&canisters, num_calls as usize).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );
        match &test {
            Ok(_) => {}
            Err(err) => panic!(
                "Query with {} calls failed, when it should have succeeded: {:?}",
                num_calls, err
            ),
        }
    }
    for num_calls in NUM_SUCCESSFUL_QUERIES..NUM_CANISTERS {
        let test = test.query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "query".to_string(),
                method_payload: generate_call_to(&canisters, num_calls as usize).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );
        match &test {
            Ok(_) => panic!("Query with {} calls should have failed!", num_calls),
            Err(err) => assert_eq!(
                err.code(),
                ErrorCode::QueryCallGraphTotalInstructionLimitExceeded
            ),
        }
    }
}

#[test]
fn composite_query_callgraph_depth_is_enforced() {
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    const NUM_CANISTERS: usize = 20;

    let mut canisters = vec![];
    for _ in 0..NUM_CANISTERS {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    fn generate_composite_call_to(
        canisters: &[ic_types::CanisterId],
        canister_idx: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        assert!(canister_idx != 0 && canister_idx < canisters.len());
        wasm().stable_grow(10).composite_query(
            canisters[canister_idx],
            call_args()
                .other_side(generate_return(canisters, canister_idx - 1))
                .on_reply(wasm().stable_size().reply_int()),
        )
    }

    // Each canister should either just return or trigger another composite query
    fn generate_return(
        canisters: &[ic_types::CanisterId],
        canister_idx: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        if canister_idx == 0 {
            wasm().reply_data(b"ignore".as_ref())
        } else {
            generate_composite_call_to(canisters, canister_idx)
        }
    }

    fn test_query(
        test: &ExecutionTest,
        canisters: &[ic_types::CanisterId],
        num_calls: usize,
    ) -> Result<WasmResult, UserError> {
        test.query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: generate_composite_call_to(canisters, num_calls).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
    }

    // Those should succeed
    for num_calls in 1..7 {
        match &test_query(&test, &canisters, num_calls) {
            Ok(_) => {}
            Err(err) => panic!(
                "Query with depth {} failed, when it should have succeeded: {:?}",
                num_calls, err
            ),
        }
    }

    // Those should fail
    for num_calls in 7..NUM_CANISTERS - 1 {
        match test_query(&test, &canisters, num_calls) {
            Ok(_) => panic!(
                "Call with depth {} should have failed with call graph being too large",
                num_calls
            ),
            Err(err) => {
                assert_eq!(err.code(), ErrorCode::QueryCallGraphTooDeep)
            }
        }
    }
}

#[test]
fn composite_query_recursive_calls() {
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    const NUM_CALLS: usize = 3;
    let canister = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    fn generate_composite_call_to(
        canister: ic_types::CanisterId,
        num_calls_left: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        wasm().stable_grow(10).composite_query(
            canister,
            call_args()
                .other_side(generate_return(canister, num_calls_left - 1))
                .on_reply(wasm().stable_size().reply_int()),
        )
    }

    // Either just return or trigger another composite query
    fn generate_return(
        canister: ic_types::CanisterId,
        num_calls_left: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        if num_calls_left == 0 {
            wasm().reply_data(b"ignore".as_ref())
        } else {
            generate_composite_call_to(canister, num_calls_left)
        }
    }

    test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canister,
            method_name: "composite_query".to_string(),
            method_payload: generate_composite_call_to(canister, NUM_CALLS).build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    )
    .unwrap();
}

#[test]
fn composite_query_callgraph_max_instructions_is_enforced() {
    const NUM_CANISTERS: u64 = 20;
    const NUM_SUCCESSFUL_QUERIES: u64 = 5; // Number of calls expected to succeed

    let mut test = ExecutionTestBuilder::new()
        .with_composite_queries() // For now, query calls are only allowed in system subnets
        .with_max_query_call_graph_instructions(NumInstructions::from(
            NUM_SUCCESSFUL_QUERIES * INSTRUCTION_OVERHEAD_PER_QUERY_CALL,
        ))
        .build();

    let mut canisters = vec![];
    for _ in 0..NUM_CANISTERS {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    // Generate call tree of depth 1.
    // Canister 0 will call into each canister 1..num_canisters exactly once in a sequential manner.
    // This will therefore *not* hit the call graph depth limit, but should hit a limit
    // on the maximum number of instructions in a call graph.
    fn generate_call_to(
        canisters: &[ic_types::CanisterId],
        canister_idx: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        assert!(canister_idx < canisters.len());

        let reply = if canister_idx <= 1 {
            wasm().stable_size().reply_int()
        } else {
            generate_call_to(canisters, canister_idx - 1)
        };

        wasm().stable_grow(10).composite_query(
            canisters[canister_idx],
            call_args()
                .other_side(wasm().reply_data(b"ignore".as_ref()))
                .on_reply(reply),
        )
    }

    // Those should succeed
    for num_calls in 1..NUM_SUCCESSFUL_QUERIES {
        let test = test.query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: generate_call_to(&canisters, num_calls as usize).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );
        match &test {
            Ok(_) => {}
            Err(err) => panic!(
                "Query with {} calls failed, when it should have succeeded: {:?}",
                num_calls, err
            ),
        }
    }
    for num_calls in NUM_SUCCESSFUL_QUERIES..NUM_CANISTERS {
        let test = test.query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: generate_call_to(&canisters, num_calls as usize).build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        );
        match &test {
            Ok(_) => panic!("Query with {} calls should have failed!", num_calls),
            Err(err) => assert_eq!(
                err.code(),
                ErrorCode::QueryCallGraphTotalInstructionLimitExceeded
            ),
        }
    }
}

#[test]
fn query_compiled_once() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    let canister_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    {
        let query_handler = downcast_query_handler(test.query_handler());
        // The canister was compiled during installation.
        assert_eq!(1, query_handler.hypervisor.compile_count());
    }

    let canister = test.state_mut().canister_state_mut(&canister_id).unwrap();
    // Drop the embedder cache and compilation cache to force
    // compilation during query handling.
    canister
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_binary
        .clear_compilation_cache();

    let query_handler_mut = downcast_query_handler_mut(test.query_handler_mut());
    query_handler_mut
        .hypervisor
        .clear_compilation_cache_for_testing();

    let result = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canister_id,
            method_name: "query".to_string(),
            method_payload: wasm().reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert!(result.is_ok());

    let query_handler = downcast_query_handler(test.query_handler());

    // Now we expect the compilation counter to increase because the query
    // had to compile.
    assert_eq!(2, query_handler.hypervisor.compile_count());

    let result = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canister_id,
            method_name: "query".to_string(),
            method_payload: wasm().reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert!(result.is_ok());

    // The last query should have reused the compiled code.
    assert_eq!(2, query_handler.hypervisor.compile_count());
}

#[test]
fn queries_to_frozen_canisters_are_rejected() {
    let mut test = ExecutionTestBuilder::new().build();
    let freezing_threshold = NumSeconds::from(3_000_000_000);

    // Create two canisters A and B with different amount of cycles.
    // Canister A will not have enough to process queries in contrast
    // to Canister B which will have more than enough.
    //
    // The amount of cycles is calculated based on previous runs of
    // the test. It needs to be _just_ enough to allow for the canister
    // to be installed (the canister is created with the provisional
    // create canister api that doesn't require additional cycles).
    //
    // 80_000_000 cycles are needed as prepayment for max install_code instructions
    //    590_000 cycles are needed for update call execution
    //     41_070 cycles are needed to cover freeze_threshold_cycles
    //                   of the canister history memory usage (134 bytes)
    let low_cycles = Cycles::new(80_000_631_070);
    let canister_a = test.universal_canister_with_cycles(low_cycles).unwrap();
    test.update_freezing_threshold(canister_a, freezing_threshold)
        .unwrap();

    let high_cycles = Cycles::new(1_000_000_000_000);
    let canister_b = test.universal_canister_with_cycles(high_cycles).unwrap();
    test.update_freezing_threshold(canister_b, freezing_threshold)
        .unwrap();

    // Canister A is below its freezing threshold, so queries will be rejected.
    let result = test.query(
        UserQuery {
            source: user_test_id(0),
            receiver: canister_a,
            method_name: "query".to_string(),
            method_payload: wasm().reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterOutOfCycles,
            format!(
                "Canister {} is unable to process query calls because it's frozen. Please top up the canister with cycles and try again.",
                canister_a
            )
        )),
    );

    // Canister B has a high cycles balance that's above its freezing
    // threshold and so it can still process queries.
    let result = test.query(
        UserQuery {
            source: user_test_id(1),
            receiver: canister_b,
            method_name: "query".to_string(),
            method_payload: wasm().reply().build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );
    assert!(result.is_ok());
}

const COMPOSITE_QUERY_WAT: &str = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32))
            )
            (func (export "canister_composite_query query")
                (call $msg_reply_data_append (i32.const 0) (i32.const 5))
                (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "hello")
        )"#;

#[test]
fn composite_query_works_in_non_replicated_mode() {
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    let canister = test.canister_from_wat(COMPOSITE_QUERY_WAT).unwrap();

    let result = test
        .query(
            UserQuery {
                source: user_test_id(0),
                receiver: canister,
                method_name: "query".to_string(),
                method_payload: vec![],
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap();

    assert_eq!(result, WasmResult::Reply("hello".as_bytes().to_vec()));
}

#[test]
fn composite_query_fails_if_disabled() {
    let mut test = ExecutionTestBuilder::new().build();

    let canister = test.canister_from_wat(COMPOSITE_QUERY_WAT).unwrap();

    let result = test
        .query(
            UserQuery {
                source: user_test_id(0),
                receiver: canister,
                method_name: "query".to_string(),
                method_payload: vec![],
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap_err();

    assert_eq!(result.code(), ErrorCode::CanisterContractViolation);
    assert_eq!(
        result.description(),
        "Composite queries are not enabled yet"
    );
}

#[test]
fn composite_query_fails_in_replicated_mode() {
    let mut test = ExecutionTestBuilder::new().build();

    let canister = test.canister_from_wat(COMPOSITE_QUERY_WAT).unwrap();

    let balance_before = test.canister_state(canister).system_state.balance();
    let err = test.ingress(canister, "query", vec![]).unwrap_err();
    let balance_after = test.canister_state(canister).system_state.balance();
    assert_eq!(err.code(), ErrorCode::CompositeQueryCalledInReplicatedMode);
    assert_eq!(
        err.description(),
        "Composite query cannot be called in replicated mode"
    );
    // Verify that we consume some cycles.
    assert!(balance_before > balance_after);
}

#[test]
fn composite_query_single_user_response() {
    // In this test canister 0 calls canisters 1, 2, 3 and produces a reply
    // only when handling the response from canister 2.
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    let mut canisters = vec![];
    for _ in 0..4 {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    let reply = |i| wasm().reply_data(&[i]).build();
    let empty = || wasm().build();

    let canister_0 = wasm()
        .composite_query(
            canisters[1],
            call_args().other_side(reply(1)).on_reply(empty()),
        )
        .composite_query(canisters[2], call_args().other_side(reply(2)))
        .composite_query(
            canisters[3],
            call_args().other_side(reply(3)).on_reply(empty()),
        );

    let result = test
        .query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply([2_u8].to_vec()));
}

#[test]
fn composite_query_single_canister_response() {
    // In this test canister 0 calls canister 1 which in turn calls canisters
    // 2, 3, 4 and produces a reply only when handling the response from
    // canister 2. That reply should propagate to the user.
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    let mut canisters = vec![];
    for _ in 0..5 {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    let reply = |i| wasm().reply_data(&[i]).build();
    let empty = || wasm().build();

    let canister_1 = wasm()
        .composite_query(
            canisters[2],
            call_args().other_side(reply(2)).on_reply(empty()),
        )
        .composite_query(canisters[3], call_args().other_side(reply(3)))
        .composite_query(
            canisters[4],
            call_args().other_side(reply(4)).on_reply(empty()),
        );

    let canister_0 = wasm().composite_query(canisters[1], call_args().other_side(canister_1));

    let result = test
        .query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply([3_u8].to_vec()));
}

#[test]
fn composite_query_no_user_response() {
    // In this test canister 0 calls canisters 1, 2, 3 and does not reply.
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    let mut canisters = vec![];
    for _ in 0..4 {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    let reply = |i| wasm().reply_data(&[i]).build();
    let empty = || wasm().build();

    let canister_0 = wasm()
        .composite_query(
            canisters[1],
            call_args().other_side(reply(1)).on_reply(empty()),
        )
        .composite_query(
            canisters[2],
            call_args().other_side(reply(2)).on_reply(empty()),
        )
        .composite_query(
            canisters[3],
            call_args().other_side(reply(3)).on_reply(empty()),
        );

    let err = test
        .query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap_err();
    assert_eq!(
        err.description(),
        format!("Canister {} did not produce a response", canisters[0])
    );
}

#[test]
fn composite_query_no_canister_response() {
    // In this test canister 0 calls canister 1 which in turn calls canisters
    // 2, 3, 4 and does not reply.
    let mut test = ExecutionTestBuilder::new()
        .with_composite_queries() // For now, query calls are only allowed in system subnets
        .build();

    let mut canisters = vec![];
    for _ in 0..5 {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    let reply = |i| wasm().reply_data(&[i]).build();
    let empty = || wasm().build();

    let canister_1 = wasm()
        .composite_query(
            canisters[2],
            call_args().other_side(reply(2)).on_reply(empty()),
        )
        .composite_query(
            canisters[3],
            call_args().other_side(reply(3)).on_reply(empty()),
        )
        .composite_query(
            canisters[4],
            call_args().other_side(reply(4)).on_reply(empty()),
        );

    let canister_0 = wasm().composite_query(
        canisters[1],
        call_args()
            .other_side(canister_1)
            .on_reject(wasm().reject_message().reject()),
    );

    let result = test
        .query(
            UserQuery {
                source: user_test_id(2),
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap();
    match result {
        WasmResult::Reply(_) => unreachable!("Expected reject"),
        WasmResult::Reject(msg) => assert_eq!(
            msg,
            format!("Canister {} did not produce a response", canisters[1])
        ),
    }
}

#[test]
fn composite_query_chained_calls() {
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let b = wasm().message_payload().append_and_reply().build();

    let a = wasm().composite_query(
        canister_b,
        call_args()
            .other_side(b.clone())
            .on_reply(wasm().composite_query(canister_b, call_args().other_side(b.clone()))),
    );

    let result = test
        .query(
            UserQuery {
                source: user_test_id(2),
                receiver: canister_a,
                method_name: "composite_query".to_string(),
                method_payload: a.build(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(test.state().clone()),
            vec![],
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(b));
}

#[test]
fn composite_query_syscalls_from_reply_reject_callback() {
    // In this test canister 0 calls canisters 1 and attempts syscalls from reply callback.
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    // Install two universal canisters
    let mut canisters = vec![];
    for _ in 0..2 {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    let reply = wasm().reply_data(&[1]).build();
    let reject = wasm().reject().build();

    let syscalls = vec![
        (wasm().msg_cycles_available().build(), "cycles_available"),
        (wasm().msg_cycles_refunded().build(), "cycles_refunded"),
        (wasm().msg_cycles_accept(42).build(), "cycles_accept"),
        (wasm().api_global_timer_set(0).build(), "global_timer_set"),
        (wasm().call_cycles_add(0).build(), "call_cycles_add"),
        (
            wasm().call_cycles_add128(0, 0).build(),
            "call_cycles_add128",
        ),
        (
            wasm().msg_cycles_available128().build(),
            "cycles_available128",
        ),
        (
            wasm().msg_cycles_refunded128().build(),
            "cycles_refunded128",
        ),
        (
            wasm().msg_cycles_accept128(4, 2).build(),
            "cycles_accept128",
        ),
        (
            wasm().certified_data_set(&[42]).build(),
            "certified_data_set",
        ),
    ];

    for (other_side, callback_type) in vec![(reply, "reply"), (reject, "reject")] {
        for (syscall, label) in &syscalls {
            let canister_0 = wasm().composite_query(
                canisters[1],
                call_args()
                    .other_side(other_side.clone())
                    .on_reply(syscall.clone())
                    .on_reject(syscall.clone()),
            );

            let output = test.query(
                UserQuery {
                    source: user_test_id(2),
                    receiver: canisters[0],
                    method_name: "composite_query".to_string(),
                    method_payload: canister_0.build(),
                    ingress_expiry: 0,
                    nonce: None,
                },
                Arc::new(test.state().clone()),
                vec![],
            );
            match output {
                Ok(_) => {
                    unreachable!(
                        "{} call should not be allowed from a composite query {} callback",
                        label, callback_type
                    )
                }
                Err(err) => assert_eq!(
                    err.code(),
                    ErrorCode::CanisterContractViolation,
                    "Incorrect return code for {} {}",
                    label,
                    callback_type
                ),
            }
        }
    }
}

#[test]
fn composite_query_state_preserved_across_sequential_calls() {
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    const NUM_CANISTERS: usize = 5;

    let mut canisters = vec![];
    for _ in 0..NUM_CANISTERS {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    // Create a chain of composite query calls
    fn generate_continuation(
        canisters: &[ic_types::CanisterId],
        canister_id: usize,
    ) -> ic_universal_canister::PayloadBuilder {
        if canister_id >= NUM_CANISTERS {
            // Reply to caller with the counter
            wasm().get_global_counter().reply_int64()
        } else {
            // Execute further composite query calls
            wasm().inc_global_counter().composite_query(
                canisters[canister_id],
                call_args()
                    .other_side(wasm().reply_data(b"ignore".as_ref()))
                    .on_reply(generate_continuation(canisters, canister_id + 1)),
            )
        }
    }

    let payload = wasm().inc_global_counter().composite_query(
        canisters[1],
        call_args()
            .other_side(wasm().reply_data(b"ignore".as_ref()))
            .on_reply(generate_continuation(&canisters, 2)),
    );

    let output = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canisters[0],
            method_name: "composite_query".to_string(),
            method_payload: payload.build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );

    // We use the global counter to count the number of composite queries we are executing (increment before each call).
    // Since we have NUM_CANISTER caniters in total, we expect to have one less calls (from the first canister to all others).
    assert_eq!(
        output,
        Ok(WasmResult::Reply(vec![
            (NUM_CANISTERS - 1).try_into().unwrap(),
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]))
    );
}

#[test]
fn composite_query_state_preserved_across_parallel_calls() {
    let mut test = ExecutionTestBuilder::new().with_composite_queries().build();

    const NUM_CANISTERS: usize = 5;

    let mut canisters = vec![];
    for _ in 0..NUM_CANISTERS {
        canisters.push(test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap());
    }

    let mut payload = wasm();

    // Call each canister once. In each reply callback, increment the counter.
    for canister in canisters.iter().take(NUM_CANISTERS - 1).skip(1) {
        payload = payload.composite_query(
            canister,
            call_args()
                .other_side(wasm().reply_data(b"ignore".as_ref()))
                .on_reply(wasm().inc_global_counter()),
        );
    }

    // From the "last" callback, return the counter value.
    // Note that this works because we actually don't run calls in parallel.
    // The implementation always sequentially executes all calls.
    payload = payload.composite_query(
        canisters[NUM_CANISTERS - 1],
        call_args()
            .other_side(wasm().reply_data(b"ignore".as_ref()))
            .on_reply(
                wasm()
                    .inc_global_counter()
                    .get_global_counter()
                    .reply_int64(),
            ),
    );

    let output = test.query(
        UserQuery {
            source: user_test_id(2),
            receiver: canisters[0],
            method_name: "composite_query".to_string(),
            method_payload: payload.build(),
            ingress_expiry: 0,
            nonce: None,
        },
        Arc::new(test.state().clone()),
        vec![],
    );

    // We use the global counter to count the number of composite queries we are executing (increment before each call).
    // Since we have NUM_CANISTER caniters in total, we expect to have one less calls (from the first canister to all others).
    assert_eq!(
        output,
        Ok(WasmResult::Reply(vec![
            (NUM_CANISTERS - 1).try_into().unwrap(),
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]))
    );
}
