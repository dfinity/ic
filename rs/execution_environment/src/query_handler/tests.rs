use crate::execution::test_utilities::{ExecutionTest, ExecutionTestBuilder};
use crate::InternalHttpQueryHandler;
use ic_base_types::NumSeconds;
use ic_config::execution_environment::INSTRUCTION_OVERHEAD_PER_QUERY_CALL;
use ic_error_types::{ErrorCode, UserError};
use ic_registry_subnet_type::SubnetType;
use ic_test_utilities::{
    types::ids::user_test_id,
    universal_canister::{call_args, wasm},
};
use ic_types::{ingress::WasmResult, messages::UserQuery, Cycles, NumInstructions};
use std::sync::Arc;

const CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

fn downcast_query_handler(query_handler: &dyn std::any::Any) -> &InternalHttpQueryHandler {
    // SAFETY:
    //
    // The type `InternalHttpQueryHandler` is imported in
    // `ic_test_utilities::execution_environment` but because this dependency is
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

    assert_eq!(1, query_handler.metrics.query.duration.get_sample_count());
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
        .with_max_instructions_per_composite_query_call(NumInstructions::from(
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
fn composite_query_callgraph_max_instructions_is_enforced() {
    const NUM_CANISTERS: u64 = 20;
    const NUM_SUCCESSFUL_QUERIES: u64 = 5; // Number of calls expected to succeed

    let mut test = ExecutionTestBuilder::new()
        .with_composite_queries() // For now, query calls are only allowed in system subnets
        .with_max_instructions_per_composite_query_call(NumInstructions::from(
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
    let low_cycles = Cycles::new(80_000_590_000);
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
