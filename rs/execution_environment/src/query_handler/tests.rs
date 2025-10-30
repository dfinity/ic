use crate::InternalHttpQueryHandler;
use ic_base_types::{CanisterId, NumSeconds};
use ic_config::execution_environment::INSTRUCTION_OVERHEAD_PER_QUERY_CALL;
use ic_error_types::{ErrorCode, UserError};
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::{
    Cycles, NumInstructions,
    ingress::WasmResult,
    messages::{Query, QuerySource},
};
use std::sync::Arc;

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

    let mut test = ExecutionTestBuilder::new().build();

    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test.non_replicated_query(
        canister_a,
        "composite_query",
        wasm()
            .inter_query(
                canister_b,
                call_args().other_side(wasm().reply_data(b"pong".as_ref())),
            )
            .build(),
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
    // - canister_a.query()
    // - canister_b.query()
    // - canister_a.on_reply()
    assert_eq!(
        3,
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
                .query_spawned_calls
                .instructions
                .get_sample_sum() as u64
    )
}

#[test]
fn composite_query_call_with_side_effects() {
    // In this test we have two canisters A and B.
    // Canister A does a side-effectful operation (stable_grow) and then
    // calls canister B. The side effect must happen once and only once.

    let mut test = ExecutionTestBuilder::new().build();

    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test.non_replicated_query(
        canister_a,
        "composite_query",
        wasm()
            .stable_grow(10)
            .inter_query(
                canister_b,
                call_args()
                    .other_side(wasm().reply_data(b"ignore".as_ref()))
                    .on_reply(wasm().stable_size().reply_int()),
            )
            .build(),
    );
    assert_eq!(output, Ok(WasmResult::Reply(10_i32.to_le_bytes().to_vec())));
}

#[test]
fn query_methods_cannot_make_downstream_calls() {
    // In this test we have two canisters A and B.
    // Canister A attempts to call canister B from within a query method.
    // This should not be allowed.

    let mut test = ExecutionTestBuilder::new().build();

    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test.non_replicated_query(
        canister_a,
        "query",
        wasm()
            .stable_grow(10)
            .inter_query(
                canister_b,
                call_args()
                    .other_side(wasm().reply_data(b"ignore".as_ref()))
                    .on_reply(wasm().stable_size().reply_int()),
            )
            .build(),
    );
    match output {
        Ok(_) => unreachable!("The query was expected to fail, but it succeeded."),
        Err(err) => assert_eq!(err.code(), ErrorCode::CanisterContractViolation),
    }
}

#[test]
fn composite_query_callgraph_depth_is_enforced() {
    let mut test = ExecutionTestBuilder::new().build();

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
        test: &mut ExecutionTest,
        canisters: &[ic_types::CanisterId],
        num_calls: usize,
    ) -> Result<WasmResult, UserError> {
        test.non_replicated_query(
            canisters[0],
            "composite_query",
            generate_composite_call_to(canisters, num_calls).build(),
        )
    }

    // Those should succeed
    for num_calls in 1..7 {
        match &test_query(&mut test, &canisters, num_calls) {
            Ok(_) => {}
            Err(err) => panic!(
                "Query with depth {num_calls} failed, when it should have succeeded: {err:?}"
            ),
        }
    }

    // Those should fail
    for num_calls in 7..NUM_CANISTERS - 1 {
        match test_query(&mut test, &canisters, num_calls) {
            Ok(_) => panic!(
                "Call with depth {num_calls} should have failed with call graph being too large"
            ),
            Err(err) => {
                assert_eq!(err.code(), ErrorCode::QueryCallGraphTooDeep)
            }
        }
    }
}

#[test]
fn composite_query_recursive_calls() {
    let mut test = ExecutionTestBuilder::new().build();

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

    test.non_replicated_query(
        canister,
        "composite_query",
        generate_composite_call_to(canister, NUM_CALLS).build(),
    )
    .unwrap();
}

#[test]
fn composite_query_callgraph_max_instructions_is_enforced() {
    const NUM_CANISTERS: u64 = 20;
    const NUM_SUCCESSFUL_QUERIES: u64 = 5; // Number of calls expected to succeed

    let mut test = ExecutionTestBuilder::new()
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
        let test = test.non_replicated_query(
            canisters[0],
            "composite_query",
            generate_call_to(&canisters, num_calls as usize).build(),
        );
        match &test {
            Ok(_) => {}
            Err(err) => panic!(
                "Query with {num_calls} calls failed, when it should have succeeded: {err:?}"
            ),
        }
    }
    for num_calls in NUM_SUCCESSFUL_QUERIES..NUM_CANISTERS {
        let test = test.non_replicated_query(
            canisters[0],
            "composite_query",
            generate_call_to(&canisters, num_calls as usize).build(),
        );
        match &test {
            Ok(_) => panic!("Query with {num_calls} calls should have failed!"),
            Err(err) => assert_eq!(
                err.code(),
                ErrorCode::QueryCallGraphTotalInstructionLimitExceeded
            ),
        }
    }
}

#[test]
fn query_compiled_once() {
    let mut test = ExecutionTestBuilder::new()
        .with_precompiled_universal_canister(false)
        .build();
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

    let result = test.non_replicated_query(canister_id, "query", wasm().reply().build());
    assert!(result.is_ok());

    let query_handler = downcast_query_handler(test.query_handler());

    // Now we expect the compilation counter to increase because the query
    // had to compile.
    assert_eq!(2, query_handler.hypervisor.compile_count());

    // The more verbose approach has to be used since `test.non_replicated_query`
    // requires a mutable reference to `test` but we take an immutable reference
    // when assigning to `query_handler` above which needs to be used later for the
    // last assertion of the test.
    let result = test.query(
        Query {
            source: QuerySource::User {
                user_id: user_test_id(2),
                ingress_expiry: 0,
                nonce: None,
            },
            receiver: canister_id,
            method_name: "query".to_string(),
            method_payload: wasm().reply().build(),
        },
        Arc::new(test.state().clone()),
        vec![],
        /*certificate_delegation_metadata=*/ None,
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
    // 300_000_002_460 cycles are needed as prepayment for max install_code instructions
    //       5_000_000 cycles are needed for update call execution
    //          41_070 cycles are needed to cover freeze_threshold_cycles
    //                 of the canister history memory usage (134 bytes)
    let low_cycles = Cycles::new(300_005_633_530);
    let canister_a = test.universal_canister_with_cycles(low_cycles).unwrap();
    test.update_freezing_threshold(canister_a, freezing_threshold)
        .unwrap();

    let high_cycles = Cycles::new(1_000_000_000_000_000);
    let canister_b = test.universal_canister_with_cycles(high_cycles).unwrap();
    test.update_freezing_threshold(canister_b, freezing_threshold)
        .unwrap();

    // Canister A is below its freezing threshold, so queries will be rejected.
    let result = test.non_replicated_query(canister_a, "query", wasm().reply().build());
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterOutOfCycles,
            format!(
                "Canister {canister_a} is unable to process query calls because it's frozen. Please top up the canister with cycles and try again."
            )
        )),
    );

    // Canister B has a high cycles balance that's above its freezing
    // threshold and so it can still process queries.
    let result = test.non_replicated_query(canister_b, "query", wasm().reply().build());
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
    let mut test = ExecutionTestBuilder::new().build();

    let canister = test.canister_from_wat(COMPOSITE_QUERY_WAT).unwrap();

    let result = test
        .query(
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(0),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canister,
                method_name: "query".to_string(),
                method_payload: vec![],
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
        )
        .unwrap();

    assert_eq!(result, WasmResult::Reply("hello".as_bytes().to_vec()));
}

#[test]
fn composite_query_fails_if_disabled() {
    let mut test = ExecutionTestBuilder::new()
        .without_composite_queries()
        .build();

    let canister = test.canister_from_wat(COMPOSITE_QUERY_WAT).unwrap();

    let result = test
        .query(
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(0),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canister,
                method_name: "query".to_string(),
                method_payload: vec![],
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
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
    let mut test = ExecutionTestBuilder::new().build();

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
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(2),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply([2_u8].to_vec()));
}

#[test]
fn composite_query_single_canister_response() {
    // In this test canister 0 calls canister 1 which in turn calls canisters
    // 2, 3, 4 and produces a reply only when handling the response from
    // canister 2. That reply should propagate to the user.
    let mut test = ExecutionTestBuilder::new().build();

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
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(2),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply([3_u8].to_vec()));
}

#[test]
fn composite_query_no_user_response() {
    // In this test canister 0 calls canisters 1, 2, 3 and does not reply.
    let mut test = ExecutionTestBuilder::new().build();

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
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(2),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
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
    let mut test = ExecutionTestBuilder::new().build();

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
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(2),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canisters[0],
                method_name: "composite_query".to_string(),
                method_payload: canister_0.build(),
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
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
    let mut test = ExecutionTestBuilder::new().build();

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
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(2),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canister_a,
                method_name: "composite_query".to_string(),
                method_payload: a.build(),
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(b));
}

#[test]
fn composite_query_syscalls_from_reply_reject_callback() {
    // In this test canister 0 calls canisters 1 and attempts syscalls from reply callback.
    let mut test = ExecutionTestBuilder::new().build();

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

    for (other_side, callback_type) in [(reply, "reply"), (reject, "reject")] {
        for (syscall, label) in &syscalls {
            let canister_0 = wasm().composite_query(
                canisters[1],
                call_args()
                    .other_side(other_side.clone())
                    .on_reply(syscall.clone())
                    .on_reject(syscall.clone()),
            );

            let output =
                test.non_replicated_query(canisters[0], "composite_query", canister_0.build());
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
                    "Incorrect return code for {label} {callback_type}"
                ),
            }
        }
    }
}

#[test]
fn composite_query_state_preserved_across_sequential_calls() {
    let mut test = ExecutionTestBuilder::new().build();

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

    let output = test.non_replicated_query(canisters[0], "composite_query", payload.build());

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
    let mut test = ExecutionTestBuilder::new().build();

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

    let output = test.non_replicated_query(canisters[0], "composite_query", payload.build());

    // We use the global counter to count the number of composite queries we are executing (increment before each call).
    // Since we have NUM_CANISTER canisters in total, we expect to have one less calls (from the first canister to all others).
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
fn query_stats_are_collected() {
    let mut test = ExecutionTestBuilder::new().with_query_stats().build();

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

    // Run query
    let _ = test.non_replicated_query(canisters[0], "composite_query", payload.build());

    // The following numbers might change, e.g. if instruction costs are updated.
    // In that case, the easiest is probably to print the values and update the test.
    // If the test fails, the output should also indicate what the new values are.

    let child_canister_num_instructions = test
        .query_stats_for_testing(&canisters[1])
        .unwrap()
        .num_instructions;
    assert_ne!(child_canister_num_instructions, 0);
    for (idx, c) in canisters.iter().enumerate() {
        let canister_query_stats = test.query_stats_for_testing(c).unwrap();

        // Each canister got one call
        assert_eq!(canister_query_stats.num_calls, 1);

        // Depending on whether we are looking at the root canister, or one of the child canisters,
        // instructions and payload sizes differ. All child canisters have the same cost though.
        if idx == 0 {
            assert!(canister_query_stats.num_instructions > child_canister_num_instructions);
            assert_eq!(canister_query_stats.ingress_payload_size, 284);
            assert_eq!(canister_query_stats.egress_payload_size, 0);
        } else {
            assert_eq!(
                canister_query_stats.num_instructions,
                child_canister_num_instructions
            );
            assert_eq!(canister_query_stats.ingress_payload_size, 13);
            assert_eq!(canister_query_stats.egress_payload_size, 6);
        }
    }
}

#[test]
fn test_incorrect_query_name() {
    let mut test = ExecutionTestBuilder::new().build();
    let method = "unknown method";
    let Err(err) = test.non_replicated_query(CanisterId::ic_00(), method, vec![]) else {
        panic!("Unexpected result.");
    };
    assert_eq!(err.code(), ErrorCode::CanisterMethodNotFound);
    assert_eq!(
        err.description(),
        format!("Query method {method} not found.")
    );
}

#[test]
fn test_call_context_performance_counter_correctly_reported_on_query() {
    let mut test = ExecutionTestBuilder::new().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        // Counter a.0
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .inter_query(
            b_id,
            call_args().on_reply(
                wasm()
                    // Counter a.2
                    .performance_counter(1)
                    .int64_to_blob()
                    .append_to_global_data()
                    .inter_query(
                        b_id,
                        call_args().on_reply(
                            wasm()
                                .get_global_data()
                                .reply_data_append()
                                // Counter a.3
                                .performance_counter(1)
                                .reply_int64(),
                        ),
                    ),
            ),
        )
        // Counter a.1
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .build();
    let result = test
        .non_replicated_query(a_id, "composite_query", a)
        .unwrap();

    let counters = result
        .bytes()
        .chunks_exact(std::mem::size_of::<u64>())
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>();

    assert!(counters[0] < counters[1]);
    assert!(counters[1] < counters[2]);
    assert!(counters[2] < counters[3]);
}

#[test]
fn test_call_context_performance_counter_correctly_reported_on_composite_query() {
    let mut test = ExecutionTestBuilder::new().build();
    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let a = wasm()
        // Counter a.0
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .composite_query(
            b_id,
            call_args().on_reply(
                wasm()
                    // Counter a.2
                    .performance_counter(1)
                    .int64_to_blob()
                    .append_to_global_data()
                    .composite_query(
                        b_id,
                        call_args().on_reply(
                            wasm()
                                .get_global_data()
                                .reply_data_append()
                                // Counter a.3
                                .performance_counter(1)
                                .reply_int64(),
                        ),
                    ),
            ),
        )
        // Counter a.1
        .performance_counter(1)
        .int64_to_blob()
        .append_to_global_data()
        .build();
    let result = test
        .non_replicated_query(a_id, "composite_query", a)
        .unwrap();

    let counters = result
        .bytes()
        .chunks_exact(std::mem::size_of::<u64>())
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>();

    assert!(counters[0] < counters[1]);
    assert!(counters[1] < counters[2]);
    assert!(counters[2] < counters[3]);
}

#[test]
fn query_call_exceeds_instructions_limit() {
    let instructions_limit = 4;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit_without_dts(instructions_limit)
        .build();

    let canister = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test
        .query(
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(1),
                    ingress_expiry: 0,
                    nonce: None,
                },
                receiver: canister,
                method_name: "query".to_string(),
                method_payload: wasm().stable_grow(10).build(),
            },
            Arc::new(test.state().clone()),
            vec![],
            /*certificate_delegation_metadata=*/ None,
        )
        .unwrap_err();
    output.assert_contains(
            ErrorCode::CanisterInstructionLimitExceeded,
            &format!(
                "Error from Canister {canister}: Canister exceeded the limit of {instructions_limit} instructions for single message execution."
            )
    );
}
