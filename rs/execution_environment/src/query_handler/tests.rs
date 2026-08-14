use crate::InternalHttpQueryHandler;
use crate::query_handler::get_latest_certified_state_and_data_certificate;
use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_base_types::{CanisterId, NumSeconds, PrincipalId, SubnetId};
use ic_config::execution_environment::INSTRUCTION_OVERHEAD_PER_QUERY_CALL;
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree, lookup_path};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    CanisterRangesCheck, DelegationVerificationError, NNSDelegationBuilder, QueryExecutionError,
};
use ic_interfaces_state_manager::StateReader;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_management_canister_types_private::{
    CanisterIdRange, CanisterIdRecord, CanisterMetricsArgs, CanisterMetricsResult,
    CanisterSettingsArgsBuilder, CanisterStatusResultV2, CanisterStatusType,
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, ListCanistersResponse, LogVisibilityV2,
    Payload,
};
use ic_nns_delegation_reader_test_utils::create_fake_certificate_delegation;
use ic_registry_routing_table::{CanisterIdRange as RoutingTableCanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    ReplicatedState, SubnetTopology,
    metadata_state::testing::{NetworkTopologyTesting, SystemMetadataTesting},
};
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_test_utilities_consensus::fake::Fake;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_test_utilities_state::CanisterStateBuilder;
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id};
use ic_types::consensus::certification::Certification;
use ic_types::messages::Certificate;
use ic_types::{
    NumInstructions,
    ingress::WasmResult,
    messages::{Query, QuerySource},
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
use more_asserts::{assert_gt, assert_lt};
use std::collections::BTreeMap;
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
    assert_lt!(
        0,
        query_handler.metrics.query.instructions.get_sample_sum() as u64
    );
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
    assert_lt!(
        0,
        query_handler
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
    assert_lt!(
        0,
        query_handler
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
fn composite_query_call_to_the_same_canister() {
    // In this test we have a single canister that makes a composite self-call.
    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test.non_replicated_query(
        canister_id,
        "composite_query",
        wasm().inter_query(canister_id, call_args()).build(),
    );
    assert!(matches!(output, Ok(WasmResult::Reply(_))));
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
        assert_ne!(canister_idx, 0);
        assert_lt!(canister_idx, canisters.len());
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
        assert_lt!(canister_idx, canisters.len());

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

    let canister = test
        .state_mut()
        .canister_state_make_mut(&canister_id)
        .unwrap();
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
                sender_info: None,
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

    // Create two canisters A and B with the same freezing threshold.
    // Canister A has few cycles and is frozen; canister B has plenty and is not.
    // Using a very high freezing threshold so that canister A is frozen
    // regardless of the exact cycle costs (no need to compute precise balances).
    let canister_a = test
        .universal_canister_with_cycles(Cycles::new(1_000_000_000_000))
        .unwrap();
    test.update_freezing_threshold(canister_a, freezing_threshold)
        .unwrap();

    let canister_b = test
        .universal_canister_with_cycles(Cycles::new(1_000_000_000_000_000))
        .unwrap();
    test.update_freezing_threshold(canister_b, freezing_threshold)
        .unwrap();

    // Canister A is frozen, so queries are rejected.
    let result = test.non_replicated_query(canister_a, "query", wasm().reply().build());
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterOutOfCycles,
            format!(
                "Canister {canister_a} is unable to process query calls because it's frozen. \
                 Please top up the canister with cycles and try again."
            )
        )),
    );

    // Canister B is not frozen, so queries succeed.
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
                    sender_info: None,
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
                    sender_info: None,
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
    assert_gt!(balance_before, balance_after);
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
                    sender_info: None,
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
                    sender_info: None,
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
                    sender_info: None,
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
                    sender_info: None,
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
                    sender_info: None,
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
            assert_gt!(
                canister_query_stats.num_instructions,
                child_canister_num_instructions
            );
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

    assert_lt!(counters[0], counters[1]);
    assert_lt!(counters[1], counters[2]);
    assert_lt!(counters[2], counters[3]);
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

    assert_lt!(counters[0], counters[1]);
    assert_lt!(counters[1], counters[2]);
    assert_lt!(counters[2], counters[3]);
}

#[test]
fn query_call_exceeds_instructions_limit() {
    let instructions_limit = 4;
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit_per_query_message(instructions_limit)
        .build();

    let canister = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let output = test
        .query(
            Query {
                source: QuerySource::User {
                    user_id: user_test_id(1),
                    ingress_expiry: 0,
                    nonce: None,
                    sender_info: None,
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

// Subnet with a Normal cost schedule has no subnet admins concept; any caller
// must be rejected with CanisterRejectedMessage.
#[test]
fn test_list_canisters_no_subnet_admins() {
    let mut test = ExecutionTestBuilder::new().build();
    let err = test
        .non_replicated_query(CanisterId::ic_00(), "list_canisters", Encode!().unwrap())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterRejectedMessage);
}

// Subnet has admins configured, but the caller is not one of them.
#[test]
fn test_list_canisters_non_admin_rejected() {
    let admin: PrincipalId = user_test_id(1).get();
    let non_admin = user_test_id(2);
    let mut test = ExecutionTestBuilder::new()
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .with_subnet_admins(vec![admin])
        .build();
    test.set_user_id(non_admin);
    let err = test
        .non_replicated_query(CanisterId::ic_00(), "list_canisters", Encode!().unwrap())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidSubnetAdmin);
}

// Admin caller receives correct ranges: 5-7 coalesced, gap, 10 alone, gap,
// 12-15 coalesced.
#[test]
fn test_list_canisters_success() {
    let admin: PrincipalId = user_test_id(1).get();
    let mut test = ExecutionTestBuilder::new()
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .with_subnet_admins(vec![admin])
        .build();
    test.set_user_id(user_test_id(1));

    // IDs 5, 6, 7 are consecutive (coalesce into [5,7]), ID 10 is isolated
    // ([10,10]), and IDs 12, 13, 14, 15 are consecutive (coalesce into [12,15]).
    for raw_id in [5_u64, 6, 7, 10, 12, 13, 14, 15] {
        test.state_mut().put_canister_state(
            CanisterStateBuilder::new()
                .with_canister_id(CanisterId::from(raw_id))
                .build(),
        );
    }

    let reply = test
        .non_replicated_query(CanisterId::ic_00(), "list_canisters", Encode!().unwrap())
        .unwrap();
    let response = Decode!(&reply.bytes(), ListCanistersResponse).unwrap();

    assert_eq!(
        response.canisters,
        vec![
            CanisterIdRange {
                start: CanisterId::from(5_u64),
                end: CanisterId::from(7_u64),
            },
            CanisterIdRange {
                start: CanisterId::from(10_u64),
                end: CanisterId::from(10_u64),
            },
            CanisterIdRange {
                start: CanisterId::from(12_u64),
                end: CanisterId::from(15_u64),
            },
        ]
    );
}

/// Returns a composite query calling the given management canister method
/// with the given payload and replying with the reply or the reject message.
fn ic00_composite_query(method_name: &str, payload: Vec<u8>) -> Vec<u8> {
    wasm()
        .call_simple(
            CanisterId::ic_00(),
            method_name,
            call_args()
                .other_side(payload)
                .on_reject(wasm().reject_message().append_and_reply()),
        )
        .build()
}

#[test]
fn composite_query_call_to_management_canister_canister_status() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    // A canister is always allowed to request its own status.
    let reply = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            ic00_composite_query(
                "canister_status",
                CanisterIdRecord::from(canister_id).encode(),
            ),
        )
        .unwrap();

    let status = Decode!(&reply.bytes(), CanisterStatusResultV2).unwrap();
    assert_eq!(status.status(), CanisterStatusType::Running);
    assert_eq!(
        status.cycles(),
        test.canister_state(canister_id)
            .system_state
            .balance()
            .get()
    );
}

#[test]
fn composite_query_call_to_management_canister_fetch_canister_logs() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    test.set_log_visibility(canister_id, LogVisibilityV2::Public)
        .unwrap();
    // Record a log entry in a replicated update call.
    test.ingress(
        canister_id,
        "update",
        wasm().debug_print(b"hi").reply().build(),
    )
    .unwrap();

    let reply = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            ic00_composite_query(
                "fetch_canister_logs",
                FetchCanisterLogsRequest::new(canister_id).encode(),
            ),
        )
        .unwrap();

    let logs = Decode!(&reply.bytes(), FetchCanisterLogsResponse).unwrap();
    assert_eq!(
        logs.canister_log_records
            .iter()
            .map(|record| String::from_utf8(record.content.clone()).unwrap())
            .collect::<Vec<_>>(),
        vec!["hi".to_string()]
    );
}

#[test]
fn composite_query_call_to_management_canister_canister_metrics() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    // Both canister A and the test user are controllers of canister B.
    let user = test.user_id().get();
    test.update_settings(
        canister_b,
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![canister_a.get(), user])
            .build(),
    )
    .unwrap();

    let reply = test
        .non_replicated_query(
            canister_a,
            "composite_query",
            ic00_composite_query(
                "canister_metrics",
                CanisterMetricsArgs::new(canister_b).encode(),
            ),
        )
        .unwrap();

    // The composite query returns the same metrics as a query sent by the user
    // directly to the management canister.
    let expected = test
        .non_replicated_query(
            CanisterId::ic_00(),
            "canister_metrics",
            CanisterMetricsArgs::new(canister_b).encode(),
        )
        .unwrap();
    assert_eq!(
        Decode!(&reply.bytes(), CanisterMetricsResult).unwrap(),
        Decode!(&expected.bytes(), CanisterMetricsResult).unwrap()
    );
}

#[test]
fn composite_query_call_to_management_canister_list_canisters() {
    // The caller must be a subnet admin to be allowed to call `list_canisters`
    // and the canister ID of the caller must hence be known upfront.
    let canister_id = canister_test_id(0);
    let mut test = ExecutionTestBuilder::new()
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .with_subnet_admins(vec![canister_id.get()])
        .build();
    assert_eq!(test.universal_canister().unwrap(), canister_id);

    let reply = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            ic00_composite_query("list_canisters", Encode!().unwrap()),
        )
        .unwrap();

    // The caller is the only canister on the subnet.
    let response = Decode!(&reply.bytes(), ListCanistersResponse).unwrap();
    assert_eq!(
        response.canisters,
        vec![CanisterIdRange {
            start: canister_id,
            end: canister_id,
        }]
    );
}

#[test]
fn composite_query_call_to_management_canister_respects_permissions() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_a = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    // Canister B is controlled by the test user, not by canister A.
    let canister_b = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let reply = test
        .non_replicated_query(
            canister_a,
            "composite_query",
            ic00_composite_query(
                "canister_status",
                CanisterIdRecord::from(canister_b).encode(),
            ),
        )
        .unwrap();

    let message = String::from_utf8(reply.bytes()).unwrap();
    assert!(
        message.contains(&format!(
            "Caller {canister_a} is not allowed to read the canister status"
        )),
        "Unexpected reject message: {message}"
    );
}

#[test]
fn composite_query_call_to_management_canister_for_unknown_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();
    let unknown = canister_test_id(42);

    let reply = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            ic00_composite_query("canister_status", CanisterIdRecord::from(unknown).encode()),
        )
        .unwrap();

    assert_eq!(
        reply,
        WasmResult::Reply(format!("Canister {unknown} not found").into_bytes())
    );
}

#[test]
fn composite_query_call_to_management_canister_rejects_non_query_methods() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let reply = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            ic00_composite_query("raw_rand", Encode!().unwrap()),
        )
        .unwrap();

    // The call is rejected with the same error as a query sent by an end user
    // to the management canister.
    assert_eq!(
        reply,
        WasmResult::Reply(b"Query method raw_rand not found.".to_vec())
    );
}

#[test]
fn composite_query_call_to_management_canister_rejects_unknown_methods() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister_with_cycles(CYCLES_BALANCE).unwrap();

    let err = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            ic00_composite_query("unknown", Encode!().unwrap()),
        )
        .unwrap_err();

    // Calls to methods not exported by the management canister are rejected
    // before the request is even pushed onto the output queue and thus the
    // reject response is not propagated to the caller.
    // TODO(EXC-1655): fix reject response propagation.
    assert_eq!(err.code(), ErrorCode::CanisterDidNotReply);
}

#[test]
fn composite_query_call_to_management_canister_charges_instructions() {
    // The number of `list_canisters` calls the instruction limit is set up for.
    const NUM_SUCCESSFUL_CALLS: u64 = 2;
    // A `list_canisters` call costs at least this many instructions, see
    // `list_canisters_instructions`.
    const LIST_CANISTERS_INSTRUCTIONS: u64 = 20_000_000;
    // The universal canister needs some instructions for its own execution.
    const CANISTER_INSTRUCTIONS: u64 = 1_000_000;

    // The caller must be a subnet admin to be allowed to call `list_canisters`
    // and the canister ID of the caller must hence be known upfront.
    let canister_id = canister_test_id(0);
    let mut test = ExecutionTestBuilder::new()
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .with_subnet_admins(vec![canister_id.get()])
        .with_max_query_call_graph_instructions(NumInstructions::from(
            NUM_SUCCESSFUL_CALLS
                * (LIST_CANISTERS_INSTRUCTIONS
                    + INSTRUCTION_OVERHEAD_PER_QUERY_CALL
                    + CANISTER_INSTRUCTIONS),
        ))
        .build();
    assert_eq!(test.universal_canister().unwrap(), canister_id);

    // A composite query calling `list_canisters` `n` times in a row.
    fn list_canisters_calls(n: u64) -> ic_universal_canister::PayloadBuilder {
        let on_reply = if n <= 1 {
            wasm().push_bytes(b"done").append_and_reply()
        } else {
            list_canisters_calls(n - 1)
        };
        wasm().call_simple(
            CanisterId::ic_00(),
            "list_canisters",
            call_args()
                .other_side(Encode!().unwrap())
                .on_reply(on_reply)
                .on_reject(wasm().reject_message().append_and_reply()),
        )
    }

    // The instructions consumed by `list_canisters` are charged towards the
    // instruction limit of the whole call graph, so a query making one more
    // call than the limit allows for must fail.
    let err = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            list_canisters_calls(NUM_SUCCESSFUL_CALLS + 1).build(),
        )
        .unwrap_err();
    assert_eq!(
        err.code(),
        ErrorCode::QueryCallGraphTotalInstructionLimitExceeded
    );

    // The number of calls the limit is set up for is still within the limit.
    let reply = test
        .non_replicated_query(
            canister_id,
            "composite_query",
            list_canisters_calls(NUM_SUCCESSFUL_CALLS).build(),
        )
        .unwrap();
    assert_eq!(reply, WasmResult::Reply(b"done".to_vec()));
}

// ---------------------------------------------------------------------------
// NNS delegation vs. certified state:
// `get_latest_certified_state_and_data_certificate` must only embed the NNS
// delegation into the data certificate after verifying it against the exact
// certified state the certificate is built from, and must return an error when
// the two do not match (e.g. around subnet splits and canister migrations).
// ---------------------------------------------------------------------------

fn all_canister_ranges_checks() -> Vec<CanisterRangesCheck> {
    vec![
        CanisterRangesCheck::NoCheck,
        CanisterRangesCheck::AllSubnetRanges,
        CanisterRangesCheck::CanisterInFlat(canister_test_id(0)),
        CanisterRangesCheck::CanisterInTree(canister_test_id(0)),
    ]
}

/// Builds an NNS delegation certifying the given canister ranges for `subnet_id`,
/// returning the delegation builder together with the raw bytes of the certified
/// `/subnet/<subnet_id>/public_key` leaf, i.e. the public key which a certified
/// state must assign to the subnet for the delegation to match it.
fn fake_delegation_builder(
    subnet_id: SubnetId,
    canister_id_ranges: &Vec<(CanisterId, CanisterId)>,
) -> (Arc<NNSDelegationBuilder>, Vec<u8>) {
    let (delegation, _nns_root_public_key) =
        create_fake_certificate_delegation(canister_id_ranges, subnet_id);

    let certificate: Certificate = serde_cbor::from_slice(&delegation.certificate).unwrap();
    let tree = LabeledTree::try_from(certificate.tree).unwrap();
    let certified_public_key =
        match lookup_path(&tree, &[b"subnet", subnet_id.get().as_ref(), b"public_key"]) {
            Some(LabeledTree::Leaf(public_key)) => public_key.clone(),
            other => panic!("The fake delegation should certify a public key, got: {other:?}"),
        };

    let builder = NNSDelegationBuilder::try_new(delegation.certificate, subnet_id)
        .expect("The fake delegation should parse");

    (Arc::new(builder), certified_public_key)
}

/// A state reader whose certified state assigns `public_key` and
/// `canister_id_ranges` to `subnet_id`. The hash tree and the certification
/// returned alongside the state are dummies: only the network topology matters
/// for the NNS delegation verification under test.
fn certified_state_reader_with_subnet_topology(
    subnet_id: SubnetId,
    public_key: Vec<u8>,
    canister_id_ranges: &[(CanisterId, CanisterId)],
) -> Arc<dyn StateReader<State = ReplicatedState>> {
    let routing_table: RoutingTable = canister_id_ranges
        .iter()
        .map(|(start, end)| {
            (
                RoutingTableCanisterIdRange {
                    start: *start,
                    end: *end,
                },
                subnet_id,
            )
        })
        .collect::<BTreeMap<_, _>>()
        .try_into()
        .unwrap();

    let mut state = ReplicatedState::new(subnet_id, SubnetType::Application);
    state.metadata.modify_network_topology(|network_topology| {
        network_topology.subnets_mut().insert(
            subnet_id,
            SubnetTopology {
                public_key,
                ..SubnetTopology::default()
            },
        );
        network_topology.set_routing_table(routing_table);
    });

    let mut state_reader = MockStateManager::new();
    state_reader
        .expect_read_certified_state()
        .return_once(move |_| Some((Arc::new(state), MixedHashTree::Empty, Certification::fake())));
    Arc::new(state_reader)
}

#[test]
fn query_handler_embeds_nns_delegation_matching_the_certified_state() {
    let subnet_id = subnet_test_id(1);
    let ranges = vec![(canister_test_id(0), canister_test_id(10))];
    let (builder, certified_public_key) = fake_delegation_builder(subnet_id, &ranges);

    for ranges_check in all_canister_ranges_checks() {
        // The certified state assigns the subnet exactly the public key and the
        // canister ranges certified by the delegation.
        let state_reader = certified_state_reader_with_subnet_topology(
            subnet_id,
            certified_public_key.clone(),
            &ranges,
        );

        let certified = get_latest_certified_state_and_data_certificate(
            state_reader,
            Some(Arc::clone(&builder)),
            ranges_check,
            canister_test_id(0),
        )
        .unwrap_or_else(|err| {
            panic!("The delegation matches the certified state, so the {ranges_check:?} check should succeed, got: {err:?}")
        });

        // The verified delegation is embedded into the data certificate.
        assert!(
            certified
                .data_certificate_with_delegation_metadata
                .certificate_delegation_metadata
                .is_some(),
            "The {ranges_check:?} check should report the metadata of the embedded delegation"
        );
        let data_certificate: Certificate = serde_cbor::from_slice(
            &certified
                .data_certificate_with_delegation_metadata
                .data_certificate,
        )
        .unwrap();
        assert!(
            data_certificate.delegation.is_some(),
            "The data certificate should embed the delegation after the {ranges_check:?} check"
        );
    }
}

#[test]
fn query_handler_returns_an_error_when_the_certified_public_key_drifts() {
    let subnet_id = subnet_test_id(1);
    let ranges = vec![(canister_test_id(0), canister_test_id(10))];
    let (builder, _certified_public_key) = fake_delegation_builder(subnet_id, &ranges);

    for ranges_check in all_canister_ranges_checks() {
        // The certified state assigns the subnet a different public key than the
        // one certified by the delegation (the canister ranges still match).
        let state_reader =
            certified_state_reader_with_subnet_topology(subnet_id, vec![0xFF; 10], &ranges);

        let result = get_latest_certified_state_and_data_certificate(
            state_reader,
            Some(Arc::clone(&builder)),
            ranges_check,
            canister_test_id(0),
        )
        .map(|_| ());

        assert_matches!(
            result,
            Err(QueryExecutionError::DelegationInconsistentWithState(
                DelegationVerificationError::Inconsistent
            )),
            "The {ranges_check:?} check should fail when the delegation does not \
             certify the subnet's public key in the certified state"
        );
    }
}

#[test]
fn query_handler_returns_an_error_when_the_certified_canister_ranges_drift() {
    let subnet_id = subnet_test_id(1);
    let delegation_ranges = vec![(canister_test_id(0), canister_test_id(10))];
    let (builder, certified_public_key) = fake_delegation_builder(subnet_id, &delegation_ranges);

    // The certified state no longer assigns the delegation's canister ranges to the
    // subnet; in particular it no longer covers `canister_test_id(0)`.
    let drifted_state_ranges = [(canister_test_id(20), canister_test_id(30))];

    for ranges_check in all_canister_ranges_checks() {
        if ranges_check == CanisterRangesCheck::NoCheck {
            continue;
        }

        let state_reader = certified_state_reader_with_subnet_topology(
            subnet_id,
            certified_public_key.clone(),
            &drifted_state_ranges,
        );

        let result = get_latest_certified_state_and_data_certificate(
            state_reader,
            Some(Arc::clone(&builder)),
            ranges_check,
            canister_test_id(0),
        )
        .map(|_| ());

        assert_matches!(
            result,
            Err(QueryExecutionError::DelegationInconsistentWithState(
                DelegationVerificationError::Inconsistent
            )),
            "The {ranges_check:?} check should fail when the certified canister \
             ranges drift away from the delegation"
        );
    }

    // `NoCheck` does not compare the canister ranges: as long as the public key
    // still matches, the delegation is embedded.
    let state_reader = certified_state_reader_with_subnet_topology(
        subnet_id,
        certified_public_key,
        &drifted_state_ranges,
    );
    let result = get_latest_certified_state_and_data_certificate(
        state_reader,
        Some(builder),
        CanisterRangesCheck::NoCheck,
        canister_test_id(0),
    );
    assert!(
        result.is_ok(),
        "The NoCheck check should ignore the drifted canister ranges"
    );
}

#[test]
fn query_handler_without_nns_delegation_embeds_no_delegation() {
    // On the NNS there is no delegation: nothing to verify and nothing to embed.
    let state_reader =
        certified_state_reader_with_subnet_topology(subnet_test_id(1), vec![1, 2, 3], &[]);

    let certified = get_latest_certified_state_and_data_certificate(
        state_reader,
        None,
        CanisterRangesCheck::NoCheck,
        canister_test_id(0),
    )
    .unwrap_or_else(|err| panic!("Without a delegation there is nothing to verify: {err:?}"));

    assert!(
        certified
            .data_certificate_with_delegation_metadata
            .certificate_delegation_metadata
            .is_none()
    );
    let data_certificate: Certificate = serde_cbor::from_slice(
        &certified
            .data_certificate_with_delegation_metadata
            .data_certificate,
    )
    .unwrap();
    assert!(data_certificate.delegation.is_none());
}
