use ic_base_types::PrincipalId;
use ic_state_machine_tests::{
    MessageOrdering, OrderedMessage, StateMachine, StateMachineBuilder, WasmResult,
};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types_cycles::Cycles;
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};
use std::panic;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

fn setup() -> StateMachine {
    StateMachineBuilder::new().with_flexible_ordering().build()
}

fn install_uc(sm: &StateMachine) -> ic_base_types::CanisterId {
    sm.install_canister_with_cycles(
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        None,
        INITIAL_CYCLES_BALANCE,
    )
    .unwrap()
}

/// Helper: check that an ingress message completed successfully and return the reply bytes.
fn get_reply(sm: &StateMachine, msg_id: &ic_types::messages::MessageId) -> Vec<u8> {
    match sm.ingress_status(msg_id) {
        IngressStatus::Known {
            state: IngressState::Completed(WasmResult::Reply(bytes)),
            ..
        } => bytes,
        other => panic!("Expected completed reply, got: {:?}", other),
    }
}

// ============================================================================
// Test 1: Basic ordering — A calls B, B replies.
//
// Ordering: Ingress(A) → Request(A→B) → Response(B→A)
// ============================================================================
#[test]
fn test_basic_inter_canister_ordering() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    let b_reply = wasm().reply_data(b"hello from B").build();
    let a_payload = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();

    let ingress_id = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering(vec![
        OrderedMessage::Ingress(canister_a, ingress_id.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_id), b"hello from B");
}

// ============================================================================
// Test 2: Two ingress messages to the same canister — verify ordering.
// ============================================================================
#[test]
fn test_ingress_ordering_on_same_canister() {
    let sm = setup();
    let canister = install_uc(&sm);

    let payload_1 = wasm().set_global_data(b"first").reply_data(b"ok1").build();
    let payload_2 = wasm().set_global_data(b"second").reply_data(b"ok2").build();

    let id1 = sm
        .buffer_ingress_as(PrincipalId::new_anonymous(), canister, "update", payload_1)
        .unwrap();
    let id2 = sm
        .buffer_ingress_as(PrincipalId::new_anonymous(), canister, "update", payload_2)
        .unwrap();

    sm.execute_with_ordering(MessageOrdering(vec![
        OrderedMessage::Ingress(canister, id1.clone()),
        OrderedMessage::Ingress(canister, id2.clone()),
    ]));

    assert_eq!(get_reply(&sm, &id1), b"ok1");
    assert_eq!(get_reply(&sm, &id2), b"ok2");

    // The last writer wins: global data should be "second".
    let read_payload = wasm().get_global_data().append_and_reply().build();
    let result = sm
        .execute_ingress(canister, "update", read_payload)
        .unwrap();
    match result {
        WasmResult::Reply(data) => assert_eq!(data, b"second"),
        _ => panic!("Expected reply"),
    }
}

// ============================================================================
// Test 3: Reversed ingress ordering — verify last-writer-wins.
// ============================================================================
#[test]
fn test_reversed_ingress_ordering() {
    let sm = setup();
    let canister = install_uc(&sm);

    let payload_1 = wasm().set_global_data(b"first").reply_data(b"ok1").build();
    let payload_2 = wasm().set_global_data(b"second").reply_data(b"ok2").build();

    let id1 = sm
        .buffer_ingress_as(PrincipalId::new_anonymous(), canister, "update", payload_1)
        .unwrap();
    let id2 = sm
        .buffer_ingress_as(PrincipalId::new_anonymous(), canister, "update", payload_2)
        .unwrap();

    // Execute ingress 2 FIRST, then ingress 1.
    sm.execute_with_ordering(MessageOrdering(vec![
        OrderedMessage::Ingress(canister, id2.clone()),
        OrderedMessage::Ingress(canister, id1.clone()),
    ]));

    assert_eq!(get_reply(&sm, &id1), b"ok1");
    assert_eq!(get_reply(&sm, &id2), b"ok2");

    // The last writer wins: global data should be "first" (since id1 ran second).
    let read_payload = wasm().get_global_data().append_and_reply().build();
    let result = sm
        .execute_ingress(canister, "update", read_payload)
        .unwrap();
    match result {
        WasmResult::Reply(data) => assert_eq!(data, b"first"),
        _ => panic!("Expected reply"),
    }
}

// ============================================================================
// Test 4: Three-canister chain — A → B → C → B → A
// ============================================================================
#[test]
fn test_three_canister_chain_ordering() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);
    let canister_c = install_uc(&sm);

    let c_reply = wasm().reply_data(b"hello from C").build();
    let b_on_reply = wasm().reply_data(b"hello from C via B").build();
    let b_payload = wasm()
        .inter_update(
            canister_c,
            CallArgs::default().other_side(c_reply).on_reply(b_on_reply),
        )
        .build();
    let a_payload = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_payload))
        .build();

    let ingress_id = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering(vec![
        OrderedMessage::Ingress(canister_a, ingress_id.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Request {
            source: canister_b,
            target: canister_c,
        },
        OrderedMessage::Response {
            source: canister_c,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_id), b"hello from C via B");
}

// ============================================================================
// Test 5: Normal tick() still works (regression test).
// ============================================================================
#[test]
fn test_normal_tick_regression() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    let b_reply = wasm().reply_data(b"normal reply").build();
    let a_payload = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();

    // Use the normal execute_ingress flow (no ordering).
    let result = sm.execute_ingress(canister_a, "update", a_payload).unwrap();
    match result {
        WasmResult::Reply(data) => assert_eq!(data, b"normal reply"),
        _ => panic!("Expected reply"),
    }
}

// ============================================================================
// Test 6: Interleaved independent call chains.
//
// Two independent inter-canister call chains (A→B and C→D) are executed
// in an alternating order. This tests that the ordering mechanism can
// interleave execution across independent call chains, where each
// canister has at most one message at any point.
//
// Ordering:
//   Ingress(A)       → chain 1: A calls B
//   Ingress(C)       → chain 2: C calls D
//   Request(A → B)   → chain 1: B processes A's request
//   Request(C → D)   → chain 2: D processes C's request
//   Response(B → A)  → chain 1: A gets B's response, completes
//   Response(D → C)  → chain 2: C gets D's response, completes
// ============================================================================
#[test]
fn test_interleaved_inter_canister_calls() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);
    let canister_c = install_uc(&sm);
    let canister_d = install_uc(&sm);

    // Chain 1: A calls B.
    let b_reply = wasm().reply_data(b"reply from B").build();
    let a_calls_b = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();

    // Chain 2: C calls D.
    let d_reply = wasm().reply_data(b"reply from D").build();
    let c_calls_d = wasm()
        .inter_update(canister_d, CallArgs::default().other_side(d_reply))
        .build();

    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_calls_b,
        )
        .unwrap();
    let ingress_c = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_c,
            "update",
            c_calls_d,
        )
        .unwrap();

    // Interleave the two chains.
    sm.execute_with_ordering(MessageOrdering(vec![
        // Chain 1: A sends request to B.
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        // Chain 2: C sends request to D.
        OrderedMessage::Ingress(canister_c, ingress_c.clone()),
        // Chain 1: B processes A's request, sends response.
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        // Chain 2: D processes C's request, sends response.
        OrderedMessage::Request {
            source: canister_c,
            target: canister_d,
        },
        // Chain 1: A processes B's response, completes.
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
        // Chain 2: C processes D's response, completes.
        OrderedMessage::Response {
            source: canister_d,
            target: canister_c,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_a), b"reply from B");
    assert_eq!(get_reply(&sm, &ingress_c), b"reply from D");
}

// ============================================================================
// Test 7: Subnet messages (management canister) in the ordering.
//
// Demonstrates that management canister operations (install_code) can be
// interleaved with canister-to-canister messages. Subnet messages are
// processed in `drain_subnet_queues` at the start of each round, so they
// execute implicitly when ticked — the Ingress variant handles them
// correctly because the Demux routes management canister messages to the
// consensus queue automatically.
// ============================================================================
#[test]
fn test_subnet_message_ordering() {
    use ic_management_canister_types_private::{CanisterInstallMode, InstallCodeArgs, Payload};

    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    // Step 1: A calls B (inter-canister).
    let b_reply = wasm().reply_data(b"before upgrade").build();
    let a_calls_b = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();

    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_calls_b,
        )
        .unwrap();

    // Step 2: Upgrade canister B with new code that replies differently.
    let new_b_wasm = UNIVERSAL_CANISTER_WASM.to_vec();
    let install_args =
        InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister_b, new_b_wasm, vec![]);
    let install_ingress = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            ic_management_canister_types_private::IC_00,
            "install_code",
            install_args.encode(),
        )
        .unwrap();

    // Step 3: A calls B again after upgrade.
    let b_reply_after = wasm().reply_data(b"after upgrade").build();
    let a_calls_b_again = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply_after))
        .build();

    let ingress_a2 = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_calls_b_again,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering(vec![
        // A calls B (before upgrade).
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        // B processes A's request.
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        // A processes B's response.
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
        // Upgrade B via management canister.
        OrderedMessage::Ingress(
            ic_management_canister_types_private::IC_00,
            install_ingress.clone(),
        ),
        // A calls B again (after upgrade).
        OrderedMessage::Ingress(canister_a, ingress_a2.clone()),
        // B processes A's second request.
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        // A processes B's second response.
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    // First call completed before upgrade.
    assert_eq!(get_reply(&sm, &ingress_a), b"before upgrade");
    // install_code completed.
    match sm.ingress_status(&install_ingress) {
        IngressStatus::Known {
            state: IngressState::Completed(_),
            ..
        } => {}
        other => panic!("Expected install_code to complete, got: {:?}", other),
    }
    // Second call completed after upgrade.
    assert_eq!(get_reply(&sm, &ingress_a2), b"after upgrade");
}

// ============================================================================
// Test 8: Canister makes an inter-canister call to the management canister.
//
// Canister A uses the UC to call `create_canister` on IC_00. The request
// goes through the subnet queue, and the response comes back to A.
// This tests that the ordering mechanism correctly handles:
// - Request { source: A, target: IC_00 } — checked via subnet_queues
// - Response { source: IC_00, target: A } — checked via A's input queue
// ============================================================================
#[test]
fn test_canister_calls_management_canister() {
    use ic_universal_canister::{CallInterface, management};

    let sm = setup();
    let canister_a = install_uc(&sm);

    // A calls create_canister on the management canister.
    // On reply, A forwards the raw reply bytes.
    let on_reply = wasm().message_payload().reply_data_append().reply().build();
    let a_payload = wasm()
        .call(management::create_canister(INITIAL_CYCLES_BALANCE.get() / 2).on_reply(on_reply))
        .build();

    // Management canister calls from a canister go through a multi-round
    // pipeline: output queue → loopback stream → subnet queue → execution →
    // response → canister callback. The Ingress variant with extra ticks
    // handles this automatically — keep ticking until the ingress completes.
    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering(vec![
        // A executes ingress, which triggers the full create_canister
        // round-trip via the management canister. The extra-tick loop in
        // execute_ordered_ingress handles the multi-round pipeline.
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
    ]));

    // A should have completed with a reply containing the new canister ID.
    let reply = get_reply(&sm, &ingress_a);
    assert!(
        !reply.is_empty(),
        "Expected non-empty reply with canister ID"
    );
}

// ============================================================================
// Test 9: Verify that subnet messages are processed one at a time via
// the ordering mechanism.
//
// Two ProvisionalCreateCanisterWithCycles ingress messages are submitted
// to the management canister via separate ordering steps. Each one
// should complete in its own set of ticks due to the limited subnet
// instruction budget.
// ============================================================================
#[test]
fn test_one_subnet_message_per_round() {
    use ic_management_canister_types_private::{
        Method, Payload, ProvisionalCreateCanisterWithCyclesArgs,
    };

    let sm = setup();

    let args = ProvisionalCreateCanisterWithCyclesArgs {
        amount: Some(candid::Nat::from(0_u64)),
        settings: None,
        specified_id: None,
        sender_canister_version: None,
    }
    .encode();

    let id1 = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            ic_management_canister_types_private::IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            args.clone(),
        )
        .unwrap();
    let id2 = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            ic_management_canister_types_private::IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            args,
        )
        .unwrap();

    // Execute first subnet message.
    sm.execute_with_ordering(MessageOrdering(vec![OrderedMessage::Ingress(
        ic_management_canister_types_private::IC_00,
        id1.clone(),
    )]));

    // First should be done, second should not have been touched.
    let is_done = |id: &ic_types::messages::MessageId| {
        matches!(
            sm.ingress_status(id),
            IngressStatus::Known {
                state: IngressState::Completed(_),
                ..
            }
        )
    };
    assert!(
        is_done(&id1),
        "First create_canister should be done: {:?}",
        sm.ingress_status(&id1)
    );
    assert!(
        !is_done(&id2),
        "Second create_canister should NOT be done yet: {:?}",
        sm.ingress_status(&id2)
    );

    // Execute second subnet message.
    sm.execute_with_ordering(MessageOrdering(vec![OrderedMessage::Ingress(
        ic_management_canister_types_private::IC_00,
        id2.clone(),
    )]));

    assert!(
        is_done(&id2),
        "Second create_canister should be done: {:?}",
        sm.ingress_status(&id2)
    );
}

// ============================================================================
// Test 10: DTS — a slow canister message gets sliced across multiple rounds.
// The loop does ~3B instructions, exceeding max_instructions_per_slice (2B)
// but staying under max_instructions_per_message (5B).
// ============================================================================
#[test]
fn test_dts_execution_completes() {
    fn slow_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "ic0" "msg_reply" (func $msg_reply))
                (func $run
                    (local $i i32)
                    (loop $loop
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br_if $loop (i32.lt_s (local.get $i) (i32.const 3000000000)))
                    )
                    (call $msg_reply))
                (memory $memory 1)
                (export "canister_update run" (func $run))
            )"#,
        )
        .unwrap()
    }

    let sm = setup();
    let canister = sm.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);
    sm.install_wasm_in_mode(
        canister,
        ic_management_canister_types_private::CanisterInstallMode::Install,
        slow_wasm(),
        vec![],
    )
    .unwrap();

    let ingress_id = sm
        .buffer_ingress_as(PrincipalId::new_anonymous(), canister, "run", vec![])
        .unwrap();

    // This message will be DTS-sliced. execute_with_ordering should tick
    // until all slices complete.
    sm.execute_with_ordering(MessageOrdering(vec![OrderedMessage::Ingress(
        canister,
        ingress_id.clone(),
    )]));

    match sm.ingress_status(&ingress_id) {
        IngressStatus::Known {
            state: IngressState::Completed(WasmResult::Reply(_)),
            ..
        } => {}
        other => panic!("Expected DTS message to complete, got: {:?}", other),
    }
}

// ============================================================================
// Test 11: execute_with_ordering panics without with_flexible_ordering.
// ============================================================================
#[test]
fn test_panics_without_flexible_ordering() {
    let sm = StateMachineBuilder::new().build();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering(vec![]));
    }));
    assert!(result.is_err(), "Should panic without flexible ordering");
}

// ============================================================================
// Test 12: Two calls from A to B, processed in batch.
//
// When two requests from A are in B's queue simultaneously,
// sender_in_queue can't distinguish them — both get consumed in one
// Request step. We verify the overall result is correct.
// ============================================================================
#[test]
fn test_batched_calls_same_source() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    let b_reply_1 = wasm().reply_data(b"reply1").build();
    let a_calls_b_1 = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply_1))
        .build();
    let b_reply_2 = wasm().reply_data(b"reply2").build();
    let a_calls_b_2 = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply_2))
        .build();

    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_calls_b_1,
        )
        .unwrap();
    let ingress_b = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_calls_b_2,
        )
        .unwrap();

    // Both ingress messages make calls A→B. We process them fully: the
    // Request step consumes all pending A→B messages, and the Response
    // step consumes all pending B→A responses.
    sm.execute_with_ordering(MessageOrdering(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Ingress(canister_a, ingress_b.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_a), b"reply1");
    assert_eq!(get_reply(&sm, &ingress_b), b"reply2");
}

// ============================================================================
// Test 13: Alternating call-response pattern.
//
// Ingress(A) → Request(B) → Response(A) → Ingress(A) → Request(B) → Response(A)
// ============================================================================
#[test]
fn test_alternating_call_response() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    let b_reply_1 = wasm().reply_data(b"first").build();
    let a_calls_b_1 = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply_1))
        .build();
    let b_reply_2 = wasm().reply_data(b"second").build();
    let a_calls_b_2 = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply_2))
        .build();

    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_calls_b_1,
        )
        .unwrap();
    let ingress_b = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_calls_b_2,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
        OrderedMessage::Ingress(canister_a, ingress_b.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_a), b"first");
    assert_eq!(get_reply(&sm, &ingress_b), b"second");
}

// ============================================================================
// Test 14: Response from uninvolved canister — impossible ordering panics.
// ============================================================================
#[test]
fn test_impossible_ordering_response_from_uninvolved() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);
    let canister_c = install_uc(&sm);

    // A calls B, but we claim C sent a response to A (C was never called).
    let b_reply = wasm().reply_data(b"hi").build();
    let a_payload = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();
    let ingress_id = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering(vec![
            OrderedMessage::Ingress(canister_a, ingress_id.clone()),
            OrderedMessage::Response {
                source: canister_c,
                target: canister_a,
            },
        ]));
    }));
    assert!(
        result.is_err(),
        "Should panic: response from uninvolved canister"
    );
}

// ============================================================================
// Test 15: Request from wrong source — impossible ordering panics.
// ============================================================================
#[test]
fn test_impossible_ordering_wrong_source() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);
    let canister_c = install_uc(&sm);

    let b_reply = wasm().reply_data(b"hi").build();
    let a_payload = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();
    let ingress_id = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    // A called B, but we claim C sent a request to B.
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering(vec![
            OrderedMessage::Ingress(canister_a, ingress_id.clone()),
            OrderedMessage::Request {
                source: canister_c,
                target: canister_b,
            },
        ]));
    }));
    assert!(result.is_err(), "Should panic: wrong source canister");
}

// ============================================================================
// Test 16: Request to canister with no messages — impossible ordering panics.
// ============================================================================
#[test]
fn test_impossible_ordering_no_messages() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    // No ingress submitted — B has no messages from A.
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering(vec![OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        }]));
    }));
    assert!(result.is_err(), "Should panic: no messages in queue");
}
