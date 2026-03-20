use ic_base_types::PrincipalId;
use ic_state_machine_tests::{
    MessageOrdering, OrderedMessage, StateMachine, StateMachineBuilder, WasmResult,
};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types_cycles::Cycles;
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};

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
