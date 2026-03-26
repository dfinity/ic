use ic_base_types::PrincipalId;
use ic_management_canister_types_private::{
    CanisterInstallMode, IC_00, InstallCodeArgs, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs,
};
use ic_replicated_state::canister_state::execution_state::NextScheduledMethod;
use ic_state_machine_tests::{
    MessageOrdering, OrderedMessage, StateMachine, StateMachineBuilder, WasmResult,
};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types_cycles::Cycles;
use ic_universal_canister::{CallArgs, CallInterface, UNIVERSAL_CANISTER_WASM, management, wasm};
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

fn get_reply(sm: &StateMachine, msg_id: &ic_types::messages::MessageId) -> Vec<u8> {
    match sm.ingress_status(msg_id) {
        IngressStatus::Known {
            state: IngressState::Completed(WasmResult::Reply(bytes)),
            ..
        } => bytes,
        other => panic!("Expected completed reply, got: {:?}", other),
    }
}

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

    sm.execute_with_ordering(MessageOrdering::new(vec![
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

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister, id1.clone()),
        OrderedMessage::Ingress(canister, id2.clone()),
    ]));

    assert_eq!(get_reply(&sm, &id1), b"ok1");
    assert_eq!(get_reply(&sm, &id2), b"ok2");

    let read_payload = wasm().get_global_data().append_and_reply().build();
    let result = sm
        .execute_ingress(canister, "update", read_payload)
        .unwrap();
    match result {
        WasmResult::Reply(data) => assert_eq!(data, b"second"),
        _ => panic!("Expected reply"),
    }
}

/// Reversed ordering — last writer wins.
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

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister, id2.clone()),
        OrderedMessage::Ingress(canister, id1.clone()),
    ]));

    assert_eq!(get_reply(&sm, &id1), b"ok1");
    assert_eq!(get_reply(&sm, &id2), b"ok2");

    let read_payload = wasm().get_global_data().append_and_reply().build();
    let result = sm
        .execute_ingress(canister, "update", read_payload)
        .unwrap();
    match result {
        WasmResult::Reply(data) => assert_eq!(data, b"first"),
        _ => panic!("Expected reply"),
    }
}

/// A → B → C → B → A chain.
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

    sm.execute_with_ordering(MessageOrdering::new(vec![
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

#[test]
fn test_normal_tick_regression() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    let b_reply = wasm().reply_data(b"normal reply").build();
    let a_payload = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();

    let result = sm.execute_ingress(canister_a, "update", a_payload).unwrap();
    match result {
        WasmResult::Reply(data) => assert_eq!(data, b"normal reply"),
        _ => panic!("Expected reply"),
    }
}

/// Two independent chains (A→B, C→D) interleaved.
#[test]
fn test_interleaved_inter_canister_calls() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);
    let canister_c = install_uc(&sm);
    let canister_d = install_uc(&sm);

    let b_reply = wasm().reply_data(b"reply from B").build();
    let a_calls_b = wasm()
        .inter_update(canister_b, CallArgs::default().other_side(b_reply))
        .build();

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

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Ingress(canister_c, ingress_c.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Request {
            source: canister_c,
            target: canister_d,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
        OrderedMessage::Response {
            source: canister_d,
            target: canister_c,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_a), b"reply from B");
    assert_eq!(get_reply(&sm, &ingress_c), b"reply from D");
}

/// install_code interleaved with inter-canister calls.
#[test]
fn test_subnet_message_ordering() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

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

    let new_b_wasm = UNIVERSAL_CANISTER_WASM.to_vec();
    let install_args =
        InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister_b, new_b_wasm, vec![]);
    let install_ingress = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            IC_00,
            "install_code",
            install_args.encode(),
        )
        .unwrap();

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

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
        OrderedMessage::Ingress(IC_00, install_ingress.clone()),
        OrderedMessage::Ingress(canister_a, ingress_a2.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_a), b"before upgrade");
    match sm.ingress_status(&install_ingress) {
        IngressStatus::Known {
            state: IngressState::Completed(_),
            ..
        } => {}
        other => panic!("Expected install_code to complete, got: {:?}", other),
    }
    assert_eq!(get_reply(&sm, &ingress_a2), b"after upgrade");
}

/// Canister calls create_canister on IC_00 via inter-canister call.
#[test]
fn test_canister_calls_management_canister() {
    let sm = setup();
    let canister_a = install_uc(&sm);

    let on_reply = wasm().message_payload().reply_data_append().reply().build();
    let a_payload = wasm()
        .call(management::create_canister(INITIAL_CYCLES_BALANCE.get() / 2).on_reply(on_reply))
        .build();

    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: IC_00,
        },
        OrderedMessage::Response {
            source: IC_00,
            target: canister_a,
        },
    ]));

    let reply = get_reply(&sm, &ingress_a);
    assert!(
        !reply.is_empty(),
        "Expected non-empty reply with canister ID"
    );
}

/// Two mgmt canister ingress in separate steps — only one completes per step.
#[test]
fn test_one_subnet_message_per_round() {
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
            IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            args.clone(),
        )
        .unwrap();
    let id2 = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            IC_00,
            Method::ProvisionalCreateCanisterWithCycles,
            args,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering::new(vec![OrderedMessage::Ingress(
        IC_00,
        id1.clone(),
    )]));

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

    sm.execute_with_ordering(MessageOrdering::new(vec![OrderedMessage::Ingress(
        IC_00,
        id2.clone(),
    )]));

    assert!(
        is_done(&id2),
        "Second create_canister should be done: {:?}",
        sm.ingress_status(&id2)
    );
}

/// DTS: message sliced across multiple rounds.
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

    sm.execute_with_ordering(MessageOrdering::new(vec![OrderedMessage::Ingress(
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

#[test]
fn test_panics_without_flexible_ordering() {
    let sm = StateMachineBuilder::new().build();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering::new(vec![]));
    }));
    assert!(result.is_err(), "Should panic without flexible ordering");
}

/// Two calls A→B, each request/response handled separately.
#[test]
fn test_two_calls_same_source_separate_steps() {
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

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Ingress(canister_a, ingress_b.clone()),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_a), b"reply1");
    assert_eq!(get_reply(&sm, &ingress_b), b"reply2");
}

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

    sm.execute_with_ordering(MessageOrdering::new(vec![
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

#[test]
fn test_impossible_ordering_response_from_uninvolved() {
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

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering::new(vec![
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

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering::new(vec![
            OrderedMessage::Ingress(canister_a, ingress_id.clone()),
            OrderedMessage::Request {
                source: canister_c,
                target: canister_b,
            },
        ]));
    }));
    assert!(result.is_err(), "Should panic: wrong source canister");
}

#[test]
fn test_impossible_ordering_no_messages() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering::new(vec![OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        }]));
    }));
    assert!(result.is_err(), "Should panic: no messages in queue");
}

#[test]
fn test_request_with_heartbeat() {
    fn heartbeat_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "ic0" "msg_reply" (func $msg_reply))
                (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
                (func $heartbeat
                    (i32.store (i32.const 0)
                        (i32.add (i32.load (i32.const 0)) (i32.const 1))))
                (func $read
                    (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                    (call $msg_reply))
                (memory 1)
                (export "canister_heartbeat" (func $heartbeat))
                (export "canister_update read" (func $read))
            )"#,
        )
        .unwrap()
    }

    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = sm.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);
    sm.install_wasm_in_mode(
        canister_b,
        ic_management_canister_types_private::CanisterInstallMode::Install,
        heartbeat_wasm(),
        vec![],
    )
    .unwrap();

    let a_payload = wasm()
        .call_simple(canister_b, "read", CallArgs::default())
        .build();
    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Heartbeat(canister_b),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    let reply = get_reply(&sm, &ingress_a);
    let counter = u32::from_le_bytes(reply[..4].try_into().unwrap());
    assert!(
        counter >= 1,
        "Heartbeat should have run, counter={}",
        counter
    );
}

#[test]
fn test_request_with_timer() {
    fn timer_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "ic0" "msg_reply" (func $msg_reply))
                (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
                (import "ic0" "global_timer_set" (func $global_timer_set (param i64) (result i64)))
                (func $init
                    (drop (call $global_timer_set (i64.const 1))))
                (func $timer
                    (i32.store (i32.const 0)
                        (i32.add (i32.load (i32.const 0)) (i32.const 1)))
                    (drop (call $global_timer_set (i64.const 1))))
                (func $read
                    (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                    (call $msg_reply))
                (memory 1)
                (export "canister_init" (func $init))
                (export "canister_global_timer" (func $timer))
                (export "canister_update read" (func $read))
            )"#,
        )
        .unwrap()
    }

    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = sm.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);
    sm.install_wasm_in_mode(
        canister_b,
        ic_management_canister_types_private::CanisterInstallMode::Install,
        timer_wasm(),
        vec![],
    )
    .unwrap();

    let a_payload = wasm()
        .call_simple(canister_b, "read", CallArgs::default())
        .build();
    let ingress_a = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister_a, ingress_a.clone()),
        OrderedMessage::Timer(canister_b),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    let reply = get_reply(&sm, &ingress_a);
    let counter = u32::from_le_bytes(reply[..4].try_into().unwrap());
    assert!(counter >= 1, "Timer should have fired, counter={}", counter);
}

#[test]
fn test_self_call() {
    let sm = setup();
    let canister = install_uc(&sm);

    let self_reply = wasm().reply_data(b"self-reply").build();
    let payload = wasm()
        .inter_update(canister, CallArgs::default().other_side(self_reply))
        .build();

    let ingress_id = sm
        .buffer_ingress_as(PrincipalId::new_anonymous(), canister, "update", payload)
        .unwrap();

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister, ingress_id.clone()),
        OrderedMessage::Request {
            source: canister,
            target: canister,
        },
        OrderedMessage::Response {
            source: canister,
            target: canister,
        },
    ]));

    assert_eq!(get_reply(&sm, &ingress_id), b"self-reply");
}

#[test]
fn test_strict_basic_ordering() {
    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = install_uc(&sm);

    let b_reply = wasm().reply_data(b"strict reply").build();
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

    sm.execute_with_ordering(MessageOrdering::strict(
        vec![
            (canister_a, NextScheduledMethod::Message),
            (canister_b, NextScheduledMethod::Message),
        ],
        vec![
            OrderedMessage::Ingress(canister_a, ingress_id.clone()),
            OrderedMessage::Request {
                source: canister_a,
                target: canister_b,
            },
            OrderedMessage::Response {
                source: canister_b,
                target: canister_a,
            },
        ],
    ));

    assert_eq!(get_reply(&sm, &ingress_id), b"strict reply");
}

/// Heartbeat before request (relaxed — strict is impractical because
/// initialize_inner_round advances round-robin for ALL canisters every round).
#[test]
fn test_strict_heartbeat_then_request() {
    fn heartbeat_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "ic0" "msg_reply" (func $msg_reply))
                (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
                (func $heartbeat
                    (i32.store (i32.const 0)
                        (i32.add (i32.load (i32.const 0)) (i32.const 1))))
                (func $read
                    (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                    (call $msg_reply))
                (memory 1)
                (export "canister_heartbeat" (func $heartbeat))
                (export "canister_update read" (func $read))
            )"#,
        )
        .unwrap()
    }

    let sm = setup();
    let canister_a = install_uc(&sm);
    let canister_b = sm.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);
    sm.install_wasm_in_mode(
        canister_b,
        ic_management_canister_types_private::CanisterInstallMode::Install,
        heartbeat_wasm(),
        vec![],
    )
    .unwrap();

    let a_payload = wasm()
        .call_simple(canister_b, "read", CallArgs::default())
        .build();
    let ingress_id = sm
        .buffer_ingress_as(
            PrincipalId::new_anonymous(),
            canister_a,
            "update",
            a_payload,
        )
        .unwrap();

    sm.execute_with_ordering(MessageOrdering::new(vec![
        OrderedMessage::Ingress(canister_a, ingress_id.clone()),
        OrderedMessage::Heartbeat(canister_b),
        OrderedMessage::Request {
            source: canister_a,
            target: canister_b,
        },
        OrderedMessage::Response {
            source: canister_b,
            target: canister_a,
        },
    ]));

    let reply = get_reply(&sm, &ingress_id);
    let counter = u32::from_le_bytes(reply[..4].try_into().unwrap());
    assert!(
        counter >= 1,
        "Heartbeat should have run, counter={}",
        counter
    );
}

#[test]
fn test_strict_wrong_ordering_panics() {
    let sm = setup();
    let canister = install_uc(&sm);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        sm.execute_with_ordering(MessageOrdering::strict(
            vec![(canister, NextScheduledMethod::Heartbeat)],
            vec![OrderedMessage::Timer(canister)],
        ));
    }));
    assert!(
        result.is_err(),
        "Should panic: prediction is Heartbeat, not GlobalTimer"
    );
}
