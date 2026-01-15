use ic_base_types::PrincipalId;
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::Cycles;
use ic_types::ingress::IngressStatus;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use maplit::btreemap;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

#[test]
fn scheduler_observes_inducted_messages_to_self() {
    let sm = StateMachine::new();

    let a_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Canister A calls self
    let a_calls_self_wasm = wasm().inter_update(a_id, call_args()).build();
    let ingress_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        a_id,
        "update",
        a_calls_self_wasm,
    );

    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known { .. }
    ));

    let inducted_messages =
        fetch_int_counter_vec(sm.metrics_registry(), "scheduler_inducted_messages_total");
    let destination_self = btreemap! {
        "destination".into() => "self".into(),
    };
    // Call and reply
    assert_eq!(2, inducted_messages[&destination_self]);
}

#[test]
fn scheduler_observes_inducted_messages_to_others() {
    let sm = StateMachine::new();

    let a_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let b_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Canister A calls canister B
    let a_calls_b_wasm = wasm().inter_update(b_id, call_args()).build();
    let ingress_id = sm.send_ingress(PrincipalId::new_anonymous(), a_id, "update", a_calls_b_wasm);

    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known { .. }
    ));

    let inducted_messages =
        fetch_int_counter_vec(sm.metrics_registry(), "scheduler_inducted_messages_total");
    let destination_others = btreemap! {
        "destination".into() => "others".into(),
    };
    // Call and reply
    assert_eq!(2, inducted_messages[&destination_others]);
}
