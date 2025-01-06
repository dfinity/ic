use candid::{Encode, Principal};
use ic_base_types::PrincipalId;
use ic_management_canister_types::{CanisterIdRecord, CanisterSettingsArgsBuilder, Method};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
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

#[test]
fn test_induct_same_subnet_management_messages() {
    let sm = StateMachine::new();
    let canister1 = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let canister_settings_args = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![canister1.into()])
        .build();
    let canister2 = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(canister_settings_args),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    sm.stop_canister_as(canister1.into(), canister2).unwrap();
    sm.tick();
    // Now, canister1 should be able to delete canister2.
    let deletion_call = wasm()
        .call_simple(
            Principal::management_canister(),
            Method::DeleteCanister,
            call_args()
                .other_side(Encode!(&CanisterIdRecord::from(canister2)).unwrap())
                .on_reply(wasm().reply())
                .on_reject(wasm().reject_message().reject()),
        )
        .build();
    let ingress_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        canister1,
        "update",
        deletion_call,
    );
    // Should be Known, but not Done yet
    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
    ));
    sm.tick();
    // due to the subnet message optimization, one tick should be enough to:
    // - execute message on canister1, which causes a message to the mgmt canister
    // - execute the message on the mgmt canister, which deletes canister2
    // - respond to canister1 and execute its callback, ending the call context.
    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known {
            state: IngressState::Completed(..),
            ..
        }
    ));
    // observe the effect: canister2 should be gone.
    assert_eq!(sm.get_latest_state().canister_state(&canister2), None);
}

#[test]
fn test_postponing_raw_rand_management_message() {
    let sm = StateMachine::new();
    let canister_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let rand_call = wasm()
        .call_simple(
            Principal::management_canister(),
            Method::RawRand,
            call_args()
                .other_side(Encode!().unwrap())
                .on_reject(wasm().reject_message().reject()),
        )
        .build();
    let ingress_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        rand_call,
    );
    sm.tick();
    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known {
            state: IngressState::Processing,
            ..
        }
    ));
    // One tick is not enough: The raw request is postponed to the next round.
    assert_eq!(
        sm.get_latest_state()
            .subnet_queues()
            .output_queues_message_count(),
        0
    );
    assert_eq!(
        sm.get_latest_state()
            .subnet_queues()
            .output_queues_message_count(),
        0
    );
    assert_eq!(
        sm.get_latest_state()
            .metadata
            .subnet_call_context_manager
            .raw_rand_contexts
            .len(),
        1
    );
    sm.tick();
    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known {
            state: IngressState::Completed(..),
            ..
        }
    ));
    println!("res: {:?}", sm.ingress_status(&ingress_id));
}
