use crate::candid::{CyclesManagement, InitArg};
use crate::state::State;
use candid::Principal;
use proptest::arbitrary::any;
use proptest::collection::{SizeRange, vec};
use proptest::option;
use proptest::prelude::Strategy;

pub fn new_state() -> State {
    new_state_from(InitArg::default())
}

pub fn new_state_from(init_arg: InitArg) -> State {
    State::try_from(init_arg).unwrap()
}

pub fn expect_panic_with_message<F: FnOnce() -> R, R: std::fmt::Debug>(
    f: F,
    expected_message: &str,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let error = result.unwrap_err();
    let panic_message = {
        if let Some(s) = error.downcast_ref::<String>() {
            s.to_string()
        } else if let Some(s) = error.downcast_ref::<&str>() {
            s.to_string()
        } else {
            format!("{error:?}")
        }
    };
    assert!(
        panic_message.contains(expected_message),
        "Expected panic message to contain: {expected_message}, but got: {panic_message}"
    );
}

pub fn arb_state() -> impl Strategy<Value = State> {
    arb_init_arg(0..=9)
        .prop_map(State::try_from)
        .prop_map(Result::unwrap)
}

pub fn arb_init_arg(size: impl Into<SizeRange>) -> impl Strategy<Value = InitArg> {
    // at most 10 principals, including the orchestrator's principal
    (
        vec(arb_principal(), size),
        option::of(arb_principal()),
        option::of(arb_cycles_management()),
    )
        .prop_map(
            |(more_controller_ids, minter_id, cycles_management)| InitArg {
                more_controller_ids,
                minter_id,
                cycles_management,
            },
        )
}

pub fn arb_principal() -> impl Strategy<Value = Principal> {
    vec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
}

fn arb_cycles_management() -> impl Strategy<Value = CyclesManagement> {
    (arb_nat(), arb_nat(), arb_nat(), arb_nat()).prop_map(
        |(
            cycles_for_ledger_creation,
            cycles_for_archive_creation,
            cycles_for_index_creation,
            cycles_top_up_increment,
        )| CyclesManagement {
            cycles_for_ledger_creation,
            cycles_for_archive_creation,
            cycles_for_index_creation,
            cycles_top_up_increment,
        },
    )
}

fn arb_nat() -> impl Strategy<Value = candid::Nat> {
    any::<u64>().prop_map(candid::Nat::from)
}
