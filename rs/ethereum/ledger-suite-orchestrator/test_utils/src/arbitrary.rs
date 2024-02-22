use candid::Principal;
use ic_ledger_suite_orchestrator::candid::InitArg;
use proptest::arbitrary::any;
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::Strategy;

pub fn arb_init_arg() -> impl Strategy<Value = InitArg> {
    // at most 10 principals, including the orchestrator's principal
    (vec(arb_principal(), 0..=9), option::of(arb_principal())).prop_map(
        |(more_controller_ids, minter_id)| InitArg {
            more_controller_ids,
            minter_id,
        },
    )
}

fn arb_principal() -> impl Strategy<Value = Principal> {
    vec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
}
