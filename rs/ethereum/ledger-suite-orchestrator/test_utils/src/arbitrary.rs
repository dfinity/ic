use candid::Principal;
use ic_ledger_suite_orchestrator::candid::InitArg;
use proptest::arbitrary::any;
use proptest::collection::vec;
use proptest::prelude::Strategy;

pub fn arb_init_arg() -> impl Strategy<Value = InitArg> {
    // at most 10 principals, including the orchestrator's principal
    vec(arb_principal(), 0..=9).prop_map(|more_controller_ids| InitArg {
        more_controller_ids,
    })
}

fn arb_principal() -> impl Strategy<Value = Principal> {
    vec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
}
