use candid::Principal;
use ic_ledger_suite_orchestrator::candid::{CyclesManagement, InitArg};
use proptest::arbitrary::any;
use proptest::collection::vec;
use proptest::option;
use proptest::prelude::Strategy;

pub fn arb_init_arg() -> impl Strategy<Value = InitArg> {
    // at most 10 principals, including the orchestrator's principal
    (
        vec(arb_principal(), 0..=9),
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
