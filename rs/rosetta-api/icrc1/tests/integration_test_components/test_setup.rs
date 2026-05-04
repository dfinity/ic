use crate::common::local_replica::{
    create_and_install_icrc_ledger, icrc_ledger_default_args_builder,
};
use pocket_ic::PocketIcBuilder;

#[test]
fn smoke_test() {
    // This is how you create and start a new local replica
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build();
    let icrc_ledger_canister_id = create_and_install_icrc_ledger(
        &pocket_ic,
        icrc_ledger_default_args_builder().build(),
        None,
    );
    println!("The canister id of the icrc ledger is: {icrc_ledger_canister_id:?}");
}
