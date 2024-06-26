use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger_sm_tests::metrics::retrieve_metrics;
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_fiduciary_state_or_panic;
use std::str::FromStr;

#[test]
fn should_upgrade_and_downgrade_icrc_canisters_with_golden_state() {
    let state_machine = new_state_machine_with_golden_fiduciary_state_or_panic();
    let ck_btc_ledger_canister_id = CanisterId::unchecked_from_principal(
        PrincipalId::from_str("mxzaz-hqaaa-aaaar-qaada-cai").unwrap(),
    );
    let metrics = retrieve_metrics(&state_machine, ck_btc_ledger_canister_id);
    for metric in &metrics {
        println!("{}", metric);
    }

    assert_eq!(1, 3);
}
