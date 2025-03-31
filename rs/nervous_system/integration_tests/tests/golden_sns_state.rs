use candid::Nat;
use ic_nervous_system_integration_tests::pocket_ic_helpers::sns;
use ic_nns_test_utils_golden_nns_state::new_pocket_ic_with_golden_state_or_panic;
use ic_base_types::PrincipalId;
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use std::str::FromStr;

#[tokio::test]
async fn golden_sns_state_test() {
    run_golden_sns_state_test().await
}

async fn run_golden_sns_state_test() {
    let pocket_ic = new_pocket_ic_with_golden_state_or_panic().await;
}
