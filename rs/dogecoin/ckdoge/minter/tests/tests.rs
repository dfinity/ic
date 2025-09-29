use candid::Principal;
use ic_ckdoge_minter::candid_api::{RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError};
use ic_ckdoge_minter_test_utils::{DOGECOIN_ADDRESS_1, Setup};

#[test]
fn should_fail_withdrawal() {
    let setup = Setup::default();
    let minter = setup.minter();

    let result = minter.retrieve_doge_with_approval(
        Principal::anonymous(),
        &RetrieveDogeWithApprovalArgs {
            amount: 100,
            address: DOGECOIN_ADDRESS_1.to_string(),
            from_subaccount: None,
        },
    );

    assert_eq!(
        result,
        Err(RetrieveDogeWithApprovalError::InsufficientAllowance { allowance: 0 })
    )
}
