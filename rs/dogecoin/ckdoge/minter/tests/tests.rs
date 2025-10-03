use assert_matches::assert_matches;
use candid::Principal;
use ic_ckdoge_minter::candid_api::{
    GetDogeAddressArgs, RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError,
};
use ic_ckdoge_minter_test_utils::{
    DOGECOIN_ADDRESS_1, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL,
};
use pocket_ic::{ErrorCode, RejectCode, RejectResponse};

#[test]
fn should_fail_withdrawal() {
    let setup = Setup::default();
    let minter = setup.minter();
    let correct_withdrawal_args = RetrieveDogeWithApprovalArgs {
        amount: RETRIEVE_DOGE_MIN_AMOUNT,
        address: DOGECOIN_ADDRESS_1.to_string(),
        from_subaccount: None,
    };

    assert_matches!(
        minter.update_call_retrieve_doge_with_approval(
            Principal::anonymous(),
            &correct_withdrawal_args
        ),
        Err(RejectResponse {reject_code, reject_message, error_code, ..}) if
            reject_code == RejectCode::CanisterError &&
            reject_message.contains("anonymous caller not allowed") &&
            error_code == ErrorCode::CanisterCalledTrap
    );

    assert_eq!(
        minter.retrieve_doge_with_approval(
            USER_PRINCIPAL,
            &RetrieveDogeWithApprovalArgs {
                amount: RETRIEVE_DOGE_MIN_AMOUNT - 1,
                ..correct_withdrawal_args.clone()
            },
        ),
        Err(RetrieveDogeWithApprovalError::AmountTooLow(
            RETRIEVE_DOGE_MIN_AMOUNT
        ))
    );

    assert_eq!(
        minter.retrieve_doge_with_approval(
            USER_PRINCIPAL,
            &RetrieveDogeWithApprovalArgs {
                amount: RETRIEVE_DOGE_MIN_AMOUNT,
                ..correct_withdrawal_args.clone()
            },
        ),
        Err(RetrieveDogeWithApprovalError::InsufficientAllowance { allowance: 0 })
    )

    // TODO XC-495: create sufficient allowance (which requires funds to pay for the ledger fee)
    // and test failure when insufficient funds
}

#[test]
fn should_fail_to_get_doge_address() {
    let setup = Setup::default();
    let minter = setup.minter();

    assert_matches!(
        minter.update_call_get_doge_address(
            USER_PRINCIPAL,
            &GetDogeAddressArgs {
                owner: Some(Principal::anonymous()),
                subaccount: None
            }
        ),
        Err(RejectResponse {reject_code, reject_message, error_code, ..}) if
            reject_code == RejectCode::CanisterError &&
            reject_message.contains("owner must be non-anonymous") &&
            error_code == ErrorCode::CanisterCalledTrap
    );

    assert_matches!(
        minter.update_call_get_doge_address(
            Principal::anonymous(),
            &GetDogeAddressArgs {
                owner: None,
                subaccount: None
            }
        ),
        Err(RejectResponse {reject_code, reject_message, error_code, ..}) if
            reject_code == RejectCode::CanisterError &&
            reject_message.contains("owner must be non-anonymous") &&
            error_code == ErrorCode::CanisterCalledTrap
    );
}
