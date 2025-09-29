use assert_matches::assert_matches;
use candid::Principal;
use ic_ckdoge_minter::candid_api::{RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError};
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
        // TODO XC-495 Fix me!
        // The error should be RetrieveDogeWithApprovalError::InsufficientAllowance, since the user
        // did not allow the minter to burn.
        Err(RetrieveDogeWithApprovalError::MalformedAddress(
            "ckBTC supports only P2WPKH and P2PKH addresses".to_string()
        ))
    )
}
