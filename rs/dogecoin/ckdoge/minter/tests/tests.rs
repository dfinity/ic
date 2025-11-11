use candid::Principal;
use ic_ckdoge_minter::candid_api::{RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError};
use ic_ckdoge_minter_test_utils::{
    DOGECOIN_ADDRESS_1, LEDGER_TRANSFER_FEE, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL,
    assert_trap, utxo_with_value,
};
use std::array;
use std::time::Duration;

#[test]
fn should_fail_withdrawal() {
    let setup = Setup::default();
    let minter = setup.minter();
    let correct_withdrawal_args = RetrieveDogeWithApprovalArgs {
        amount: RETRIEVE_DOGE_MIN_AMOUNT,
        address: DOGECOIN_ADDRESS_1.to_string(),
        from_subaccount: None,
    };

    assert_trap(
        minter.update_call_retrieve_doge_with_approval(
            Principal::anonymous(),
            &correct_withdrawal_args,
        ),
        "anonymous caller not allowed",
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
    );

    setup
        .deposit_flow()
        .minter_get_dogecoin_deposit_address(USER_PRINCIPAL)
        .dogecoin_simulate_transaction(utxo_with_value(RETRIEVE_DOGE_MIN_AMOUNT))
        .minter_update_balance()
        .expect_mint();
    let _ledger_approval_index = setup
        .ledger()
        .icrc2_approve(USER_PRINCIPAL, RETRIEVE_DOGE_MIN_AMOUNT, minter.id())
        .unwrap();

    assert_eq!(
        minter.retrieve_doge_with_approval(
            USER_PRINCIPAL,
            &RetrieveDogeWithApprovalArgs {
                amount: RETRIEVE_DOGE_MIN_AMOUNT,
                ..correct_withdrawal_args.clone()
            },
        ),
        Err(RetrieveDogeWithApprovalError::InsufficientFunds {
            balance: RETRIEVE_DOGE_MIN_AMOUNT - LEDGER_TRANSFER_FEE
        })
    );
}

mod get_doge_address {
    use candid::Principal;
    use ic_ckdoge_minter::candid_api::GetDogeAddressArgs;
    use ic_ckdoge_minter_test_utils::{Setup, USER_PRINCIPAL, assert_trap};

    #[test]
    fn should_fail_to_get_doge_address() {
        let setup = Setup::default();
        let minter = setup.minter();

        assert_trap(
            minter.update_call_get_doge_address(
                USER_PRINCIPAL,
                &GetDogeAddressArgs {
                    owner: Some(Principal::anonymous()),
                    subaccount: None,
                },
            ),
            "owner must be non-anonymous",
        );

        assert_trap(
            minter.update_call_get_doge_address(
                Principal::anonymous(),
                &GetDogeAddressArgs {
                    owner: None,
                    subaccount: None,
                },
            ),
            "owner must be non-anonymous",
        );
    }

    #[test]
    fn should_get_doge_address() {
        let setup = Setup::default();
        let minter = setup.minter();

        let address_from_caller = minter.get_doge_address(
            USER_PRINCIPAL,
            &GetDogeAddressArgs {
                owner: None,
                subaccount: None,
            },
        );

        let address_with_owner = minter.get_doge_address(
            Principal::anonymous(),
            &GetDogeAddressArgs {
                owner: Some(USER_PRINCIPAL),
                subaccount: None,
            },
        );

        assert_eq!(address_from_caller, address_with_owner);
        assert_eq!(
            address_from_caller, "D95u8BQWiN21ER5LqrNwSk4WDVe25WHWHT",
            "BUG: result of public key derivation changed!"
        );

        let address_with_subaccount = minter.get_doge_address(
            USER_PRINCIPAL,
            &GetDogeAddressArgs {
                owner: None,
                subaccount: Some([42_u8; 32]),
            },
        );
        assert_ne!(address_from_caller, address_with_subaccount);
        assert_eq!(
            address_with_subaccount, "DPZ2c7wS53i9nGrMh25iCZABdPs718NRA9",
            "BUG: result of public key derivation changed!"
        );
    }
}

mod deposit {
    use ic_ckdoge_minter_test_utils::{
        LEDGER_TRANSFER_FEE, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL, utxo_with_value,
    };
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_mint_ckdoge() {
        let setup = Setup::default();
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_simulate_transaction(utxo_with_value(
                RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE,
            ))
            .minter_update_balance()
            .expect_mint();
    }
}

mod withdrawal {
    use ic_ckdoge_minter::candid_api::RetrieveDogeWithApprovalError;
    use ic_ckdoge_minter_test_utils::{
        DOGECOIN_ADDRESS_1, LEDGER_TRANSFER_FEE, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL,
        utxo_with_value,
    };
    use icrc_ledger_types::icrc1::account::Account;
    use std::array;

    #[test]
    fn should_withdraw_doge() {
        let setup = Setup::default();
        let dogecoin = setup.dogecoin();
        let fee_percentiles = array::from_fn(|i| i as u64);
        let median_fee = fee_percentiles[50];
        assert_eq!(median_fee, 50);
        dogecoin.set_fee_percentiles(fee_percentiles);
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };
        let utxo = utxo_with_value(RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE);

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_simulate_transaction(utxo.clone())
            .minter_update_balance()
            .expect_mint();

        setup
            .withdrawal_flow()
            .ledger_approve_minter(account, RETRIEVE_DOGE_MIN_AMOUNT)
            .minter_retrieve_doge_with_approval(RETRIEVE_DOGE_MIN_AMOUNT, DOGECOIN_ADDRESS_1)
            .expect_withdrawal_request_accepted()
            .dogecoin_await_transaction(vec![utxo])
            .verify_withdrawal_transaction()
    }

    #[test]
    fn should_fail_to_withdraw_when_ledger_stopped() {
        let setup = Setup::default();
        let dogecoin = setup.dogecoin();
        let fee_percentiles = array::from_fn(|i| i as u64);
        let median_fee = fee_percentiles[50];
        assert_eq!(median_fee, 50);
        dogecoin.set_fee_percentiles(fee_percentiles);
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };
        let utxo = utxo_with_value(RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE);

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_simulate_transaction(utxo.clone())
            .minter_update_balance()
            .expect_mint();

        let withdrawal_flow = setup
            .withdrawal_flow()
            .ledger_approve_minter(account, RETRIEVE_DOGE_MIN_AMOUNT);

        setup.ledger().stop();

        withdrawal_flow
            .minter_retrieve_doge_with_approval(RETRIEVE_DOGE_MIN_AMOUNT, DOGECOIN_ADDRESS_1)
            .expect_error_matching(|e| {
                matches!(e, RetrieveDogeWithApprovalError::TemporarilyUnavailable(_))
            })
    }
}

#[test]
fn should_refresh_fee_percentiles() {
    let setup = Setup::default();
    let dogecoin = setup.dogecoin();
    let minter = setup.minter();
    let fee_percentiles = array::from_fn(|i| i as u64);
    let median_fee = fee_percentiles[50];
    assert_eq!(median_fee, 50);
    dogecoin.set_fee_percentiles(fee_percentiles);
    setup.env.advance_time(Duration::from_secs(60 * 6 + 1));
    setup.env.tick();
    setup.env.tick();
    setup.env.tick();

    minter
        .assert_that_metrics()
        .assert_contains_metric_matching(format!("ckbtc_minter_median_fee_per_vbyte {median_fee}"));
}

#[test]
fn should_get_logs() {
    let setup = Setup::default();
    let minter = setup.minter();

    let logs = minter.get_logs();
    let init_log = logs.first().unwrap();

    assert!(
        init_log.message.contains("[init]"),
        "Expected first log message to be for canister initialization but got: {}",
        init_log.message
    );
}
