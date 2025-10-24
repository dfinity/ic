use candid::Principal;
use ic_ckdoge_minter::candid_api::{RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError};
use ic_ckdoge_minter_test_utils::{
    DOGECOIN_ADDRESS_1, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL, assert_trap,
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
    )

    // TODO XC-495: create sufficient allowance (which requires funds to pay for the ledger fee)
    // and test failure when insufficient funds
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
    use candid::Principal;
    use ic_ckdoge_minter::{
        EventType, MintMemo, OutPoint, UpdateBalanceArgs, Utxo, UtxoStatus,
        candid_api::GetDogeAddressArgs, memo_encode,
    };
    use ic_ckdoge_minter_test_utils::{Setup, USER_PRINCIPAL, txid};
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use icrc_ledger_types::icrc3::transactions::Mint;

    #[test]
    fn should_mint_ckdoge() {
        let setup = Setup::default();
        let minter = setup.minter();
        let ledger = setup.ledger();
        let dogecoin = setup.dogecoin();
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };

        let deposit_address = minter.get_doge_address(
            Principal::anonymous(),
            &GetDogeAddressArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
        );

        let utxo = Utxo {
            height: 0,
            outpoint: OutPoint {
                txid: txid(),
                vout: 1,
            },
            value: 1_000_000_000,
        };
        dogecoin.simulate_transaction(utxo.clone(), deposit_address);

        let utxo_status = minter
            .update_balance(
                account.owner,
                &UpdateBalanceArgs {
                    owner: Some(account.owner),
                    subaccount: account.subaccount,
                },
            )
            .unwrap();
        assert_eq!(
            utxo_status,
            vec![UtxoStatus::Minted {
                block_index: 0,
                minted_amount: utxo.value,
                utxo: utxo.clone(),
            }]
        );

        ledger
            .assert_that_transaction(0_u64)
            .equals_mint_ignoring_timestamp(Mint {
                amount: utxo.value.into(),
                to: account,
                memo: Some(Memo::from(memo_encode(&MintMemo::Convert {
                    txid: Some(utxo.outpoint.txid.as_ref()),
                    vout: Some(utxo.outpoint.vout),
                    kyt_fee: Some(0),
                }))),
                created_at_time: None,
                fee: None,
            });

        minter.assert_that_events().contains_only_once_in_order(&[
            EventType::CheckedUtxoV2 {
                utxo: utxo.clone(),
                account,
            },
            EventType::ReceivedUtxos {
                mint_txid: Some(0),
                to_account: account,
                utxos: vec![utxo],
            },
        ]);
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
