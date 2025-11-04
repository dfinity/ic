use candid::Principal;
use ic_ckdoge_minter::candid_api::{RetrieveDogeWithApprovalArgs, RetrieveDogeWithApprovalError};
use ic_ckdoge_minter_test_utils::{
    DOGECOIN_ADDRESS_1, LEDGER_TRANSFER_FEE, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL,
    assert_trap, utxo_wth_value,
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
        .dogecoin_simulate_transaction(utxo_wth_value(RETRIEVE_DOGE_MIN_AMOUNT))
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
        LEDGER_TRANSFER_FEE, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL, utxo_wth_value,
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
            .dogecoin_simulate_transaction(utxo_wth_value(
                RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE,
            ))
            .minter_update_balance()
            .expect_mint();
    }
}

mod withdrawal {
    use candid::Principal;
    use ic_ckdoge_minter::address::DogecoinAddress;
    use ic_ckdoge_minter::candid_api::{RetrieveDogeStatus, RetrieveDogeWithApprovalArgs};
    use ic_ckdoge_minter::lifecycle::init::Network;
    use ic_ckdoge_minter::{
        BitcoinAddress, BurnMemo, ChangeOutput, EventType, RetrieveBtcRequest, WithdrawalFee,
        candid_api::GetDogeAddressArgs, memo_encode,
    };
    use ic_ckdoge_minter_test_utils::{
        DOGECOIN_ADDRESS_1, LEDGER_TRANSFER_FEE, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL,
        into_outpoint, parse_dogecoin_address, utxo_wth_value,
    };
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use icrc_ledger_types::icrc3::transactions::Burn;
    use pocket_ic::Time;
    use std::array;

    #[test]
    fn should_withdraw_doge() {
        let setup = Setup::default();
        let minter = setup.minter();
        let ledger = setup.ledger();
        let dogecoin = setup.dogecoin();
        let fee_percentiles = array::from_fn(|i| i as u64);
        let median_fee = fee_percentiles[50];
        assert_eq!(median_fee, 50);
        dogecoin.set_fee_percentiles(fee_percentiles);
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };
        let minter_address = minter.get_doge_address(
            Principal::anonymous(),
            &GetDogeAddressArgs {
                owner: Some(minter.id()),
                subaccount: None,
            },
        );
        let utxo = utxo_wth_value(RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE);

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_simulate_transaction(utxo.clone())
            .minter_update_balance()
            .expect_mint();

        let _ledger_approval_index = ledger
            .icrc2_approve(account, RETRIEVE_DOGE_MIN_AMOUNT, minter.id())
            .unwrap();
        assert_eq!(RETRIEVE_DOGE_MIN_AMOUNT, ledger.icrc1_balance_of(account));

        let beneficiary_address =
            DogecoinAddress::parse(DOGECOIN_ADDRESS_1, &Network::Mainnet).unwrap();
        let time_of_retrieval = Time::from_nanos_since_unix_epoch(1760709476000000000);

        setup.env.set_time(time_of_retrieval);
        let retrieve_doge_id = minter
            .retrieve_doge_with_approval(
                USER_PRINCIPAL,
                &RetrieveDogeWithApprovalArgs {
                    amount: RETRIEVE_DOGE_MIN_AMOUNT,
                    from_subaccount: account.subaccount,
                    address: DOGECOIN_ADDRESS_1.to_string(),
                },
            )
            .unwrap();
        assert_eq!(
            minter.retrieve_doge_status(retrieve_doge_id.block_index),
            RetrieveDogeStatus::Pending
        );
        minter.assert_that_events().contains_only_once_in_order(&[
            EventType::AcceptedRetrieveBtcRequest(RetrieveBtcRequest {
                amount: RETRIEVE_DOGE_MIN_AMOUNT,
                address: BitcoinAddress::P2pkh(
                    beneficiary_address.as_bytes().to_vec().try_into().unwrap(),
                ),
                block_index: retrieve_doge_id.block_index,
                received_at: time_of_retrieval.as_nanos_since_unix_epoch(),
                kyt_provider: None,
                reimbursement_account: Some(account),
            }),
        ]);

        ledger
            .assert_that_transaction(retrieve_doge_id.block_index)
            .equals_burn_ignoring_timestamp(Burn {
                amount: RETRIEVE_DOGE_MIN_AMOUNT.into(),
                from: account,
                spender: Some(minter.id().into()),
                memo: Some(Memo::from(memo_encode(&BurnMemo::Convert {
                    address: Some(DOGECOIN_ADDRESS_1),
                    kyt_fee: None,
                    status: None,
                }))),
                created_at_time: None,
                fee: None,
            });

        let txid = minter.await_doge_transaction(retrieve_doge_id.block_index);
        // TODO XC-496: fix fee handling
        let change_amount = 1_000_300;
        let withdrawal_fee = WithdrawalFee {
            minter_fee: 300,
            bitcoin_fee: 220,
        };
        minter
            .assert_that_events()
            .ignoring_timestamp()
            .contains_only_once_in_order(&[EventType::SentBtcTransaction {
                request_block_indices: vec![retrieve_doge_id.block_index],
                txid,
                utxos: vec![utxo.clone()],
                change_output: Some(ChangeOutput {
                    vout: 1,
                    value: change_amount,
                }),
                submitted_at: 0, //not relevant
                fee_per_vbyte: Some(1_500),
                withdrawal_fee: Some(withdrawal_fee),
            }]);
        let mempool = dogecoin.mempool();
        assert_eq!(
            mempool.len(),
            1,
            "ckDOGE transaction did not appear in the mempool"
        );
        let tx = mempool
            .get(&txid)
            .expect("the mempool does not contain the withdrawal transaction");
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, into_outpoint(utxo.outpoint));

        assert_eq!(tx.output.len(), 2);
        let beneficiary = parse_dogecoin_address(setup.network(), tx.output.first().unwrap());
        assert_eq!(DOGECOIN_ADDRESS_1, beneficiary.to_string());
        let amount_received =
            RETRIEVE_DOGE_MIN_AMOUNT - withdrawal_fee.bitcoin_fee - withdrawal_fee.minter_fee;
        assert_eq!(amount_received, tx.output.first().unwrap().value.to_sat());

        let change_beneficiary = parse_dogecoin_address(setup.network(), tx.output.get(1).unwrap());
        assert_eq!(minter_address, change_beneficiary.to_string());
        assert_eq!(change_amount, tx.output.get(1).unwrap().value.to_sat());

        assert_eq!(
            utxo.value - amount_received - change_amount,
            withdrawal_fee.bitcoin_fee
        );

        assert_eq!(ledger.icrc1_balance_of(account), 0);
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
