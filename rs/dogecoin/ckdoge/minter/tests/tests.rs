use candid::Principal;
use ic_ckdoge_minter::{
    candid_api::{
        EstimateWithdrawalFeeError, MinterInfo, RetrieveDogeWithApprovalArgs,
        RetrieveDogeWithApprovalError, WithdrawalFee,
    },
    lifecycle::init::Network,
};
use ic_ckdoge_minter_test_utils::{
    DOGE, DogecoinUsers, LEDGER_TRANSFER_FEE, MEDIAN_TRANSACTION_FEE, MIN_CONFIRMATIONS,
    MinterCanister, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL, assert_trap, utxos_with_value,
};
use ic_management_canister_types::CanisterStatusType;

#[test]
fn should_fail_withdrawal() {
    let setup = Setup::new(Network::Regtest);
    let minter = setup.minter();
    let correct_withdrawal_args = RetrieveDogeWithApprovalArgs {
        amount: RETRIEVE_DOGE_MIN_AMOUNT,
        address: DogecoinUsers::WithdrawalRecipientUser.address().to_string(),
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

    setup.dogecoind().setup_user_with_balance();
    setup
        .deposit_flow()
        .minter_get_dogecoin_deposit_address(USER_PRINCIPAL)
        .dogecoin_send_transaction(vec![RETRIEVE_DOGE_MIN_AMOUNT])
        .dogecoin_mine_blocks(MIN_CONFIRMATIONS)
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
    use ic_ckdoge_minter::lifecycle::init::Network;
    use ic_ckdoge_minter::{OutPoint, Utxo};
    use ic_ckdoge_minter_test_utils::{
        LEDGER_TRANSFER_FEE, MIN_CONFIRMATIONS, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL,
        txid, utxo_with_value,
    };
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_mint_ckdoge() {
        let setup = Setup::new(Network::Regtest).with_doge_balance();
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_send_transaction(vec![RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE])
            .dogecoin_mine_blocks(MIN_CONFIRMATIONS)
            .minter_update_balance()
            .expect_mint();
    }

    // DOGE total supply will overflow a u64 around 2030.
    // However, the maximum output value in a single Dogecoin transaction is 10B DOGE,
    // so that the value of a single UTXO is guaranteed to fit into a u64.
    #[test]
    fn should_handle_large_balances() {
        let large_utxo_1 = utxo_with_value(u64::MAX);
        let large_utxo_2 = Utxo {
            outpoint: OutPoint {
                txid: txid([43; 32]),
                vout: 1,
            },
            ..large_utxo_1.clone()
        };
        assert_ne!(large_utxo_1, large_utxo_2);

        let setup = Setup::default();
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_simulate_transaction(vec![large_utxo_1, large_utxo_2])
            .minter_update_balance()
            .expect_mint();

        assert_eq!(
            setup.ledger().icrc1_balance_of(account),
            (u64::MAX as u128) * 2
        );
    }
}

mod withdrawal {
    use ic_ckdoge_minter::{
        DEFAULT_MAX_NUM_INPUTS_IN_TRANSACTION, InvalidTransactionError, UTXOS_COUNT_THRESHOLD,
        WithdrawalReimbursementReason, candid_api::RetrieveDogeWithApprovalError,
        lifecycle::init::Network,
    };
    use ic_ckdoge_minter_test_utils::flow::withdrawal::assert_uses_utxos;
    use ic_ckdoge_minter_test_utils::{
        DOGECOIN_ADDRESS_1, DogecoinUsers, LEDGER_TRANSFER_FEE, MEDIAN_TRANSACTION_FEE,
        MIN_CONFIRMATIONS, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL,
        flow::withdrawal::WithdrawalFlowEnd, only_one, txid, utxo_with_value, utxos_with_value,
    };
    use icrc_ledger_types::icrc1::account::Account;
    use std::array;

    #[test]
    fn should_withdraw_doge() {
        let setup = Setup::new(Network::Regtest).with_doge_balance();

        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_send_transaction(vec![RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE])
            .dogecoin_mine_blocks(MIN_CONFIRMATIONS)
            .minter_update_balance()
            .expect_mint();

        setup
            .withdrawal_flow()
            .ledger_approve_minter(account, RETRIEVE_DOGE_MIN_AMOUNT)
            .minter_retrieve_doge_with_approval(
                RETRIEVE_DOGE_MIN_AMOUNT,
                DogecoinUsers::WithdrawalRecipientUser.address().to_string(),
            )
            .expect_withdrawal_request_accepted()
            .dogecoin_await_transaction_in_mempool()
            .assert_sent_transactions(|txs| {only_one(txs);})
            .dogecoin_mine_blocks(MIN_CONFIRMATIONS)
            .minter_await_finalized_single_transaction()
    }

    #[test]
    fn should_fail_to_withdraw_when_ledger_stopped() {
        let setup = Setup::new(Network::Regtest).with_doge_balance();
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_send_transaction(vec![RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE])
            .dogecoin_mine_blocks(MIN_CONFIRMATIONS)
            .minter_update_balance()
            .expect_mint();

        let withdrawal_flow = setup
            .withdrawal_flow()
            .ledger_approve_minter(account, RETRIEVE_DOGE_MIN_AMOUNT);

        setup.ledger().stop();

        withdrawal_flow
            .minter_retrieve_doge_with_approval(RETRIEVE_DOGE_MIN_AMOUNT,  DogecoinUsers::WithdrawalRecipientUser.address().to_string())
            .expect_error_matching(|e| {
                matches!(e, RetrieveDogeWithApprovalError::TemporarilyUnavailable(_))
            })
    }

    #[test]
    fn should_resubmit_transaction() {
        // Do a deposit and withdrawal flow, up to the point where
        // a first transaction was sent to the network, but is not yet confirmed.
        //
        // To avoid recreating a fresh setup for each call, which is an expensive operation,
        // we reuse the same setup. The independence of the flows is ensured by the `id` parameter,
        // which is assumed to be unique across all calls to that method.
        // This `id` is used to target a unique ledged account and uniquely identifies the used UTXOs.
        fn deposit_and_withdraw(setup: &Setup, id: u8) -> WithdrawalFlowEnd<&Setup> {
            let account = Account {
                owner: USER_PRINCIPAL,
                subaccount: Some([id; 32]),
            };
            let mut utxo = utxo_with_value(RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE);
            utxo.outpoint.txid = txid([id; 32]);

            setup
                .deposit_flow()
                .minter_get_dogecoin_deposit_address(account)
                .dogecoin_simulate_transaction(vec![utxo.clone()])
                .minter_update_balance()
                .expect_mint();

            setup
                .withdrawal_flow()
                .ledger_approve_minter(account, RETRIEVE_DOGE_MIN_AMOUNT)
                .minter_retrieve_doge_with_approval(RETRIEVE_DOGE_MIN_AMOUNT, DOGECOIN_ADDRESS_1)
                .expect_withdrawal_request_accepted()
                .dogecoin_await_transaction_in_mempool()
                .assert_sent_transactions(|sent| {
                    assert_uses_utxos(only_one(sent), vec![utxo.clone()])
                })
        }

        let setup = Setup::default().with_median_fee_percentile(MEDIAN_TRANSACTION_FEE);

        deposit_and_withdraw(&setup, 42)
            .minter_await_resubmission()
            .assert_sent_transactions(|sent| assert_eq!(sent.len(), 2))
            .minter_await_finalized_transaction_by(|sent| {
                // Finalize the oldest transaction, the first one that was sent.
                &sent[0]
            });

        deposit_and_withdraw(&setup, 43)
            .minter_await_resubmission()
            .assert_sent_transactions(|sent| assert_eq!(sent.len(), 2))
            .minter_await_finalized_transaction_by(|sent| {
                // Finalize the newest transaction, the last one that was sent.
                &sent[1]
            });

        deposit_and_withdraw(&setup, 44)
            .minter_await_resubmission()
            .minter_await_resubmission()
            .assert_sent_transactions(|sent| assert_eq!(sent.len(), 3))
            .minter_await_finalized_transaction_by(|sent| {
                // Finalize the middle transaction, the second one (out-of-3) that was sent.
                &sent[1]
            });
    }

    #[test]
    fn should_resubmit_transaction_when_many_utxos() {
        // Step 1: deposit btc
        // Create many utxos that exceeds threshold by 2 so that after consuming
        // one, the remaining available count is still greater than the threshold.
        // This is to make sure utxo count optimization is triggered.
        const COUNT: usize = UTXOS_COUNT_THRESHOLD + 2;

        let setup = Setup::default().with_median_fee_percentile(MEDIAN_TRANSACTION_FEE);

        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };
        let deposit_value = RETRIEVE_DOGE_MIN_AMOUNT + 1;
        let utxos = utxos_with_value(&[deposit_value; COUNT]);

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_simulate_transaction(utxos.clone())
            .minter_update_balance()
            .expect_mint();

        // Step 2: request a withdrawal
        // This withdraw_amount only needs 1 input utxo, but due to
        // available_utxos.len() > UTXOS_COUNT_THRESHOLD, the minter will
        // include 2 input utxos.
        let withdrawal_amount = RETRIEVE_DOGE_MIN_AMOUNT;
        assert!(
            deposit_value > withdrawal_amount,
            "ensure only 1 utxo is needed",
        );

        setup
            .withdrawal_flow()
            .ledger_approve_minter(account, withdrawal_amount)
            .minter_retrieve_doge_with_approval(withdrawal_amount, DOGECOIN_ADDRESS_1)
            .expect_withdrawal_request_accepted()
            .dogecoin_await_transaction_in_mempool()
            //also ensures the resubmission transaction uses 2 inputs.
            .minter_await_resubmission()
            .assert_sent_transactions(|sent| {
                assert_eq!(sent.len(), 2);
                sent.iter().for_each(|tx| assert_eq!(tx.input.len(), 2));
            })
            .minter_await_finalized_transaction_by(|sent| &sent[1]);
    }

    #[test]
    fn should_cancel_and_reimburse_large_withdrawal() {
        let setup = Setup::default().with_median_fee_percentile(MEDIAN_TRANSACTION_FEE);

        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };
        // Step 1: deposit a lot of small UTXOs
        // < 2_000 to avoid ledger spawning an archive.
        const NUM_UXTOS: usize = 1_900;
        let deposit_value = RETRIEVE_DOGE_MIN_AMOUNT;
        let utxos = utxos_with_value(&[deposit_value; NUM_UXTOS]);
        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_simulate_transaction(utxos.clone())
            .minter_update_balance()
            .expect_mint();

        let too_large_num_inputs = 1_800;
        let withdrawal_amount = too_large_num_inputs * deposit_value;

        setup
            .withdrawal_flow()
            .ledger_approve_minter(account, withdrawal_amount)
            .minter_retrieve_doge_with_approval(withdrawal_amount, DOGECOIN_ADDRESS_1)
            .expect_withdrawal_request_accepted()
            .minter_await_withdrawal_reimbursed(WithdrawalReimbursementReason::InvalidTransaction(
                InvalidTransactionError::TooManyInputs {
                    num_inputs: too_large_num_inputs as usize,
                    max_num_inputs: DEFAULT_MAX_NUM_INPUTS_IN_TRANSACTION,
                },
            ));
    }
}

#[test]
fn should_estimate_withdrawal_fee() {
    fn estimate_withdrawal_fee_and_check(
        minter: &MinterCanister,
        withdrawal_amount: u64,
    ) -> Result<WithdrawalFee, EstimateWithdrawalFeeError> {
        let utxos_before = minter.get_known_utxos(USER_PRINCIPAL);
        let result = minter.estimate_withdrawal_fee(withdrawal_amount);
        let utxos_after = minter.get_known_utxos(USER_PRINCIPAL);
        assert_eq!(
            utxos_before, utxos_after,
            "BUG: a query endpoint should not be able to modify state!"
        );
        result
    }

    let setup = Setup::default().with_median_fee_percentile(MEDIAN_TRANSACTION_FEE);
    let minter = setup.minter();

    assert_eq!(
        estimate_withdrawal_fee_and_check(&minter, DOGE),
        Err(EstimateWithdrawalFeeError::AmountTooHigh),
        "Any amount should be too high since there are no UTXOs"
    );

    setup
        .deposit_flow()
        .minter_get_dogecoin_deposit_address(USER_PRINCIPAL)
        .dogecoin_simulate_transaction(utxos_with_value(&[RETRIEVE_DOGE_MIN_AMOUNT; 2]))
        .minter_update_balance()
        .expect_mint();

    assert_eq!(
        estimate_withdrawal_fee_and_check(&minter, DOGE),
        Err(EstimateWithdrawalFeeError::AmountTooLow {
            min_amount: RETRIEVE_DOGE_MIN_AMOUNT
        })
    );

    let expected_fee = WithdrawalFee {
        minter_fee: 180_000_000,
        dogecoin_fee: 11_350_000,
    };
    assert_eq!(
        estimate_withdrawal_fee_and_check(&minter, RETRIEVE_DOGE_MIN_AMOUNT),
        Ok(expected_fee)
    );
    assert_eq!(
        estimate_withdrawal_fee_and_check(&minter, RETRIEVE_DOGE_MIN_AMOUNT),
        Ok(expected_fee),
        "BUG: estimate_withdrawal_fee should be idempotent"
    );
}

mod post_upgrade {
    use ic_ckdoge_minter::lifecycle::init::Network;
    use ic_ckdoge_minter_test_utils::{LEDGER_TRANSFER_FEE, MIN_CONFIRMATIONS, MinterCanister, RETRIEVE_DOGE_MIN_AMOUNT, Setup, USER_PRINCIPAL, only_one, DogecoinUsers };
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_deposit_and_withdraw_with_interleaved_upgrades() {
        fn upgrade_and_check<F: Fn(&MinterCanister)>(minter: &MinterCanister, check: F) {
            check(minter);
            minter.upgrade(None);
            check(minter)
        }

        let setup = Setup::new(Network::Regtest).with_doge_balance();

        let minter = setup.minter();
        let account = Account {
            owner: USER_PRINCIPAL,
            subaccount: Some([42_u8; 32]),
        };

        minter.upgrade(None);

        setup
            .deposit_flow()
            .minter_get_dogecoin_deposit_address(account)
            .dogecoin_send_transaction(vec![RETRIEVE_DOGE_MIN_AMOUNT + LEDGER_TRANSFER_FEE])
            .dogecoin_mine_blocks(MIN_CONFIRMATIONS)
            .minter_update_balance()
            .expect_mint();

        upgrade_and_check(&minter, |m| {
            assert_eq!(m.get_known_utxos(account).len(), 1);
        });

        setup
            .withdrawal_flow()
            .ledger_approve_minter(account, RETRIEVE_DOGE_MIN_AMOUNT)
            .minter_retrieve_doge_with_approval(
                RETRIEVE_DOGE_MIN_AMOUNT,
                DogecoinUsers::WithdrawalRecipientUser.address().to_string(),
            )
            .expect_withdrawal_request_accepted()
            .dogecoin_await_transaction_in_mempool()
            .assert_sent_transactions(|txs| {only_one(txs);})
            .dogecoin_mine_blocks(MIN_CONFIRMATIONS)
            .minter_await_finalized_single_transaction();

        upgrade_and_check(&minter, |m| {
            assert_eq!(m.get_known_utxos(account), vec![]);
            assert_eq!(
                m.get_known_utxos(m.id()).len(),
                1,
                "BUG: expected change output"
            );
        });
    }
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

#[test]
fn should_get_canister_status() {
    let setup = Setup::default();
    let status = setup.minter().get_canister_status();
    assert_eq!(status.status, CanisterStatusType::Running);
}

#[test]
fn should_get_minter_info() {
    let setup = Setup::default();
    let minter = setup.minter();

    let minter_info = minter.get_minter_info();

    assert_eq!(
        minter_info,
        MinterInfo {
            min_confirmations: MIN_CONFIRMATIONS,
            retrieve_doge_min_amount: RETRIEVE_DOGE_MIN_AMOUNT,
        }
    );

    let mut setup = setup;
    for i in 0..8 {
        setup = setup.with_median_fee_percentile(MEDIAN_TRANSACTION_FEE << i);
        assert_eq!(setup.minter().get_minter_info(), minter_info);
    }

    setup = setup.with_median_fee_percentile(MEDIAN_TRANSACTION_FEE << 8);
    assert_eq!(
        setup.minter().get_minter_info(),
        MinterInfo {
            retrieve_doge_min_amount: RETRIEVE_DOGE_MIN_AMOUNT + RETRIEVE_DOGE_MIN_AMOUNT / 2,
            ..minter_info
        }
    );
}
