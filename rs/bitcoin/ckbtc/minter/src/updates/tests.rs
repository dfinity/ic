mod update_balance {
    use crate::state::{audit, eventlog::Event, mutate_state, read_state, SuspendedReason};
    use crate::test_fixtures::{
        ecdsa_public_key, get_uxos_response, ignored_utxo, init_args, init_state, ledger_account,
        mock::MockCanisterRuntime, quarantined_utxo, BTC_CHECKER_CANISTER_ID, DAY,
        MINTER_CANISTER_ID, NOW,
    };
    use crate::updates::update_balance;
    use crate::updates::update_balance::{
        SuspendedUtxo, UpdateBalanceArgs, UpdateBalanceError, UtxoStatus,
    };
    use crate::{storage, Timestamp};
    use ic_btc_checker::CheckTransactionResponse;
    use ic_btc_interface::{GetUtxosResponse, Utxo};
    use icrc_ledger_types::icrc1::account::Account;
    use std::time::Duration;

    #[tokio::test]
    async fn should_not_add_event_when_reevaluated_utxo_still_ignored() {
        test_suspended_utxo_last_time_checked_timestamp(
            ignored_utxo(),
            SuspendedReason::ValueTooSmall,
        )
        .await;
    }

    #[tokio::test]
    async fn should_do_btc_check_when_reevaluating_ignored_utxo() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let ignored_utxo = ignored_utxo();
        mutate_state(|s| {
            audit::ignore_utxo(
                s,
                ignored_utxo.clone(),
                account,
                NOW.checked_sub(DAY).unwrap(),
            )
        });
        mutate_state(|s| s.check_fee = ignored_utxo.value - 1);
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
        mock_get_utxos_for_account(&mut runtime, account, vec![ignored_utxo.clone()]);
        let num_time_called = 0_usize;
        mock_time(
            &mut runtime,
            vec![NOW, NOW.saturating_add(Duration::from_secs(1))],
            num_time_called,
        );
        expect_check_transaction_returning(
            &mut runtime,
            ignored_utxo.clone(),
            CheckTransactionResponse::Failed(vec![]),
        );
        mock_schedule_now_process_logic(&mut runtime);

        let result = update_balance(
            UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
            &runtime,
        )
        .await;

        assert_eq!(result, Ok(vec![UtxoStatus::Tainted(ignored_utxo.clone())]));
        assert_has_new_events(
            &events_before,
            &[Event::SuspendedUtxo {
                utxo: ignored_utxo.clone(),
                account,
                reason: SuspendedReason::Quarantined,
            }],
        );
        assert_eq!(
            suspended_utxo(&ignored_utxo),
            Some(SuspendedReason::Quarantined)
        );
    }

    #[tokio::test]
    async fn should_mint_reevaluated_ignored_utxo() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let ignored_utxo = ignored_utxo();
        mutate_state(|s| {
            audit::ignore_utxo(
                s,
                ignored_utxo.clone(),
                account,
                NOW.checked_sub(DAY).unwrap(),
            )
        });
        mutate_state(|s| s.check_fee = ignored_utxo.value - 1);
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
        mock_get_utxos_for_account(&mut runtime, account, vec![ignored_utxo.clone()]);
        let num_time_called = 0_usize;
        mock_time(
            &mut runtime,
            vec![NOW, NOW.saturating_add(Duration::from_secs(1))],
            num_time_called,
        );
        expect_check_transaction_returning(
            &mut runtime,
            ignored_utxo.clone(),
            CheckTransactionResponse::Passed,
        );
        runtime
            .expect_mint_ckbtc()
            .times(1)
            .withf(move |amount, account_, _memo| amount == &1 && account_ == &account)
            .return_const(Ok(1));
        mock_schedule_now_process_logic(&mut runtime);

        let result = update_balance(
            UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
            &runtime,
        )
        .await;

        assert_eq!(suspended_utxo(&ignored_utxo), None);
        assert_eq!(
            result,
            Ok(vec![UtxoStatus::Minted {
                block_index: 1,
                minted_amount: 1,
                utxo: ignored_utxo.clone(),
            }])
        );
        assert_has_new_events(
            &events_before,
            &[
                checked_utxo_event(ignored_utxo.clone(), account),
                Event::ReceivedUtxos {
                    mint_txid: Some(1),
                    to_account: account,
                    utxos: vec![ignored_utxo],
                },
            ],
        );
    }

    #[tokio::test]
    async fn should_not_add_event_when_reevaluated_utxo_still_tainted() {
        test_suspended_utxo_last_time_checked_timestamp(
            quarantined_utxo(),
            SuspendedReason::Quarantined,
        )
        .await;
    }

    #[tokio::test]
    async fn should_mint_reevaluated_tainted_utxo() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let quarantined_utxo = quarantined_utxo();
        let utxo = quarantined_utxo.clone();
        mutate_state(|s| {
            audit::quarantine_utxo(s, utxo, account, NOW.checked_sub(DAY).unwrap());
        });
        let check_fee = read_state(|s| s.check_fee);
        let minted_amount = quarantined_utxo.value - check_fee;
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
        mock_get_utxos_for_account(&mut runtime, account, vec![quarantined_utxo.clone()]);
        let num_time_called = 0_usize;
        mock_time(
            &mut runtime,
            vec![NOW, NOW.saturating_add(Duration::from_secs(1))],
            num_time_called,
        );
        expect_check_transaction_returning(
            &mut runtime,
            quarantined_utxo.clone(),
            CheckTransactionResponse::Passed,
        );
        runtime
            .expect_mint_ckbtc()
            .times(1)
            .withf(move |amount, account_, _memo| amount == &minted_amount && account_ == &account)
            .return_const(Ok(1));
        mock_schedule_now_process_logic(&mut runtime);
        let result = update_balance(
            UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
            &runtime,
        )
        .await;

        assert_eq!(suspended_utxo(&quarantined_utxo), None);
        assert_eq!(
            result,
            Ok(vec![UtxoStatus::Minted {
                block_index: 1,
                minted_amount,
                utxo: quarantined_utxo.clone(),
            }])
        );
        assert_has_new_events(
            &events_before,
            &[
                checked_utxo_event(quarantined_utxo.clone(), account),
                Event::ReceivedUtxos {
                    mint_txid: Some(1),
                    to_account: account,
                    utxos: vec![quarantined_utxo],
                },
            ],
        );
    }
    async fn test_suspended_utxo_last_time_checked_timestamp(utxo: Utxo, reason: SuspendedReason) {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        match &reason {
            SuspendedReason::ValueTooSmall => mutate_state(|s| {
                audit::ignore_utxo(s, utxo.clone(), account, NOW.checked_sub(DAY).unwrap())
            }),
            SuspendedReason::Quarantined => mutate_state(|s| {
                audit::quarantine_utxo(s, utxo.clone(), account, NOW.checked_sub(DAY).unwrap());
            }),
        };
        let events_before: Vec<_> = storage::events().collect();
        let update_balance_args = UpdateBalanceArgs {
            owner: Some(account.owner),
            subaccount: account.subaccount,
        };

        let mut runtime = MockCanisterRuntime::new();
        mock_get_utxos_for_account(&mut runtime, account, vec![utxo.clone()]);
        let num_time_called = 0_usize;
        mock_time(
            &mut runtime,
            vec![NOW.checked_sub(Duration::from_secs(1)).unwrap()],
            num_time_called,
        );

        let result = update_balance(update_balance_args.clone(), &runtime).await;

        assert_eq!(
            result,
            Err(UpdateBalanceError::NoNewUtxos {
                current_confirmations: None,
                required_confirmations: 6,
                pending_utxos: Some(vec![]),
                suspended_utxos: Some(vec![SuspendedUtxo {
                    utxo: utxo.clone(),
                    reason,
                    earliest_retry: NOW.as_nanos_since_unix_epoch(),
                }]),
            })
        );
        assert_has_no_new_events(&events_before);

        runtime.checkpoint();

        mock_get_utxos_for_account(&mut runtime, account, vec![utxo.clone()]);
        let num_time_called = 0_usize;
        mock_time(
            &mut runtime,
            vec![NOW, NOW.saturating_add(Duration::from_secs(1))],
            num_time_called,
        );
        match &reason {
            SuspendedReason::ValueTooSmall => {}
            SuspendedReason::Quarantined => {
                expect_check_transaction_returning(
                    &mut runtime,
                    utxo.clone(),
                    CheckTransactionResponse::Failed(vec![]),
                );
            }
        }
        mock_schedule_now_process_logic(&mut runtime);

        let result = update_balance(update_balance_args.clone(), &runtime).await;

        assert_eq!(
            result,
            Ok(vec![match &reason {
                SuspendedReason::ValueTooSmall => UtxoStatus::ValueTooSmall(utxo.clone()),
                SuspendedReason::Quarantined => UtxoStatus::Tainted(utxo.clone()),
            }])
        );
        assert_has_no_new_events(&events_before);

        runtime.checkpoint();

        mock_get_utxos_for_account(&mut runtime, account, vec![utxo.clone()]);
        let num_time_called = 0_usize;
        mock_time(
            &mut runtime,
            vec![NOW.checked_add(Duration::from_secs(1)).unwrap()],
            num_time_called,
        );

        let result = update_balance(update_balance_args.clone(), &runtime).await;

        assert_eq!(
            result,
            Err(UpdateBalanceError::NoNewUtxos {
                current_confirmations: None,
                required_confirmations: 6,
                pending_utxos: Some(vec![]),
                suspended_utxos: Some(vec![SuspendedUtxo {
                    utxo: utxo.clone(),
                    reason,
                    earliest_retry: NOW.checked_add(DAY).unwrap().as_nanos_since_unix_epoch(),
                }]),
            })
        );
        assert_has_no_new_events(&events_before);
    }

    fn init_state_with_ecdsa_public_key() {
        use crate::lifecycle::init::InitArgs;
        use ic_base_types::CanisterId;
        init_state(InitArgs {
            btc_checker_principal: Some(CanisterId::unchecked_from_principal(
                BTC_CHECKER_CANISTER_ID.into(),
            )),
            ..init_args()
        });
        mutate_state(|s| s.ecdsa_public_key = Some(ecdsa_public_key()))
    }

    fn expect_bitcoin_get_utxos_returning(runtime: &mut MockCanisterRuntime, utxos: Vec<Utxo>) {
        runtime
            .expect_bitcoin_get_utxos()
            .return_const(Ok(GetUtxosResponse {
                utxos,
                ..get_uxos_response()
            }));
    }

    fn expect_check_transaction_returning(
        runtime: &mut MockCanisterRuntime,
        utxo: Utxo,
        response: CheckTransactionResponse,
    ) {
        runtime
            .expect_check_transaction()
            .times(1)
            .withf(move |btc_checker_principal, utxo_, _cycles| {
                btc_checker_principal == &BTC_CHECKER_CANISTER_ID && utxo_ == &utxo
            })
            .return_const(Ok(response));
    }

    fn mock_schedule_now_process_logic(runtime: &mut MockCanisterRuntime) {
        runtime.expect_global_timer_set().return_const(());
    }

    fn mock_time(
        runtime: &mut MockCanisterRuntime,
        timestamps: Vec<Timestamp>,
        mut time_counter: usize,
    ) {
        runtime.expect_time().returning(move || {
            assert!(
                time_counter < timestamps.len(),
                "BUG: unexpected call to CanisterRuntime::time. Expected at most {} calls.",
                timestamps.len()
            );
            let result = timestamps[time_counter];
            time_counter += 1;
            result.as_nanos_since_unix_epoch()
        });
    }

    fn mock_get_utxos_for_account(
        runtime: &mut MockCanisterRuntime,
        account: Account,
        utxos: Vec<Utxo>,
    ) {
        runtime.expect_caller().return_const(account.owner);
        runtime.expect_id().return_const(MINTER_CANISTER_ID);
        expect_bitcoin_get_utxos_returning(runtime, utxos);
    }

    fn assert_has_new_events(events_before: &[Event], expected_new_events: &[Event]) {
        let expected_events = events_before
            .iter()
            .chain(expected_new_events.iter())
            .collect::<Vec<_>>();
        let actual_events: Vec<_> = storage::events().collect();
        let actual_events_ref = actual_events.iter().collect::<Vec<_>>();

        assert_eq!(expected_events.as_slice(), actual_events_ref.as_slice());
    }

    fn assert_has_no_new_events(events_before: &[Event]) {
        assert_has_new_events(events_before, &[]);
    }

    fn checked_utxo_event(utxo: Utxo, account: Account) -> Event {
        Event::CheckedUtxoV2 { utxo, account }
    }

    fn suspended_utxo(utxo: &Utxo) -> Option<SuspendedReason> {
        read_state(|s| {
            s.suspended_utxos
                .iter()
                .find_map(|(suspended_utxo, reason)| {
                    if suspended_utxo == utxo {
                        Some(*reason)
                    } else {
                        None
                    }
                })
        })
    }
}
