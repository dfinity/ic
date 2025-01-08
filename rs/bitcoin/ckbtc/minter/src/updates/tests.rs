mod update_balance {
    use crate::metrics::LatencyHistogram;
    use crate::state::{audit, eventlog::EventType, mutate_state, read_state, SuspendedReason};
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
    use std::iter;
    use std::time::Duration;

    #[tokio::test]
    async fn should_not_add_event_when_reevaluated_utxo_still_ignored() {
        mock_constant_time(&mut MockCanisterRuntime::new(), NOW, 1);

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
        let mut runtime = MockCanisterRuntime::new();
        mock_increasing_time(&mut runtime, NOW, Duration::from_secs(1));

        let ignored_utxo = ignored_utxo();
        mutate_state(|s| {
            audit::ignore_utxo(
                s,
                ignored_utxo.clone(),
                account,
                NOW.checked_sub(DAY).unwrap(),
                &runtime,
            )
        });
        mutate_state(|s| s.check_fee = ignored_utxo.value - 1);
        let events_before: Vec<_> = storage::events().map(|event| event.payload).collect();

        mock_get_utxos_for_account(&mut runtime, account, vec![ignored_utxo.clone()]);
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
            &[EventType::SuspendedUtxo {
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
        let mut runtime = MockCanisterRuntime::new();
        mock_increasing_time(&mut runtime, NOW, Duration::from_secs(1));

        let ignored_utxo = ignored_utxo();
        mutate_state(|s| {
            audit::ignore_utxo(
                s,
                ignored_utxo.clone(),
                account,
                NOW.checked_sub(DAY).unwrap(),
                &runtime,
            )
        });
        mutate_state(|s| s.check_fee = ignored_utxo.value - 1);
        let events_before: Vec<_> = storage::events().map(|event| event.payload).collect();

        mock_get_utxos_for_account(&mut runtime, account, vec![ignored_utxo.clone()]);
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
                EventType::ReceivedUtxos {
                    mint_txid: Some(1),
                    to_account: account,
                    utxos: vec![ignored_utxo],
                },
            ],
        );
    }

    #[tokio::test]
    async fn should_not_add_event_when_reevaluated_utxo_still_tainted() {
        mock_constant_time(&mut MockCanisterRuntime::new(), NOW, 1);

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
        let mut runtime = MockCanisterRuntime::new();
        mock_increasing_time(&mut runtime, NOW, Duration::from_secs(1));

        let quarantined_utxo = quarantined_utxo();
        let utxo = quarantined_utxo.clone();
        mutate_state(|s| {
            audit::quarantine_utxo(s, utxo, account, NOW.checked_sub(DAY).unwrap(), &runtime);
        });
        let check_fee = read_state(|s| s.check_fee);
        let minted_amount = quarantined_utxo.value - check_fee;
        let events_before: Vec<_> = storage::events().map(|event| event.payload).collect();

        mock_get_utxos_for_account(&mut runtime, account, vec![quarantined_utxo.clone()]);
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
                EventType::ReceivedUtxos {
                    mint_txid: Some(1),
                    to_account: account,
                    utxos: vec![quarantined_utxo],
                },
            ],
        );
    }

    #[tokio::test]
    async fn should_observe_latency_metrics() {
        init_state_with_ecdsa_public_key();

        async fn update_balance_with_latency(
            latency: Duration,
            account_utxos: Vec<Utxo>,
        ) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
            let account = ledger_account();
            let update_balance_args = UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            };
            let mut runtime = MockCanisterRuntime::new();
            mock_schedule_now_process_logic(&mut runtime);
            mock_get_utxos_for_account(&mut runtime, account, account_utxos);
            mock_time(
                &mut runtime,
                vec![
                    NOW,                         // start time of `update_balance` method
                    NOW,                         // time used to triage processable UTXOs
                    NOW.saturating_add(latency), // event timestamp
                    NOW.saturating_add(latency), // time used in `schedule_now` call at end of `update_balance`
                    NOW.saturating_add(latency), // end time of `update_balance` method
                ],
            );

            update_balance(update_balance_args.clone(), &runtime).await
        }

        // update_balance calls with no new UTXOs.
        let no_new_utxo_latencies_ms =
            [0, 100, 499, 500, 2_250, 3_000, 3_400, 4_000, 8_000, 100_000];
        for millis in &no_new_utxo_latencies_ms {
            let result = update_balance_with_latency(Duration::from_millis(*millis), vec![]).await;
            assert!(matches!(result, Err(UpdateBalanceError::NoNewUtxos { .. })));
        }

        // update_balance call with 1 new UTXO.
        let _ = update_balance_with_latency(Duration::from_millis(250), vec![ignored_utxo()])
            .await
            .is_ok();

        let histogram = get_latency_histogram(0);
        assert_eq!(
            histogram.iter().collect::<Vec<_>>(),
            vec![
                (500., 4.),
                (1_000., 0.),
                (2_000., 0.),
                (4_000., 4.),
                (8_000., 1.),
                (16_000., 0.),
                (32_000., 0.),
                (f64::INFINITY, 1.)
            ]
        );
        assert_eq!(
            histogram.sum(),
            no_new_utxo_latencies_ms.iter().sum::<u64>()
        );

        let histogram = get_latency_histogram(1);
        assert_eq!(
            histogram.iter().collect::<Vec<_>>(),
            vec![
                (500., 1.),
                (1_000., 0.),
                (2_000., 0.),
                (4_000., 0.),
                (8_000., 0.),
                (16_000., 0.),
                (32_000., 0.),
                (f64::INFINITY, 0.)
            ]
        );
        assert_eq!(histogram.sum(), 250);
    }

    fn get_latency_histogram(num_new_utxos: usize) -> LatencyHistogram {
        crate::metrics::UPDATE_CALL_LATENCY.with_borrow(|histograms| {
            *histograms
                .get(&num_new_utxos)
                .expect("No histogram for given number of new UTXOs")
        })
    }

    async fn test_suspended_utxo_last_time_checked_timestamp(utxo: Utxo, reason: SuspendedReason) {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let mut runtime = MockCanisterRuntime::new();
        mock_constant_time(
            &mut runtime,
            NOW.checked_sub(Duration::from_secs(1)).unwrap(),
            4,
        );

        match &reason {
            SuspendedReason::ValueTooSmall => mutate_state(|s| {
                audit::ignore_utxo(
                    s,
                    utxo.clone(),
                    account,
                    NOW.checked_sub(DAY).unwrap(),
                    &runtime,
                )
            }),
            SuspendedReason::Quarantined => mutate_state(|s| {
                audit::quarantine_utxo(
                    s,
                    utxo.clone(),
                    account,
                    NOW.checked_sub(DAY).unwrap(),
                    &runtime,
                );
            }),
        };

        let events_before: Vec<_> = storage::events().map(|event| event.payload).collect();
        let update_balance_args = UpdateBalanceArgs {
            owner: Some(account.owner),
            subaccount: account.subaccount,
        };
        mock_get_utxos_for_account(&mut runtime, account, vec![utxo.clone()]);

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
        mock_time(
            &mut runtime,
            vec![NOW, NOW, NOW, NOW.saturating_add(Duration::from_secs(1))],
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
        mock_constant_time(&mut runtime, NOW.saturating_add(Duration::from_secs(1)), 4);

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

    fn mock_increasing_time(
        runtime: &mut MockCanisterRuntime,
        start: Timestamp,
        interval: Duration,
    ) {
        let increment = move |time: Timestamp| time.saturating_add(interval);
        let mut current_time = start;
        runtime.expect_time().returning(move || {
            let previous_time = current_time;
            current_time = increment(current_time);
            previous_time.as_nanos_since_unix_epoch()
        });
    }

    fn mock_constant_time(
        runtime: &mut MockCanisterRuntime,
        timestamp: Timestamp,
        num_times: usize,
    ) {
        mock_time(runtime, iter::repeat_n(timestamp, num_times).collect());
    }

    fn mock_time(runtime: &mut MockCanisterRuntime, timestamps: Vec<Timestamp>) {
        let mut time_counter = 0;
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

    fn assert_has_new_events(events_before: &[EventType], expected_new_events: &[EventType]) {
        let expected_events = events_before
            .iter()
            .chain(expected_new_events.iter())
            .collect::<Vec<_>>();
        let actual_events: Vec<_> = storage::events().map(|event| event.payload).collect();
        let actual_events_ref = actual_events.iter().collect::<Vec<_>>();

        assert_eq!(expected_events.as_slice(), actual_events_ref.as_slice());
    }

    fn assert_has_no_new_events(events_before: &[EventType]) {
        assert_has_new_events(events_before, &[]);
    }

    fn checked_utxo_event(utxo: Utxo, account: Account) -> EventType {
        EventType::CheckedUtxoV2 { utxo, account }
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
