mod update_balance {
    use crate::management::{CallError, CallSource, get_utxos, sign_with_ecdsa};
    use crate::metrics::{Histogram, NumUtxoPages};
    use crate::metrics::{LatencyHistogram, MetricsResult};
    use crate::state::{SuspendedReason, audit, eventlog::EventType, mutate_state, read_state};
    use crate::test_fixtures::{
        BTC_CHECKER_CANISTER_ID, DAY, MINTER_CANISTER_ID, NOW, ecdsa_public_key, get_uxos_response,
        ignored_utxo, init_args, init_state, ledger_account, mock::MockCanisterRuntime,
        quarantined_utxo, utxo,
    };
    use crate::updates::get_btc_address::account_to_p2wpkh_address_from_state;
    use crate::updates::update_balance;
    use crate::updates::update_balance::{
        SuspendedUtxo, UpdateBalanceArgs, UpdateBalanceError, UtxoStatus,
    };
    use crate::{CanisterRuntime, GetUtxosResponse, Timestamp, storage};
    #[cfg(feature = "tla")]
    use crate::tla::{TLA_TRACES_LKEY, check_traces as tla_check_traces};
    use ic_btc_checker::{CheckTransactionResponse, CheckTransactionStatus};
    use ic_btc_interface::Utxo;
    use ic_management_canister_types_private::BoundedVec;
    use icrc_ledger_types::icrc1::account::Account;
    use std::iter;
    use std::time::Duration;
    #[cfg(feature = "tla")]
    use tla_instrumentation_proc_macros::with_tla_trace_check;

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
    #[cfg_attr(feature = "tla", with_tla_trace_check)]
    async fn should_call_check_transaction_again_when_cycles_not_enough() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let mut runtime = MockCanisterRuntime::new();
        mock_increasing_time(&mut runtime, NOW, Duration::from_secs(1));
        let test_utxo = utxo();
        let amount = test_utxo.value - read_state(|s| s.check_fee);
        mock_derive_user_address(&mut runtime, account);
        mock_get_utxos_for_account(&mut runtime, account, vec![test_utxo.clone()]);
        // The expectation below also ensures check_transaction is called exactly 3 times
        expect_check_transaction_returning_responses(
            &mut runtime,
            test_utxo.clone(),
            vec![
                CheckTransactionResponse::Unknown(CheckTransactionStatus::NotEnoughCycles),
                CheckTransactionResponse::Unknown(CheckTransactionStatus::NotEnoughCycles),
                CheckTransactionResponse::Passed,
            ],
        );
        runtime
            .expect_mint_ckbtc()
            .times(1)
            .withf(move |amount_, account_, _memo| amount_ == &amount && account_ == &account)
            .return_const(Ok(amount));
        mock_schedule_now_process_logic(&mut runtime);

        let result = update_balance(
            UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
            &runtime,
        )
        .await;

        // Check if the mint is successful in the end.
        assert!(result.is_ok());
        assert_matches::assert_matches!(&result.unwrap()[0], UtxoStatus::Minted { utxo, .. } if *utxo == test_utxo);
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

        mock_derive_user_address(&mut runtime, account);
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
    #[cfg_attr(feature = "tla", with_tla_trace_check)]
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

        mock_derive_user_address(&mut runtime, account);
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

        mock_derive_user_address(&mut runtime, account);
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
    #[cfg_attr(feature = "tla", with_tla_trace_check)]
    async fn should_not_evaluate_mint_unknown_utxo() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let mut runtime = MockCanisterRuntime::new();
        mock_increasing_time(&mut runtime, NOW, Duration::from_secs(1));

        // Create two utxos, first one is already checked but with unknown mint status.
        let checked_but_mint_unknown_utxo = quarantined_utxo();
        let utxo = crate::test_fixtures::utxo();
        mutate_state(|s| {
            audit::mark_utxo_checked_mint_unknown(
                s,
                checked_but_mint_unknown_utxo.clone(),
                account,
                &runtime,
            );
        });
        let check_fee = read_state(|s| s.check_fee);
        let minted_amount = utxo.value - check_fee;
        let events_before: Vec<_> = storage::events().map(|event| event.payload).collect();

        mock_derive_user_address(&mut runtime, account);
        mock_get_utxos_for_account(
            &mut runtime,
            account,
            vec![checked_but_mint_unknown_utxo.clone(), utxo.clone()],
        );
        expect_check_transaction_returning(
            &mut runtime,
            utxo.clone(),
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

        assert_eq!(suspended_utxo(&checked_but_mint_unknown_utxo), None);
        assert_eq!(suspended_utxo(&utxo), None);
        // Only the 2nd utxo is minted
        assert_eq!(
            result,
            Ok(vec![UtxoStatus::Minted {
                block_index: 1,
                minted_amount,
                utxo: utxo.clone()
            }])
        );
        assert_has_new_events(
            &events_before,
            &[
                checked_utxo_event(utxo.clone(), account),
                EventType::ReceivedUtxos {
                    mint_txid: Some(1),
                    to_account: account,
                    utxos: vec![utxo],
                },
            ],
        );
    }

    #[tokio::test]
    async fn should_observe_update_balance_latency_metrics() {
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
            mock_derive_user_address(&mut runtime, account);
            mock_get_utxos_for_account(&mut runtime, account, account_utxos);
            mock_time(
                &mut runtime,
                vec![
                    NOW,                         // start time of `update_balance` method
                    NOW,                         // start time of `get_utxos` method
                    NOW.saturating_add(latency), // time used by `get_utxos_cache.insert
                    NOW.saturating_add(latency), // end time of `get_utxos` method
                    NOW.saturating_add(latency), // time used to triage processable UTXOs
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

        let histogram = update_balance_latency_histogram(0);
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

        let histogram = update_balance_latency_histogram(1);
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

    fn update_balance_latency_histogram(num_new_utxos: NumUtxoPages) -> Histogram<8> {
        crate::metrics::UPDATE_CALL_LATENCY.with_borrow(|histograms| {
            let &LatencyHistogram(histogram) = histograms
                .get(&num_new_utxos)
                .expect("No histogram for given number of new UTXOs");
            histogram
        })
    }

    #[tokio::test]
    async fn should_observe_get_utxos_latency_metrics() {
        init_state_with_ecdsa_public_key();

        fn mock_get_utxos_for_account_with_num_pages(
            runtime: &mut MockCanisterRuntime,
            account: Account,
            utxos: Vec<Utxo>,
            num_pages: usize,
        ) {
            let mut responses =
                std::iter::repeat_n(utxos, num_pages)
                    .enumerate()
                    .map(move |(idx, utxos)| {
                        let next_page = if idx == num_pages - 1 {
                            None
                        } else {
                            Some(vec![idx as u8].into())
                        };
                        Ok(GetUtxosResponse {
                            next_page: next_page.clone(),
                            utxos: utxos.clone(),
                            ..get_uxos_response()
                        })
                    });

            runtime.expect_caller().return_const(account.owner);
            runtime.expect_id().return_const(MINTER_CANISTER_ID);
            runtime
                .expect_get_utxos()
                .times(num_pages)
                .returning(move |_| responses.next().unwrap());
        }

        async fn get_utxos_with_latency(
            now: &mut Timestamp,
            latency: Duration,
            account_utxos: Vec<Utxo>,
            num_pages: usize,
            call_source: CallSource,
        ) -> Result<Vec<Utxo>, CallError> {
            let account = ledger_account();
            let (btc_network, min_confirmations) =
                read_state(|s| (s.btc_network, s.min_confirmations));
            let address = read_state(|s| account_to_p2wpkh_address_from_state(s, &account));
            let mut runtime = MockCanisterRuntime::new();
            mock_get_utxos_for_account_with_num_pages(
                &mut runtime,
                account,
                account_utxos,
                num_pages,
            );
            mock_increasing_time(&mut runtime, *now, latency);
            let utxos = get_utxos(
                btc_network,
                &address,
                min_confirmations,
                call_source,
                &runtime,
            )
            .await?
            .utxos;
            // The following is to make sure time sequence is strictly increasing
            *now = runtime.time().into();
            *now = now.saturating_add(Duration::from_secs(1));
            Ok(utxos)
        }

        let mut now = NOW;
        // get_utxos calls with 1 page
        let get_utxos_latencies_ms = [0, 100, 499, 500, 2_250, 3_000, 3_400, 4_000, 8_000, 100_000];
        for millis in &get_utxos_latencies_ms {
            let result = get_utxos_with_latency(
                &mut now,
                Duration::from_millis(*millis),
                vec![utxo()],
                1,
                CallSource::Minter,
            )
            .await;
            assert_eq!(result, Ok(vec![utxo()]));
        }

        // get_utxos calls with 3 pages
        let result = get_utxos_with_latency(
            &mut now,
            Duration::from_millis(1_200),
            vec![utxo()],
            3,
            CallSource::Minter,
        )
        .await;
        assert_eq!(result, Ok(vec![utxo(), utxo(), utxo()]));

        let histogram = get_utxos_latency_histogram(1, CallSource::Minter);
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
        assert_eq!(histogram.sum(), get_utxos_latencies_ms.iter().sum::<u64>());

        let histogram = get_utxos_latency_histogram(3, CallSource::Minter);
        assert_eq!(
            histogram.iter().collect::<Vec<_>>(),
            vec![
                (500., 0.),
                (1_000., 0.),
                (2_000., 0.),
                (4_000., 1.),
                (8_000., 0.),
                (16_000., 0.),
                (32_000., 0.),
                (f64::INFINITY, 0.)
            ]
        );
        assert_eq!(histogram.sum(), 3_600);
    }

    #[tokio::test]
    async fn should_observe_get_utxos_cache_metrics() {
        init_state_with_ecdsa_public_key();
        mutate_state(|s| {
            s.get_utxos_cache
                .set_expiration(Duration::from_millis(2500))
        });

        async fn get_utxos_with_no_latency(
            now: Timestamp,
            account_utxos: Vec<Utxo>,
            call_source: CallSource,
        ) -> Result<Vec<Utxo>, CallError> {
            let account = ledger_account();
            let (btc_network, min_confirmations) =
                read_state(|s| (s.btc_network, s.min_confirmations));
            let address = read_state(|s| account_to_p2wpkh_address_from_state(s, &account));
            let mut runtime = MockCanisterRuntime::new();
            mock_get_utxos_for_account(&mut runtime, account, account_utxos);
            mock_constant_time(&mut runtime, now, 3);
            Ok(get_utxos(
                btc_network,
                &address,
                min_confirmations,
                call_source,
                &runtime,
            )
            .await?
            .utxos)
        }

        let mut now = NOW;
        // get_utxos calls with 1 page
        let get_utxos_latencies_ms = [100, 499, 500, 2_250, 3_000, 3_400, 4_000, 8_000, 100_000];
        for millis in &get_utxos_latencies_ms {
            let result = get_utxos_with_no_latency(now, vec![utxo()], CallSource::Minter).await;
            now = now.saturating_add(Duration::from_millis(*millis));
            assert_eq!(result, Ok(vec![utxo()]));
        }
        assert_eq!(
            crate::metrics::GET_UTXOS_MINTER_CALLS.with(|calls| calls.get()),
            get_utxos_latencies_ms.len() as u64
        );
        // Because the latency between each call to `get_utxos` follows the above
        // `get_utxos_latencies_ms` setting, there are only 3 cache hits for the
        // 2nd, 3rd and 4th call. By the time of 5th call (at time 3349ms), the
        // cached entry (at time 0ms) is already considered expired for an expiry
        // setting of 2500ms. All later calls are more than 2500ms inbetween. So
        // in totally we have 3 hits.
        assert_eq!(
            crate::metrics::GET_UTXOS_CACHE_HITS.with(|calls| calls.get()),
            3,
        );
        assert_eq!(
            crate::metrics::GET_UTXOS_CACHE_MISSES.with(|calls| calls.get()),
            6,
        );
    }

    fn get_utxos_latency_histogram(
        num_pages: NumUtxoPages,
        call_source: CallSource,
    ) -> Histogram<8> {
        crate::metrics::GET_UTXOS_CALL_LATENCY.with_borrow(|histograms| {
            let &LatencyHistogram(histogram) = histograms
                .get(&(num_pages, call_source))
                .expect("No histogram for given call source and number of pages");
            histogram
        })
    }

    #[tokio::test]
    async fn should_observe_sign_with_ecdsa_metrics() {
        init_state_with_ecdsa_public_key();

        async fn sign_with_ecdsa_with_latency(
            latency: Duration,
            result: MetricsResult,
        ) -> Result<Vec<u8>, CallError> {
            let key_name = "test_key".to_string();
            let derivation_path = BoundedVec::new(vec![]);
            let message_hash = [0u8; 32];

            let mut runtime = MockCanisterRuntime::new();

            mock_increasing_time(&mut runtime, NOW, latency);

            let mock_result = match result {
                MetricsResult::Ok => Ok(vec![]),
                MetricsResult::Err => Err(CallError::from_sign_error(
                    ic_cdk::management_canister::SignCallError::CallFailed(
                        ic_cdk::call::CallFailed::CallPerformFailed(
                            ic_cdk::call::CallPerformFailed {},
                        ),
                    ),
                )),
            };
            runtime.expect_sign_with_ecdsa().return_const(mock_result);

            sign_with_ecdsa(key_name, derivation_path, message_hash, &runtime).await
        }

        let sign_with_ecdsa_ms = [
            500, 1_000, 1_250, 2_500, 3_250, 4_000, 8_000, 15_000, 50_000,
        ];
        for millis in &sign_with_ecdsa_ms {
            let result =
                sign_with_ecdsa_with_latency(Duration::from_millis(*millis), MetricsResult::Ok)
                    .await;
            assert!(result.is_ok());
        }

        let result =
            sign_with_ecdsa_with_latency(Duration::from_millis(5_000), MetricsResult::Err).await;
        assert!(result.is_err());

        let histogram = sign_with_ecdsa_histogram(MetricsResult::Ok);
        assert_eq!(
            histogram.iter().collect::<Vec<_>>(),
            vec![
                (1_000., 2.),
                (2_000., 1.),
                (4_000., 3.),
                (6_000., 0.),
                (8_000., 1.),
                (12_000., 0.),
                (20_000., 1.),
                (f64::INFINITY, 1.)
            ]
        );
        assert_eq!(histogram.sum(), sign_with_ecdsa_ms.iter().sum::<u64>());

        let histogram = sign_with_ecdsa_histogram(MetricsResult::Err);
        assert_eq!(
            histogram.iter().collect::<Vec<_>>(),
            vec![
                (1_000., 0.),
                (2_000., 0.),
                (4_000., 0.),
                (6_000., 1.),
                (8_000., 0.),
                (12_000., 0.),
                (20_000., 0.),
                (f64::INFINITY, 0.)
            ]
        );
        assert_eq!(histogram.sum(), 5_000);
    }

    fn sign_with_ecdsa_histogram(result: MetricsResult) -> Histogram<8> {
        crate::metrics::SIGN_WITH_ECDSA_LATENCY.with_borrow(|histograms| {
            let &LatencyHistogram(histogram) = histograms
                .get(&result)
                .expect("No histogram for given metric result");
            histogram
        })
    }

    async fn test_suspended_utxo_last_time_checked_timestamp(utxo: Utxo, reason: SuspendedReason) {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let mut runtime = MockCanisterRuntime::new();
        mock_constant_time(
            &mut runtime,
            NOW.checked_sub(Duration::from_secs(1)).unwrap(),
            8,
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
        mock_derive_user_address(&mut runtime, account);
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

        mock_derive_user_address(&mut runtime, account);
        mock_get_utxos_for_account(&mut runtime, account, vec![utxo.clone()]);
        mock_constant_time(&mut runtime, NOW, 6);
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

        mock_derive_user_address(&mut runtime, account);
        mock_get_utxos_for_account(&mut runtime, account, vec![utxo.clone()]);
        mock_constant_time(&mut runtime, NOW.saturating_add(Duration::from_secs(1)), 8);

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
            .expect_get_utxos()
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
                btc_checker_principal == &Some(BTC_CHECKER_CANISTER_ID) && utxo_ == &utxo
            })
            .return_const(Ok(response));
    }

    fn expect_check_transaction_returning_responses(
        runtime: &mut MockCanisterRuntime,
        utxo: Utxo,
        mut responses: Vec<CheckTransactionResponse>,
    ) {
        runtime
            .expect_check_transaction()
            .times(responses.len())
            .returning(move |btc_checker_principal, utxo_, _cycles| {
                assert!(btc_checker_principal == Some(BTC_CHECKER_CANISTER_ID) && utxo_ == &utxo);
                assert!(!responses.is_empty());
                Ok(responses.remove(0))
            });
    }

    fn mock_schedule_now_process_logic(runtime: &mut MockCanisterRuntime) {
        runtime.expect_global_timer_set().return_const(());
    }

    fn mock_increasing_time(
        runtime: &mut MockCanisterRuntime,
        start: Timestamp,
        interval: Duration,
    ) {
        let mut current_time = start;
        runtime.expect_time().returning(move || {
            let previous_time = current_time;
            current_time = current_time.saturating_add(interval);
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

    fn mock_derive_user_address(runtime: &mut MockCanisterRuntime, account: Account) {
        runtime
            .expect_derive_user_address()
            .withf(move |_state, account_| account_ == &account)
            .return_const("bc1p3jcdy9fn2g68jzafdlayrkvsltq8ttm7y2vkhxpxhxr9yw3jukks03ufup");
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
