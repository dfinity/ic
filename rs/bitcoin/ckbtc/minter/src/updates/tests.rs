mod update_balance {
    use crate::state::{audit, eventlog::Event, mutate_state, read_state, UtxoCheckStatus};
    use crate::storage;
    use crate::test_fixtures::{
        ecdsa_public_key, get_uxos_response, ignored_utxo, init_args, init_state, ledger_account,
        mock::MockCanisterRuntime, quarantined_utxo, KYT_CANISTER_ID, MINTER_CANISTER_ID,
    };
    use crate::updates::update_balance;
    use crate::updates::update_balance::{UpdateBalanceArgs, UtxoStatus};
    use ic_btc_interface::{GetUtxosResponse, Utxo};
    use ic_btc_kyt::CheckTransactionResponse;
    use icrc_ledger_types::icrc1::account::Account;

    #[tokio::test]
    async fn should_not_add_event_when_reevaluated_utxo_still_ignored() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let ignored_utxo = ignored_utxo();
        mutate_state(|s| audit::ignore_utxo(s, ignored_utxo.clone()));
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
        mock_get_utxos_for_account(&mut runtime, account, vec![ignored_utxo.clone()]);
        mock_schedule_now_process_logic(&mut runtime);

        let result = update_balance(
            UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
            &runtime,
        )
        .await;

        assert_eq!(result, Ok(vec![UtxoStatus::ValueTooSmall(ignored_utxo)]));
        assert_has_no_new_events(&events_before);
    }

    #[tokio::test]
    async fn should_do_kyt_when_reevaluating_ignored_utxo() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let ignored_utxo = ignored_utxo();
        mutate_state(|s| audit::ignore_utxo(s, ignored_utxo.clone()));
        mutate_state(|s| s.kyt_fee = ignored_utxo.value - 1);
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
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
            &[checked_utxo_event(ignored_utxo.clone(), false)],
        );
        assert!(!read_state(|s| s.has_ignored_utxo(&ignored_utxo)));
        assert_eq!(
            read_state(|s| s.utxo_checked_status(&ignored_utxo).cloned()),
            Some(UtxoCheckStatus::Tainted)
        );
    }

    #[tokio::test]
    async fn should_mint_reevaluated_ignored_utxo() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let ignored_utxo = ignored_utxo();
        mutate_state(|s| audit::ignore_utxo(s, ignored_utxo.clone()));
        mutate_state(|s| s.kyt_fee = ignored_utxo.value - 1);
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
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

        assert!(!read_state(|s| s.has_ignored_utxo(&ignored_utxo)));
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
                checked_utxo_event(ignored_utxo.clone(), true),
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
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let quarantined_utxo = quarantined_utxo();
        register_utxo_checked(&quarantined_utxo, UtxoCheckStatus::Tainted);
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
        mock_get_utxos_for_account(&mut runtime, account, vec![quarantined_utxo.clone()]);
        expect_check_transaction_returning(
            &mut runtime,
            quarantined_utxo.clone(),
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

        assert_eq!(result, Ok(vec![UtxoStatus::Tainted(quarantined_utxo)]));
        assert_has_no_new_events(&events_before);
    }

    #[tokio::test]
    async fn should_mint_reevaluated_tainted_utxo() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let quarantined_utxo = quarantined_utxo();
        register_utxo_checked(&quarantined_utxo, UtxoCheckStatus::Tainted);
        let kyt_fee = read_state(|s| s.kyt_fee);
        let minted_amount = quarantined_utxo.value - kyt_fee;
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
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

        assert!(!read_state(|s| s.has_ignored_utxo(&quarantined_utxo)));
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
                checked_utxo_event(quarantined_utxo.clone(), true),
                Event::ReceivedUtxos {
                    mint_txid: Some(1),
                    to_account: account,
                    utxos: vec![quarantined_utxo],
                },
            ],
        );
    }

    fn init_state_with_ecdsa_public_key() {
        use crate::lifecycle::init::InitArgs;
        use ic_base_types::CanisterId;
        init_state(InitArgs {
            new_kyt_principal: Some(CanisterId::unchecked_from_principal(KYT_CANISTER_ID.into())),
            ..init_args()
        });
        mutate_state(|s| s.ecdsa_public_key = Some(ecdsa_public_key()))
    }

    fn register_utxo_checked(utxo: &Utxo, status: UtxoCheckStatus) {
        mutate_state(|s| {
            audit::mark_utxo_checked(s, utxo, None, status, None);
        });
    }

    fn expect_bitcoin_get_utxos_returning(runtime: &mut MockCanisterRuntime, utxos: Vec<Utxo>) {
        runtime
            .expect_bitcoin_get_utxos()
            .times(1)
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
            .withf(move |kyt_principal, utxo_, _cycles| {
                kyt_principal == &KYT_CANISTER_ID && utxo_ == &utxo
            })
            .return_const(Ok(response));
    }

    fn mock_schedule_now_process_logic(runtime: &mut MockCanisterRuntime) {
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());
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

    fn checked_utxo_event(utxo: Utxo, clean: bool) -> Event {
        Event::CheckedUtxo {
            utxo,
            uuid: String::default(),
            clean,
            kyt_provider: None,
        }
    }
}
